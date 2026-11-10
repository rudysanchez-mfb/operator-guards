"""Serialized claims, epoch fencing, and crash reconciliation (plan §4, Task 10).

A :class:`ClaimManager` wraps the durable :class:`~operator_guards.r2d2.store.
IncidentStore` and layers claim/fence semantics on top of its per-incident
lock, atomic snapshot writes, and write-ahead event append — it does NOT
re-implement durability.

Contracts enforced here:

* **Single-winner claim** — epoch allocation and claim identity are written
  under the store's ONE stable per-incident lock; two processes contending for
  the same incident yield exactly one winner (the loser sees a live claim and
  fails). Claim identity (epoch/claimant/nonce/pid/pid-start-time/lease-expiry/
  owned-proc) is durable in the incident state.
* **Epoch fencing before each side effect** — :func:`validate_claim` checks the
  current epoch, claimant, nonce, PID identity (PID **includes start time**, so
  a reused PID with a different start time is a different principal), and lease
  before any mutation is authorized. This is the launch barrier. **The fence
  carries no authority of its own: every fence field (claimant, epoch, nonce,
  pid, pid-start-time, owned-proc, lease-expiry) is checked against the
  DURABLE incident record — the fence's self-reported ``lease_expiry`` can
  never extend a lapsed durable lease.**
* **One queued/in-flight operation per incident** — a durable receipt
  (``queued -> started -> settled``) is recorded under the lock; an EXPIRED
  queued request is rejected at the launch barrier, and a STARTED receipt
  blocks a new mutating epoch until it settles or is reconciled.
* **Crash after side effect is UNKNOWN, never a blind replay** —
  :meth:`ClaimManager.reconcile` reads the durable receipt: ``started`` without
  a settled result means the side effect may or may not have happened, so the
  verdict is ``UNKNOWN`` and a re-diagnosis is required — the mutation is not
  re-run.
* **Bounded cleanup, no unsupervised kill** — :meth:`ClaimManager.takeover`
  only proceeds after lease expiry. A claimant whose ``(pid, start_time)`` is
  NOT attested in the store's owned-process registry (set at SPAWN TIME by the
  executor) is FROZEN and ESCALATED, never SIGTERMed — the self-asserted
  ``owned_proc`` flag carries no kill authority. Only a registry-attested
  disposable subprocess may be terminated as cleanup, after exact PID +
  start-time validation, with a bounded TERM/wait; it must be PROVEN dead
  before takeover.
* **Default max attempts is three** (reuses ``DEFAULT_MAX_ATTEMPTS``);
  exhaustion escalates and blocks further mutation.
"""

from __future__ import annotations

import os
import signal
import time
import uuid
from dataclasses import dataclass, replace
from typing import Callable

from operator_guards.common.proof import Verdict
from operator_guards.r2d2.schema import (
    PHASE_ESCALATED,
    PHASE_RESOLVED,
    RECEIPT_QUEUED,
    RECEIPT_SETTLED,
    RECEIPT_STARTED,
    Incident,
)
from operator_guards.r2d2.store import IncidentNotFoundError, IncidentStore

DEFAULT_LEASE_SECONDS = 30.0

# Bounded executor cleanup: how long to wait for a TERM'd owned proc to die.
_TERM_GRACE_SECONDS = 5.0

# Escalation reason recorded when max attempts are exhausted without resolution.
_ESCALATION_EXHAUSTED = "max attempts exhausted without resolution"


class ClaimError(Exception):
    """Base error for the claim/fence layer."""


class ClaimConflictError(ClaimError):
    """A live (unexpired) claim already exists for the incident."""


class LeaseExpiredError(ClaimError):
    """The fence's lease has lapsed (identity otherwise intact)."""


class StaleFenceError(ClaimError):
    """The fence is no longer authoritative: epoch/claim/nonce/pid mismatch or missing."""


class FrozenLaneError(ClaimError):
    """A stuck client/shared session is frozen for mutation and escalated.

    Raised instead of an unsupervised SIGTERM: a non-disposable claimant (or an
    owned proc that could not be proven dead) must not be killed without
    independent authority.
    """


class InFlightOperationError(ClaimError):
    """An operation is already queued/started; a new mutating op is blocked."""


@dataclass(frozen=True)
class Claim:
    """The durable identity of a claim holder (plan §4).

    ``pid`` and ``pid_start_time`` together are the process identity: a reused
    PID with a different start time is a DIFFERENT principal. ``owned_proc`` is
    True only for a dedicated R2-D2-owned disposable subprocess that may be
    terminated as executor cleanup.
    """

    incident_id: str
    epoch: int
    claimant_id: str
    nonce: str
    pid: int
    pid_start_time: float
    lease_expiry: float
    owned_proc: bool = False


@dataclass(frozen=True)
class Reconciliation:
    """The outcome of reconciling an incident's durable operation receipt."""

    incident_id: str
    verdict: Verdict
    receipt_state: str
    re_diagnose: bool


class Fence:
    """A validated claim handle; the only path to authorized mutation."""

    def __init__(self, manager: "ClaimManager", claim: Claim):
        self.manager = manager
        self.claim = claim

    def renew(self) -> "Fence":
        return self.manager.renew(self)

    def release(self) -> None:
        self.manager.release(self)


# ---------------------------------------------------------------------------
# Process identity (PID includes start time)
# ---------------------------------------------------------------------------

def proc_start_time(pid: int) -> float | None:
    """Return ``pid``'s start time (clock ticks) from /proc, or None if absent.

    Reading /proc/<pid>/stat field 22 (``starttime``). Returns None when the
    process does not exist (or the field is unreadable), which is the "dead"
    signal used by takeover.
    """
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            raw = f.read().decode("ascii", "replace")
    except OSError:
        return None
    close = raw.rfind(")")
    if close == -1:
        return None
    fields = raw[close + 2:].split()
    # After the comm (field 2), field 22 (starttime) is fields[19].
    if len(fields) <= 19:
        return None
    if fields[0] == "Z":
        return None  # zombie: the process is dead (not executing), pending reap
    try:
        return float(fields[19])
    except ValueError:
        return None


def _proc_matches(pid: int, start_time: float) -> bool:
    """True iff a live process with ``pid`` AND the recorded ``start_time`` exists.

    A reused PID with a different start time returns False: the ORIGINAL
    principal is dead even though the pid is recycled.
    """
    if pid <= 0:
        return False
    current = proc_start_time(pid)
    return current is not None and current == start_time


# ---------------------------------------------------------------------------
# Pure claim validation (the launch barrier)
# ---------------------------------------------------------------------------

def validate_claim(incident: Incident, claim: Claim, now: float) -> None:
    """Pure: assert ``claim`` is still the authority for ``incident`` at ``now``.

    The fence carries NO authority of its own: every field — claimant, epoch,
    nonce, pid, pid-start-time, owned-proc, and lease-expiry — is validated
    against the DURABLE incident record (the source of truth). Raises
    :class:`ClaimError` subclasses in a deterministic order: terminal phase
    first, then identity (claimant/epoch/nonce/pid/pid-start-time/owned-proc),
    then durable lease expiry, then lease-expiry equality.
    """
    if incident.phase in (PHASE_ESCALATED, PHASE_RESOLVED):
        raise ClaimError(
            f"incident {incident.id!r} is {incident.phase}; no further mutation"
        )
    if incident.claimant != claim.claimant_id:
        raise StaleFenceError(
            f"claim for {incident.id!r} is missing or held by another claimant"
        )
    if incident.epoch != claim.epoch:
        raise StaleFenceError(
            f"stale epoch for {incident.id!r}: fence={claim.epoch} current={incident.epoch}"
        )
    if incident.nonce != claim.nonce:
        raise StaleFenceError(f"claim nonce mismatch for {incident.id!r}")
    if incident.pid != claim.pid:
        raise StaleFenceError(f"claim PID mismatch for {incident.id!r}")
    if incident.pid_start_time != claim.pid_start_time:
        raise StaleFenceError(
            f"claim PID start-time mismatch for {incident.id!r} (PID reuse)"
        )
    if incident.owned_proc != claim.owned_proc:
        raise StaleFenceError(f"claim owned_proc mismatch for {incident.id!r}")
    # The lease is decided by the DURABLE record, never the fence's self-reported
    # field: a forged fence that extends its own lease_expiry must NOT revive an
    # already-lapsed durable lease.
    if incident.lease_expiry <= now:
        raise LeaseExpiredError(
            f"claim lease for {incident.id!r} expired at {incident.lease_expiry!r} (now {now!r})"
        )
    if incident.lease_expiry != claim.lease_expiry:
        raise StaleFenceError(
            f"claim lease_expiry mismatch for {incident.id!r}: "
            f"fence={claim.lease_expiry!r} durable={incident.lease_expiry!r}"
        )


# ---------------------------------------------------------------------------
# Claim manager / fence
# ---------------------------------------------------------------------------

class ClaimManager:
    """Serialized claims + epoch fencing around an :class:`IncidentStore`."""

    def __init__(
        self,
        store: IncidentStore,
        *,
        lease_seconds: float = DEFAULT_LEASE_SECONDS,
        clock: Callable[[], float] | None = None,
    ):
        self.store = store
        self.lease_seconds = lease_seconds
        self.clock = clock if clock is not None else time.time

    # -- reads --------------------------------------------------------------

    def _get(self, incident_id: str) -> Incident:
        self.store.refresh()
        inc = self.store.get_incident(incident_id)
        if inc is None:
            raise ClaimError(f"no incident {incident_id!r}")
        return inc

    def _update(self, incident_id: str, transform) -> Incident:
        try:
            return self.store.update_incident(incident_id, transform)
        except IncidentNotFoundError:
            raise ClaimError(f"no incident {incident_id!r}") from None

    @staticmethod
    def _resolve_pid(pid: int | None) -> int:
        return os.getpid() if pid is None else pid

    def _resolve_start_time(self, pid: int, pid_start_time: float | None) -> float:
        if pid_start_time is not None:
            return pid_start_time
        return proc_start_time(pid) or 0.0

    # -- claim lifecycle ----------------------------------------------------

    def acquire(
        self,
        incident_id: str,
        claimant_id: str,
        *,
        pid: int | None = None,
        pid_start_time: float | None = None,
        owned_proc: bool = False,
    ) -> Fence:
        """Claim an UNCLAIMED incident; single-winner under the incident lock.

        Raises :class:`ClaimConflictError` if a claim exists (live OR expired —
        an expired claim must go through :meth:`takeover`, which proves the old
        owner dead).
        """
        pid = self._resolve_pid(pid)
        pid_start_time = self._resolve_start_time(pid, pid_start_time)
        now = self.clock()

        def _take(inc: Incident) -> Incident:
            if inc.claimant:
                raise ClaimConflictError(
                    f"incident {incident_id!r} has an existing claim by {inc.claimant!r}"
                )
            if inc.op_state == RECEIPT_STARTED:
                raise InFlightOperationError(
                    f"incident {incident_id!r} has an in-flight operation; reconcile first"
                )
            return self._new_claim(inc, claimant_id, pid, pid_start_time, owned_proc, now)

        updated = self._update(incident_id, _take)
        return self._fence_for(updated)

    def takeover(
        self,
        incident_id: str,
        new_claimant_id: str,
        *,
        pid: int | None = None,
        pid_start_time: float | None = None,
        owned_proc: bool = False,
    ) -> Fence:
        """Reclaim an EXPIRED claim after proving the old owner is dead.

        Only after lease expiry. A non-disposable claimant (shared
        client/session/gateway/MCP owner) is FROZEN + ESCALATED, never killed.
        A disposable owner may be TERM'd (bounded) after exact PID + start-time
        validation, and must be PROVEN dead before the new epoch is allocated.
        """
        pid = self._resolve_pid(pid)
        pid_start_time = self._resolve_start_time(pid, pid_start_time)
        now = self.clock()

        def _take(inc: Incident) -> Incident:
            if inc.claimant and inc.lease_expiry > now:
                raise ClaimConflictError(
                    f"incident {incident_id!r} is still held by {inc.claimant!r} "
                    f"(lease unexpired)"
                )
            if inc.claimant:
                self._prove_old_owner_dead(inc)
            return self._new_claim(inc, new_claimant_id, pid, pid_start_time, owned_proc, now)

        updated = self._update(incident_id, _take)
        return self._fence_for(updated)

    def _prove_old_owner_dead(self, inc: Incident) -> None:
        # Ownership is ATTESTED at spawn time by the executor into the store's
        # owned-process registry. The self-asserted ``owned_proc`` flag carries
        # NO kill authority: a process absent from the registry is never
        # SIGTERMed (a claimant setting owned_proc=True + an arbitrary pid
        # cannot cause a takeover to kill an unrelated process).
        if not self.store.is_owned_process(inc.id, inc.pid, inc.pid_start_time):
            raise FrozenLaneError(
                f"incident {inc.id!r}: pid {inc.pid} (start {inc.pid_start_time!r}) "
                f"is not in the owned-process registry; never SIGTERM an "
                f"unregistered process"
            )
        if _proc_matches(inc.pid, inc.pid_start_time):
            self._terminate_owned_proc(inc.pid, inc.pid_start_time)
        # old owner is now provably dead (or never existed with that identity)

    def _terminate_owned_proc(self, pid: int, start_time: float) -> None:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return  # already gone
        except PermissionError as exc:
            raise FrozenLaneError(
                f"no permission to terminate owned proc {pid}"
            ) from exc
        deadline = time.monotonic() + _TERM_GRACE_SECONDS
        while time.monotonic() < deadline:
            if not _proc_matches(pid, start_time):
                return
            time.sleep(0.05)
        raise FrozenLaneError(
            f"owned proc {pid} did not die within {_TERM_GRACE_SECONDS}s; "
            f"freeze + escalate, do not escalate the kill"
        )

    def _new_claim(
        self,
        inc: Incident,
        claimant_id: str,
        pid: int,
        pid_start_time: float,
        owned_proc: bool,
        now: float,
    ) -> Incident:
        return replace(
            inc,
            epoch=inc.epoch + 1,
            claimant=claimant_id,
            nonce=uuid.uuid4().hex,
            pid=pid,
            pid_start_time=pid_start_time,
            lease_expiry=now + self.lease_seconds,
            owned_proc=owned_proc,
        )

    def _fence_for(self, updated: Incident) -> Fence:
        claim = Claim(
            incident_id=updated.id,
            epoch=updated.epoch,
            claimant_id=updated.claimant,
            nonce=updated.nonce,
            pid=updated.pid,
            pid_start_time=updated.pid_start_time,
            lease_expiry=updated.lease_expiry,
            owned_proc=updated.owned_proc,
        )
        return Fence(self, claim)

    # -- fence mutation helpers --------------------------------------------

    def validate_for_mutation(self, fence: Fence) -> None:
        """Assert ``fence`` is still authoritative (the launch barrier)."""
        inc = self._get(fence.claim.incident_id)
        validate_claim(inc, fence.claim, self.clock())

    def renew(self, fence: Fence) -> Fence:
        now = self.clock()

        def _r(inc: Incident) -> Incident:
            validate_claim(inc, fence.claim, now)
            return replace(inc, lease_expiry=now + self.lease_seconds)

        updated = self._update(fence.claim.incident_id, _r)
        return self._fence_for(updated)

    def release(self, fence: Fence) -> None:
        now = self.clock()

        def _r(inc: Incident) -> Incident:
            validate_claim(inc, fence.claim, now)
            return replace(
                inc,
                claimant="",
                nonce="",
                pid=0,
                pid_start_time=0.0,
                lease_expiry=0.0,
                owned_proc=False,
            )

        self._update(fence.claim.incident_id, _r)

    # -- operation receipt --------------------------------------------------

    def queue_operation(self, fence: Fence, op_id: str) -> None:
        now = self.clock()

        def _q(inc: Incident) -> Incident:
            validate_claim(inc, fence.claim, now)
            if inc.op_state == RECEIPT_STARTED:
                raise InFlightOperationError(
                    f"incident {inc.id!r} has an in-flight operation; settle/reconcile first"
                )
            return replace(
                inc,
                op_id=op_id,
                op_state=RECEIPT_QUEUED,
                op_epoch=fence.claim.epoch,
                op_verdict="",
            )

        self._update(fence.claim.incident_id, _q)

    def mark_started(self, fence: Fence, op_id: str) -> None:
        """The launch barrier: queued -> started, only for a CURRENT fence.

        Rejects an EXPIRED/stale fence, and rejects a queued op recorded under
        a DIFFERENT epoch (a queued old request cannot be resurrected).
        """
        now = self.clock()

        def _s(inc: Incident) -> Incident:
            validate_claim(inc, fence.claim, now)
            if inc.op_state != RECEIPT_QUEUED or inc.op_id != op_id:
                raise InFlightOperationError(
                    f"no queued operation {op_id!r} to start for {inc.id!r}"
                )
            if inc.op_epoch != fence.claim.epoch:
                raise StaleFenceError(
                    f"queued operation {op_id!r} belongs to a stale epoch "
                    f"({inc.op_epoch}) — rejected at the launch barrier"
                )
            return replace(inc, op_state=RECEIPT_STARTED)

        self._update(fence.claim.incident_id, _s)

    def mark_settled(self, fence: Fence, op_id: str, verdict: Verdict) -> None:
        """started -> settled, recording the verdict and bumping attempts.

        Max-attempt exhaustion with a non-PASS verdict ESCALATES the incident
        (no further mutation).
        """
        now = self.clock()

        def _t(inc: Incident) -> Incident:
            validate_claim(inc, fence.claim, now)
            if inc.op_state != RECEIPT_STARTED or inc.op_id != op_id:
                raise ClaimError(f"no started operation {op_id!r} to settle for {inc.id!r}")
            attempts = min(inc.attempts + 1, inc.max_attempts)
            updated = replace(
                inc,
                op_state=RECEIPT_SETTLED,
                op_verdict=verdict.value,
                attempts=attempts,
            )
            if attempts >= inc.max_attempts and verdict is not Verdict.PASS:
                updated = replace(
                    updated,
                    phase=PHASE_ESCALATED,
                    notification=_ESCALATION_EXHAUSTED,
                )
            return updated

        self._update(fence.claim.incident_id, _t)

    # -- reconciliation -----------------------------------------------------

    def reconcile(self, incident_id: str) -> Reconciliation:
        """Reconcile the durable operation receipt (read-only).

        * ``settled`` -> the recorded verdict (no re-diagnosis).
        * ``started`` -> the side effect may or may not have happened: verdict
          is UNKNOWN and a re-diagnosis is required (NEVER a blind replay).
        * ``queued``/empty -> nothing was launched; safe, no re-diagnosis.
        """
        inc = self._get(incident_id)
        state = inc.op_state
        if state == RECEIPT_SETTLED:
            verdict = Verdict(inc.op_verdict) if inc.op_verdict else Verdict.UNKNOWN
            return Reconciliation(incident_id, verdict, state, re_diagnose=False)
        if state == RECEIPT_STARTED:
            return Reconciliation(incident_id, Verdict.UNKNOWN, state, re_diagnose=True)
        return Reconciliation(incident_id, Verdict.UNKNOWN, state, re_diagnose=False)


__all__ = [
    "DEFAULT_LEASE_SECONDS",
    "RECEIPT_QUEUED",
    "RECEIPT_STARTED",
    "RECEIPT_SETTLED",
    "Claim",
    "ClaimError",
    "ClaimConflictError",
    "LeaseExpiredError",
    "StaleFenceError",
    "FrozenLaneError",
    "InFlightOperationError",
    "Reconciliation",
    "Fence",
    "ClaimManager",
    "validate_claim",
    "proc_start_time",
]
