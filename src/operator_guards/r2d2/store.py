"""Durable R2-D2 incident store: write-ahead event log + atomic snapshots.

Implements plan §4's durability contract exactly:

* **State root** — ``{events.jsonl (or numbered segments), incidents/,
  spool/, heartbeat, clients/}``. Tests pass an explicit ``root``; the runtime
  default is ``<OPERATOR_GUARDS_HOME>/r2d2/``.
* **One stable lock file per incident** — serializes read/modify/write and
  epoch/state updates; under it, exclusive claim creation and epoch/state
  update are single-winner (``O_CREAT|O_EXCL`` fence, mirroring ed209/state).
* **A separate stable event-log lock** — the ENTIRE read-modify-write (scan
  segments, allocate the next ``seq``, append a COMPLETE, bounded,
  NEWLINE-TERMINATED JSON record, fsync) happens under it, so sequence
  allocation is serialized and strictly monotonic across processes.
* **Readers accept ONLY newline-terminated valid records in sequence.** A
  partial OR JSON-valid-but-not-newline-terminated final suffix is
  UNCOMMITTED: its exact bytes are preserved for diagnosis, the segment is
  SEALED, and subsequent committed records go to a NEW numbered segment
  starting after the last committed sequence. We never append after a corrupt
  tail, never silently skip interior corruption, never rewrite prior valid
  rows. INTERIOR corruption stops recovery and ESCALATES
  (:class:`StoreCorruptionError`). No CRC is introduced.
* **Atomic state writes** — temp file + fsync + ``os.replace`` + parent-dir
  fsync (all strict: a failure raises, it does not silently succeed).
* **Startup reconciliation** — durable events whose snapshot update was
  interrupted are replayed into their snapshots; request/event IDs are
  deduplicated across segments.
* **raise commits before the id** — ``raise_incident`` appends the CREATE
  event (fsync) THEN writes the snapshot (atomic); the CLI prints the id only
  after both. A failed raise followed by a retry never produces two committed
  incidents (idempotent by id and dedupe_key).

``done`` takes a NONEMPTY proof but validates it against the current
incident: a bare prose string (``"fixed"``) cannot authorize closure; only a
structural ``PASS`` with a resolvable mutation plan resolves, while a manual
closure reason (``--reason``) escalates distinctly from verified resolution.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

from operator_guards.common.paths import default_home, env_path
from operator_guards.common.proof import Verdict
from operator_guards.r2d2.schema import (
    NOTIFICATION_MAX_CHARS,
    PHASE_ESCALATED,
    PHASE_RESOLVED,
    Incident,
    IncidentError,
    incident_from_dict,
    incident_to_dict,
    load_incident,
)

# Default runtime state root (tests MUST pass an explicit root).
# Configurable: OPERATOR_GUARDS_R2D2_STATE, else <home>/r2d2.
DEFAULT_STATE_ROOT = env_path(
    "OPERATOR_GUARDS_R2D2_STATE",
    str(Path(default_home()) / "r2d2"),
)

# Lock tuning (mirrors ed209/state.py).
_LOCK_POLL_SECONDS = 0.01
_LOCK_WAIT_SECONDS = 5.0
_LOCK_STALE_SECONDS = 30.0

# Event types emitted by this leaf.
EVENT_CREATED = "incident.created"
EVENT_RESOLVED = "incident.resolved"
EVENT_ESCALATED = "incident.escalated"
EVENT_UPDATED = "incident.updated"

_EVENT_STATE_TYPES = frozenset(
    {EVENT_CREATED, EVENT_RESOLVED, EVENT_ESCALATED, EVENT_UPDATED}
)

_FILENAME_SAFE = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)
_MAX_NAME = 120


class StoreError(Exception):
    """Base error for the durable store (surfaces as a clean CLI failure)."""


class StoreCorruptionError(StoreError):
    """Interior event-log corruption: recovery stops and ESCALATES."""


class IncidentNotFoundError(StoreError):
    """A requested incident is not committed in the store."""


def _safe_name(value: str) -> str:
    """Map an incident id to a safe basename (no traversal, stable)."""
    if not isinstance(value, str) or not value:
        raise StoreError("incident id must be a non-empty string")
    safe = "".join(c if c in _FILENAME_SAFE else "_" for c in value)
    if safe != value or safe in (".", ".."):
        safe = "s_" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
    if len(safe) > _MAX_NAME:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        safe = f"{safe[:_MAX_NAME - 9]}_{digest[:8]}"
    return safe


class _FileLock:
    """Single-winner exclusive lock via O_CREAT|O_EXCL (cross-process fence).

    A stale lock (older than ``stale_seconds``, e.g. a crashed holder) is
    broken; acquisition is bounded, and failure raises :class:`StoreError`
    (fail closed).
    """

    def __init__(self, path: str, wait_seconds: float = _LOCK_WAIT_SECONDS):
        self.path = path
        self.wait_seconds = wait_seconds
        self._fd: int | None = None

    def __enter__(self) -> "_FileLock":
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        deadline = time.monotonic() + self.wait_seconds
        while True:
            try:
                self._fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
                break
            except FileExistsError:
                # A vanished lock is NOT staleness: retry without unlinking,
                # or we could delete a replacement lock owned by a new holder.
                try:
                    age = time.time() - os.path.getmtime(self.path)
                except FileNotFoundError:
                    continue
                except OSError:
                    age = None
                if age is not None and age > _LOCK_STALE_SECONDS:
                    try:
                        stat = os.stat(self.path)
                    except OSError:
                        continue
                    if time.time() - stat.st_mtime > _LOCK_STALE_SECONDS:
                        try:
                            os.unlink(self.path)
                        except OSError:
                            pass
                    continue
                if time.monotonic() >= deadline:
                    raise StoreError(f"lock unavailable: {self.path}")
                time.sleep(_LOCK_POLL_SECONDS)
        return self

    def __exit__(self, *exc) -> bool:
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        try:
            os.unlink(self.path)
        except OSError:
            pass
        return False

    def _stale(self) -> bool:
        """Whether an EXISTING lock is stale; a missing lock is never stale."""
        try:
            return time.time() - os.path.getmtime(self.path) > _LOCK_STALE_SECONDS
        except FileNotFoundError:
            return False
        except OSError:
            return False


class IncidentStore:
    """Durable incident store: write-ahead events + atomic per-incident snapshots."""

    def __init__(self, root: str = DEFAULT_STATE_ROOT):
        self.root = root
        self.incidents_dir = os.path.join(root, "incidents")
        self.spool_dir = os.path.join(root, "spool")
        self.clients_dir = os.path.join(root, "clients")
        self.owned_dir = os.path.join(root, "owned")
        self._recovered = False
        self._incidents: dict[str, Incident] = {}
        self._committed_events: list[dict] = []
        self._event_ids: set[str] = set()
        self._active_segment = 0

    # -- paths --------------------------------------------------------------

    def _segment_path(self, index: int) -> str:
        if index == 0:
            return os.path.join(self.root, "events.jsonl")
        return os.path.join(self.root, f"events.{index}.jsonl")

    def _segment_indices(self) -> list[int]:
        idxs: set[int] = set()
        try:
            names = os.listdir(self.root)
        except OSError:
            return []
        for name in names:
            if name == "events.jsonl":
                idxs.add(0)
            elif name.startswith("events.") and name.endswith(".jsonl"):
                mid = name[len("events."):-len(".jsonl")]
                if mid.isdigit():
                    idxs.add(int(mid))
        return sorted(idxs)

    def _snapshot_path(self, incident_id: str) -> str:
        return os.path.join(self.incidents_dir, _safe_name(incident_id) + ".json")

    def _incident_lock_path(self, incident_id: str) -> str:
        return os.path.join(self.incidents_dir, _safe_name(incident_id) + ".lock")

    def _event_lock_path(self) -> str:
        return os.path.join(self.root, "events.lock")

    # -- public read API ----------------------------------------------------

    def get_incident(self, incident_id: str) -> Incident | None:
        self._ensure_recovered()
        return self._incidents.get(incident_id)

    def list_incidents(self) -> list[Incident]:
        self._ensure_recovered()
        return [self._incidents[i] for i in sorted(self._incidents)]

    def list_incident_ids(self) -> list[str]:
        self._ensure_recovered()
        return sorted(self._incidents)

    def list_events(self, limit: int | None = None) -> list[dict]:
        self._ensure_recovered()
        events = self._committed_events
        return events if limit is None else events[:limit]

    # -- public mutation API ------------------------------------------------

    def raise_incident(self, record: Mapping[str, Any]) -> Incident:
        """Durably create (or reconcile) an incident; idempotent by id/key.

        Appends a durable CREATE event (fsync) then writes the snapshot
        atomically. Any durability failure raises :class:`StoreError` with
        nothing reported as a success id; a retry yields exactly one committed
        incident (deduped by id and dedupe_key across the event log).
        """
        inc = load_incident(record)  # IncidentError on invalid -> propagates
        incident_id = inc.id
        try:
            return self._raise_committed(inc)
        except (StoreError, StoreCorruptionError):
            raise
        except OSError as exc:
            raise StoreError(
                f"failed to durably commit incident {incident_id!r}: {exc}"
            ) from exc

    def _raise_committed(self, inc: Incident) -> Incident:
        incident_id = inc.id
        self._ensure_recovered()
        with self._incident_lock(incident_id):
            if incident_id in self._incidents:
                return self._incidents[incident_id]
            for other_id in list(self._incidents):
                other = self._incidents[other_id]
                if other.dedupe_key and other.dedupe_key == inc.dedupe_key:
                    return other
            now = time.time()
            committed = replace(inc, created_at=now, updated_at=now)
            event = self._make_event(EVENT_CREATED, committed)
            self._append_event(event)
            self._incidents[incident_id] = committed
            self._write_snapshot(committed)
            return committed

    def done(
        self,
        incident_id: str,
        *,
        proof: str | None = None,
        reason: str | None = None,
    ) -> Incident:
        """Close an incident: verified PASS resolution or manual escalation.

        ``proof`` must be a NONEMPTY structural verdict; a bare prose string
        cannot authorize closure. Verified resolution requires a PASS verdict
        AND a resolvable mutation plan (validated by the closed schema). A
        manual ``reason`` escalates — distinct from verified resolution.
        """
        self._ensure_recovered()
        with self._incident_lock(incident_id):
            inc = self._incidents.get(incident_id)
            if inc is None:
                raise IncidentNotFoundError(f"no committed incident {incident_id!r}")
            updated, event_type = self._resolve_done(inc, proof, reason)
            event = self._make_event(event_type, updated)
            self._append_event(event)
            self._incidents[incident_id] = updated
            self._write_snapshot(updated)
            return updated

    def update_incident(
        self,
        incident_id: str,
        transform,
        *,
        event_type: str = EVENT_UPDATED,
    ) -> Incident:
        """Atomically read-modify-write an incident under its per-incident lock.

        ``transform(incident) -> Incident`` computes the new state. The store
        re-reads the incident's CURRENT durable state from disk UNDER the lock
        (so claim/epoch/receipt writes made by OTHER processes are observed),
        appends a durable ``event_type`` event, and writes the snapshot
        atomically — the same durability path as ``raise``/``done``. Raises
        :class:`IncidentNotFoundError` when the incident is absent.
        """
        self._ensure_recovered()
        with self._incident_lock(incident_id):
            self._recovered = False
            self._ensure_recovered()  # fresh state under the lock (cross-process)
            inc = self._incidents.get(incident_id)
            if inc is None:
                raise IncidentNotFoundError(f"no committed incident {incident_id!r}")
            updated = transform(inc)
            if updated is inc:
                return inc
            if not isinstance(updated, Incident):
                raise StoreError(
                    f"transform for incident {incident_id!r} must return an Incident"
                )
            event = self._make_event(event_type, updated)
            self._append_event(event)
            self._incidents[incident_id] = updated
            self._write_snapshot(updated)
            return updated

    def refresh(self) -> None:
        """Re-read durable state from disk (cross-process visibility).

        Claims/executor need to observe state written by OTHER processes after
        this instance has recovered; ``refresh`` forces a fresh recovery pass.
        """
        self._recovered = False
        self._ensure_recovered()

    # -- owned-process registry (spawn-time attestation; Task 11) -----------

    def register_owned_process(self, incident_id: str, pid: int, start_time: float) -> None:
        """ATTEST that ``(pid, start_time)`` is an R2-D2-owned disposable proc.

        Recorded at SPAWN TIME by the executor (the only writer). A later
        takeover validates ownership against this registry — NOT a
        claimant-supplied ``owned_proc`` flag — so a process absent from the
        registry is never SIGTERMed. Append-only per incident; written via the
        same atomic temp+fsync+replace path as snapshots.
        """
        os.makedirs(self.owned_dir, exist_ok=True)
        entry = [int(pid), float(start_time)]
        procs = self._read_owned_procs(incident_id)
        if entry not in procs:
            procs.append(entry)
        data = (
            json.dumps(
                {"incident_id": incident_id, "procs": procs}, sort_keys=True
            )
            + "\n"
        ).encode("utf-8")
        self._atomic_write(self._owned_procs_path(incident_id), data)

    def is_owned_process(self, incident_id: str, pid: int, start_time: float) -> bool:
        """Whether ``(pid, start_time)`` was attested as owned for ``incident_id``."""
        return [int(pid), float(start_time)] in self._read_owned_procs(incident_id)

    def _owned_procs_path(self, incident_id: str) -> str:
        return os.path.join(self.owned_dir, _safe_name(incident_id) + ".json")

    def _read_owned_procs(self, incident_id: str) -> list:
        path = self._owned_procs_path(incident_id)
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return []
        raw = data.get("procs") if isinstance(data, dict) else None
        if not isinstance(raw, list):
            return []
        out: list = []
        for p in raw:
            if isinstance(p, list) and len(p) == 2:
                try:
                    out.append([int(p[0]), float(p[1])])
                except (TypeError, ValueError):
                    continue
        return out

    # -- done validation ----------------------------------------------------

    def _resolve_done(self, inc: Incident, proof: str | None, reason: str | None):
        if inc.phase in (PHASE_RESOLVED, PHASE_ESCALATED):
            raise StoreError(f"incident {inc.id!r} is already {inc.phase}")
        now = time.time()
        if proof is not None:
            proof = proof.strip()
            if not proof:
                raise StoreError(
                    "proof must be non-empty (a blank proof cannot authorize closure)"
                )
            verdict = self._coerce_verdict(proof)
            if verdict != Verdict.PASS:
                raise StoreError(
                    f"cannot close with proof {proof!r}: only a structural PASS "
                    f"authorizes verified resolution"
                )
            updated = replace(inc, phase=PHASE_RESOLVED, proof=Verdict.PASS, updated_at=now)
            # The closed schema enforces "resolved requires PASS proof + a
            # non-empty mutation plan whose EVERY op PASSes".
            try:
                load_incident(incident_to_dict(updated))
            except IncidentError as exc:
                raise StoreError(f"cannot resolve {inc.id!r}: {exc}") from exc
            return updated, EVENT_RESOLVED
        if reason is not None:
            reason = reason.strip()
            if not reason:
                raise StoreError("manual closure reason must be non-empty")
            updated = replace(
                inc,
                phase=PHASE_ESCALATED,
                notification=reason[:NOTIFICATION_MAX_CHARS],
                updated_at=now,
            )
            return updated, EVENT_ESCALATED
        raise StoreError("done requires --proof PASS (verified) or --reason (manual closure)")

    @staticmethod
    def _coerce_verdict(text: str) -> Verdict:
        try:
            return Verdict(text.strip().upper())
        except ValueError:
            raise StoreError(
                f"proof {text!r} must be a structural verdict (PASS|FAIL|UNKNOWN), "
                f"not prose"
            ) from None

    # -- event construction -------------------------------------------------

    def _make_event(self, type_: str, incident: Incident) -> dict:
        data: dict[str, Any] = {"incident": incident_to_dict(incident)}
        if type_ == EVENT_ESCALATED:
            data["reason"] = incident.notification
        # "seq" is assigned under the event-log lock in _append_event so seq
        # allocation is serialized and strictly monotonic across processes.
        return {
            "event_id": uuid.uuid4().hex,
            "type": type_,
            "incident_id": incident.id,
            "ts": incident.updated_at,
            "data": data,
        }

    # -- event-log append (write + fsync, rollback on failure) --------------

    def _append_event(self, event: dict) -> None:
        """Append one newline-terminated record to the active segment + fsync.

        The ENTIRE read-modify-write of the event log — scan segments, derive
        the next sequence, append the newline-terminated record, fsync — happens
        while holding the single stable event-log lock, so sequence allocation
        is serialized and strictly monotonic across processes. A failed
        write/fsync rolls the append back (truncate to the original size) so no
        uncommitted record lingers; a leftover that cannot be rolled back is
        sealed as a torn tail by the next recovery.
        """
        with self._event_lock():
            events = self._scan_segments()
            seq = max((int(ev.get("seq", 0)) for ev in events), default=0) + 1
            event["seq"] = seq
            data = (
                json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
            ).encode("utf-8")
            path = self._segment_path(self._active_segment)
            existed = os.path.exists(path)
            wrote = False
            pos = 0
            try:
                with open(path, "ab") as f:
                    pos = f.tell()
                    f.write(data)
                    wrote = True
                    f.flush()
                    os.fsync(f.fileno())
                if not existed:
                    self._fsync_dir(self.root)
            except BaseException:
                if wrote:
                    self._truncate_to(path, pos)
                raise
        self._committed_events.append(event)
        self._event_ids.add(event["event_id"])

    @staticmethod
    def _truncate_to(path: str, size: int) -> None:
        try:
            with open(path, "r+b") as f:
                f.truncate(size)
                f.flush()
        except OSError:
            pass  # best effort; recovery seals any leftover torn tail

    # -- atomic snapshot write (temp + fsync + replace + dir fsync) ---------

    def _write_snapshot(self, incident: Incident) -> None:
        data = (
            json.dumps(
                incident_to_dict(incident), ensure_ascii=False, sort_keys=True, indent=2
            )
            + "\n"
        ).encode("utf-8")
        self._atomic_write(self._snapshot_path(incident.id), data)

    def _atomic_write(self, path: str, data: bytes) -> None:
        dirpath = os.path.dirname(path) or "."
        os.makedirs(dirpath, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=dirpath)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            self._fsync_dir(dirpath)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _fsync_dir(self, dirpath: str) -> None:
        """Strict directory fsync (a failure propagates, per the durability contract)."""
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        dfd = os.open(dirpath, flags)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    # -- snapshot read ------------------------------------------------------

    def _load_snapshot(self, incident_id: str) -> Incident | None:
        path = self._snapshot_path(incident_id)
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            return incident_from_dict(data)
        except (OSError, ValueError, IncidentError, TypeError, KeyError):
            return None

    def _load_all_snapshots(self) -> list[Incident]:
        out: list[Incident] = []
        try:
            names = os.listdir(self.incidents_dir)
        except OSError:
            return out
        for name in names:
            if not name.endswith(".json"):
                continue
            inc_id = name[:-len(".json")]
            snap = self._load_snapshot(inc_id)
            if snap is not None:
                out.append(snap)
        return out

    # -- locking ------------------------------------------------------------

    @contextmanager
    def _incident_lock(self, incident_id: str):
        with _FileLock(self._incident_lock_path(incident_id)):
            yield

    @contextmanager
    def _event_lock(self):
        with _FileLock(self._event_lock_path()):
            yield

    # -- recovery + reconciliation ------------------------------------------

    def _ensure_recovered(self) -> None:
        if self._recovered:
            return
        os.makedirs(self.root, exist_ok=True)
        os.makedirs(self.incidents_dir, exist_ok=True)
        os.makedirs(self.spool_dir, exist_ok=True)
        os.makedirs(self.clients_dir, exist_ok=True)

        events = self._scan_segments()

        self._incidents = {}
        self._event_ids = set()
        for ev in events:
            if ev["event_id"] in self._event_ids:
                continue  # dedupe event ids across segments
            self._event_ids.add(ev["event_id"])
            if ev.get("type") in _EVENT_STATE_TYPES:
                inc_dict = (ev.get("data") or {}).get("incident")
                if isinstance(inc_dict, dict):
                    try:
                        self._incidents[inc_dict["id"]] = incident_from_dict(inc_dict)
                    except (IncidentError, KeyError, TypeError) as exc:
                        raise StoreCorruptionError(
                            f"invalid incident payload in event {ev.get('event_id')!r}: {exc}"
                        ) from exc

        # Merge any snapshot whose event was somehow absent (defensive).
        for snap in self._load_all_snapshots():
            if snap.id not in self._incidents:
                self._incidents[snap.id] = snap

        # Reconcile: materialize snapshots whose write was interrupted.
        for inc in self._incidents.values():
            snap = self._load_snapshot(inc.id)
            if snap is None or snap.updated_at < inc.updated_at:
                self._write_snapshot(inc)

        self._committed_events = events
        self._recovered = True

    def _scan_segments(self) -> list[dict]:
        idxs = self._segment_indices()
        events: list[dict] = []
        torn_on_last = False
        last_index = max(idxs, default=0)
        for idx in idxs:
            committed, torn = self._read_segment(self._segment_path(idx))
            events.extend(committed)
            if torn and idx == last_index:
                torn_on_last = True
        self._active_segment = last_index + 1 if torn_on_last else last_index
        return events

    @staticmethod
    def _read_segment(path: str) -> tuple[list[dict], bool]:
        """Read one segment: return (committed_records, has_torn_tail).

        A torn tail is the FINAL suffix (partial OR JSON-valid but not
        newline-terminated). Any invalid/empty record that is NOT the final
        suffix is INTERIOR corruption and raises :class:`StoreCorruptionError`.
        """
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except FileNotFoundError:
            return [], False
        if raw == b"":
            return [], False
        lines = raw.split(b"\n")
        committed: list[dict] = []
        for i, line in enumerate(lines):
            is_last = i == len(lines) - 1
            if is_last:
                if line == b"":
                    break  # clean newline-terminated end
                return committed, True  # uncommitted suffix (torn tail)
            # interior line: must be a valid non-empty JSON record
            if line.strip() == b"":
                raise StoreCorruptionError(
                    f"interior corruption in {path}: empty record at line {i + 1}"
                )
            try:
                committed.append(json.loads(line.decode("utf-8")))
            except (ValueError, UnicodeDecodeError) as exc:
                raise StoreCorruptionError(
                    f"interior corruption in {path}: invalid record at line {i + 1}: {exc}"
                ) from exc
        return committed, False
