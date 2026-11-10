"""R2-D2 supervisor — the systemd user-unit daemon entrypoint (plan Task 16).

The daemon's bounded loop ties together the existing R2-D2 pieces:

* **heartbeat** — refresh ``<home>/r2d2/heartbeat`` every tick (immediately at
  startup), so the observer's 60 s staleness check stays satisfied;
* **observe** — consume BOUNDED observations (tail, never slurp) through
  :class:`~operator_guards.r2d2.observer.Observer`, which auto-raises deduped
  incidents and emits local alerts;
* **claim/execute** — for each open incident, reconcile any in-flight
  operation, acquire (or takeover) the claim through the serialized
  :class:`~operator_guards.r2d2.claims.ClaimManager`, and run a bounded
  read-only diagnostic plan through the
  :class:`~operator_guards.r2d2.executor.Executor`;
* **IPC (client side)** — wire the
  :class:`~operator_guards.r2d2.client.OwningClientAdapter` so an incident that
  carries an explicit ``mcp_reconnect`` mutation plan + a live owning client can
  request native recovery over the owning-client socket (the supervisor never
  touches another process's MCP registry itself);
* **status** — expose heartbeat/incident/client/reconnect state.

Hard non-negotiable constraints honoured here:

* **No unhandled crash loop** — every stage of the tick is individually
  contained; an exception logs and the loop continues. ``SIGTERM``/``SIGINT``
  trigger a clean shutdown (exit 0).
* **Bounded** — observation consumption is tail-bounded, the incident sweep is
  over the durable store's committed incidents only, and the diagnostic
  subprocess (if any) runs under the handler's bounded deadline.
* **Never restart Hermes, never kill a non-owned process** — this module
  imports no systemctl/Hermes launcher and never signals a process directly;
  the only kill path is ``ClaimManager.takeover``, which requires the victim to
  be ATTESTED in the store's owned-process registry (spawn-time only) before it
  may be TERM'd. A non-owned claimant is FROZEN (``FrozenLaneError``), never
  signalled.
* **No hardcoded profile home** — ``home`` is an explicit argument (the unit
  passes ``--home``); the CLI default is the derived ``HERMES_HOME``/``~/.hermes``.

The supervisor runs DIAGNOSTICS autonomously (read-only). It does NOT
autonomously authorize mutations: the autonomous sweep is diagnostic-only and
matches "R2-D2 fails closed on authority". Recovery MUTATIONS are REACHABLE but
EXPLICIT: the supervisor constructs a real ED-209 :class:`Policy` (from the
runtime rules doc + shared ledger) and exposes :meth:`recovery_plan` /
:meth:`execute_recovery`, which run a supported mutation (``rule_add`` /
``notify_human`` / ``mcp_reconnect``) through that policy and, on full PASS,
append typed proof and RESOLVE the incident. A deny/FAIL/UNKNOWN aborts
(recorded, never resolved) — R2-D2 may never route around an ED-209 deny.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
from typing import Any

from operator_guards.common.identity import (
    client_id_for,
    ipc_socket_path,
    profile_id_for,
)
from operator_guards.common.proof import Verdict
from operator_guards.ed209.ledger import HitLedger
from operator_guards.r2d2.claims import (
    ClaimConflictError,
    ClaimError,
    ClaimManager,
    FrozenLaneError,
    InFlightOperationError,
    LeaseExpiredError,
    StaleFenceError,
)
from operator_guards.r2d2.client import OwningClientAdapter, record_typed_proof
from operator_guards.r2d2.executor import Executor, Plan, Policy, Step
from operator_guards.r2d2.handlers import (
    CHANNEL_LOCAL,
    OP_MCP_RECONNECT,
    OP_NOTIFY_HUMAN,
    OP_RULE_ADD,
    OP_SHELL_DIAG,
    PROBE_CLIENT_HEARTBEAT,
    HandlerContext,
)
from operator_guards.r2d2.observer import (
    Observer,
    iter_observations,
    list_client_records,
    read_heartbeat_file,
    state_root_for,
    write_heartbeat_file,
)
from operator_guards.r2d2.schema import PHASE_ESCALATED, PHASE_RESOLVED
from operator_guards.r2d2.store import IncidentStore

log = logging.getLogger("r2d2.supervisor")

DEFAULT_TICK_SECONDS = 15.0
OBSERVATIONS_PER_TICK = 500
CLAIMANT_ID = "r2d2-supervisor"
_TERMINAL_PHASES = frozenset({PHASE_RESOLVED, PHASE_ESCALATED})


class Supervisor:
    """The R2-D2 daemon: heartbeat + bounded observe + claim/execute + status."""

    def __init__(
        self,
        home: str,
        *,
        tick_seconds: float = DEFAULT_TICK_SECONDS,
        clock=None,
    ):
        self.home = os.path.abspath(home)
        self.root = state_root_for(self.home)
        self.tick_seconds = tick_seconds
        self._clock = clock if clock is not None else time.monotonic
        self._stop = threading.Event()

        self.store = IncidentStore(self.root)
        self.claims = ClaimManager(self.store)
        self.observer = Observer(self.root, store=self.store)
        self.adapter = self._build_adapter()
        self.policy = self._build_policy()
        self.executor = Executor(
            self.store,
            self.claims,
            policy=self.policy,  # real ED-209 policy: recovery mutations are reachable
            context=self._build_context(),
        )

    # -- wiring -------------------------------------------------------------

    def _build_context(self) -> HandlerContext:
        return HandlerContext(
            heartbeat_path=os.path.join(self.root, "heartbeat"),
            rules_path=os.path.join(self.home, "ed209", "rules.json"),
            hits_db=os.path.join(self.home, "ed209", "hits.db"),
            notify_dir=os.path.join(self.root, "notifications"),
            mcp_reconnect_adapter=self.adapter,
        )

    def _build_policy(self) -> Policy:
        """A real ED-209 policy from the runtime rules doc + shared ledger.

        Re-reads and re-compiles the rules document on every check, so a prior
        daemon-side ``rule_add`` is visible to subsequent re-checks. A deny is
        recorded in the shared ledger (a rule firing is provable, never silent).
        """
        rules_path = os.path.join(self.home, "ed209", "rules.json")
        hits_db = os.path.join(self.home, "ed209", "hits.db")
        return Policy(
            rules_path=rules_path,
            ledger=HitLedger(hits_db),
            session_id="r2d2-supervisor",
            profile_home=self.home,
        )

    def _build_adapter(self) -> OwningClientAdapter:
        """The client side of the owning-client IPC socket (resolved at call time)."""
        profile_id = profile_id_for(self.home)
        client_id = client_id_for(self.home)
        socket_path = ipc_socket_path(profile_id, client_id)
        return OwningClientAdapter(self.root, socket_path=socket_path)

    # -- the bounded tick ---------------------------------------------------

    def tick(self) -> None:
        """One bounded iteration: heartbeat, observe, claim/execute."""
        self._refresh_heartbeat()
        self._consume_observations()
        self._check_clients()
        self._process_incidents()

    def _refresh_heartbeat(self) -> None:
        try:
            write_heartbeat_file(self.root)
        except Exception as exc:  # noqa: BLE001 - heartbeat must not crash the daemon
            log.warning("heartbeat write failed: %s", exc)

    def _consume_observations(self) -> None:
        for obs in iter_observations(self.root, limit=OBSERVATIONS_PER_TICK):
            try:
                effects = self.observer.consume(obs)
            except Exception as exc:  # noqa: BLE001
                log.warning("observation consume failed: %s", exc)
                continue
            self._apply_effects(effects)

    def _check_clients(self) -> None:
        try:
            self._apply_effects(self.observer.check_clients())
        except Exception as exc:  # noqa: BLE001
            log.warning("client check failed: %s", exc)

    def _apply_effects(self, effects) -> None:
        # RaiseIncident/RecoveryRequest/Unsupported effects were already applied
        # by the observer to the durable store; local alerts are logged here.
        for e in effects:
            if getattr(e, "kind", None) == "local_alert":
                log.warning("r2d2 local alert: %s", getattr(e, "message", e))

    # -- incident processing -------------------------------------------------

    def _process_incidents(self) -> None:
        try:
            incidents = self.store.list_incidents()
        except Exception as exc:  # noqa: BLE001 - a corrupt state dir must not crash the daemon
            log.warning("list incidents failed: %s", exc)
            return
        for inc in incidents:
            if inc.phase in _TERMINAL_PHASES:
                continue
            try:
                self._process_incident(inc.id)
            except Exception as exc:  # noqa: BLE001 - one bad incident must not stop the sweep
                log.warning("incident %s processing failed: %s", inc.id, exc)

    def _process_incident(self, incident_id: str) -> None:
        try:
            rec = self.claims.reconcile(incident_id)
        except Exception:  # noqa: BLE001
            return
        if rec.re_diagnose:
            self._escalate(incident_id, "in-flight operation requires reconciliation")
            return

        fence = self._acquire(incident_id)
        if fence is None:
            return  # live claim elsewhere, or frozen lane — leave it
        try:
            report = self.executor.execute(fence, self._diagnostic_plan())
            log.info("incident %s diagnosed: %s", incident_id, report.verdict.value)
        finally:
            try:
                self.claims.release(fence)
            except Exception:  # noqa: BLE001
                pass

    def _acquire(self, incident_id: str):
        """Claim an incident, or takeover an expired one — never killing unowned.

        ``takeover`` is the only path that can signal a process, and it requires
        the victim to be ATTESTED in the store's owned-process registry; a
        non-owned claimant raises ``FrozenLaneError`` (caught here), never a
        signal. Returns ``None`` when the claim cannot be taken.
        """
        try:
            return self.claims.acquire(incident_id, CLAIMANT_ID, owned_proc=False)
        except (ClaimConflictError, InFlightOperationError):
            return None
        except (LeaseExpiredError, StaleFenceError):
            pass  # stale/expired claim -> try takeover
        except ClaimError:
            return None
        try:
            return self.claims.takeover(incident_id, CLAIMANT_ID, owned_proc=False)
        except (FrozenLaneError, ClaimConflictError, InFlightOperationError, ClaimError):
            return None
        except Exception:  # noqa: BLE001
            return None

    def _diagnostic_plan(self) -> Plan:
        """A bounded read-only diagnostic (no mutation)."""
        return Plan(
            diagnostics=(
                Step(
                    op_id="diag-heartbeat",
                    operation=OP_SHELL_DIAG,
                    params={"probe": PROBE_CLIENT_HEARTBEAT},
                    verify_kind="contains",
                    expected="host",
                ),
            ),
            mutations=(),
        )

    # -- recovery (explicit; the autonomous sweep stays diagnostic-only) -----

    _RECOVERY_OPS = frozenset({OP_RULE_ADD, OP_NOTIFY_HUMAN, OP_MCP_RECONNECT})

    def recovery_plan(self, incident, *, operation, params, verify_kind, expected) -> Plan:
        """Build a real recovery plan: diagnostics + ONE supported mutation.

        ``operation`` must be a supported recovery op (``rule_add`` /
        ``notify_human`` / ``mcp_reconnect``). ``params`` are the validated
        enumerated step params and ``verify_kind``/``expected`` the fresh
        post-mutation verification target. The daemon does NOT fabricate an
        operation — the caller supplies it — so recovery is reachable without
        inventing autonomy. ``mcp_reconnect`` is only supported when a live
        owning client + adapter exist (the handler reports UNSUPPORTED with a
        reason otherwise — never faked).
        """
        if operation not in self._RECOVERY_OPS:
            raise ValueError(
                f"operation {operation!r} is not a supported recovery op "
                f"(supported: {sorted(self._RECOVERY_OPS)})"
            )
        return Plan(
            diagnostics=(
                Step(
                    op_id="diag-heartbeat",
                    operation=OP_SHELL_DIAG,
                    params={"probe": PROBE_CLIENT_HEARTBEAT},
                    verify_kind="contains",
                    expected="host",
                ),
            ),
            mutations=(
                Step(
                    op_id=f"recover-{operation}",
                    operation=operation,
                    params=dict(params),
                    verify_kind=verify_kind,
                    expected=expected,
                ),
            ),
        )

    def execute_recovery(self, incident_id: str, plan: Plan):
        """Execute a recovery plan end-to-end (diagnose → mutate → verify → resolve).

        Runs under the wired ED-209 policy. On a full PASS the typed mutation
        proof is appended to the incident's durable ``mutation_plan`` and the
        incident is RESOLVED (proof=PASS). A deny/FAIL/UNKNOWN aborts (recorded,
        never resolved) — R2-D2 may never route around an ED-209 deny. Returns
        the executor's :class:`RunReport`, or ``None`` when the incident cannot
        be claimed.
        """
        fence = self._acquire(incident_id)
        if fence is None:
            return None
        try:
            report = self.executor.execute(fence, plan)
            if report.resolved:
                self._persist_resolution(plan, report)
            return report
        finally:
            try:
                self.claims.release(fence)
            except Exception:  # noqa: BLE001
                pass

    def _persist_resolution(self, plan: Plan, report) -> None:
        """Append typed PASS mutation proof and RESOLVE the incident."""
        steps = {s.op_id: s for s in plan.mutations}
        for outcome in report.mutations:
            step = steps.get(outcome.op_id)
            if step is None or outcome.verdict is not Verdict.PASS:
                continue
            record_typed_proof(
                self.store,
                report.incident_id,
                {
                    "op_id": outcome.op_id,
                    "kind": step.verify_kind or "contains",
                    "verdict": outcome.verdict.value,
                    "expected": step.expected,
                    "observed": (),
                    "evidence": outcome.evidence,
                },
            )
        self.store.done(report.incident_id, proof="PASS", reason="recovery verified end-to-end")

    def _escalate(self, incident_id: str, reason: str) -> None:
        try:
            self.store.done(incident_id, reason=reason[:200])
        except Exception as exc:  # noqa: BLE001
            log.warning("escalate %s failed: %s", incident_id, exc)

    # -- status -------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        try:
            incidents = self.store.list_incidents()
        except Exception:  # noqa: BLE001 - status must not crash on a corrupt state dir
            incidents = []
        return {
            "home": self.home,
            "root": self.root,
            "heartbeat_ts": read_heartbeat_file(self.root),
            "open_incidents": [
                inc.id
                for inc in incidents
                if inc.phase not in _TERMINAL_PHASES
            ],
            "clients": sorted(list_client_records(self.root)),
            "mcp_reconnect": "available" if self.adapter is not None else "unavailable",
        }

    # -- lifecycle ----------------------------------------------------------

    def request_shutdown(self) -> None:
        """Ask the loop to stop at the next boundary (clean shutdown)."""
        self._stop.set()

    def run_forever(self) -> None:
        """Run the bounded tick loop until ``request_shutdown`` is called."""
        try:
            self.tick()  # write a fresh heartbeat immediately
        except Exception:  # noqa: BLE001 - a corrupt state dir must not crash startup
            log.exception("initial tick failed; continuing")
        while not self._stop.is_set():
            self._stop.wait(self.tick_seconds)
            if self._stop.is_set():
                break
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - no unhandled crash loop
                log.exception("tick failed; continuing")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="r2d2-supervisor",
        description="R2-D2 capability-recovery supervisor (systemd user unit entrypoint).",
    )
    p.add_argument(
        "--home",
        default=None,
        help="profile home (default: $HERMES_HOME or ~/.hermes)",
    )
    p.add_argument(
        "--tick-seconds",
        type=float,
        default=DEFAULT_TICK_SECONDS,
        help=f"seconds between ticks (default {DEFAULT_TICK_SECONDS})",
    )
    p.add_argument(
        "--once",
        action="store_true",
        help="run one tick, print status JSON, and exit",
    )
    return p


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    home = (
        args.home
        or os.environ.get("HERMES_HOME", "").strip()
        or os.path.expanduser("~/.hermes")
    )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    sup = Supervisor(home, tick_seconds=args.tick_seconds)

    def _on_signal(signum, frame):  # noqa: ARG001 - signal handler signature
        sup.request_shutdown()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    if args.once:
        sup.tick()
        print(json.dumps(sup.status(), sort_keys=True))
        return 0
    sup.run_forever()
    return 0


__all__ = [
    "DEFAULT_TICK_SECONDS",
    "CLAIMANT_ID",
    "Supervisor",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
