"""Typed R2-D2 executor (plan §4/§6, Task 11).

The executor runs a validated plan (diagnostics first, then mutations) against
a fenced incident and enforces the §4 invariants:

* **Every diagnostic must PASS before any mutation runs** (PASS-before-side-
  effect). A FAIL/UNKNOWN diagnostic aborts the plan and no mutation runs.
* **Every mutation is gated twice**: the claim/authority is re-checked via the
  :class:`~operator_guards.r2d2.claims.ClaimManager` launch barrier AND the
  shared ED-209 policy is re-evaluated (engine ``evaluate`` + the sanctioned
  rules document) BEFORE the mutation — including daemon-side ``rule_add``.
  A deny/block is recorded in the shared ledger and the mutation does NOT run;
  R2-D2 may NEVER route around an ED-209 deny. A policy reviewer may BLOCK but
  cannot mint a kill grant or change the allowlist (there is no such path).
* **A mutation is FRESHLY verified afterward** (PASS/FAIL/UNKNOWN via
  ``common.proof.verify``) against post-mutation state re-read by the handler,
  never against the handler's self-report.
* **Zero verified operations or an unsupported adapter cannot resolve** — and a
  partial plan failure does not resolve.
* **Spawn-time owned-process attestation**: :meth:`Executor.spawn_owned`
  launches a dedicated R2-D2-owned disposable subprocess (``shell=False``) and
  records its ``(pid, start_time)`` into the store's owned-process registry at
  spawn time, so a later takeover validates ownership against the REGISTRY, not
  a claimant-supplied flag.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from operator_guards.common.proof import Verdict, verify
from operator_guards.ed209.engine import (
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_DENY,
    Decision,
    EvaluationContext,
    evaluate,
)
from operator_guards.ed209.ledger import HitLedger
from operator_guards.ed209.rules import compile_rules, load_rules
from operator_guards.r2d2.claims import ClaimManager, proc_start_time
from operator_guards.r2d2.handlers import (
    FORBIDDEN_PARAM_KEYS,
    OPERATION_NAMES,
    HandlerContext,
    HandlerError,
    get_handler,
)
from operator_guards.r2d2.store import IncidentStore

# Default maximum evidence age (seconds) before a step is rejected as stale.
DEFAULT_MAX_EVIDENCE_AGE = 300.0


# ---------------------------------------------------------------------------
# Executor errors
# ---------------------------------------------------------------------------

class PlanError(HandlerError):
    """A plan is structurally invalid (unknown op, forbidden key, duplicate id)."""


class StaleEvidenceError(HandlerError):
    """A step's evidence is older than the allowed freshness bound."""


class MissingPolicyError(HandlerError):
    """A mutation was attempted without an ED-209 policy (fails closed)."""


# ---------------------------------------------------------------------------
# Plan / outcome types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Step:
    """One planned operation (diagnostic or mutation)."""

    op_id: str
    operation: str
    params: Mapping[str, Any] = field(default_factory=dict)
    verify_kind: str | None = None  # VERIFY_KINDS member; None -> cannot PASS
    expected: Any = None
    evidence_time: float | None = None  # freshness timestamp for staleness check


@dataclass(frozen=True)
class Plan:
    """A plan: diagnostics (read-only, all must PASS) then mutations."""

    diagnostics: tuple = ()
    mutations: tuple = ()


@dataclass(frozen=True)
class StepOutcome:
    op_id: str
    operation: str
    verdict: Verdict
    evidence: str = ""
    unsupported: bool = False
    denied: bool = False
    timed_out: bool = False


@dataclass(frozen=True)
class RunReport:
    incident_id: str
    resolved: bool
    verdict: Verdict
    diagnostics: tuple = ()
    mutations: tuple = ()
    unsupported: tuple = ()
    denied: tuple = ()
    timed_out: tuple = ()


@dataclass
class OwnedProcess:
    """A disposable subprocess the executor launched and attested as owned."""

    pid: int
    start_time: float
    proc: Any = None  # subprocess.Popen handle


# ---------------------------------------------------------------------------
# Policy adapter: re-evaluate the shared ED-209 policy + record hits
# ---------------------------------------------------------------------------

@dataclass
class Policy:
    """Re-checks the shared ED-209 policy before a mutation.

    Reads and re-compiles the rules document on every check so a prior
    ``rule_add`` (which rewrites the document) is visible to subsequent
    re-checks. ``record`` writes deny/block hits to the shared ledger.
    """

    rules_path: str
    ledger: HitLedger | None = None
    session_id: str = "r2d2-executor"
    profile_home: str = os.path.expanduser("~")

    def _read_doc(self) -> dict:
        try:
            with open(self.rules_path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return {"rules": []}
        return data if isinstance(data, dict) else {"rules": []}

    def compile(self):
        return compile_rules(load_rules(self._read_doc()))

    def check(self, tool_name: str, payload: str, *, capabilities=frozenset()) -> Decision:
        compiled = self.compile()
        ctx = EvaluationContext(
            profile_home=self.profile_home,
            client_id="r2d2",
            session_id=self.session_id,
            turn_id="r2d2",
            surface="tool",
            tool_name=tool_name,
            capabilities=frozenset(capabilities),
            payload=payload,
            # No memory/gh/reviewer interfaces: a matched escalate/check cannot
            # be "deferred" into an authorization; it fails closed here.
            available=frozenset(),
        )
        return evaluate(compiled, ctx)

    def record(self, decision: Decision, *, tool_name: str, client_id: str | None = None) -> None:
        if self.ledger is None:
            return
        if decision.action not in (ACTION_DENY, ACTION_BLOCK):
            return
        self.ledger.record_hit(
            rule_id=(decision.matched_rule_ids[0] if decision.matched_rule_ids else ""),
            session_id=self.session_id,
            outcome=decision.action,
            counted_fact=decision.counted_fact,
            surface="tool",
            client_id=client_id,
        )


# ---------------------------------------------------------------------------
# The executor
# ---------------------------------------------------------------------------

class Executor:
    """Typed orchestrator over the fixed handler allowlist + claim/ED-209 gates.

    Contract: an Executor MAY run read-only diagnostics without a policy, but
    any MUTATION requires ``policy`` — a mutation attempted without one raises
    :class:`MissingPolicyError` (fails closed, never silently skips the ED-209
    recheck, never resolves).
    """

    def __init__(
        self,
        store: IncidentStore,
        claims: ClaimManager,
        *,
        policy: Policy | None = None,
        context: HandlerContext | None = None,
        clock=None,
        max_evidence_age: float | None = None,
    ):
        self.store = store
        self.claims = claims
        # ``policy=None`` is only valid for diagnostics-only use; mutations fail
        # closed in _run_mutation when no policy is present.
        self.policy = policy
        self.context = context if context is not None else HandlerContext()
        self.clock = clock if clock is not None else time.time
        self.max_evidence_age = max_evidence_age

    # -- entry point --------------------------------------------------------

    def execute(self, fence, plan: Plan) -> RunReport:
        incident_id = fence.claim.incident_id
        # Launch barrier: claim/authority re-check before anything runs.
        self.claims.validate_for_mutation(fence)
        self._validate_plan(plan)

        diag_outcomes: list[StepOutcome] = []
        for step in plan.diagnostics:
            self._assert_evidence_fresh(step)
            outcome = self._run_diagnostic(incident_id, step)
            diag_outcomes.append(outcome)
            if outcome.verdict is not Verdict.PASS:
                # PASS-before-side-effect: a non-PASS diagnostic aborts the plan.
                return self._build_report(incident_id, tuple(diag_outcomes), ())

        mut_outcomes: list[StepOutcome] = []
        for step in plan.mutations:
            self._assert_evidence_fresh(step)
            mut_outcomes.append(self._run_mutation(fence, incident_id, step))

        return self._build_report(incident_id, tuple(diag_outcomes), tuple(mut_outcomes))

    # -- plan validation ----------------------------------------------------

    def _validate_plan(self, plan: Plan) -> None:
        seen: set[str] = set()
        for step in (*plan.diagnostics, *plan.mutations):
            if not step.op_id or not step.op_id.strip():
                raise PlanError("every plan step requires a non-empty op_id")
            if step.op_id in seen:
                raise PlanError(f"duplicate op_id {step.op_id!r}")
            seen.add(step.op_id)
            if step.operation not in OPERATION_NAMES:
                raise PlanError(
                    f"unknown operation {step.operation!r}; not in the §4 allowlist"
                )
            self._check_forbidden_keys(step)
            get_handler(step.operation).validate(step.params)

    def _check_forbidden_keys(self, step: Step) -> None:
        for key in step.params:
            if key in FORBIDDEN_PARAM_KEYS:
                raise PlanError(
                    f"operation {step.operation!r}: forbidden param key {key!r} "
                    f"(no incident-provided command/path/kill/config/hook/authority)"
                )

    def _assert_evidence_fresh(self, step: Step) -> None:
        if self.max_evidence_age is None or step.evidence_time is None:
            return
        age = self.clock() - step.evidence_time
        if age > self.max_evidence_age:
            raise StaleEvidenceError(
                f"step {step.op_id!r}: evidence is stale "
                f"(age {age:.1f}s exceeds the {self.max_evidence_age}s bound)"
            )

    # -- diagnostics --------------------------------------------------------

    def _run_diagnostic(self, incident_id: str, step: Step) -> StepOutcome:
        handler = get_handler(step.operation)
        if handler.phase != "diagnostic":
            raise PlanError(f"operation {step.operation!r} is a mutation, not a diagnostic")
        try:
            result = handler.run(step.params, self.context, incident_id)
        except Exception as exc:  # noqa: BLE001 - a raising handler is contained
            return StepOutcome(
                op_id=step.op_id, operation=step.operation,
                verdict=Verdict.FAIL, evidence=self._handler_error_evidence(exc),
            )
        if result.timed_out:
            return StepOutcome(
                op_id=step.op_id, operation=step.operation,
                verdict=Verdict.UNKNOWN, evidence=result.evidence, timed_out=True,
            )
        verdict = self._verdict(step.verify_kind, result.actual, step.expected)
        return StepOutcome(
            op_id=step.op_id, operation=step.operation, verdict=verdict,
            evidence=result.evidence,
        )

    # -- mutations ----------------------------------------------------------

    def _run_mutation(self, fence, incident_id: str, step: Step) -> StepOutcome:
        # Recheck claim/authority before EVERY mutation.
        self.claims.validate_for_mutation(fence)

        handler = get_handler(step.operation)
        if not handler.is_supported(self.context):
            return StepOutcome(
                op_id=step.op_id, operation=step.operation,
                verdict=Verdict.UNKNOWN, unsupported=True,
            )
        if handler.phase != "mutation":
            raise PlanError(f"operation {step.operation!r} is a diagnostic, not a mutation")

        # Recheck the shared ED-209 policy before the mutation (never route
        # around a deny; a reviewer may block but cannot grant).
        if self.policy is None:
            # Fail CLOSED: a mutation may never run without an ED-209 policy.
            # Refuse loudly rather than silently skipping the recheck.
            raise MissingPolicyError(
                f"mutation {step.operation!r} requires an ED-209 policy; "
                f"Executor was constructed without one"
            )

        decision = self.policy.check(step.operation, self._payload(step))
        self.policy.record(decision, tool_name=step.operation)
        if decision.action != ACTION_ALLOW:
            return StepOutcome(
                op_id=step.op_id, operation=step.operation,
                verdict=Verdict.FAIL, denied=True, evidence=decision.counted_fact,
            )

        try:
            result = handler.run(step.params, self.context, incident_id)
        except Exception as exc:  # noqa: BLE001 - a raising handler is contained
            return StepOutcome(
                op_id=step.op_id, operation=step.operation,
                verdict=Verdict.FAIL, evidence=self._handler_error_evidence(exc),
            )
        if result.timed_out:
            # The side effect may or may not have happened; UNKNOWN -> route to
            # reconciliation, never resolve, never a blind retry.
            return StepOutcome(
                op_id=step.op_id, operation=step.operation,
                verdict=Verdict.UNKNOWN, evidence=result.evidence, timed_out=True,
            )
        if not result.performed:
            return StepOutcome(
                op_id=step.op_id, operation=step.operation,
                verdict=Verdict.UNKNOWN, evidence=result.evidence,
            )

        # FRESH verification AFTER the mutation: re-read post-mutation state.
        try:
            fresh = handler.verify(step.params, self.context, incident_id)
        except Exception as exc:  # noqa: BLE001 - a raising handler is contained
            return StepOutcome(
                op_id=step.op_id, operation=step.operation,
                verdict=Verdict.FAIL, evidence=self._handler_error_evidence(exc),
            )
        verdict = self._verdict(step.verify_kind, fresh, step.expected)
        return StepOutcome(
            op_id=step.op_id, operation=step.operation, verdict=verdict,
            evidence=result.evidence,
        )

    def _payload(self, step: Step) -> str:
        return json.dumps(
            {"operation": step.operation, "params": dict(step.params)}, sort_keys=True
        )

    @staticmethod
    def _verdict(verify_kind: str | None, actual: Any, expected: Any) -> Verdict:
        if verify_kind is None:
            return Verdict.UNKNOWN
        return verify(verify_kind, actual, expected)

    @staticmethod
    def _handler_error_evidence(exc: Exception) -> str:
        """Surface a contained handler exception in the step's evidence."""
        return f"{type(exc).__name__}: {exc}"

    # -- report -------------------------------------------------------------

    def _build_report(self, incident_id, diag_outcomes, mut_outcomes) -> RunReport:
        unsupported = tuple(o.operation for o in mut_outcomes if o.unsupported)
        denied = tuple(o.op_id for o in mut_outcomes if o.denied)
        timed_out = tuple(
            o.op_id for o in (*diag_outcomes, *mut_outcomes) if o.timed_out
        )
        resolved = bool(mut_outcomes) and all(
            o.verdict is Verdict.PASS for o in mut_outcomes
        )
        verdict = Verdict.PASS if resolved else Verdict.FAIL
        return RunReport(
            incident_id=incident_id,
            resolved=resolved,
            verdict=verdict,
            diagnostics=diag_outcomes,
            mutations=mut_outcomes,
            unsupported=unsupported,
            denied=denied,
            timed_out=timed_out,
        )

    # -- spawn-time owned-process attestation -------------------------------

    def spawn_owned(self, incident_id: str, argv) -> OwnedProcess:
        """Launch a dedicated disposable subprocess and ATTEST ownership.

        The ``(pid, start_time)`` of the spawned process is recorded into the
        store's owned-process registry at spawn time, so a later takeover
        validates against the REGISTRY — never a claimant-supplied flag. A
        process not in the registry is never SIGTERMed.
        """
        argv = [str(a) for a in argv]
        proc = subprocess.Popen(
            argv, shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        start_time = proc_start_time(proc.pid) or 0.0
        self.store.register_owned_process(incident_id, proc.pid, start_time)
        return OwnedProcess(pid=proc.pid, start_time=start_time, proc=proc)


__all__ = [
    "DEFAULT_MAX_EVIDENCE_AGE",
    "PlanError",
    "StaleEvidenceError",
    "MissingPolicyError",
    "Step",
    "Plan",
    "StepOutcome",
    "RunReport",
    "OwnedProcess",
    "Policy",
    "Executor",
]
