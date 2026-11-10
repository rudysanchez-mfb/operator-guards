"""Typed R2-D2 executor + fixed handler allowlist (plan §4/§6, Task 11).

Locks the executor contract with REAL store/claim/ledger state:

* every diagnostic must PASS before any mutation runs (PASS-before-side-effect);
* an empty plan / zero verified operations / an unsupported adapter cannot
  resolve an incident (proof-before-closure);
* R2-D2 can never route around an ED-209 deny: the shared policy is re-checked
  before every mutation (including daemon-side ``rule_add``), a deny is
  recorded in the ledger, and the mutation's side effect does not occur;
* operations are dispatched to FIXED handlers with VALIDATED ENUMERATED params
  — arbitrary commands/executables/paths, config keys, hook/approval edits,
  guard unlocks, and broad process-pattern kills are all rejected; the incident
  must never carry a shell command, executable path, or arbitrary config key;
* a mutation is FRESHLY verified against post-mutation state after it runs;
* spawn-time owned-process attestation: the executor records the (pid,
  start_time) of a disposable subprocess it launches into a store registry, and
  a takeover only ever SIGTERMs a process present in that registry — a
  non-registered pid is never killed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest

from operator_guards.common.proof import Verdict
from operator_guards.ed209.ledger import HitLedger
from operator_guards.r2d2.claims import ClaimManager, FrozenLaneError, proc_start_time
from operator_guards.r2d2.executor import (
    Executor,
    MissingPolicyError,
    Plan,
    PlanError,
    Policy,
    StaleEvidenceError,
    Step,
)
from operator_guards.r2d2.handlers import (
    CHANNEL_LOCAL,
    EXECUTABLE_OPERATIONS,
    OPERATION_NAMES,
    OP_CONFIG_SET,
    OP_MCP_RECONNECT,
    OP_NOTIFY_HUMAN,
    OP_RULE_ADD,
    OP_SESSION_STOP_RESUME,
    OP_SHELL_DIAG,
    PROBE_CLIENT_HEARTBEAT,
    PROBE_LOG_TAIL,
    HandlerContext,
    InvalidParamsError,
    run_bounded,
)
from operator_guards.r2d2.store import IncidentStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _raise(store, incident_id="inc-1"):
    return store.raise_incident(
        {
            "id": incident_id,
            "severity": "mechanical",
            "symptom": "service unreachable",
            "phase": "open",
            "dedupe_key": f"d-{incident_id}",
        }
    )


def _ctx(tmp_path, **overrides):
    defaults = dict(
        heartbeat_path=str(tmp_path / "heartbeat.txt"),
        mcp_status_path=str(tmp_path / "mcp_status.txt"),
        log_targets={"r2d2": str(tmp_path / "r2d2.log")},
        rules_path=str(tmp_path / "rules.json"),
        hits_db=str(tmp_path / "hits.db"),
        notify_dir=str(tmp_path / "notify"),
    )
    defaults.update(overrides)
    return HandlerContext(**defaults)


def _setup(tmp_path, *, context=None, policy=None, clock=None, max_evidence_age=None):
    root = str(tmp_path / "r2d2")
    store = IncidentStore(root)
    _raise(store)
    clk = clock or (lambda: 0.0)
    claims = ClaimManager(store, clock=clk)
    executor = Executor(
        store,
        claims,
        policy=policy,
        context=context or HandlerContext(),
        clock=clk,
        max_evidence_age=max_evidence_age,
    )
    fence = claims.acquire("inc-1", "daemon", owned_proc=False)
    return store, claims, executor, fence


def _write_rules(path, rules):
    with open(path, "w") as f:
        json.dump({"version": 1, "rules": rules}, f)


def _allow_policy(tmp_path, rules_path=None):
    """A permissive (allow-all) ED-209 policy: empty rules, no ledger."""
    rp = rules_path or str(tmp_path / "rules.json")
    _write_rules(rp, [])
    return Policy(rules_path=rp, ledger=None)


def _notify_step(op_id="m1", message="repaired", expected="repaired", **params):
    p = {"channel": CHANNEL_LOCAL, "scope": "summary", "message": message}
    p.update(params)
    return Step(op_id=op_id, operation=OP_NOTIFY_HUMAN, params=p,
                verify_kind="contains", expected=expected)


# ---------------------------------------------------------------------------
# PASS-before-side-effect
# ---------------------------------------------------------------------------

def test_unknown_diagnosis_prevents_mutation(tmp_path):
    ctx = _ctx(tmp_path)
    (tmp_path / "heartbeat.txt").write_text("alive")
    store, claims, executor, fence = _setup(tmp_path, context=ctx)

    plan = Plan(
        diagnostics=(
            Step(op_id="d1", operation=OP_SHELL_DIAG,
                 params={"probe": PROBE_CLIENT_HEARTBEAT},
                 verify_kind="process_alive", expected="alive"),  # stateful -> UNKNOWN
        ),
        mutations=(_notify_step(),),
    )
    report = executor.execute(fence, plan)
    assert report.resolved is False
    assert report.verdict is not Verdict.PASS
    # PASS-before-side-effect: the mutation never ran
    assert not (tmp_path / "notify" / "inc-1.notify").exists()
    assert report.mutations == ()


def test_failed_diagnosis_blocks_mutation(tmp_path):
    ctx = _ctx(tmp_path)
    (tmp_path / "heartbeat.txt").write_text("alive")
    store, claims, executor, fence = _setup(tmp_path, context=ctx)

    plan = Plan(
        diagnostics=(
            Step(op_id="d1", operation=OP_SHELL_DIAG,
                 params={"probe": PROBE_CLIENT_HEARTBEAT},
                 verify_kind="contains", expected="dead"),  # FAIL
        ),
        mutations=(_notify_step(),),
    )
    report = executor.execute(fence, plan)
    assert report.resolved is False
    assert report.diagnostics[0].verdict is Verdict.FAIL
    assert not (tmp_path / "notify" / "inc-1.notify").exists()


# ---------------------------------------------------------------------------
# proof-before-closure
# ---------------------------------------------------------------------------

def test_empty_plan_cannot_resolve(tmp_path):
    store, claims, executor, fence = _setup(tmp_path)
    report = executor.execute(fence, Plan())
    assert report.resolved is False
    assert report.verdict is not Verdict.PASS


def test_zero_verified_ops_cannot_resolve(tmp_path):
    ctx = _ctx(tmp_path)
    (tmp_path / "heartbeat.txt").write_text("alive")
    store, claims, executor, fence = _setup(tmp_path, context=ctx)

    # every diagnostic PASSes, but there are NO mutations -> nothing verified
    plan = Plan(
        diagnostics=(
            Step(op_id="d1", operation=OP_SHELL_DIAG,
                 params={"probe": PROBE_CLIENT_HEARTBEAT},
                 verify_kind="contains", expected="alive"),
        ),
    )
    report = executor.execute(fence, plan)
    assert report.resolved is False
    assert report.verdict is not Verdict.PASS


# ---------------------------------------------------------------------------
# Mutation-capable execution FAILS CLOSED without a policy (Task 11 hardening)
# ---------------------------------------------------------------------------

def test_mutation_without_policy_is_refused(tmp_path):
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx)

    with pytest.raises(MissingPolicyError):
        executor.execute(fence, Plan(mutations=(_notify_step(),)))

    # the mutation's side effect never happened
    assert not (tmp_path / "notify" / "inc-1.notify").exists()


def test_rule_add_without_policy_is_refused(tmp_path):
    rules_path = str(tmp_path / "rules.json")
    with open(rules_path, "w") as f:
        json.dump({"version": 1, "rules": []}, f)
    ctx = _ctx(tmp_path, rules_path=rules_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx)

    with pytest.raises(MissingPolicyError):
        executor.execute(fence, Plan(mutations=(
            Step(op_id="m1", operation=OP_RULE_ADD,
                 params={"id": "r2d2-deny-rm", "surface": "tool", "rule_class": "restrict",
                         "action": "deny", "pattern": "rm -rf",
                         "reason": "block destructive rm", "origin": "test"},
                 verify_kind="contains", expected="r2d2-deny-rm"),
        )))

    # the daemon-side rule_add did NOT mutate the rules document
    doc = json.load(open(rules_path))
    assert doc["rules"] == []


def test_diagnostic_without_policy_still_runs(tmp_path):
    ctx = _ctx(tmp_path)
    (tmp_path / "heartbeat.txt").write_text("alive")
    store, claims, executor, fence = _setup(tmp_path, context=ctx)

    report = executor.execute(fence, Plan(diagnostics=(
        Step(op_id="d1", operation=OP_SHELL_DIAG,
             params={"probe": PROBE_CLIENT_HEARTBEAT},
             verify_kind="contains", expected="alive"),
    )))

    # read-only diagnostics are policy-independent; nothing resolves
    assert report.diagnostics[0].verdict is Verdict.PASS
    assert report.resolved is False


# ---------------------------------------------------------------------------
# R2-D2 cannot route around an ED-209 deny
# ---------------------------------------------------------------------------

def test_external_operation_respects_ed209(tmp_path):
    rules_path = str(tmp_path / "rules.json")
    _write_rules(
        rules_path,
        [
            {
                "id": "deny-notify",
                "surface": "tool",
                "class": "restrict",
                "action": "deny",
                "pattern": "notify_human",
                "reason": "test deny of outbound notify",
                "origin": "test",
            }
        ],
    )
    ledger = HitLedger(str(tmp_path / "hits.db"))
    policy = Policy(rules_path=rules_path, ledger=ledger, session_id="s1")
    ctx = _ctx(tmp_path, rules_path=rules_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx, policy=policy)

    plan = Plan(mutations=(_notify_step(message="boom", expected="boom"),))
    report = executor.execute(fence, plan)

    assert report.resolved is False
    assert report.denied == ("m1",)
    # the mutation's side effect never happened (protected sentinel absent)
    assert not (tmp_path / "notify" / "inc-1.notify").exists()
    # the deny was recorded in the shared ledger (a rule firing is provable)
    assert ledger.outcomes_for_rule("deny-notify") == {"deny": 1}


def test_rule_add_via_sanctioned_cli(tmp_path):
    rules_path = str(tmp_path / "rules.json")
    policy = _allow_policy(tmp_path, rules_path=rules_path)
    ctx = _ctx(tmp_path, rules_path=rules_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx, policy=policy)

    plan = Plan(mutations=(
        Step(op_id="m1", operation=OP_RULE_ADD,
             params={"id": "r2d2-deny-rm", "surface": "tool", "rule_class": "restrict",
                     "action": "deny", "pattern": "rm -rf",
                     "reason": "block destructive rm", "origin": "test"},
             verify_kind="contains", expected="r2d2-deny-rm"),
    ))
    report = executor.execute(fence, plan)
    assert report.resolved is True
    assert report.verdict is Verdict.PASS
    # the rule was added via the sanctioned CLI and FRESHLY verified in the doc
    doc = json.load(open(rules_path))
    assert [r["id"] for r in doc["rules"]] == ["r2d2-deny-rm"]
    assert doc["rules"][0]["action"] == "deny"
    assert doc["rules"][0]["origin"] == "test"


def test_rule_add_itself_respects_ed209(tmp_path):
    rules_path = str(tmp_path / "rules.json")
    _write_rules(
        rules_path,
        [
            {
                "id": "deny-rule-add",
                "surface": "tool",
                "class": "restrict",
                "action": "deny",
                "pattern": "rule_add",
                "reason": "deny daemon-side rule mutations",
                "origin": "test",
            }
        ],
    )
    ledger = HitLedger(str(tmp_path / "hits.db"))
    policy = Policy(rules_path=rules_path, ledger=ledger, session_id="s2")
    ctx = _ctx(tmp_path, rules_path=rules_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx, policy=policy)

    plan = Plan(mutations=(
        Step(op_id="m1", operation=OP_RULE_ADD,
             params={"id": "r2d2-x", "surface": "tool", "rule_class": "restrict",
                     "action": "deny", "pattern": "x", "reason": "r", "origin": "o"},
             verify_kind="contains", expected="r2d2-x"),
    ))
    report = executor.execute(fence, plan)
    assert report.resolved is False
    assert report.denied == ("m1",)
    # the daemon-side rule_add was refused: the rule was NOT added
    doc = json.load(open(rules_path))
    assert [r["id"] for r in doc["rules"]] == ["deny-rule-add"]
    assert ledger.outcomes_for_rule("deny-rule-add") == {"deny": 1}


# ---------------------------------------------------------------------------
# FIXED handlers + VALIDATED ENUMERATED params (rejections)
# ---------------------------------------------------------------------------

def test_malformed_enum_rejected(tmp_path):
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx)

    # shell_diag probe outside the fixed read-only table (Mac Teams probe)
    with pytest.raises(InvalidParamsError):
        executor.execute(fence, Plan(diagnostics=(
            Step(op_id="d1", operation=OP_SHELL_DIAG, params={"probe": "teams"},
                 verify_kind="contains", expected="x"),
        )))

    # notify scope outside the permitted scope enum
    with pytest.raises(InvalidParamsError):
        executor.execute(fence, Plan(mutations=(
            _notify_step(scope="banana"),
        )))

    # rule_add action outside the RESTRICTIVE set (would weaken a denial)
    with pytest.raises(InvalidParamsError):
        executor.execute(fence, Plan(mutations=(
            Step(op_id="m1", operation=OP_RULE_ADD,
                 params={"id": "r1", "surface": "tool", "rule_class": "x",
                         "action": "allow", "pattern": ".*",
                         "reason": "r", "origin": "o"},
                 verify_kind=None, expected=None),
        )))


def test_arbitrary_command_rejected(tmp_path):
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx)

    # a forbidden command key smuggled into an otherwise-supported operation
    with pytest.raises(PlanError):
        executor.execute(fence, Plan(diagnostics=(
            Step(op_id="d1", operation=OP_SHELL_DIAG,
                 params={"probe": PROBE_CLIENT_HEARTBEAT, "command": "rm -rf /"},
                 verify_kind="contains", expected="x"),
        )))

    # an operation name that is not in the allowlist at all
    with pytest.raises(PlanError):
        executor.execute(fence, Plan(mutations=(
            Step(op_id="m1", operation="run_shell_command", params={},
                 verify_kind=None, expected=None),
        )))


def test_arbitrary_path_rejected(tmp_path):
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx)

    with pytest.raises(PlanError):
        executor.execute(fence, Plan(diagnostics=(
            Step(op_id="d1", operation=OP_SHELL_DIAG,
                 params={"probe": PROBE_CLIENT_HEARTBEAT, "path": "/etc/passwd"},
                 verify_kind="contains", expected="x"),
        )))


def test_unauthorized_config_key_rejected(tmp_path):
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx)

    with pytest.raises(PlanError):
        executor.execute(fence, Plan(mutations=(
            _notify_step(config_key="session_budget"),
        )))


def test_hook_approval_edit_rejected(tmp_path):
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx)

    with pytest.raises(PlanError):
        executor.execute(fence, Plan(mutations=(
            Step(op_id="m1", operation="edit_hook", params={},
                 verify_kind=None, expected=None),
        )))

    with pytest.raises(PlanError):
        executor.execute(fence, Plan(mutations=(
            _notify_step(hook="before_tool"),
        )))


def test_guard_unlock_rejected(tmp_path):
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx)

    with pytest.raises(PlanError):
        executor.execute(fence, Plan(mutations=(
            Step(op_id="m1", operation="guard_unlock", params={},
                 verify_kind=None, expected=None),
        )))

    with pytest.raises(PlanError):
        executor.execute(fence, Plan(mutations=(
            _notify_step(unlock=True),
        )))


def test_broad_process_pattern_kill_rejected(tmp_path):
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx)

    with pytest.raises(PlanError):
        executor.execute(fence, Plan(mutations=(
            Step(op_id="m1", operation="kill_procs", params={"pattern": "python"},
                 verify_kind=None, expected=None),
        )))

    with pytest.raises(PlanError):
        executor.execute(fence, Plan(mutations=(
            _notify_step(kill="*"),
        )))


# ---------------------------------------------------------------------------
# Reviewer may BLOCK but cannot mint a kill grant / change the allowlist
# ---------------------------------------------------------------------------

def test_no_freeform_reviewer_authorization(tmp_path):
    rules_path = str(tmp_path / "rules.json")
    _write_rules(
        rules_path,
        [
            {
                "id": "blk-notify",
                "surface": "tool",
                "class": "restrict",
                "action": "block",
                "pattern": "notify_human",
                "reason": "reviewer block",
                "origin": "test",
            }
        ],
    )
    policy = Policy(rules_path=rules_path, ledger=None)
    ctx = _ctx(tmp_path, rules_path=rules_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx, policy=policy)

    report = executor.execute(fence, Plan(mutations=(_notify_step(),)))
    # a reviewer can only BLOCK — the mutation is refused, never authorized
    assert report.resolved is False
    assert not (tmp_path / "notify" / "inc-1.notify").exists()

    # there is no kill / authorize / unlock operation in the allowlist at all
    assert "kill" not in OPERATION_NAMES
    for name in OPERATION_NAMES:
        for bad in ("kill", "authorize", "unlock", "approve"):
            assert bad not in name


# ---------------------------------------------------------------------------
# Unsupported operations report 'unsupported' (never faked, never resolve)
# ---------------------------------------------------------------------------

def test_config_set_reports_unsupported(tmp_path):
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx)

    report = executor.execute(fence, Plan(mutations=(
        Step(op_id="m1", operation=OP_CONFIG_SET, params={},
             verify_kind=None, expected=None),
    )))
    assert report.resolved is False
    assert report.unsupported == ("config_set",)
    assert report.mutations[0].unsupported is True
    # config_set is a known name but is NOT an executable operation
    assert OP_CONFIG_SET not in EXECUTABLE_OPERATIONS


def test_mcp_reconnect_unsupported(tmp_path):
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx)

    # mcp_reconnect now has a real ``server`` param (Task 13), but with no
    # owning-client IPC adapter wired it remains UNSUPPORTED.
    report = executor.execute(fence, Plan(mutations=(
        Step(op_id="m1", operation=OP_MCP_RECONNECT, params={"server": "demo-server"},
             verify_kind=None, expected=None),
    )))
    assert report.resolved is False
    assert report.unsupported == ("mcp_reconnect",)


def test_session_stop_resume_unsupported(tmp_path):
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx)

    report = executor.execute(fence, Plan(mutations=(
        Step(op_id="m1", operation=OP_SESSION_STOP_RESUME, params={},
             verify_kind=None, expected=None),
    )))
    assert report.resolved is False
    assert report.unsupported == ("session_stop_resume",)


def test_unsupported_adapter_cannot_resolve(tmp_path):
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx, policy=_allow_policy(tmp_path))

    # a PASS mutation alongside an unsupported adapter still cannot resolve
    plan = Plan(mutations=(
        _notify_step(op_id="m1"),
        Step(op_id="m2", operation=OP_CONFIG_SET, params={},
             verify_kind=None, expected=None),
    ))
    report = executor.execute(fence, plan)
    assert report.resolved is False
    assert "config_set" in report.unsupported


# ---------------------------------------------------------------------------
# Partial plan failure does not resolve
# ---------------------------------------------------------------------------

def test_partial_plan_failure_not_resolved(tmp_path):
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx, policy=_allow_policy(tmp_path))

    plan = Plan(mutations=(
        _notify_step(op_id="m1", message="ok", expected="ok"),        # PASS
        _notify_step(op_id="m2", message="bad", expected="not-here"),  # fresh FAIL
    ))
    report = executor.execute(fence, plan)
    assert report.resolved is False
    assert report.verdict is not Verdict.PASS
    # the successful mutation still happened (it is not rolled back)
    assert (tmp_path / "notify" / "inc-1.notify").exists()


# ---------------------------------------------------------------------------
# A mutation is FRESHLY verified after it runs
# ---------------------------------------------------------------------------

def test_mutation_is_freshly_verified_after_run(tmp_path):
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx, policy=_allow_policy(tmp_path))

    report = executor.execute(fence, Plan(mutations=(
        _notify_step(message="repaired", expected="repaired"),
    )))
    assert report.resolved is True
    assert report.verdict is Verdict.PASS
    assert report.mutations[0].verdict is Verdict.PASS
    # the fresh verification read the ACTUAL post-mutation delivery file
    delivered = (tmp_path / "notify" / "inc-1.notify").read_text()
    assert "repaired" in delivered


def test_fresh_verification_failure_not_resolved(tmp_path):
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(tmp_path, context=ctx, policy=_allow_policy(tmp_path))

    report = executor.execute(fence, Plan(mutations=(
        _notify_step(message="repaired", expected="different"),
    )))
    assert report.resolved is False
    assert report.mutations[0].verdict is Verdict.FAIL


# ---------------------------------------------------------------------------
# Stale evidence is rejected
# ---------------------------------------------------------------------------

def test_stale_evidence_rejected(tmp_path):
    now = [1000.0]
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(
        tmp_path, context=ctx, clock=lambda: now[0], max_evidence_age=60.0
    )

    plan = Plan(mutations=(
        Step(op_id="m1", operation=OP_NOTIFY_HUMAN,
             params={"channel": CHANNEL_LOCAL, "scope": "summary", "message": "x"},
             verify_kind="contains", expected="x", evidence_time=0.0),
    ))
    with pytest.raises(StaleEvidenceError):
        executor.execute(fence, plan)


# ---------------------------------------------------------------------------
# Spawn-time owned-process attestation (carry-forward from Task 10)
# ---------------------------------------------------------------------------

def test_spawn_time_owned_process_attestation(tmp_path):
    store, claims, executor, fence = _setup(tmp_path)
    op = executor.spawn_owned(
        "inc-1", [sys.executable, "-c", "import time; time.sleep(30)"]
    )
    try:
        assert op.pid > 0
        assert op.start_time > 0.0
        # the (pid, start_time) pair is ATTESTED in the store registry
        assert store.is_owned_process("inc-1", op.pid, op.start_time) is True
        # a different start time for the same pid is NOT attested (PID reuse)
        assert store.is_owned_process("inc-1", op.pid, op.start_time + 999.0) is False
        # a different pid is NOT attested
        assert store.is_owned_process("inc-1", op.pid + 1, op.start_time) is False
    finally:
        op.proc.terminate()
        op.proc.wait(timeout=10)


def test_non_registered_pid_never_killed(tmp_path):
    root = str(tmp_path / "r2d2")
    store = IncidentStore(root)
    _raise(store)
    now = [0.0]
    claims = ClaimManager(store, clock=lambda: now[0])

    # a real process that a claimant points at with owned_proc=True ...
    victim = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    vstart = proc_start_time(victim.pid)
    try:
        claims.acquire(
            "inc-1", "w-old", pid=victim.pid, pid_start_time=vstart, owned_proc=True
        )
        now[0] = 100.0  # lease lapses -> takeover path reached

        # ... but it was NEVER attested by the executor's spawn, so takeover
        # must NOT SIGTERM it (FrozenLaneError, not a kill).
        with pytest.raises(FrozenLaneError):
            claims.takeover(
                "inc-1", "w-new",
                pid=os.getpid(), pid_start_time=proc_start_time(os.getpid()),
                owned_proc=False,
            )
        # the process survives: a process absent from the registry is never killed
        assert victim.poll() is None
    finally:
        victim.terminate()
        victim.wait(timeout=10)


def test_registered_proc_is_terminated_on_takeover(tmp_path):
    root = str(tmp_path / "r2d2")
    store = IncidentStore(root)
    _raise(store)
    now = [0.0]
    claims = ClaimManager(store, clock=lambda: now[0])
    executor = Executor(store, claims, clock=lambda: now[0])

    op = executor.spawn_owned(
        "inc-1", [sys.executable, "-c", "import time; time.sleep(30)"]
    )
    claims.acquire(
        "inc-1", "w-old", pid=op.pid, pid_start_time=op.start_time, owned_proc=True
    )
    now[0] = 100.0  # lease lapses

    # the executor ATTESTED this process, so takeover may TERM it (exact match)
    claims.takeover(
        "inc-1", "w-new",
        pid=os.getpid(), pid_start_time=proc_start_time(os.getpid()), owned_proc=False,
    )
    op.proc.wait(timeout=10)
    assert op.proc.poll() is not None  # proven dead


# ---------------------------------------------------------------------------
# The allowlist is closed and fixed
# ---------------------------------------------------------------------------

def test_allowlist_is_closed_and_fixed():
    # the §4 allowlist: exactly these six names, no more
    assert OPERATION_NAMES == frozenset({
        OP_SHELL_DIAG, OP_MCP_RECONNECT, OP_RULE_ADD,
        OP_NOTIFY_HUMAN, OP_SESSION_STOP_RESUME, OP_CONFIG_SET,
    })
    # only the supported handlers are executable; the rest report unsupported
    assert EXECUTABLE_OPERATIONS == frozenset({OP_SHELL_DIAG, OP_RULE_ADD, OP_NOTIFY_HUMAN})


# ---------------------------------------------------------------------------
# Bounded subprocess deadline: a hung handler child is TERM'd + proven dead
# (Task 11 review: no hung child may block the daemon indefinitely)
# ---------------------------------------------------------------------------

def test_run_bounded_timeout_terminates_and_proves_dead():
    # A child that sleeps far longer than the deadline: run_bounded must
    # TERM -> prove dead -> return timed_out, and the pid must be GONE
    # (no orphan child remains).
    t0 = time.monotonic()
    res = run_bounded(
        [sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5
    )
    elapsed = time.monotonic() - t0
    assert res.timed_out is True
    assert res.returncode is not None          # reaped (proven dead)
    assert proc_start_time(res.pid) is None     # pid gone — no orphan child
    assert elapsed < 5.0                        # bounded, not the full 30s sleep


def test_log_tail_subprocess_timeout_bounded_and_not_resolved(tmp_path):
    # A FIFO with no writer makes `tail -n` block forever on open(): a hung
    # child. The handler must bound it and record UNKNOWN, never resolve.
    fifo = tmp_path / "r2d2.log"
    os.mkfifo(fifo)
    ctx = _ctx(tmp_path, log_targets={"r2d2": str(fifo)}, subprocess_timeout=0.5)
    store, claims, executor, fence = _setup(tmp_path, context=ctx)

    plan = Plan(diagnostics=(
        Step(op_id="d1", operation=OP_SHELL_DIAG,
             params={"probe": PROBE_LOG_TAIL, "target": "r2d2", "lines": 10},
             verify_kind="contains", expected="needle"),
    ))
    t0 = time.monotonic()
    report = executor.execute(fence, plan)  # must NOT hang and must NOT raise
    elapsed = time.monotonic() - t0

    assert report.resolved is False
    assert report.diagnostics[0].verdict is Verdict.UNKNOWN
    assert report.diagnostics[0].timed_out is True
    assert elapsed < 5.0


# ---------------------------------------------------------------------------
# Handler exceptions are contained: a raising step is a reported FAIL, never
# an uncaught traceback out of the executor
# ---------------------------------------------------------------------------

def test_handler_exception_contained_diagnostic(tmp_path):
    ctx = _ctx(tmp_path)  # log_targets has only "r2d2"
    store, claims, executor, fence = _setup(tmp_path, context=ctx)
    # 'target' passes param validation (a non-empty string) but is absent from
    # ctx.log_targets -> run() raises InvalidParamsError mid-execution.
    plan = Plan(diagnostics=(
        Step(op_id="d1", operation=OP_SHELL_DIAG,
             params={"probe": PROBE_LOG_TAIL, "target": "missing", "lines": 5},
             verify_kind="contains", expected="x"),
    ))
    report = executor.execute(fence, plan)  # must NOT raise
    assert report.resolved is False
    assert report.diagnostics[0].verdict is Verdict.FAIL
    assert "InvalidParamsError" in report.diagnostics[0].evidence


def test_handler_exception_contained_mutation(tmp_path):
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(
        tmp_path, context=ctx, policy=_allow_policy(tmp_path)
    )
    # outbound channel not in opt_in_channels -> run() raises InvalidParamsError
    plan = Plan(mutations=(
        Step(op_id="m1", operation=OP_NOTIFY_HUMAN,
             params={"channel": "telegram", "scope": "summary", "message": "hi"},
             verify_kind="contains", expected="hi"),
    ))
    report = executor.execute(fence, plan)  # must NOT raise
    assert report.resolved is False
    assert report.mutations[0].verdict is Verdict.FAIL
    assert "InvalidParamsError" in report.mutations[0].evidence


# ---------------------------------------------------------------------------
# Partial plan: first step PASS, later step hangs/raises -> still not resolved
# and the first step's outcome is preserved
# ---------------------------------------------------------------------------

def test_partial_plan_second_raises_preserves_first(tmp_path):
    ctx = _ctx(tmp_path)
    store, claims, executor, fence = _setup(
        tmp_path, context=ctx, policy=_allow_policy(tmp_path)
    )
    plan = Plan(mutations=(
        _notify_step(op_id="m1", message="ok", expected="ok"),   # PASS
        Step(op_id="m2", operation=OP_NOTIFY_HUMAN,
             params={"channel": "telegram", "scope": "summary", "message": "boom"},
             verify_kind="contains", expected="boom"),           # raises -> FAIL
    ))
    report = executor.execute(fence, plan)
    assert report.resolved is False
    assert report.mutations[0].verdict is Verdict.PASS
    assert report.mutations[1].verdict is Verdict.FAIL
    # the first (PASS) step's side effect is preserved, not rolled back
    assert (tmp_path / "notify" / "inc-1.notify").exists()


def test_partial_plan_second_hangs_not_resolved(tmp_path):
    # first diagnostic PASSes, second hangs -> aborted, first outcome preserved
    (tmp_path / "heartbeat.txt").write_text("alive")
    fifo = tmp_path / "r2d2.log"
    os.mkfifo(fifo)
    ctx = _ctx(tmp_path, log_targets={"r2d2": str(fifo)}, subprocess_timeout=0.5)
    store, claims, executor, fence = _setup(tmp_path, context=ctx)
    plan = Plan(diagnostics=(
        Step(op_id="d1", operation=OP_SHELL_DIAG,
             params={"probe": PROBE_CLIENT_HEARTBEAT},
             verify_kind="contains", expected="alive"),   # PASS
        Step(op_id="d2", operation=OP_SHELL_DIAG,
             params={"probe": PROBE_LOG_TAIL, "target": "r2d2", "lines": 10},
             verify_kind="contains", expected="needle"),  # hangs -> UNKNOWN
    ))
    report = executor.execute(fence, plan)
    assert report.resolved is False
    assert report.diagnostics[0].verdict is Verdict.PASS
    assert report.diagnostics[1].verdict is Verdict.UNKNOWN
    assert report.diagnostics[1].timed_out is True
