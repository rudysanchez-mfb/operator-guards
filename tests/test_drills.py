"""Task 17a — the plan §6 real drills, run in isolated home/client state.

Each §6 acceptance-matrix row is mapped to a test in this file. Where the drill
is an ALIAS of an already-committed test (the real assertion already lives in
its home module), the alias re-exports that exact test function under the §6
name — no copy, so the two can never drift. Where the drill is a NEW
end-to-end exercise (supervisor genuinely external, resume-is-not-copy,
opted-in exact-receipt), the test is written here against real temp
filesystems / real subprocesses.

The real-dispatch rows (nested/child gates, MCP round-trip recovery, A→B→A
isolation) import Hermes and are marked ``requires_hermes``; they SKIP under
the standalone G/.venv and RUN under ``G/scripts/run_plugin_tests.sh``'s
environment (or ``PYTHONPATH=H:G/src H/venv/bin/python -m pytest``).

Drill → test mapping (plan §6):

  Nested/child gates            → test_nested_and_delegated_denial (ALIAS)
  Actual recovery               → test_mcp_dies_while_owner_lives_then_roundtrip_recovers (ALIAS)
  Supervisor genuinely external → test_supervisor_genuinely_external (NEW)
  Resume is not copy            → test_resume_is_not_copy (NEW)
  No phantom notification       → test_no_opt_in_means_local_only (ALIAS)
                                  test_opted_in_delivery_requires_exact_receipt (NEW)
  Default profile isolation     → test_two_isolated_homes_a_b_a (ALIAS)

NO real Hermes profile, systemd unit, or core rollout is touched by any test
here: every drill runs against ``tmp_path`` throwaway homes.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# ALIASES — re-export the real committed tests under the plan §6 names.
# ---------------------------------------------------------------------------
# The alias names are the *required* test names from the §6 acceptance matrix.
# The imported functions are the SAME objects pytest already collects in their
# home modules, so their ``requires_hermes`` skip marker is inherited verbatim.

from test_authz import test_no_opt_in_means_local_only  # noqa: E402,F401
from test_execution_paths import (  # noqa: E402,F401
    test_nested_and_delegated_denial,
    test_two_isolated_homes_a_b_a,
)
from test_ipc import (  # noqa: E402,F401
    test_real_fixture_mcp_dies_owner_lives_native_reconnect_typed_proof
    as test_mcp_dies_while_owner_lives_then_roundtrip_recovers,
)


# ---------------------------------------------------------------------------
# Helpers (new drills)
# ---------------------------------------------------------------------------

def _poll(cond, timeout: float = 20.0, interval: float = 0.05) -> bool:
    """Poll ``cond()`` until it returns truthy, or the deadline passes."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(interval)
    return False


def _pid_dead(pid: int) -> bool:
    """True once ``pid`` is gone or a zombie (a reaped child counts as dead)."""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
            state = fh.read().split(")")[1].split()[0]
        return state == "Z"
    except (OSError, IndexError):
        return True


# ---------------------------------------------------------------------------
# Supervisor genuinely external (plan §6).
#
# Proves R2-D2 is an independent service, not an in-agent thread:
#   * a committed incident SURVIVES a supervisor kill + restart, and
#   * killing a disposable "owning client" (the Hermes fixture) does NOT stop
#     the supervisor — its heartbeat keeps advancing AND it observes the dead
#     client and durably commits a stale-client incident (event processing
#     continues).
# ---------------------------------------------------------------------------

def test_supervisor_genuinely_external(tmp_path):
    from operator_guards.r2d2.claims import proc_start_time
    from operator_guards.r2d2.observer import (
        ClientRecord,
        read_heartbeat_file,
        write_client_record,
    )
    from operator_guards.r2d2.store import IncidentStore

    home = tmp_path / "home"
    root = home / "r2d2"

    # 1. Commit an incident durably via the REAL store BEFORE any supervisor.
    store = IncidentStore(str(root))
    inc = store.raise_incident(
        {
            "id": "inc-committed",
            "severity": "mechanical",
            "symptom": "pre-supervisor committed incident",
            "phase": "open",
            "dedupe_key": "committed-1",
        }
    )
    assert inc.id == "inc-committed"

    # 2. Register a disposable owning client (a stand-in "Hermes fixture") as a
    #    REAL live process with its verified /proc start time.
    victim = subprocess.Popen(["sleep", "60"])
    victim_start = proc_start_time(victim.pid)
    assert victim_start is not None
    write_client_record(
        str(root),
        ClientRecord(
            client_id="host:default",
            pid=victim.pid,
            pid_start_time=victim_start,
            last_seen=time.monotonic(),
            capabilities=frozenset({"echo"}),
        ),
    )

    sup_argv = [
        sys.executable,
        "-m",
        "operator_guards.r2d2.supervisor",
        "--home",
        str(home),
        "--tick-seconds",
        "0.2",
    ]

    # 3. Start the supervisor as a REAL external process.
    sup1 = subprocess.Popen(
        sup_argv,
        cwd=str(REPO),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    rc = None
    try:
        assert _poll(lambda: (root / "heartbeat").exists(), timeout=20), (
            f"supervisor never wrote a heartbeat; rc={sup1.poll()}; "
            f"stderr={sup1.stderr.read() if sup1.poll() is not None else ''}"
        )
        hb_before = read_heartbeat_file(str(root))
        assert hb_before is not None

        # 4. Kill the disposable Hermes fixture. The EXTERNAL supervisor must
        #    keep running: its heartbeat advances and it observes the dead
        #    client and durably commits a stale-client incident.
        os.kill(victim.pid, signal.SIGKILL)
        assert _poll(lambda: _pid_dead(victim.pid), timeout=10)

        def _stale_client_seen():
            try:
                return any(
                    i.dedupe_key.startswith("stale-client:")
                    for i in IncidentStore(str(root)).list_incidents()
                )
            except Exception:  # noqa: BLE001 - transient store read while writing
                return False

        assert _poll(_stale_client_seen, timeout=20), (
            "supervisor did not observe + commit the dead-client incident; "
            f"stderr={sup1.stderr.read() if sup1.poll() is not None else ''}"
        )
        hb_after = read_heartbeat_file(str(root))
        assert hb_after is not None
        assert hb_after > hb_before, "supervisor heartbeat did not advance"
    finally:
        # Deterministic cleanup: reap the supervisor AND the killed fixture even
        # when an assertion above fails (no lingering `sleep 60` child / zombie).
        if sup1.poll() is None:
            sup1.send_signal(signal.SIGTERM)
        rc = sup1.wait(timeout=20)
        if victim.poll() is None:
            victim.kill()
        victim.wait(timeout=10)
    assert rc == 0, f"supervisor exited {rc} (expected clean 0); stderr={sup1.stderr.read()}"

    # 5. Restart a FRESH supervisor against the same home; a committed incident
    #    must SURVIVE the kill/restart (read from a FRESH store instance).
    sup2 = subprocess.run(
        sup_argv + ["--once"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert sup2.returncode == 0, sup2.stderr
    fresh = IncidentStore(str(root))
    committed = fresh.get_incident("inc-committed")
    assert committed is not None, "committed incident did not survive supervisor restart"
    assert committed.phase == "open"
    stale = [i for i in fresh.list_incidents() if i.dedupe_key.startswith("stale-client:")]
    assert stale, "auto-raised stale-client incident did not survive the restart"
    assert stale[0].phase == "open"


# ---------------------------------------------------------------------------
# Recovery is REACHABLE end-to-end (Finding 3): the supervisor wires a real
# ED-209 policy and can execute a supported mutation (diagnose → mutate →
# verify → resolve with typed proof), and a mutate can NEVER route around an
# ED-209 deny.
# ---------------------------------------------------------------------------

def _write_rules_doc(home, rules):
    (home / "ed209").mkdir(parents=True, exist_ok=True)
    (home / "ed209" / "rules.json").write_text(json.dumps({"version": 1, "rules": rules}))


def test_supervisor_recovery_end_to_end_resolves_with_typed_proof(tmp_path):
    from operator_guards.common.proof import Verdict
    from operator_guards.r2d2.supervisor import Supervisor
    from operator_guards.r2d2.store import IncidentStore

    home = tmp_path / "home"
    _write_rules_doc(home, [])  # empty -> allow-all policy
    root = home / "r2d2"

    store = IncidentStore(str(root))
    store.raise_incident(
        {
            "id": "inc-recover", "severity": "mechanical",
            "symptom": "capability lost", "phase": "open", "dedupe_key": "r-1",
        }
    )

    sup = Supervisor(str(home))
    sup._refresh_heartbeat()  # the diagnostic reads the heartbeat -> PASS

    plan = sup.recovery_plan(
        store.get_incident("inc-recover"),
        operation="notify_human",
        params={"channel": "local", "scope": "summary", "message": "recovered"},
        verify_kind="contains",
        expected="recovered",
    )
    report = sup.execute_recovery("inc-recover", plan)

    assert report is not None
    assert report.resolved is True
    assert report.verdict is Verdict.PASS

    # Fresh-store read: the incident is RESOLVED with a typed PASS mutation op
    # (proof=PASS, mutation_plan non-empty), and the mutation side effect landed.
    fresh = IncidentStore(str(root))
    inc = fresh.get_incident("inc-recover")
    assert inc is not None
    assert inc.phase == "resolved"
    assert inc.proof is Verdict.PASS
    assert inc.mutation_plan, "no typed mutation proof persisted"
    assert inc.mutation_plan[-1].verdict is Verdict.PASS
    assert (root / "notifications" / "inc-recover.notify").exists()


def test_supervisor_recovery_cannot_route_around_ed209_deny(tmp_path):
    from operator_guards.ed209.ledger import HitLedger
    from operator_guards.r2d2.supervisor import Supervisor
    from operator_guards.r2d2.store import IncidentStore

    home = tmp_path / "home"
    _write_rules_doc(
        home,
        [{
            "id": "deny-notify", "surface": "tool", "class": "restrict",
            "action": "deny", "pattern": "notify_human",
            "reason": "no autonomous notify", "origin": "test",
        }],
    )
    root = home / "r2d2"

    store = IncidentStore(str(root))
    store.raise_incident(
        {
            "id": "inc-denied", "severity": "mechanical",
            "symptom": "capability lost", "phase": "open", "dedupe_key": "r-2",
        }
    )

    sup = Supervisor(str(home))
    sup._refresh_heartbeat()

    plan = sup.recovery_plan(
        store.get_incident("inc-denied"),
        operation="notify_human",
        params={"channel": "local", "scope": "summary", "message": "recovered"},
        verify_kind="contains",
        expected="recovered",
    )
    report = sup.execute_recovery("inc-denied", plan)

    assert report is not None
    assert report.resolved is False
    assert report.denied == ("recover-notify_human",)

    # The mutation's side effect did NOT happen, and the incident stays open.
    assert not (root / "notifications" / "inc-denied.notify").exists()
    fresh = IncidentStore(str(root))
    assert fresh.get_incident("inc-denied").phase == "open"

    # The deny is RECORDED in the shared ledger (a rule firing is provable).
    ledger = HitLedger(str(home / "ed209" / "hits.db"))
    assert ledger.outcomes_for_rule("deny-notify").get("deny", 0) >= 1


# ---------------------------------------------------------------------------
# Resume is not copy (plan §6).
#
# ``session_stop_resume`` stays UNSUPPORTED: the executor reports resolved=False
# (an ambiguous/copied resume is never silently resolved). The scoped grant that
# WOULD authorize a real resume binds EXACT session/client/pid/start identity +
# an issuer-generated single-use nonce — a copied session identity or a reused
# nonce never authorizes. No real/shared session is touched.
# ---------------------------------------------------------------------------

def test_resume_is_not_copy(tmp_path):
    from operator_guards.common.proof import Verdict
    from operator_guards.r2d2.authz import (
        GrantAlreadyConsumedError,
        GrantIdentityMismatchError,
        GrantNonceMismatchError,
        GrantStore,
    )
    from operator_guards.r2d2.claims import ClaimManager
    from operator_guards.r2d2.executor import Executor, Plan, Step
    from operator_guards.r2d2.handlers import OP_SESSION_STOP_RESUME
    from operator_guards.r2d2.store import IncidentStore

    root = str(tmp_path / "r2d2")
    store = IncidentStore(root)
    store.raise_incident(
        {
            "id": "inc-resume",
            "severity": "mechanical",
            "symptom": "session stop/resume drill",
            "phase": "open",
            "dedupe_key": "resume-1",
            "session_id": "sess-other",
        }
    )

    # The resume adapter is UNSUPPORTED: the executor must NOT resolve it.
    claims = ClaimManager(store)
    fence = claims.acquire("inc-resume", "drill")
    report = Executor(store, claims).execute(
        fence,
        Plan(mutations=(Step(op_id="m1", operation=OP_SESSION_STOP_RESUME, params={}),)),
    )
    assert report.resolved is False
    assert report.unsupported == ("session_stop_resume",)
    assert report.verdict is Verdict.FAIL

    # Identity + nonce: a grant names the EXACT other-session principal and
    # carries an issuer-generated single-use nonce. A COPY (different session
    # identity) or a wrong nonce NEVER authorizes; a consumed grant never refunds.
    gstore = GrantStore(str(tmp_path / "grants"))
    grant = gstore.issue(
        incident_id="inc-resume",
        scope="session_stop_resume",
        session_id="sess-other",
        client_id="client-other",
        pid=12345,
        start_time=1700000000.0,
        issuer="rudy",
        ttl_seconds=1800,
    )
    assert grant.nonce

    sid, cid, gpid, gst, gscope = (
        grant.session_id, grant.client_id, grant.pid, grant.start_time, grant.scope,
    )
    with pytest.raises(GrantIdentityMismatchError):
        gstore.consume(grant.grant_id, grant.nonce,
                       session_id="sess-COPY", client_id=cid, pid=gpid, start_time=gst, scope=gscope)
    with pytest.raises(GrantNonceMismatchError):
        gstore.consume(grant.grant_id, "wrong-nonce",
                       session_id=sid, client_id=cid, pid=gpid, start_time=gst, scope=gscope)
    # Exact identity + nonce authorizes exactly once.
    gstore.consume(grant.grant_id, grant.nonce,
                   session_id=sid, client_id=cid, pid=gpid, start_time=gst, scope=gscope)
    with pytest.raises(GrantAlreadyConsumedError):
        gstore.consume(grant.grant_id, grant.nonce,
                       session_id=sid, client_id=cid, pid=gpid, start_time=gst, scope=gscope)


# ---------------------------------------------------------------------------
# No phantom notification — opted-in delivery requires an EXACT receipt
# (plan §6). Uses a FAKE channel (no real outbound); the receipt readback must
# match the accepted delivery byte-for-byte, and a second delivery is refused.
# ---------------------------------------------------------------------------

def test_opted_in_delivery_requires_exact_receipt(tmp_path):
    from operator_guards.r2d2.authz import CHANNEL_LOCAL, NotificationPolicy

    # The local sink is always opted-in; a FAKE channel must be explicitly
    # opted in by the operator. No real outbound transport is involved.
    policy = NotificationPolicy(
        opt_in_channels=frozenset({"fake-smtp"}),
        receipts_dir=str(tmp_path / "receipts"),
    )
    assert policy.resolve("inc-1", "fake-smtp").status == "opted_in"
    # An un-opted channel stays local-only (no phantom notification).
    assert policy.resolve("inc-1", "sms").status == "local_only"
    assert policy.resolve("inc-1", CHANNEL_LOCAL).status == "opted_in"

    receipt = "provider-receipt: msg_1234567890"
    assert policy.accept_delivery("inc-1", "fake-smtp", receipt) is True
    # EXACT readback — the accepted receipt is returned byte-for-byte.
    assert policy.read_receipt("inc-1", "fake-smtp") == receipt
    # At most ONE accepted delivery per incident+channel (durable dedupe).
    assert policy.accept_delivery("inc-1", "fake-smtp", "receipt-2") is False
    assert policy.read_receipt("inc-1", "fake-smtp") == receipt
