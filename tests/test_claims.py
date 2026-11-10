"""Serialized claims, epoch fencing, and crash reconciliation (plan §4/§6, Task 10).

Locks the R2-D2 claim contract with REAL temp-filesystem state, REAL file
locks, and REAL OS processes where the contract demands cross-process
single-winner behaviour (O_EXCL alone is not proof):

* exactly ONE of two worker PROCESSES wins a claim for the same incident
  (real subprocesses, not threads, not O_EXCL-only);
* an expired worker is taken over only after exact PID+start-time validation
  and termination of the R2-D2-owned disposable proc; the OLD fence can then
  no longer pass the mutation barrier;
* a crash after the side effect but before the result yields UNKNOWN and a
  re-diagnosis (never a blind replay); a guarded sentinel side effect runs at
  most once;
* stale epoch, missing claim, PID reuse / start-time mismatch are rejected at
  the launch barrier;
* supervisor restart resumes with a monotonic epoch and correct reconcile;
* max_attempts exhaustion escalates (no further mutation);
* an already-STARTED request blocks a NEW mutating epoch until it settles or
  reconciles; a queued old request is rejected at the launch barrier.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import replace

import pytest

from operator_guards.common.proof import Verdict
from operator_guards.r2d2.claims import (
    Claim,
    ClaimError,
    ClaimManager,
    Fence,
    FrozenLaneError,
    InFlightOperationError,
    LeaseExpiredError,
    RECEIPT_QUEUED,
    RECEIPT_SETTLED,
    RECEIPT_STARTED,
    Reconciliation,
    StaleFenceError,
    proc_start_time,
)
from operator_guards.r2d2.schema import PHASE_ESCALATED
from operator_guards.r2d2.store import IncidentStore

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Guaranteed-dead PIDs (above Linux pid_max) so takeover can "prove dead"
# deterministically without a real child process.
_DEAD_PID = 999_999_999
_DEAD_PID_2 = 999_999_998


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


def _manager(root, lease_seconds=30.0, clock=None):
    return ClaimManager(IncidentStore(root), lease_seconds=lease_seconds, clock=clock)


# ---------------------------------------------------------------------------
# Real-process worker scripts (single-winner and expired-worker contend here)
# ---------------------------------------------------------------------------

_CONTEND_WORKER = """\
import sys
from operator_guards.r2d2.store import IncidentStore
from operator_guards.r2d2.claims import ClaimManager, ClaimError

root, incident_id, claimant_id = sys.argv[1:4]
mgr = ClaimManager(IncidentStore(root))
try:
    fence = mgr.acquire(incident_id, claimant_id, owned_proc=True)
    print(f"WIN {claimant_id} {fence.claim.epoch}")
except ClaimError as exc:
    print(f"LOSE {claimant_id} {type(exc).__name__}")
except Exception as exc:  # noqa: BLE001
    print(f"ERROR {claimant_id} {exc!r}")
    sys.exit(2)
"""

_BLOCK_WORKER = """\
import sys, os, json, time
from operator_guards.r2d2.store import IncidentStore
from operator_guards.r2d2.claims import ClaimManager, ClaimError, proc_start_time

root, incident_id, claimant_id, gate, fencefile = sys.argv[1:6]
mgr = ClaimManager(IncidentStore(root), lease_seconds=1.0)
pid = os.getpid()
fence = mgr.acquire(incident_id, claimant_id, pid=pid,
                    pid_start_time=proc_start_time(pid), owned_proc=True)
with open(fencefile, "w") as f:
    json.dump({
        "claimant_id": fence.claim.claimant_id,
        "epoch": fence.claim.epoch,
        "nonce": fence.claim.nonce,
        "pid": fence.claim.pid,
        "pid_start_time": fence.claim.pid_start_time,
    }, f)
# suspended near mutation: block until the gate file appears (it never does)
while not os.path.exists(gate):
    time.sleep(0.05)
try:
    mgr.queue_operation(fence, "op-1")
    mgr.mark_started(fence, "op-1")
    print("MUTATED")
except ClaimError as exc:
    print(f"BLOCKED {type(exc).__name__}")
"""


# ---------------------------------------------------------------------------
# Single-winner (real processes)
# ---------------------------------------------------------------------------

def test_only_one_claim_winner(tmp_path):
    root = str(tmp_path / "root")
    _raise(IncidentStore(root), "inc-1")

    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _CONTEND_WORKER, root, "inc-1", f"w{i}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=_REPO,
        )
        for i in range(2)
    ]
    results = []
    for p in procs:
        out, err = p.communicate(timeout=60)
        assert p.returncode == 0, f"worker failed: {err}"
        results.append(out.strip())

    wins = [r for r in results if r.startswith("WIN")]
    loses = [r for r in results if r.startswith("LOSE")]
    assert len(wins) == 1, f"expected exactly one winner, got: {results}"
    assert len(loses) == 1, f"expected exactly one loser, got: {results}"

    # durable: a FRESH reader sees exactly one claimant at epoch 1
    inc = IncidentStore(root).get_incident("inc-1")
    assert inc.epoch == 1
    assert inc.claimant in ("w0", "w1")


# ---------------------------------------------------------------------------
# Expired worker cannot mutate (deterministic race: suspend -> expire -> take
# over -> old fence rejected at the barrier)
# ---------------------------------------------------------------------------

def test_expired_worker_cannot_mutate(tmp_path):
    root = str(tmp_path / "root")
    _raise(IncidentStore(root), "inc-1")
    gate = str(tmp_path / "gate")
    fencefile = str(tmp_path / "fence.json")

    proc = subprocess.Popen(
        [sys.executable, "-c", _BLOCK_WORKER, root, "inc-1", "w-old", gate, fencefile],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=_REPO,
    )

    # wait until the worker has durably acquired and recorded its identity
    deadline = time.time() + 30
    while not os.path.exists(fencefile) and time.time() < deadline:
        time.sleep(0.05)
    assert os.path.exists(fencefile), f"worker never acquired: {proc.stderr.read() if proc.poll() else ''}"
    old = json.load(open(fencefile))

    # let the 1s lease lapse while the worker stays suspended near mutation
    time.sleep(1.5)

    # a new claimant (R2-D2-owned disposable) takes over: exact PID+start-time
    # validation, then TERM the old disposable proc, prove it dead, new epoch.
    # (The executor would have attested the old worker's (pid, start_time) into
    # the owned-process registry at spawn time; the test records that here.)
    mgr = _manager(root)
    mgr.store.register_owned_process("inc-1", old["pid"], old["pid_start_time"])
    new_pid = os.getpid()
    fence_b = mgr.takeover(
        "inc-1", "w-new",
        pid=new_pid, pid_start_time=proc_start_time(new_pid), owned_proc=True,
    )
    mgr.validate_for_mutation(fence_b)  # must NOT raise

    # the old authority can no longer pass the barrier: reconstruct its stale
    # fence (same claimant/epoch/nonce/pid/start-time) and reject it
    old_claim = Claim(
        incident_id="inc-1",
        epoch=old["epoch"],
        claimant_id=old["claimant_id"],
        nonce=old["nonce"],
        pid=old["pid"],
        pid_start_time=old["pid_start_time"],
        lease_expiry=0.0,
        owned_proc=True,
    )
    with pytest.raises(StaleFenceError):
        mgr.validate_for_mutation(Fence(mgr, old_claim))

    # the suspended worker was terminated by takeover (proven dead, not left hanging)
    proc.wait(timeout=30)
    assert proc.poll() is not None

    # durable state shows the NEW claimant at epoch 2
    inc = IncidentStore(root).get_incident("inc-1")
    assert inc.epoch == 2
    assert inc.claimant == "w-new"


# ---------------------------------------------------------------------------
# Crash after mutation => UNKNOWN + re-diagnose; sentinel runs at most once
# ---------------------------------------------------------------------------

def test_crash_after_mutation_requires_reconciliation(tmp_path):
    root = str(tmp_path / "root")
    _raise(IncidentStore(root), "inc-1")
    sentinel_path = tmp_path / "sentinel.log"
    now = [0.0]

    mgr = _manager(root, clock=lambda: now[0])
    fence = mgr.acquire("inc-1", "w1", owned_proc=True)
    mgr.queue_operation(fence, "op-1")
    mgr.mark_started(fence, "op-1")  # durable: STARTED

    # guarded sentinel side effect executes exactly once here
    with open(sentinel_path, "a") as f:
        f.write("x\n")

    # CRASH before settling the result (no mark_settled). A restarted
    # supervisor reconciles against the durable receipt.
    fresh = _manager(root, clock=lambda: now[0])
    recon = fresh.reconcile("inc-1")
    assert recon.verdict is Verdict.UNKNOWN
    assert recon.receipt_state == RECEIPT_STARTED
    assert recon.re_diagnose is True

    # never blindly replay: the sentinel ran at most once (reconcile re-runs
    # DIAGNOSIS, not the mutation)
    assert open(sentinel_path).read() == "x\n"

    # a re-launch of the same operation is rejected (receipt already STARTED,
    # not queued) — the mutation cannot run twice
    with pytest.raises(InFlightOperationError):
        fresh.mark_started(fence, "op-1")


# ---------------------------------------------------------------------------
# Fencing: stale epoch / missing claim / PID reuse / start-time mismatch
# ---------------------------------------------------------------------------

def test_stale_epoch_rejected(tmp_path):
    root = str(tmp_path / "root")
    _raise(IncidentStore(root), "inc-1")
    mgr = _manager(root, clock=lambda: 0.0)
    f1 = mgr.acquire("inc-1", "w1", owned_proc=True)  # epoch 1
    f1.release()
    f2 = mgr.acquire("inc-1", "w2", owned_proc=True)  # epoch 2

    mgr.validate_for_mutation(f2)  # current fence is fine
    with pytest.raises(StaleFenceError):
        mgr.validate_for_mutation(f1)  # epoch 1 != current 2


def test_missing_claim_rejected(tmp_path):
    root = str(tmp_path / "root")
    _raise(IncidentStore(root), "inc-1")
    mgr = _manager(root, clock=lambda: 0.0)
    f = mgr.acquire("inc-1", "w1", owned_proc=True)
    f.release()  # claim cleared
    with pytest.raises(StaleFenceError):
        mgr.validate_for_mutation(f)  # no claim -> stale


def test_pid_reuse_start_time_mismatch_rejected(tmp_path):
    root = str(tmp_path / "root")
    _raise(IncidentStore(root), "inc-1")
    mgr = _manager(root, clock=lambda: 0.0)
    f = mgr.acquire("inc-1", "w1", pid=1234, pid_start_time=100.0, owned_proc=True)

    # same pid but a DIFFERENT start time (PID reuse by another process)
    reused = replace(f.claim, pid_start_time=999.0)
    with pytest.raises(StaleFenceError):
        mgr.validate_for_mutation(Fence(mgr, reused))

    # a different pid entirely
    wrong_pid = replace(f.claim, pid=4321)
    with pytest.raises(StaleFenceError):
        mgr.validate_for_mutation(Fence(mgr, wrong_pid))

    # the genuine fence still validates (identity unchanged)
    mgr.validate_for_mutation(f)


# ---------------------------------------------------------------------------
# Supervisor restart resumes correctly (monotonic epoch + reconcile)
# ---------------------------------------------------------------------------

def test_supervisor_restart_resumes_correctly(tmp_path):
    root = str(tmp_path / "root")
    _raise(IncidentStore(root), "inc-1")
    now = [0.0]
    mgr_a = _manager(root, clock=lambda: now[0])
    f = mgr_a.acquire(
        "inc-1", "supervisor",
        pid=_DEAD_PID, pid_start_time=1.0, owned_proc=True,
    )
    mgr_a.queue_operation(f, "op-1")
    mgr_a.mark_started(f, "op-1")
    mgr_a.mark_settled(f, "op-1", Verdict.PASS)
    # supervisor "crashes" without releasing; its lease lapses
    now[0] = 1000.0

    # a RESTARTED supervisor (fresh manager, same store) resumes
    fresh = _manager(root, clock=lambda: now[0])
    recon = fresh.reconcile("inc-1")
    assert recon.receipt_state == RECEIPT_SETTLED
    assert recon.verdict is Verdict.PASS
    assert recon.re_diagnose is False

    # takeover proves the old (dead) pid and resumes with a MONOTONIC epoch
    # (the old owner's (pid, start_time) is registry-attested as owned).
    fresh.store.register_owned_process("inc-1", _DEAD_PID, 1.0)
    f2 = fresh.takeover(
        "inc-1", "supervisor",
        pid=_DEAD_PID_2, pid_start_time=2.0, owned_proc=True,
    )
    assert f2.claim.epoch == 2
    fresh.validate_for_mutation(f2)


# ---------------------------------------------------------------------------
# max_attempts exhaustion escalates (no further mutation)
# ---------------------------------------------------------------------------

def test_max_attempts_exhaustion_escalates(tmp_path):
    root = str(tmp_path / "root")
    _raise(IncidentStore(root), "inc-1")
    mgr = _manager(root, clock=lambda: 0.0)
    f = mgr.acquire("inc-1", "w1", owned_proc=True)
    for i in range(3):  # DEFAULT_MAX_ATTEMPTS == 3
        mgr.queue_operation(f, f"op-{i}")
        mgr.mark_started(f, f"op-{i}")
        mgr.mark_settled(f, f"op-{i}", Verdict.UNKNOWN)  # never resolves

    inc = IncidentStore(root).get_incident("inc-1")
    assert inc.phase == PHASE_ESCALATED

    # no further mutation after escalation
    with pytest.raises(ClaimError):
        mgr.queue_operation(f, "op-extra")


# ---------------------------------------------------------------------------
# An already-STARTED request blocks a NEW mutating epoch until settle/reconcile
# ---------------------------------------------------------------------------

def test_started_request_blocks_new_mutating_epoch(tmp_path):
    root = str(tmp_path / "root")
    _raise(IncidentStore(root), "inc-1")
    now = [0.0]
    mgr = _manager(root, clock=lambda: now[0])

    # a STUCK shared client/session (non-disposable) with an in-flight op
    f = mgr.acquire(
        "inc-1", "stuck-client",
        pid=_DEAD_PID, pid_start_time=3.0, owned_proc=False,
    )
    mgr.queue_operation(f, "op-1")
    mgr.mark_started(f, "op-1")  # in-flight
    now[0] = 60.0  # lease lapses; the op may still be executing

    # a NEW claimant must NOT allocate a new mutating epoch (freeze+escalate)
    with pytest.raises(FrozenLaneError):
        mgr.takeover(
            "inc-1", "w-new",
            pid=_DEAD_PID_2, pid_start_time=4.0, owned_proc=True,
        )
    assert IncidentStore(root).get_incident("inc-1").epoch == 1  # unchanged


def test_started_request_unblocks_after_reconcile(tmp_path):
    root = str(tmp_path / "root")
    _raise(IncidentStore(root), "inc-1")
    now = [0.0]
    mgr = _manager(root, clock=lambda: now[0])

    # R2-D2-owned disposable worker: in-flight op, then its owner dies
    f = mgr.acquire(
        "inc-1", "worker-a",
        pid=_DEAD_PID, pid_start_time=5.0, owned_proc=True,
    )
    mgr.queue_operation(f, "op-1")
    mgr.mark_started(f, "op-1")
    now[0] = 60.0  # lease lapses

    # takeover proves the owner dead and resumes with a new epoch
    # (the old owner's (pid, start_time) is registry-attested as owned).
    mgr.store.register_owned_process("inc-1", _DEAD_PID, 5.0)
    f2 = mgr.takeover(
        "inc-1", "worker-b",
        pid=_DEAD_PID_2, pid_start_time=6.0, owned_proc=True,
    )
    assert f2.claim.epoch == 2

    # ...but the STARTED receipt still blocks a NEW mutation until reconciled
    with pytest.raises(InFlightOperationError):
        mgr.queue_operation(f2, "op-2")
    recon = mgr.reconcile("inc-1")
    assert recon.receipt_state == RECEIPT_STARTED
    assert recon.verdict is Verdict.UNKNOWN
    assert recon.re_diagnose is True

    # after settling the old op (re-diagnosis result), a new op can start
    mgr.mark_settled(f2, "op-1", Verdict.UNKNOWN)
    mgr.queue_operation(f2, "op-2")
    mgr.mark_started(f2, "op-2")
    assert IncidentStore(root).get_incident("inc-1").op_id == "op-2"


# ---------------------------------------------------------------------------
# A queued old request is rejected at the launch barrier
# ---------------------------------------------------------------------------

def test_queued_old_request_rejected_at_launch_barrier(tmp_path):
    root = str(tmp_path / "root")
    _raise(IncidentStore(root), "inc-1")
    now = [0.0]
    mgr = _manager(root, clock=lambda: now[0])

    f = mgr.acquire(
        "inc-1", "worker-a",
        pid=_DEAD_PID, pid_start_time=7.0, owned_proc=True,
    )
    mgr.queue_operation(f, "op-1")  # queued, never started
    now[0] = 60.0  # lease lapses

    # (the old owner's (pid, start_time) is registry-attested as owned)
    mgr.store.register_owned_process("inc-1", _DEAD_PID, 7.0)
    f2 = mgr.takeover(
        "inc-1", "worker-b",
        pid=_DEAD_PID_2, pid_start_time=8.0, owned_proc=True,
    )
    assert f2.claim.epoch == 2

    # the OLD fence (epoch 1) is rejected at the launch barrier
    with pytest.raises(StaleFenceError):
        mgr.mark_started(f, "op-1")
    # a FRESH fence cannot resurrect the old queued op either (op_epoch mismatch)
    with pytest.raises(StaleFenceError):
        mgr.mark_started(f2, "op-1")


# ---------------------------------------------------------------------------
# Lease expiry surfaced distinctly (a fence whose lease lapsed but identity is
# otherwise intact)
# ---------------------------------------------------------------------------

def test_lease_expiry_is_distinct(tmp_path):
    root = str(tmp_path / "root")
    _raise(IncidentStore(root), "inc-1")
    now = [0.0]
    mgr = _manager(root, clock=lambda: now[0])
    f = mgr.acquire("inc-1", "w1", owned_proc=True)
    now[0] = 100.0  # lease (30s) lapsed; identity still matches
    with pytest.raises(LeaseExpiredError):
        mgr.validate_for_mutation(f)


# ---------------------------------------------------------------------------
# Forged fence must NOT bypass durable lease expiry (Task 10 security fix).
# A fence carries no authority of its own: every field is checked against the
# DURABLE incident record, including lease_expiry.
# ---------------------------------------------------------------------------

def test_forged_future_lease_rejected_after_durable_lease_lapses(tmp_path):
    root = str(tmp_path / "root")
    _raise(IncidentStore(root), "inc-1")
    now = [0.0]
    mgr = _manager(root, lease_seconds=30.0, clock=lambda: now[0])
    f = mgr.acquire("inc-1", "w1", owned_proc=True)

    now[0] = 130.0  # durable lease (30.0) has lapsed
    inc = IncidentStore(root).get_incident("inc-1")
    assert inc.lease_expiry == 30.0  # the DURABLE lease really did lapse

    # forged fence: identical identity fields, but self-reported lease_expiry
    # extended arbitrarily far into the future.
    forged = replace(f.claim, lease_expiry=10_000.0)
    with pytest.raises(LeaseExpiredError):
        mgr.validate_for_mutation(Fence(mgr, forged))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("nonce", "forged-nonce"),
        ("epoch", 99),
        ("claimant_id", "forged-claimant"),
        ("pid", 7777),
        ("pid_start_time", 12345.6),
        ("lease_expiry", 10_000.0),
    ],
)
def test_forged_identity_field_rejected_against_durable(tmp_path, field, value):
    root = str(tmp_path / "root")
    _raise(IncidentStore(root), "inc-1")
    now = [0.0]
    mgr = _manager(root, lease_seconds=30.0, clock=lambda: now[0])
    f = mgr.acquire("inc-1", "w1", owned_proc=True)
    forged = replace(f.claim, **{field: value})
    with pytest.raises(StaleFenceError):
        mgr.validate_for_mutation(Fence(mgr, forged))


def test_legitimate_fence_passes_while_durable_lease_valid(tmp_path):
    root = str(tmp_path / "root")
    _raise(IncidentStore(root), "inc-1")
    now = [0.0]
    mgr = _manager(root, lease_seconds=30.0, clock=lambda: now[0])
    f = mgr.acquire("inc-1", "w1", owned_proc=True)
    now[0] = 10.0  # still within the durable 30s lease
    mgr.validate_for_mutation(f)  # must NOT raise
    mgr.renew(f)  # still authorized to renew


def test_takeover_after_expiry_new_epoch_and_old_fence_blocked(tmp_path):
    root = str(tmp_path / "root")
    _raise(IncidentStore(root), "inc-1")
    now = [0.0]
    mgr = _manager(root, lease_seconds=30.0, clock=lambda: now[0])
    f_old = mgr.acquire(
        "inc-1", "w-old",
        pid=_DEAD_PID, pid_start_time=1.0, owned_proc=True,
    )
    now[0] = 130.0  # durable lease lapsed

    # (the old owner's (pid, start_time) is registry-attested as owned)
    mgr.store.register_owned_process("inc-1", _DEAD_PID, 1.0)
    f_new = mgr.takeover(
        "inc-1", "w-new",
        pid=_DEAD_PID_2, pid_start_time=2.0, owned_proc=True,
    )
    assert f_new.claim.epoch == 2
    mgr.validate_for_mutation(f_new)  # new epoch fence is authoritative

    # the old fence (epoch 1) can no longer mutate
    with pytest.raises(StaleFenceError):
        mgr.validate_for_mutation(f_old)

    # a forged-future-lease OLD fence is also blocked (its epoch is now stale)
    forged = replace(f_old.claim, lease_expiry=10_000.0)
    with pytest.raises(StaleFenceError):
        mgr.validate_for_mutation(Fence(mgr, forged))
