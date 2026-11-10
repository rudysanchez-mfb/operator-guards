"""Per-session state / budget tests (Task 3).

Locks the state contract from ED-209-HANDOFF.md §1/§5/§7 and plan §2 (C2):
atomic persistence with a 7-day TTL; the once-per-session-per-rule injection
guard survives concurrent tool calls (threads AND processes — exactly one
winner); budget overspend is impossible across parallel tools; real sessions
are counted separately from turns and from delegated children; and a tool deny
remains effective after the reply (block) budget is exhausted.
"""

import json
import multiprocessing as mp
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from operator_guards.ed209.engine import ACTION_DENY, EvaluationContext, evaluate
from operator_guards.ed209.ledger import HitLedger
from operator_guards.ed209.rules import Rule, compile_rules
from operator_guards.ed209.state import SessionStateStore


def _deny_rule():
    return Rule(
        id="secret-deny",
        surface="tool",
        rule_class="known-bad",
        action="deny",
        pattern=r"\bSECRET_TOKEN\b",
        reason="denied '{match}'",
        origin="test",
    )


def _deny_ctx():
    return EvaluationContext(
        profile_home="/home/u",
        client_id="c",
        session_id="sess",
        turn_id="turn",
        surface="tool",
        tool_name="Bash",
        capabilities=frozenset({"shell"}),
        payload="echo SECRET_TOKEN",
    )


# --- block / reviewer budgets -----------------------------------------------

def test_consume_block_budget_exhausts_exactly(tmp_path):
    s = SessionStateStore(str(tmp_path))
    results = [s.consume_block("sess", max_blocks=3) for _ in range(5)]
    assert results == [True, True, True, False, False]
    assert s.blocks_used("sess") == 3


def test_consume_reviewer_budget_exhausts_exactly(tmp_path):
    s = SessionStateStore(str(tmp_path))
    results = [s.consume_reviewer("sess", max_reviewer=2) for _ in range(4)]
    assert results == [True, True, False, False]
    assert s.reviewer_calls_used("sess") == 2


# --- once-per-session-per-rule injection guard ------------------------------

def test_injection_once_per_session_per_rule(tmp_path):
    s = SessionStateStore(str(tmp_path))
    assert s.try_mark_injected("sess", "rule-a") is True
    assert s.try_mark_injected("sess", "rule-a") is False  # same session + rule
    assert s.try_mark_injected("sess", "rule-b") is True   # different rule
    assert s.try_mark_injected("sess2", "rule-a") is True  # different session


# --- persistence + TTL ------------------------------------------------------

def test_state_persists_across_store_instances(tmp_path):
    s = SessionStateStore(str(tmp_path))
    s.consume_block("sess")
    s.try_mark_injected("sess", "r")
    s2 = SessionStateStore(str(tmp_path))  # fresh instance, same dir
    assert s2.blocks_used("sess") == 1
    assert s2.is_injected("sess", "r") is True


def test_ttl_expiry_resets_counters(tmp_path):
    s = SessionStateStore(str(tmp_path), ttl_seconds=1000)
    t0 = 1_000_000.0
    assert s.consume_block("sess", now=t0) is True
    assert s.try_mark_injected("sess", "r", now=t0) is True
    assert s.blocks_used("sess", now=t0 + 1) == 1  # still fresh
    # after the TTL elapses, counters read as a fresh session
    assert s.blocks_used("sess", now=t0 + 1001) == 0
    assert s.is_injected("sess", "r", now=t0 + 1001) is False


def test_atomic_write_leaves_no_tmp_or_lock_files(tmp_path):
    s = SessionStateStore(str(tmp_path))
    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(lambda _: s.consume_block("sess", max_blocks=4), range(8)))
    # the persisted JSON is complete and correct
    with open(s.state_path("sess"), encoding="utf-8") as f:
        data = json.load(f)
    assert data["blocks"] == 4
    # no partial temp files or abandoned lock files remain
    leftovers = [
        p for p in os.listdir(str(tmp_path)) if p.startswith(".tmp") or p.endswith(".lock")
    ]
    assert leftovers == []


# --- real sessions vs turns vs delegated children ---------------------------

def test_turns_share_session_budget_not_double_counted(tmp_path):
    s = SessionStateStore(str(tmp_path))
    # turn 1 and turn 2 of the SAME session share one counter — a second turn
    # is not a second session.
    assert s.consume_block("sess-A") is True  # turn 1
    assert s.consume_block("sess-A") is True  # turn 2
    assert s.blocks_used("sess-A") == 2


def test_child_session_does_not_share_parent_counters(tmp_path):
    s = SessionStateStore(str(tmp_path))
    # A delegated child is a distinct real session (its own session_id); it
    # must NOT inherit the parent's per-session counters.
    assert s.consume_block("parent") is True
    assert s.consume_block("child") is True
    assert s.blocks_used("parent") == 1
    assert s.blocks_used("child") == 1


def test_store_keys_strictly_on_session_id(tmp_path):
    s = SessionStateStore(str(tmp_path))
    s.consume_block("real-session")
    assert s.blocks_used("real-session") == 1
    # turn_id / parent_id / task_id are never keys — the store has no notion
    # of them and they map to independent (empty) state.
    assert s.blocks_used("turn-123") == 0
    assert s.blocks_used("parent-of-real") == 0
    assert s.blocks_used("task-456") == 0


# --- concurrency: threads ---------------------------------------------------

def test_parallel_injection_exactly_one_winner_threads(tmp_path):
    s = SessionStateStore(str(tmp_path))
    with ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(lambda _: s.try_mark_injected("sess", "rule"), range(20)))
    assert sum(results) == 1


def test_parallel_block_budget_no_overspend_threads(tmp_path):
    s = SessionStateStore(str(tmp_path))
    with ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(lambda _: s.consume_block("sess", max_blocks=5), range(20)))
    assert sum(results) == 5
    assert s.blocks_used("sess") == 5


# --- concurrency: processes (O_EXCL lock is cross-process) ------------------

def _mp_inject_worker(state_dir, session_id, rule_id, q):
    store = SessionStateStore(state_dir)
    q.put(store.try_mark_injected(session_id, rule_id))


def test_parallel_injection_exactly_one_winner_processes(tmp_path):
    try:
        ctx = mp.get_context("fork")
    except ValueError:
        pytest.importorskip("multiprocessing fork unavailable")
        return
    q = ctx.Queue()
    procs = [
        ctx.Process(target=_mp_inject_worker, args=(str(tmp_path), "sess", "rule", q))
        for _ in range(8)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=30)
        assert p.exitcode == 0
    results = [q.get(timeout=5) for _ in procs]
    assert sum(results) == 1


# --- malformed / wrong-shaped state degrades to a fresh session -------------

def _write_raw_state(store, session_id, payload):
    with open(store.state_path(session_id), "w", encoding="utf-8") as f:
        json.dump(payload, f)


@pytest.mark.parametrize(
    "payload",
    [
        [1, 2, 3],                       # top-level list
        "just-a-string",                 # top-level string
        12345,                           # top-level number
        {"injected": "not-a-dict"},      # injected: wrong container type (str)
        {"injected": [1, 2, 3]},         # injected: wrong container type (list)
        {"updated_at": None},            # numeric field null
        {"blocks": "not-a-number"},      # numeric field wrong type
    ],
)
def test_malformed_state_degrades_to_fresh_session(tmp_path, payload):
    s = SessionStateStore(str(tmp_path))
    _write_raw_state(s, "sess", payload)

    # Reading a malformed/wrong-shaped file never raises; it reads as fresh.
    assert s.blocks_used("sess") == 0
    assert s.reviewer_calls_used("sess") == 0
    assert s.is_injected("sess", "rule-a") is False

    # And the mutation paths still work on the degraded state (no crash).
    assert s.consume_block("sess", max_blocks=1) is True
    assert s.try_mark_injected("sess", "rule-a") is True


def test_long_session_ids_sharing_prefix_do_not_collide(tmp_path):
    s = SessionStateStore(str(tmp_path))
    # Two all-safe ids longer than the 120-char filename cap sharing a prefix.
    shared = "a" * 130
    id_a = shared + "X"
    id_b = shared + "Y"
    assert len(id_a) > 120 and len(id_b) > 120

    # Distinct long ids must map to distinct files (no cross-session bleed).
    assert s.state_path(id_a) != s.state_path(id_b)

    s.consume_block(id_a, max_blocks=1)
    assert s.blocks_used(id_a) == 1
    assert s.blocks_used(id_b) == 0  # no shared counter

    assert s.consume_block(id_b, max_blocks=1) is True
    assert s.blocks_used(id_a) == 1
    assert s.blocks_used(id_b) == 1


# --- C2: tool deny survives reply-budget exhaustion (named acceptance row) ---

def test_tool_deny_survives_reply_budget_exhaustion(tmp_path):
    # Exhaust the reply-surface block budget (max_blocks_per_session).
    store = SessionStateStore(str(tmp_path))
    for _ in range(12):
        assert store.consume_block("sess", max_blocks=12) is True
    assert store.consume_block("sess", max_blocks=12) is False  # budget spent

    # A tool deny is evaluated independently of the block budget …
    decision = evaluate(compile_rules([_deny_rule()]), _deny_ctx())
    assert decision.action == ACTION_DENY

    # … and recorded in the ledger, provably, even though the budget is gone.
    ledger = HitLedger(str(tmp_path / "hits.db"))
    rec = ledger.record_hit(
        rule_id="secret-deny",
        session_id="sess",
        outcome=decision.action,
        counted_fact=decision.counted_fact,
    )
    assert rec.ok
    assert ledger.outcomes_for_rule("secret-deny").get("deny", 0) == 1


def test_tool_deny_survives_reviewer_budget_exhaustion(tmp_path):
    # Exhaust the per-session reviewer budget.
    store = SessionStateStore(str(tmp_path))
    for _ in range(2):
        assert store.consume_reviewer("sess", max_reviewer=2) is True
    assert store.consume_reviewer("sess", max_reviewer=2) is False  # budget spent

    # A tool deny is evaluated independently of the reviewer budget …
    decision = evaluate(compile_rules([_deny_rule()]), _deny_ctx())
    assert decision.action == ACTION_DENY

    # … and recorded in the ledger, provably, even though the budget is gone.
    ledger = HitLedger(str(tmp_path / "hits.db"))
    rec = ledger.record_hit(
        rule_id="secret-deny",
        session_id="sess",
        outcome=decision.action,
        counted_fact=decision.counted_fact,
    )
    assert rec.ok
    assert ledger.outcomes_for_rule("secret-deny").get("deny", 0) == 1
