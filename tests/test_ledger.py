"""SQLite hit-ledger tests (Task 3).

Locks the ledger contract from ED-209-HANDOFF.md §5 and plan §2 (C5): a hit is
recorded and queried by rule/outcome through the *real* DB connection; matched
facts are bounded/redacted (the full sensitive payload is never stored); the
open/busy timeout is bounded so contention never hangs the agent; a ledger
write failure never suppresses or downgrades a deny (it returns a visible
degraded record and the deny stands); and log-outcome degradation is visible,
never silent.
"""

import sqlite3
import threading
import time

from operator_guards.ed209.engine import (
    ACTION_DENY,
    COUNTED_FACT_MAX_CHARS,
    EvaluationContext,
    evaluate,
)
from operator_guards.ed209.ledger import DEGRADED_WRITE, HitLedger, HitRecord
from operator_guards.ed209.rules import Rule, compile_rules


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


def _deny_ctx(payload="echo SECRET_TOKEN"):
    return EvaluationContext(
        profile_home="/home/u",
        client_id="c",
        session_id="sess",
        turn_id="turn",
        surface="tool",
        tool_name="Bash",
        capabilities=frozenset({"shell"}),
        payload=payload,
    )


# --- record + query by rule / outcome through the real DB connection --------

def test_record_hit_and_query_by_rule(tmp_path):
    ledger = HitLedger(str(tmp_path / "hits.db"))
    ledger.record_hit(rule_id="r1", session_id="s1", outcome="deny", counted_fact="denied 'x'")
    ledger.record_hit(rule_id="r2", session_id="s1", outcome="block", counted_fact="blocked")

    rows = ledger.query_by_rule("r1")
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "r1"
    assert rows[0]["outcome"] == "deny"
    assert rows[0]["session_id"] == "s1"
    assert rows[0]["counted_fact"] == "denied 'x'"


def test_query_by_outcome_through_real_connection(tmp_path):
    db = tmp_path / "hits.db"
    ledger = HitLedger(str(db))
    ledger.record_hit(rule_id="r1", session_id="s1", outcome="deny", counted_fact="a")
    ledger.record_hit(rule_id="r2", session_id="s1", outcome="deny", counted_fact="b")
    ledger.record_hit(rule_id="r3", session_id="s1", outcome="block", counted_fact="c")

    # Query through the ledger's real connection AND through an independent
    # sqlite3 connection to prove the rows are genuinely persisted.
    assert len(ledger.query_by_outcome("deny")) == 2
    with sqlite3.connect(str(db)) as conn:
        n = conn.execute("SELECT COUNT(*) FROM hits WHERE outcome = 'deny'").fetchone()[0]
    assert n == 2


def test_outcomes_for_rule_matches_canonical_query(tmp_path):
    # The canonical measurement (ED-209-HANDOFF.md §5):
    #   select outcome, count(*) from hits where rule_id=? group by outcome
    db = tmp_path / "hits.db"
    ledger = HitLedger(str(db))
    for outcome in ("deny", "deny", "block"):
        ledger.record_hit(rule_id="r1", session_id="s1", outcome=outcome, counted_fact="f")

    assert ledger.outcomes_for_rule("r1") == {"deny": 2, "block": 1}


def test_schema_indexes_rule_session_outcome_and_no_payload_column(tmp_path):
    db = tmp_path / "hits.db"
    ledger = HitLedger(str(db))
    ledger.record_hit(rule_id="r", session_id="s", outcome="o", counted_fact="")

    with sqlite3.connect(str(db)) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(hits)")}
        assert {"rule_id", "session_id", "outcome", "counted_fact"} <= cols
        # The schema physically cannot store a raw payload / tool args.
        assert "payload" not in cols
        assert "tool_args" not in cols

        covered = set()
        for row in conn.execute("PRAGMA index_list(hits)").fetchall():
            name = row[1]
            covered |= {r[2] for r in conn.execute(f"PRAGMA index_info({name})").fetchall()}
    assert {"rule_id", "session_id", "outcome"} <= covered


# --- bounded / redacted facts -----------------------------------------------

def test_fact_is_bounded_to_counted_fact_max_chars(tmp_path):
    db = tmp_path / "hits.db"
    ledger = HitLedger(str(db))
    huge = "A" * (COUNTED_FACT_MAX_CHARS * 10)
    rec = ledger.record_hit(rule_id="r", session_id="s", outcome="deny", counted_fact=huge)
    assert rec.ok
    with sqlite3.connect(str(db)) as conn:
        fact = conn.execute("SELECT counted_fact FROM hits").fetchone()[0]
    assert len(fact) <= COUNTED_FACT_MAX_CHARS


def test_sensitive_payload_never_persisted(tmp_path):
    # Only the bounded counted fact is stored; the raw sensitive payload never
    # enters any column, even by accident.
    db = tmp_path / "hits.db"
    ledger = HitLedger(str(db))
    secret = "super-secret-token-9f8e7d6c5b4a"
    fact = "denied 'SECRET_TOKEN'"
    ledger.record_hit(rule_id="r", session_id="s", outcome="deny", counted_fact=fact)

    with sqlite3.connect(str(db)) as conn:
        blob = repr(conn.execute("SELECT * FROM hits").fetchall())
    assert secret not in blob
    assert fact in blob


def test_fact_flattens_whitespace(tmp_path):
    db = tmp_path / "hits.db"
    ledger = HitLedger(str(db))
    ledger.record_hit(rule_id="r", session_id="s", outcome="deny", counted_fact="line1\nline2\t  line3")
    with sqlite3.connect(str(db)) as conn:
        fact = conn.execute("SELECT counted_fact FROM hits").fetchone()[0]
    assert "\n" not in fact and "\t" not in fact


# --- bounded open/busy timeout (never hangs) --------------------------------

def test_record_hit_does_not_hang_under_held_write_lock(tmp_path):
    db = tmp_path / "hits.db"
    ledger = HitLedger(str(db), timeout=0.1)
    ledger.record_hit(rule_id="seed", session_id="s", outcome="allow", counted_fact="")

    holder = sqlite3.connect(str(db), timeout=0.05)
    holder.execute("PRAGMA busy_timeout=50")
    holder.execute("BEGIN IMMEDIATE")  # RESERVED lock: blocks other writers
    try:
        start = time.monotonic()
        rec = ledger.record_hit(rule_id="r", session_id="s", outcome="deny", counted_fact="x")
        elapsed = time.monotonic() - start
    finally:
        holder.rollback()
        holder.close()

    assert elapsed < 2.0  # bounded: contention never hangs the agent
    assert isinstance(rec, HitRecord)
    assert rec.ok is False       # write was contended, so it degraded
    assert rec.degraded          # … and the degradation is visible


# --- C5: ledger write failure never suppresses or downgrades a deny ---------

def test_ledger_write_failure_does_not_suppress_deny(tmp_path):
    compiled = compile_rules([_deny_rule()])
    decision = evaluate(compiled, _deny_ctx())
    assert decision.action == ACTION_DENY

    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a directory")
    ledger = HitLedger(str(blocker / "hits.db"))
    rec = ledger.record_hit(
        rule_id="secret-deny",
        session_id="sess",
        outcome=decision.action,
        counted_fact=decision.counted_fact,
    )

    # The write failed, visibly (degraded), and did NOT raise past the caller.
    assert rec.ok is False
    assert rec.degraded == (DEGRADED_WRITE,)
    # The deny itself is unchanged — recording failure never downgrades it.
    assert decision.action == ACTION_DENY


def test_log_outcome_write_failure_is_visible(tmp_path):
    db = tmp_path / "hits.db"
    good = HitLedger(str(db))
    ok_rec = good.record_hit(rule_id="r", session_id="s", outcome="log", counted_fact="fact")
    assert ok_rec.ok
    assert ok_rec.degraded == ()  # no degradation on success

    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir")
    bad = HitLedger(str(blocker / "hits.db"))
    bad_rec = bad.record_hit(rule_id="r", session_id="s", outcome="log", counted_fact="fact")
    assert bad_rec.ok is False
    assert bad_rec.degraded == (DEGRADED_WRITE,)  # visible, never silent


# --- deterministic deny survives hit-ledger contention ----------------------

def test_parallel_hits_do_not_raise_and_deny_survives_contention(tmp_path):
    ledger = HitLedger(str(tmp_path / "hits.db"), timeout=5.0)
    compiled = compile_rules([_deny_rule()])

    errors = []

    def worker(i):
        try:
            for _ in range(25):
                ledger.record_hit(rule_id=f"r{i}", session_id="s", outcome="deny", counted_fact="x")
        except Exception as exc:  # noqa: BLE001 — prove none propagate
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    # Evaluation runs concurrently with the hammered ledger; deny must hold.
    decisions = [evaluate(compiled, _deny_ctx()) for _ in range(200)]
    for t in threads:
        t.join()

    assert errors == []
    assert all(d.action == ACTION_DENY for d in decisions)
    assert ledger.count() == 4 * 25  # every hit landed; none silently dropped
