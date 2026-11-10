"""SQLite hit ledger for ED-209.

Every hit is recorded and queryable by rule and by outcome through a real
SQLite connection — a rule existing is not a rule firing, and the only way to
prove one fired is to read the ledger (ED-209-HANDOFF.md §5).

Design constraints honored here (plan §2, C5):

* **Bounded open/busy timeout** — ``sqlite3.connect(path, timeout=...)`` plus
  ``PRAGMA busy_timeout``, so lock contention never hangs the agent. A write
  that cannot acquire the lock within the timeout fails fast.
* **Indexed** ``rule_id`` / ``session_id`` / ``outcome`` columns.
* **Bounded, redacted facts only** — the schema has no column for a raw payload
  or tool arguments. Only the caller-supplied counted fact is stored, and it is
  defensively truncated to ``COUNTED_FACT_MAX_CHARS`` and whitespace-flattened.
* **Fail-open, never silent** — a failed write returns a :class:`HitRecord`
  with ``ok=False`` and a visible ``degraded`` marker. It never raises past the
  caller, so a deny is never suppressed or downgraded by a ledger failure.

The database is opened with ``journal_mode=DELETE`` (matching the upstream
``~/.claude/ed209/hits.db``). Default runtime path is
``<OPERATOR_GUARDS_HOME>/ed209/hits.db``; tests inject an explicit ``tmp_path``.
"""

from __future__ import annotations

import os
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Mapping

from ..common.paths import default_home, env_path
from .engine import COUNTED_FACT_MAX_CHARS

# Default runtime ledger path (tests MUST pass an explicit tmp_path).
# Configurable: OPERATOR_GUARDS_ED209_DB, else <home>/ed209/hits.db.
DEFAULT_HITS_DB = env_path(
    "OPERATOR_GUARDS_ED209_DB",
    str(Path(default_home()) / "ed209" / "hits.db"),
)

# Visible degradation marker recorded on a failed ledger write (never silent).
DEGRADED_WRITE = "ledger:write_failed"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    rule_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    surface TEXT,
    counted_fact TEXT NOT NULL,
    client_id TEXT,
    turn_id TEXT,
    task_id TEXT,
    parent_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_hits_rule_id ON hits(rule_id);
CREATE INDEX IF NOT EXISTS idx_hits_session_id ON hits(session_id);
CREATE INDEX IF NOT EXISTS idx_hits_outcome ON hits(outcome);
"""


@dataclass(frozen=True)
class HitRecord:
    """Result of recording a hit.

    ``ok`` is False when the write failed; ``degraded`` carries a visible
    marker (never silent); ``row_id`` is the inserted row's id on success.
    """

    ok: bool
    degraded: tuple = ()
    row_id: int | None = None


def _bound_fact(text: Any) -> str:
    """Bound and flatten a matched fact; never store the raw sensitive payload."""
    if text is None:
        text = ""
    if not isinstance(text, str):
        text = str(text)
    if len(text) > COUNTED_FACT_MAX_CHARS:
        text = text[:COUNTED_FACT_MAX_CHARS]
    return re.sub(r"\s+", " ", text)


class HitLedger:
    """Append-only SQLite ledger of ED-209 hits, opened lazily and per-operation.

    Each operation opens its own connection, so the instance is safe to share
    across threads; SQLite's file locking serializes writers across processes.
    """

    def __init__(self, path: str = DEFAULT_HITS_DB, timeout: float = 1.0):
        self.path = path
        self.timeout = float(timeout)

    # -- recording ----------------------------------------------------------

    def record_hit(
        self,
        *,
        rule_id: str,
        session_id: str,
        outcome: str,
        counted_fact: str = "",
        surface: str | None = None,
        client_id: str | None = None,
        turn_id: str | None = None,
        task_id: str | None = None,
        parent_id: str | None = None,
        timestamp: float | None = None,
    ) -> HitRecord:
        """Record one hit. Never raises: a failed write returns a degraded record."""
        fact = _bound_fact(counted_fact)
        ts = time.time() if timestamp is None else float(timestamp)
        try:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "INSERT INTO hits (ts, rule_id, session_id, outcome, surface,"
                    " counted_fact, client_id, turn_id, task_id, parent_id)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        ts,
                        rule_id,
                        session_id,
                        outcome,
                        surface,
                        fact,
                        client_id,
                        turn_id,
                        task_id,
                        parent_id,
                    ),
                )
                conn.commit()
                row_id = cur.lastrowid
            finally:
                conn.close()
            return HitRecord(ok=True, row_id=row_id)
        except (sqlite3.Error, OSError):
            # Fail-open and visible: a deny must never be suppressed by a
            # ledger write failure (C5).
            return HitRecord(ok=False, degraded=(DEGRADED_WRITE,))

    # -- querying (through the real DB connection) --------------------------

    def query_by_rule(self, rule_id: str) -> List[Mapping]:
        return self._query(
            "SELECT * FROM hits WHERE rule_id = ? ORDER BY id", (rule_id,)
        )

    def query_by_outcome(self, outcome: str) -> List[Mapping]:
        return self._query(
            "SELECT * FROM hits WHERE outcome = ? ORDER BY id", (outcome,)
        )

    def outcomes_for_rule(self, rule_id: str) -> Mapping[str, int]:
        """Outcome histogram for a rule — the canonical §5 measurement query."""
        rows = self._query(
            "SELECT outcome, COUNT(*) AS n FROM hits WHERE rule_id = ? GROUP BY outcome",
            (rule_id,),
        )
        return {str(r["outcome"]): int(r["n"]) for r in rows}

    def count(self) -> int:
        rows = self._query("SELECT COUNT(*) AS n FROM hits", ())
        return int(rows[0]["n"]) if rows else 0

    # -- internals ----------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=self.timeout)
        try:
            conn.execute(f"PRAGMA busy_timeout={int(self.timeout * 1000)}")
            conn.executescript(_SCHEMA)
        except BaseException:
            conn.close()  # never leak the connection on schema/PRAGMA failure
            raise
        return conn

    def _query(self, sql: str, params: tuple) -> List[Mapping]:
        try:
            conn = self._connect()
            try:
                conn.row_factory = sqlite3.Row
                cur = conn.execute(sql, params)
                return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            return []
