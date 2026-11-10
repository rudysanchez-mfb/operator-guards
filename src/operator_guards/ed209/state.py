"""Per-session state and budget counters for ED-209.

One JSON file per real session at ``<state_dir>/<session_id>.json``, holding
memories injected (once per session per rule), reviewer calls used, and blocks
used, with a 7-day TTL (ED-209-HANDOFF.md §1/§5). ``limits`` in the rules doc
binds the budgets: ``max_blocks_per_session`` (12) and
``max_reviewer_calls_per_session`` (12).

Contracts honored here (plan §2, C2):

* **Atomic writes** — every mutation is written to a temp file in the same
  directory, ``fsync``'d, ``os.replace``'d over the target, then the parent
  directory is ``fsync``'d. A reader only ever sees a complete file; a torn or
  partial write is impossible, and concurrent writers never corrupt the JSON.
* **7-day TTL** — a state whose ``updated_at`` is older than the TTL reads as a
  fresh session (counters reset).
* **Once-per-session-per-rule injection guard** — serialized by an
  ``O_CREAT|O_EXCL`` lock file (the single-winner primitive documented in
  R2D2-HANDOFF.md §4/§8). Exactly one of N concurrent callers wins; the rest
  see "already injected". If the lock cannot be acquired within a bounded
  window, the guard fails *closed* (returns False — never a duplicate
  injection; a missed injection is benign).
* **Budget overspend impossible** — ``consume_block`` / ``consume_reviewer``
  do a locked read-modify-write, so parallel tool calls can never overspend a
  session budget.
* **Sessions are keyed strictly by ``session_id``** — turns (same session) share
  one counter and are never double-counted as sessions; a delegated child (its
  own ``session_id``) gets independent counters and never shares the parent's.
  ``turn_id`` / ``task_id`` / ``parent_id`` are *not* keys — this store has no
  notion of them.

Default runtime dir is ``<OPERATOR_GUARDS_HOME>/ed209/state``; tests inject an
explicit ``tmp_path``.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict

from ..common.paths import default_home, env_path

# Default runtime state dir (tests MUST pass an explicit tmp_path).
# Configurable: OPERATOR_GUARDS_ED209_STATE, else <home>/ed209/state.
DEFAULT_STATE_DIR = env_path(
    "OPERATOR_GUARDS_ED209_STATE",
    str(Path(default_home()) / "ed209" / "state"),
)

TTL_SECONDS = 7 * 24 * 60 * 60  # 7-day source TTL
DEFAULT_MAX_BLOCKS = 12
DEFAULT_MAX_REVIEWER_CALLS = 12

_LOCK_POLL_SECONDS = 0.01
_LOCK_WAIT_SECONDS = 5.0
_LOCK_STALE_SECONDS = 30.0

_FILENAME_SAFE = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)

# Max length of a state-file basename (avoids over-long filenames).
_MAX_NAME = 120


class _LockUnavailable(Exception):
    """Raised internally when the per-session lock cannot be acquired in time."""


def _is_number(value) -> bool:
    """True for a real number (int/float), but not bool."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _coerce_int(value, default: int = 0) -> int:
    """Coerce a value to int only if it is a real number; else the default."""
    return int(value) if _is_number(value) else default


def _coerce_float(value, default: float = 0.0) -> float:
    """Coerce a value to float only if it is a real number; else the default."""
    return float(value) if _is_number(value) else default


@dataclass
class SessionState:
    session_id: str
    injected: Dict[str, float] = field(default_factory=dict)  # rule_id -> ts
    reviewer_calls: int = 0
    blocks: int = 0
    updated_at: float = 0.0

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "injected": dict(self.injected),
            "reviewer_calls": self.reviewer_calls,
            "blocks": self.blocks,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SessionState":
        if not isinstance(d, dict):
            raise ValueError("state must be a JSON object")
        injected: Dict[str, float] = {}
        raw_injected = d.get("injected")
        if isinstance(raw_injected, dict):
            for key, value in raw_injected.items():
                if _is_number(value):
                    injected[str(key)] = float(value)
        session_id = d.get("session_id")
        return cls(
            session_id=session_id if isinstance(session_id, str) else "",
            injected=injected,
            reviewer_calls=_coerce_int(d.get("reviewer_calls")),
            blocks=_coerce_int(d.get("blocks")),
            updated_at=_coerce_float(d.get("updated_at")),
        )


def _safe_name(session_id: str) -> str:
    """Map a session id to a safe basename (no traversal, stable across runs)."""
    if not isinstance(session_id, str) or not session_id:
        raise ValueError("session_id must be a non-empty string")
    safe = "".join(c if c in _FILENAME_SAFE else "_" for c in session_id)
    if safe != session_id or safe in (".", ".."):
        safe = "s_" + hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:32]
    if len(safe) > _MAX_NAME:
        # Truncate but keep the key unique: append a short hash of the full id
        # so distinct long ids sharing a prefix map to distinct files.
        digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
        safe = f"{safe[:_MAX_NAME - 9]}_{digest[:8]}"
    return safe


class SessionStateStore:
    def __init__(
        self,
        state_dir: str = DEFAULT_STATE_DIR,
        ttl_seconds: float = TTL_SECONDS,
        max_blocks: int = DEFAULT_MAX_BLOCKS,
        max_reviewer_calls: int = DEFAULT_MAX_REVIEWER_CALLS,
    ):
        self.state_dir = state_dir
        self.ttl_seconds = float(ttl_seconds)
        self.max_blocks = max_blocks
        self.max_reviewer_calls = max_reviewer_calls

    # -- paths --------------------------------------------------------------

    def state_path(self, session_id: str) -> str:
        return os.path.join(self.state_dir, _safe_name(session_id) + ".json")

    def _lock_path(self, session_id: str) -> str:
        return self.state_path(session_id) + ".lock"

    # -- reads --------------------------------------------------------------

    def load(self, session_id: str, now: float | None = None) -> SessionState:
        """Load a session's state; an expired or unreadable file is a fresh state."""
        ts = _now(now)
        path = self.state_path(session_id)
        try:
            with open(path, encoding="utf-8") as f:
                state = SessionState.from_dict(json.load(f))
        except (OSError, ValueError, json.JSONDecodeError, TypeError, AttributeError):
            return SessionState(session_id=session_id)
        state.session_id = session_id  # a wrong/missing id in the file is ignored
        if ts - state.updated_at > self.ttl_seconds:
            return SessionState(session_id=session_id)  # expired -> reset
        return state

    def blocks_used(self, session_id: str, now: float | None = None) -> int:
        return self.load(session_id, now=now).blocks

    def reviewer_calls_used(self, session_id: str, now: float | None = None) -> int:
        return self.load(session_id, now=now).reviewer_calls

    def is_injected(self, session_id: str, rule_id: str, now: float | None = None) -> bool:
        return rule_id in self.load(session_id, now=now).injected

    # -- mutations (locked read-modify-write) -------------------------------

    def try_mark_injected(
        self, session_id: str, rule_id: str, now: float | None = None
    ) -> bool:
        """Record an injection once per session per rule.

        Returns True only for the single winning caller; every other concurrent
        or subsequent call returns False. Fails closed (False) if the lock is
        unavailable — a missed injection is benign, a duplicate is not.
        """
        ts = _now(now)
        try:
            with self._lock(session_id):
                state = self.load(session_id, now=ts)
                if rule_id in state.injected:
                    return False
                state.injected[rule_id] = ts
                state.updated_at = ts
                self._save(state)
                return True
        except _LockUnavailable:
            return False

    def consume_block(
        self, session_id: str, max_blocks: int | None = None, now: float | None = None
    ) -> bool:
        """Consume one block from the session's block budget.

        Returns True if the block was allowed and consumed, False if the budget
        is exhausted (or the lock is unavailable — overspend is never allowed).
        """
        limit = self.max_blocks if max_blocks is None else max_blocks
        return self._consume_counter(session_id, "blocks", limit, now)

    def consume_reviewer(
        self,
        session_id: str,
        max_reviewer: int | None = None,
        now: float | None = None,
    ) -> bool:
        """Consume one reviewer call from the session's reviewer budget."""
        limit = self.max_reviewer_calls if max_reviewer is None else max_reviewer
        return self._consume_counter(session_id, "reviewer_calls", limit, now)

    def _consume_counter(
        self, session_id: str, field: str, limit: int, now: float | None
    ) -> bool:
        ts = _now(now)
        try:
            with self._lock(session_id):
                state = self.load(session_id, now=ts)
                if getattr(state, field) >= limit:
                    return False
                setattr(state, field, getattr(state, field) + 1)
                state.updated_at = ts
                self._save(state)
                return True
        except _LockUnavailable:
            return False

    # -- persistence --------------------------------------------------------

    def _save(self, state: SessionState) -> None:
        data = json.dumps(state.to_dict(), sort_keys=True).encode("utf-8")
        self._atomic_write(self.state_path(state.session_id), data)

    def _atomic_write(self, path: str, data: bytes) -> None:
        """Durable, atomic write: temp file + fsync + os.replace + dir fsync."""
        dirpath = os.path.dirname(path)
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
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @staticmethod
    def _fsync_dir(dirpath: str) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            dfd = os.open(dirpath, flags)
        except OSError:
            return  # filesystem does not support directory fsync; best effort
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    # -- locking (O_EXCL claim fence) --------------------------------------

    @contextmanager
    def _lock(self, session_id: str):
        """Per-session exclusive lock via O_CREAT|O_EXCL (single-winner fence).

        A stale lock (older than _LOCK_STALE_SECONDS, e.g. a crashed holder) is
        broken. Acquisition is bounded: if the lock cannot be taken within
        _LOCK_WAIT_SECONDS, _LockUnavailable is raised and the caller fails
        closed.
        """
        lock_path = self._lock_path(session_id)
        os.makedirs(self.state_dir, exist_ok=True)
        deadline = time.monotonic() + _LOCK_WAIT_SECONDS
        fd = None
        while fd is None:
            try:
                fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            except FileExistsError:
                # A vanished lock is NOT staleness: the holder released it
                # between our failed open and this stat. Retry without unlinking
                # (unlinking here would delete a NEW holder's lock).
                try:
                    age = time.time() - os.path.getmtime(lock_path)
                except FileNotFoundError:
                    continue
                except OSError:
                    age = None  # unreadable: never break someone else's lock
                if age is not None and age > _LOCK_STALE_SECONDS:
                    # Re-stat immediately before unlink to narrow the TOCTOU
                    # window against a concurrently created replacement lock.
                    try:
                        stat = os.stat(lock_path)
                    except OSError:
                        continue
                    if time.time() - stat.st_mtime > _LOCK_STALE_SECONDS:
                        try:
                            os.unlink(lock_path)
                        except OSError:
                            pass
                    continue
                if time.monotonic() >= deadline:
                    raise _LockUnavailable(session_id)
                time.sleep(_LOCK_POLL_SECONDS)
        try:
            yield
        finally:
            os.close(fd)
            try:
                os.unlink(lock_path)
            except OSError:
                pass

    @staticmethod
    def _stale(lock_path: str) -> bool:
        """Whether an EXISTING lock is older than the stale threshold.

        A missing lock is never reported stale: callers must retry acquisition
        rather than unlink a path that a new holder may already own.
        """
        try:
            return time.time() - os.path.getmtime(lock_path) > _LOCK_STALE_SECONDS
        except FileNotFoundError:
            return False
        except OSError:
            return False


def _now(now: float | None) -> float:
    return time.time() if now is None else float(now)
