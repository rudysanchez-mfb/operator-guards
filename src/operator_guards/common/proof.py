"""Shared verification types for operator-guards (dependency-free).

R2-D2 will extend this later; ED-209's check/reviewer adapters use it now.

* ``Verdict`` — a verification verdict with exactly three states
  (PASS / FAIL / UNKNOWN); there is deliberately no fourth state.
* The closed verification-kind union (R2-D2-HANDOFF.md §5 "Verify kinds
  (closed union)"): ``exit_code``, ``contains``, ``not_contains``, ``jq_path``,
  ``file_mtime``, ``mcp_status``, ``process_alive``, ``process_dead`` — each
  with a validator for its expected-value shape.
* ``Evidence`` — a bounded reference/summary record of proof.

Only stdlib is used (dataclasses, enum, json, re, typing). No third-party
dependencies, no network.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


class Verdict(Enum):
    """A verification verdict. Exactly three states; no fourth."""

    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


# Closed verification kinds (R2-D2-HANDOFF.md §5 "Verify kinds (closed union)").
VERIFY_EXIT_CODE = "exit_code"
VERIFY_CONTAINS = "contains"
VERIFY_NOT_CONTAINS = "not_contains"
VERIFY_JQ_PATH = "jq_path"
VERIFY_FILE_MTIME = "file_mtime"
VERIFY_MCP_STATUS = "mcp_status"
VERIFY_PROCESS_ALIVE = "process_alive"
VERIFY_PROCESS_DEAD = "process_dead"

VERIFY_KINDS = frozenset(
    {
        VERIFY_EXIT_CODE,
        VERIFY_CONTAINS,
        VERIFY_NOT_CONTAINS,
        VERIFY_JQ_PATH,
        VERIFY_FILE_MTIME,
        VERIFY_MCP_STATUS,
        VERIFY_PROCESS_ALIVE,
        VERIFY_PROCESS_DEAD,
    }
)


# ---------------------------------------------------------------------------
# Expected-shape validators (one per kind)
# ---------------------------------------------------------------------------

def _expect_int(expected: Any) -> bool:
    return isinstance(expected, int) and not isinstance(expected, bool)


def _expect_number(expected: Any) -> bool:
    return isinstance(expected, (int, float)) and not isinstance(expected, bool)


def _expect_nonempty_str(expected: Any) -> bool:
    return isinstance(expected, str) and bool(expected.strip())


_EXPECTED_VALIDATORS = {
    VERIFY_EXIT_CODE: _expect_int,
    VERIFY_CONTAINS: _expect_nonempty_str,
    VERIFY_NOT_CONTAINS: _expect_nonempty_str,
    VERIFY_JQ_PATH: _expect_nonempty_str,
    VERIFY_FILE_MTIME: _expect_number,
    VERIFY_MCP_STATUS: _expect_nonempty_str,
    VERIFY_PROCESS_ALIVE: _expect_nonempty_str,
    VERIFY_PROCESS_DEAD: _expect_nonempty_str,
}


def validate_expected(kind: str, expected: Any) -> bool:
    """Whether ``expected`` has the correct shape for verification ``kind``.

    An unknown kind is never valid — the union is closed.
    """
    validator = _EXPECTED_VALIDATORS.get(kind)
    if validator is None:
        return False
    return validator(expected)


# ---------------------------------------------------------------------------
# Bounded evidence / reference
# ---------------------------------------------------------------------------

EVIDENCE_REF_MAX_CHARS = 256
EVIDENCE_SUMMARY_MAX_CHARS = 1000


def _bound(text: Any, limit: int) -> str:
    if not isinstance(text, str):
        text = str(text)
    return text[:limit]


@dataclass(frozen=True)
class Evidence:
    """Bounded reference to proof of a verification result.

    ``kind`` must be a member of the closed ``VERIFY_KINDS`` union;
    ``reference`` and ``summary`` are truncated to fixed bounds. The bounds and
    the closed-kind union are enforced here (``__post_init__``), so direct
    construction cannot bypass them either.
    """

    kind: str
    reference: str = ""
    summary: str = ""

    def __post_init__(self):
        if self.kind not in VERIFY_KINDS:
            raise ValueError(f"unknown verification kind: {self.kind!r}")
        object.__setattr__(self, "reference", _bound(self.reference, EVIDENCE_REF_MAX_CHARS))
        object.__setattr__(self, "summary", _bound(self.summary, EVIDENCE_SUMMARY_MAX_CHARS))


def make_evidence(kind: str, reference: str = "", summary: str = "") -> Evidence:
    """Build a bounded :class:`Evidence`; rejects unknown kinds."""
    return Evidence(kind=kind, reference=reference, summary=summary)


# ---------------------------------------------------------------------------
# Pure-string verification (used by ED-209's gh check)
# ---------------------------------------------------------------------------

def verify(kind: str, actual: Any, expected: Any) -> Verdict:
    """Return the :class:`Verdict` of applying ``kind`` to ``actual`` vs ``expected``.

    Pure string kinds (``contains`` / ``not_contains`` / ``exit_code`` /
    ``jq_path``) are verified here. Stateful kinds (``file_mtime`` /
    ``mcp_status`` / ``process_alive`` / ``process_dead``) require live system
    state and return ``UNKNOWN`` here — R2-D2's executor verifies them against
    the running system, never against a string.

    ``jq_path`` is an EXISTENCE check, not a value comparison: it PASSes when
    the resolved value is non-None, so a JSON ``false`` or ``0`` at the path
    counts as present (PASS). ``expected`` is the path string itself; the
    resolved value is never compared to it.
    """
    if kind not in VERIFY_KINDS:
        return Verdict.UNKNOWN
    if kind == VERIFY_EXIT_CODE:
        return Verdict.PASS if actual == expected else Verdict.FAIL
    if kind == VERIFY_CONTAINS:
        return Verdict.PASS if expected in (actual or "") else Verdict.FAIL
    if kind == VERIFY_NOT_CONTAINS:
        return Verdict.PASS if expected not in (actual or "") else Verdict.FAIL
    if kind == VERIFY_JQ_PATH:
        return Verdict.PASS if _jq_get(actual, expected) is not None else Verdict.FAIL
    # stateful kinds: cannot be verified from a string
    return Verdict.UNKNOWN


def _jq_get(data: Any, path: str) -> Any:
    """Resolve a minimal jq-style path (``a.b``, ``a[0]``, ``.a``) over JSON.

    Returns the resolved value, or ``None`` when the path is absent/malformed.
    Callers treat non-None as "present": VERIFY_JQ_PATH is an existence check,
    so a JSON ``false``/``0`` value still resolves to a non-None value and
    counts as a PASS.
    """
    try:
        obj = json.loads(data) if isinstance(data, str) else data
    except (ValueError, TypeError):
        return None
    return _resolve_path(obj, path)


def _resolve_path(obj: Any, path: str) -> Any:
    cur = obj
    for token in _tokenize_path(path):
        if isinstance(cur, list):
            idx = _as_index(token)
            if idx is None or idx < 0 or idx >= len(cur):
                return None
            cur = cur[idx]
        elif isinstance(cur, dict):
            if token not in cur:
                return None
            cur = cur[token]
        else:
            return None
    return cur


def _as_index(token: str) -> int | None:
    try:
        return int(token)
    except ValueError:
        return None


_PATH_TOKEN_RE = re.compile(r"([^.[\]'\"]+)|'([^']*)'|\"([^\"]*)\"")


def _tokenize_path(path: str) -> list[str]:
    if not path:
        return []
    tokens: list[str] = []
    for m in _PATH_TOKEN_RE.finditer(path):
        token = m.group(1) if m.group(1) is not None else (
            m.group(2) if m.group(2) is not None else m.group(3)
        )
        if token is not None and token != "":
            tokens.append(token)
    return tokens
