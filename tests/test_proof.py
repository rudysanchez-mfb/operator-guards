"""Shared proof-type locks (``common/proof.py``) — preserved verbatim from the
retired ``test_checks.py``.

``src/operator_guards/ed209/checks.py`` (the fixed ``gh`` check + memory-first
adapters) was DEAD code: only these tests imported it, and neither the ED-209
plugin nor the engine wired its dynamic adapters (the plugin records ``check``
as ``unavailable`` and serves ``memory-first`` context from the rule's static
``memory`` entries). It was removed rather than wired; this file keeps the
proof-contract coverage that lived alongside it.
"""

import pytest

from operator_guards.common.proof import (
    VERIFY_CONTAINS,
    VERIFY_EXIT_CODE,
    VERIFY_FILE_MTIME,
    VERIFY_JQ_PATH,
    VERIFY_KINDS,
    VERIFY_NOT_CONTAINS,
    Evidence,
    Verdict,
    make_evidence,
    validate_expected,
)


# --- shared proof types -----------------------------------------------------

def test_verdict_has_exactly_three_states():
    assert {v for v in Verdict} == {Verdict.PASS, Verdict.FAIL, Verdict.UNKNOWN}
    assert len(Verdict) == 3


def test_closed_verification_kinds():
    assert VERIFY_KINDS == frozenset({
        "exit_code", "contains", "not_contains", "jq_path",
        "file_mtime", "mcp_status", "process_alive", "process_dead",
    })


def test_validate_expected_shapes():
    assert validate_expected(VERIFY_EXIT_CODE, 0) is True
    assert validate_expected(VERIFY_EXIT_CODE, "0") is False
    assert validate_expected(VERIFY_EXIT_CODE, True) is False  # bool isn't an exit code
    assert validate_expected(VERIFY_CONTAINS, "x") is True
    assert validate_expected(VERIFY_CONTAINS, "") is False
    assert validate_expected(VERIFY_NOT_CONTAINS, "x") is True
    assert validate_expected(VERIFY_JQ_PATH, ".a.b") is True
    assert validate_expected(VERIFY_FILE_MTIME, 1.5) is True
    assert validate_expected(VERIFY_FILE_MTIME, "1.5") is False
    assert validate_expected("bogus_kind", "x") is False  # closed union


def test_evidence_bounded():
    ev = make_evidence(VERIFY_CONTAINS, reference="r" * 1000, summary="s" * 2000)
    assert isinstance(ev, Evidence)
    assert len(ev.reference) <= 256
    assert len(ev.summary) <= 1000


def test_evidence_rejects_unknown_kind():
    with pytest.raises(ValueError):
        make_evidence("nope", reference="r")


def test_evidence_direct_construction_bounded_and_validated():
    # Direct construction must not bypass the bounds or the closed kind union.
    ev = Evidence(kind=VERIFY_CONTAINS, reference="r" * 1000, summary="s" * 2000)
    assert len(ev.reference) <= 256
    assert len(ev.summary) <= 1000
    with pytest.raises(ValueError):
        Evidence(kind="nope")
