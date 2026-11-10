"""Schema contract tests for the R2-D2 incident record (plan §4).

Locks the validation contract before the durable store (leaf 9b) exists:

* severity is a closed union of exactly mechanical/blocked/stuck_critical;
* the top-level incident schema is CLOSED (unknown fields rejected, not dropped);
* symptom and observed values are bounded (over-cap REJECTED, not truncated);
* evidence references are truncated to EVIDENCE_REF_MAX_CHARS on load;
* an incident author cannot assert kill/exec authority (message says "authority"),
  including camelCase and Unicode-homoglyph (NFKC/fullwidth, dotless-ı) keys;
* no command-injection fields (command/argv/shell/executable, at any depth);
* no empty repair resolution (resolved requires PASS proof + non-empty plan
  whose EVERY mutation op verdict is PASS);
* lifecycle phase validation (open->claimed->...->resolved, plus escalated);
* attempts <= max_attempts; max_attempts defaults to 3; epochs/claims non-negative;
* OpResult reuses Verdict (PASS/FAIL/UNKNOWN) and validates each verification
  kind's expected-value shape via common/proof.py's closed VERIFY_KINDS union.
"""

import pytest

from operator_guards.common.proof import EVIDENCE_REF_MAX_CHARS, VERIFY_KINDS, Verdict
from operator_guards.r2d2.schema import (
    DEFAULT_MAX_ATTEMPTS,
    LIFECYCLE_PHASES,
    OBSERVED_VALUE_MAX_CHARS,
    SYMPTOM_MAX_CHARS,
    Incident,
    IncidentError,
    OpResult,
    load_incident,
    load_op_result,
    validate_incident,
    validate_op_result,
)


def _op_result(**overrides):
    op = {
        "op_id": "op-1",
        "kind": "exit_code",
        "verdict": "PASS",
        "expected": 0,
        "observed": [],
        "evidence": "ev-1",
        "started_at": 0.0,
        "ended_at": 0.0,
        "epoch": 0,
        "client_id": "client-1",
        "exit_status": 0,
    }
    op.update(overrides)
    return op


# --- error type + record shape ---------------------------------------------

def test_incident_error_is_a_value_error():
    assert issubclass(IncidentError, ValueError)


def test_non_mapping_record_rejected():
    with pytest.raises(IncidentError):
        validate_incident(["not", "a", "mapping"])  # type: ignore[arg-type]


def test_valid_incident_passes(valid_incident):
    validate_incident(valid_incident)


def test_load_incident_returns_incident(valid_incident):
    incident = load_incident(valid_incident)
    assert isinstance(incident, Incident)
    assert incident.id == "inc-1"
    assert incident.severity == "mechanical"
    assert incident.phase == "open"


# --- severity union --------------------------------------------------------

def test_severity_accepts_all_three(valid_incident):
    for severity in ("mechanical", "blocked", "stuck_critical"):
        validate_incident({**valid_incident, "severity": severity})


@pytest.mark.parametrize("severity", ["critical", "info", "", "SEVERE", 1, None])
def test_severity_rejects_others(valid_incident, severity):
    with pytest.raises(IncidentError):
        validate_incident({**valid_incident, "severity": severity})


def test_missing_severity_rejected(valid_incident):
    record = dict(valid_incident)
    del record["severity"]
    with pytest.raises(IncidentError):
        validate_incident(record)


# --- bounded symptom / payload --------------------------------------------

def test_symptom_over_cap_rejected(valid_incident):
    record = {**valid_incident, "symptom": "x" * (SYMPTOM_MAX_CHARS + 1)}
    with pytest.raises(IncidentError, match="symptom"):
        validate_incident(record)


def test_symptom_at_cap_accepted(valid_incident):
    validate_incident({**valid_incident, "symptom": "x" * SYMPTOM_MAX_CHARS})


def test_observed_value_over_cap_rejected(valid_incident):
    op = _op_result(observed=["x" * (OBSERVED_VALUE_MAX_CHARS + 1)])
    record = {**valid_incident, "mutation_plan": [op]}
    with pytest.raises(IncidentError):
        validate_incident(record)


# --- no author-supplied kill authority ------------------------------------

def test_author_cannot_assert_kill_authority(valid_incident):
    record = {**valid_incident, "kill_authorized": True}
    with pytest.raises(IncidentError, match="authority"):
        validate_incident(record)


@pytest.mark.parametrize(
    "key", ["kill_authorized", "kill", "authority", "authorized", "can_kill", "exec_authorized"]
)
def test_kill_authority_fields_rejected(valid_incident, key):
    record = {**valid_incident, key: True}
    with pytest.raises(IncidentError, match="authority"):
        validate_incident(record)


# --- no command-injection fields -------------------------------------------

@pytest.mark.parametrize("key", ["command", "argv", "shell", "executable", "exec", "cmd"])
def test_command_injection_fields_rejected(valid_incident, key):
    record = {**valid_incident, key: "rm -rf /"}
    with pytest.raises(IncidentError):
        validate_incident(record)


def test_command_field_nested_in_operation_rejected(valid_incident):
    op = {**_op_result(), "command": "rm -rf /"}
    record = {**valid_incident, "mutation_plan": [op]}
    with pytest.raises(IncidentError):
        validate_incident(record)


# --- no empty repair resolution --------------------------------------------

def test_resolved_requires_proof(valid_incident):
    record = {**valid_incident, "phase": "resolved", "mutation_plan": [_op_result()]}
    with pytest.raises(IncidentError, match="proof"):
        validate_incident(record)


def test_resolved_requires_mutation_plan(valid_incident):
    record = {**valid_incident, "phase": "resolved", "proof": "PASS"}
    with pytest.raises(IncidentError, match="mutation"):
        validate_incident(record)


def test_resolved_with_proof_and_plan_accepted(valid_incident):
    record = {**valid_incident, "phase": "resolved", "proof": "PASS", "mutation_plan": [_op_result()]}
    validate_incident(record)


def test_escalated_does_not_require_proof(valid_incident):
    validate_incident({**valid_incident, "phase": "escalated"})


# --- lifecycle phase -------------------------------------------------------

def test_phase_accepts_full_lifecycle(valid_incident):
    for phase in ("open", "claimed", "diagnosing", "repairing", "verifying", "resolved", "escalated"):
        record = {**valid_incident, "phase": phase}
        if phase == "resolved":
            record["proof"] = "PASS"
            record["mutation_plan"] = [_op_result()]
        validate_incident(record)


@pytest.mark.parametrize("phase", ["destroying", "done", "", "OPEN", 1, None])
def test_phase_rejects_unknown(valid_incident, phase):
    with pytest.raises(IncidentError):
        validate_incident({**valid_incident, "phase": phase})


def test_lifecycle_phases_are_the_seven_expected():
    assert LIFECYCLE_PHASES == frozenset({
        "open", "claimed", "diagnosing", "repairing", "verifying", "resolved", "escalated",
    })


# --- attempts / max_attempts / epoch / lease -------------------------------

def test_attempts_exceed_max_rejected(valid_incident):
    record = {**valid_incident, "attempts": 4, "max_attempts": 3}
    with pytest.raises(IncidentError, match="max_attempts"):
        validate_incident(record)


def test_attempts_equal_max_accepted(valid_incident):
    validate_incident({**valid_incident, "attempts": 3, "max_attempts": 3})


def test_max_attempts_defaults_to_3(valid_incident):
    assert "max_attempts" not in valid_incident
    incident = load_incident(valid_incident)
    assert incident.max_attempts == DEFAULT_MAX_ATTEMPTS == 3


@pytest.mark.parametrize("field", ["epoch", "lease", "attempts", "max_attempts"])
def test_negative_counters_rejected(valid_incident, field):
    with pytest.raises(IncidentError):
        validate_incident({**valid_incident, field: -1})


# --- ids are non-empty strings ---------------------------------------------

@pytest.mark.parametrize("field", ["id", "dedupe_key"])
def test_nonempty_string_fields_reject_blank(valid_incident, field):
    with pytest.raises(IncidentError):
        validate_incident({**valid_incident, field: "   "})


# --- OpResult: verdict reuses Verdict --------------------------------------

def test_opresult_rejects_bad_verdict():
    with pytest.raises(IncidentError, match="verdict"):
        load_op_result(_op_result(verdict="MAYBE"))


@pytest.mark.parametrize("verdict", ["PASS", "FAIL", "UNKNOWN"])
def test_opresult_accepts_verdict(verdict):
    op = load_op_result(_op_result(verdict=verdict))
    assert op.verdict is Verdict(verdict)


def test_verdict_enum_has_exactly_three_states():
    assert set(Verdict) == {Verdict.PASS, Verdict.FAIL, Verdict.UNKNOWN}


def test_opresult_returns_opresult():
    op = load_op_result(_op_result())
    assert isinstance(op, OpResult)
    assert op.kind == "exit_code"
    assert op.verdict is Verdict.PASS


# --- OpResult: verification-kind expected shape ----------------------------

@pytest.mark.parametrize(
    "kind,expected,valid",
    [
        ("exit_code", 0, True),
        ("exit_code", -1, True),
        ("exit_code", "0", False),
        ("exit_code", True, False),
        ("contains", "needle", True),
        ("contains", "", False),
        ("contains", 123, False),
        ("not_contains", "needle", True),
        ("not_contains", "", False),
        ("jq_path", ".a.b", True),
        ("file_mtime", 1234.5, True),
        ("file_mtime", "now", False),
        ("mcp_status", "running", True),
        ("mcp_status", "", False),
        ("process_alive", "nginx", True),
        ("process_dead", "nginx", True),
    ],
)
def test_opresult_expected_shape(kind, expected, valid):
    op = _op_result(kind=kind, expected=expected)
    if valid:
        load_op_result(op)
    else:
        with pytest.raises(IncidentError):
            load_op_result(op)


def test_opresult_unknown_kind_rejected():
    with pytest.raises(IncidentError, match="kind"):
        load_op_result(_op_result(kind="spawn_process"))


def test_opresult_rejects_unknown_field():
    # Closed schema: the executor uses a fixed handler + enumerated params, so
    # an arbitrary config key inside an operation is rejected.
    with pytest.raises(IncidentError):
        load_op_result({**_op_result(), "config": {"arbitrary": True}})


def test_all_verify_kinds_have_shape_validators():
    # Every member of the closed VERIFY_KINDS union must be accepted by
    # validate_op_result when given the canonical expected shape (sanity that
    # we did not drop a kind from the shared proof module).
    canonical = {
        "exit_code": 0,
        "contains": "x",
        "not_contains": "x",
        "jq_path": ".a",
        "file_mtime": 1.0,
        "mcp_status": "up",
        "process_alive": "proc",
        "process_dead": "proc",
    }
    assert set(canonical) == set(VERIFY_KINDS)
    for kind, expected in canonical.items():
        load_op_result(_op_result(kind=kind, expected=expected))


# --- closed top-level schema (unknown fields rejected) ----------------------

def test_unknown_top_level_field_rejected(valid_incident):
    record = {**valid_incident, "foo": 1}
    with pytest.raises(IncidentError, match="foo"):
        validate_incident(record)


def test_load_incident_does_not_silently_drop_unknown_fields(valid_incident):
    # Symmetry with the already-closed OpResult: unknown top-level keys are
    # REJECTED, never silently dropped by load_incident.
    record = {**valid_incident, "extra_thing": "nope"}
    with pytest.raises(IncidentError):
        load_incident(record)


def test_cyclic_record_does_not_hang(valid_incident):
    # An in-process cyclic mapping (unreachable from JSON) must not hang the
    # forbidden-key depth walk; the visited guard bounds it, and the unknown
    # top-level field is still rejected.
    record = dict(valid_incident)
    record["self"] = record
    with pytest.raises(IncidentError):
        validate_incident(record)


# --- required string fields reject non-strings (not just blank) -------------

@pytest.mark.parametrize("field", ["id", "symptom", "dedupe_key"])
@pytest.mark.parametrize("bad", [123, None, 3.14, True, ["x"], {"a": 1}])
def test_required_str_fields_reject_non_str(valid_incident, field, bad):
    with pytest.raises(IncidentError):
        validate_incident({**valid_incident, field: bad})


# --- forbidden-key tokenizer: camelCase + Unicode homoglyphs -----------------

@pytest.mark.parametrize(
    "key",
    [
        "killAuthorized",
        "execCommand",
        "runShell",
        "commandArgv",
        "executablePath",
        "bashScript",
        "kıll_authorızed",  # dotless-ı homoglyphs for "kill_authorized"
        "ｋｉｌｌ",  # fullwidth "kill"
    ],
)
def test_camelcase_and_unicode_homoglyph_keys_rejected(valid_incident, key):
    record = {**valid_incident, key: True}
    with pytest.raises(IncidentError):
        validate_incident(record)


# --- resolved requires every mutation op verdict PASS -----------------------

@pytest.mark.parametrize("verdict", ["FAIL", "UNKNOWN"])
def test_resolved_rejects_non_pass_mutation_op(valid_incident, verdict):
    op = _op_result(verdict=verdict)
    record = {
        **valid_incident,
        "phase": "resolved",
        "proof": "PASS",
        "mutation_plan": [op],
    }
    with pytest.raises(IncidentError):
        validate_incident(record)


def test_resolved_accepts_all_pass_mutation_ops(valid_incident):
    record = {
        **valid_incident,
        "phase": "resolved",
        "proof": "PASS",
        "mutation_plan": [_op_result(op_id="op-1"), _op_result(op_id="op-2")],
    }
    validate_incident(record)


# --- evidence-ref load truncation (documented behavior) ---------------------

def test_observed_ref_over_cap_truncated_on_load(valid_incident):
    long_ref = "e" * (EVIDENCE_REF_MAX_CHARS + 100)
    incident = load_incident({**valid_incident, "observed": [long_ref]})
    assert incident.observed == (long_ref[:EVIDENCE_REF_MAX_CHARS],)


def test_op_evidence_over_cap_truncated_on_load():
    long_ev = "e" * (EVIDENCE_REF_MAX_CHARS + 100)
    op = load_op_result(_op_result(evidence=long_ev))
    assert op.evidence == long_ev[:EVIDENCE_REF_MAX_CHARS]
