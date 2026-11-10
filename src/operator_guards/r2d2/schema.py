"""R2-D2 incident schema and validation (schema-only leaf; no store I/O).

This leaf defines the incident record contract from plan §4 and validates it.
The durable store (write-ahead events, segments, torn-tail recovery) is a
separate leaf (9b) and is deliberately NOT built here.

Contracts enforced here:

* **Incident lifecycle** — ``open -> claimed -> diagnosing -> repairing ->
  verifying -> resolved``, with ``escalated`` as the alternative terminal
  state. ``phase`` must be one of these seven values.
* **Severity union** — exactly ``mechanical`` | ``blocked`` | ``stuck_critical``.
* **Bounded fields** — symptom, observed values, and notification are capped;
  over-cap input is REJECTED with a message (not silently truncated) so bad
  author-supplied input stays visible. Caps: ``SYMPTOM_MAX_CHARS``,
  ``OBSERVED_VALUE_MAX_CHARS``, ``NOTIFICATION_MAX_CHARS``.
* **Closed top-level schema** — unknown top-level incident fields are REJECTED
  (matching the already-closed ``OpResult``), never silently dropped on load.
  Forward-compat is handled by bumping ``schema_version`` together with the
  explicit allowlist — not by accepting unknown keys.
* **No author-supplied kill authority** — a key is rejected when any token
  derived from it (NFKC-normalized, lowercased, then split on case boundaries
  and non-alphanumerics) matches the forbidden kill/authority set. The error
  message always contains the word "authority". Kill capability is granted by
  the executor's own wiring, never by an incident field.
* **No command injection** — a key whose derived tokens match the forbidden
  command/exec set (``exec``, ``command``, ``argv``, ``shell``, ``script``,
  ``bash``, ...) is rejected at any depth. The executor uses a fixed handler
  with enumerated params; the incident must not carry a command, executable
  path, or arbitrary config key. ``OpResult`` is a CLOSED schema (unknown keys
  rejected).
* **No empty repair resolution** — a ``resolved`` incident requires a conclusive
  ``PASS`` proof AND a non-empty mutation plan whose EVERY operation verdict is
  ``PASS`` (a repair cannot resolve on FAIL/UNKNOWN).
* **Non-negative counters** — epoch/lease/attempts/max_attempts are non-negative
  ints; ``attempts <= max_attempts``; ``max_attempts`` defaults to 3.
* **Non-empty ids** — id/dedupe_key/host_id/profile_id/client_id/session_id and
  ``OpResult.op_id`` are non-empty strings.

``OpResult`` reuses :class:`~operator_guards.common.proof.Verdict` (exactly
PASS/FAIL/UNKNOWN) and the closed ``VERIFY_KINDS`` union; each operation's
``expected`` value is shape-validated with
:func:`~operator_guards.common.proof.validate_expected`.

Reject-vs-truncate choice (documented): the author-supplied record fields are
REJECTED when over the bound (a visible, actionable error), never silently
truncated. Only non-narrative data is truncated on load: evidence references
are capped to ``EVIDENCE_REF_MAX_CHARS`` (matching ``common/proof.py``).

Round-trip serialization is deliberately NOT provided in this leaf: there is no
``to_dict``/serializer, and none is added here. Leaf 9b (store) MUST provide and
test a lossless ``Incident -> dict -> Incident`` round-trip covering every field
listed above.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping

from operator_guards.common.proof import (
    EVIDENCE_REF_MAX_CHARS,
    VERIFY_KINDS,
    Verdict,
    validate_expected,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_VERSION = 2

SEVERITY_MECHANICAL = "mechanical"
SEVERITY_BLOCKED = "blocked"
SEVERITY_STUCK_CRITICAL = "stuck_critical"
SEVERITIES = frozenset(
    {SEVERITY_MECHANICAL, SEVERITY_BLOCKED, SEVERITY_STUCK_CRITICAL}
)

PHASE_OPEN = "open"
PHASE_CLAIMED = "claimed"
PHASE_DIAGNOSING = "diagnosing"
PHASE_REPAIRING = "repairing"
PHASE_VERIFYING = "verifying"
PHASE_RESOLVED = "resolved"
PHASE_ESCALATED = "escalated"
LIFECYCLE_PHASES = frozenset(
    {
        PHASE_OPEN,
        PHASE_CLAIMED,
        PHASE_DIAGNOSING,
        PHASE_REPAIRING,
        PHASE_VERIFYING,
        PHASE_RESOLVED,
        PHASE_ESCALATED,
    }
)

DEFAULT_MAX_ATTEMPTS = 3

# Operation-receipt states (Task 10: one queued/in-flight operation per incident).
RECEIPT_QUEUED = "queued"
RECEIPT_STARTED = "started"
RECEIPT_SETTLED = "settled"
RECEIPT_STATES = frozenset({RECEIPT_QUEUED, RECEIPT_STARTED, RECEIPT_SETTLED})

# Bounded-field caps (documented in the module docstring).
SYMPTOM_MAX_CHARS = 2000
OBSERVED_VALUE_MAX_CHARS = 1000
NOTIFICATION_MAX_CHARS = 200

# Forbidden author-supplied key tokens. Keys are NFKC-normalized, folded through
# a small homoglyph map, lowercased, and split on case boundaries AND
# non-alphanumerics, so ``kill_authorized`` -> {"kill", "authorized"} and
# ``killAuthorized`` / ``ｋｉｌｌ`` / ``kıll_authorızed`` all collapse to the
# same forbidden tokens.
_KILL_TOKENS = frozenset({"kill", "authority", "authorize", "authorized"})
_COMMAND_TOKENS = frozenset(
    {
        "exec",
        "executable",
        "execute",
        "command",
        "cmd",
        "argv",
        "shell",
        "script",
        "bash",
        "zsh",
    }
)

# Visual homoglyphs of ASCII letters that NFKC deliberately leaves intact
# (the Turkic dotted/dotless-I pair) but which read as the same letter in a
# key. Folded before tokenization so ``kıll_authorızed`` -> ``kill_authorized``.
_HOMOGLYPH_TRANSLATION = str.maketrans(
    {
        "\u0130": "i",  # LATIN CAPITAL LETTER I WITH DOT ABOVE (İ)
        "\u0131": "i",  # LATIN SMALL LETTER DOTLESS I (ı)
    }
)


class IncidentError(ValueError):
    """Raised when an incident record fails schema validation."""


# ---------------------------------------------------------------------------
# Dataclasses (frozen, like ED-209's engine)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OpResult:
    """One verification operation's result (plan §4).

    ``verdict`` is a :class:`Verdict` (exactly PASS/FAIL/UNKNOWN); ``kind`` is a
    member of the closed ``VERIFY_KINDS`` union; ``expected`` is shape-validated
    per kind; ``observed`` are bounded actual values (str-ified and capped).
    """

    op_id: str
    kind: str
    verdict: Verdict
    expected: Any = None
    observed: tuple = ()
    evidence: str = ""
    started_at: float = 0.0
    ended_at: float = 0.0
    epoch: int = 0
    client_id: str = ""
    exit_status: int | None = None


@dataclass(frozen=True)
class Incident:
    """A validated R2-D2 incident record (plan §4)."""

    id: str
    severity: str
    symptom: str
    phase: str
    dedupe_key: str
    schema_version: int = SCHEMA_VERSION
    created_at: float = 0.0
    updated_at: float = 0.0
    host_id: str = ""
    profile_id: str = ""
    client_id: str = ""
    session_id: str = ""
    observed: tuple = ()  # observed evidence references
    diagnostic_plan: tuple = ()  # OpResult list
    mutation_plan: tuple = ()  # OpResult list
    epoch: int = 0
    claimant: str = ""
    lease: int = 0
    attempts: int = 0
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    authorization: tuple = ()  # authorization references
    proof: Verdict | None = None
    notification: str = ""
    nonce: str = ""
    pid: int = 0
    pid_start_time: float = 0.0
    lease_expiry: float = 0.0
    owned_proc: bool = False
    op_id: str = ""
    op_state: str = ""
    op_epoch: int = 0
    op_verdict: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_nonneg_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _nonneg_int(value: Any, field_name: str) -> int:
    if not _is_nonneg_int(value):
        raise IncidentError(
            f"incident field {field_name!r} must be a non-negative int, got {value!r}"
        )
    return value


def _bound_reject(value: str, cap: int, field_name: str) -> str:
    if len(value) > cap:
        raise IncidentError(
            f"incident field {field_name!r} exceeds the {cap}-char bound "
            f"({len(value)} chars); reject the record, do not truncate"
        )
    return value


def _coerce_verdict(value: Any, field_name: str) -> Verdict | None:
    if value is None:
        return None
    if isinstance(value, Verdict):
        return value
    if isinstance(value, str):
        try:
            return Verdict(value.strip().upper())
        except ValueError:
            raise IncidentError(
                f"incident field {field_name!r} must be PASS|FAIL|UNKNOWN, got {value!r}"
            ) from None
    raise IncidentError(
        f"incident field {field_name!r} must be a verdict (PASS|FAIL|UNKNOWN), "
        f"got {type(value).__name__}"
    )


def _key_tokens(key: Any) -> frozenset[str]:
    text = unicodedata.normalize("NFKC", str(key))
    text = text.translate(_HOMOGLYPH_TRANSLATION)
    # Split on case boundaries (camelCase/acronyms) so ``killAuthorized`` ->
    # {"kill", "authorized"}; non-alphanumerics are split by the final regex.
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text)
    return frozenset(re.findall(r"[a-z0-9]+", text.lower()))


def _forbidden_category(key: Any) -> str | None:
    """Classify a key as an 'authority' grant or a 'command' field, else None."""
    tokens = _key_tokens(key)
    if tokens & _KILL_TOKENS:
        return "authority"
    if tokens & _COMMAND_TOKENS:
        return "command"
    return None


def _first_forbidden(record: Any) -> tuple[Any, str] | None:
    """Return (key, category) for the first forbidden key at any depth.

    Walks every mapping/list in the record (values included), so a smuggled
    ``command``/``kill_*`` key inside a nested operation or observed value is
    also rejected — fail closed on authority/command fields. (This may reject
    benign observed-data dict keys that merely *mention* a forbidden word; that
    over-rejection is the documented trade-off of a security guard.)

    A visited set makes the walk cyclic-safe: an in-process cyclic mapping
    (unreachable from JSON, but possible via direct construction) cannot hang
    the traversal, since each container is inspected at most once.
    """
    stack: list[Any] = [record]
    seen: set[int] = set()
    while stack:
        node = stack.pop()
        if not isinstance(node, (Mapping, list, tuple)):
            continue
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, Mapping):
            for key, value in node.items():
                category = _forbidden_category(key)
                if category is not None:
                    return key, category
                stack.append(value)
        else:  # list / tuple
            stack.extend(node)
    return None


# ---------------------------------------------------------------------------
# OpResult validation
# ---------------------------------------------------------------------------

_OP_FIELDS = frozenset(
    {
        "op_id",
        "kind",
        "verdict",
        "expected",
        "observed",
        "evidence",
        "started_at",
        "ended_at",
        "epoch",
        "client_id",
        "exit_status",
    }
)


def validate_op_result(op: Mapping[str, Any]) -> None:
    """Validate one operation result; raise :class:`IncidentError` on invalid.

    ``OpResult`` is a CLOSED schema: unknown keys are rejected so an incident
    cannot smuggle an arbitrary config key into the executor.
    """
    if not isinstance(op, Mapping):
        raise IncidentError("each operation must be a mapping")

    for key in op:
        if key not in _OP_FIELDS:
            raise IncidentError(
                f"operation field {key!r} is not allowed (fixed handler + "
                f"enumerated params; no arbitrary config)"
            )

    for field in ("op_id", "kind"):
        if field not in op or not isinstance(op[field], str) or not op[field].strip():
            raise IncidentError(
                f"operation field {field!r} must be a non-empty string"
            )

    kind = op["kind"]
    if kind not in VERIFY_KINDS:
        raise IncidentError(
            f"operation kind {kind!r} is not a known verification kind; "
            f"must be one of {sorted(VERIFY_KINDS)}"
        )

    if "verdict" not in op:
        raise IncidentError("operation is missing required field 'verdict'")
    verdict = _coerce_verdict(op["verdict"], "verdict")
    if verdict is None:
        raise IncidentError("operation 'verdict' must be PASS|FAIL|UNKNOWN")

    if "expected" not in op:
        raise IncidentError("operation is missing required field 'expected'")
    if not validate_expected(kind, op["expected"]):
        raise IncidentError(
            f"operation expected value {op['expected']!r} has the wrong shape "
            f"for verification kind {kind!r}"
        )

    observed = op.get("observed", ())
    if not isinstance(observed, (list, tuple)):
        raise IncidentError("operation 'observed' must be a list of values")
    for item in observed:
        text = item if isinstance(item, str) else str(item)
        if len(text) > OBSERVED_VALUE_MAX_CHARS:
            raise IncidentError(
                f"operation observed value exceeds the {OBSERVED_VALUE_MAX_CHARS}-char "
                f"bound ({len(text)} chars)"
            )

    evidence = op.get("evidence", "")
    if not isinstance(evidence, str):
        raise IncidentError("operation 'evidence' must be a string")

    if "epoch" in op:
        _nonneg_int(op["epoch"], "operation epoch")
    if "exit_status" in op and op["exit_status"] is not None:
        if not isinstance(op["exit_status"], int) or isinstance(op["exit_status"], bool):
            raise IncidentError("operation 'exit_status' must be an int or null")
    for field in ("started_at", "ended_at"):
        if field in op and not _is_number(op[field]):
            raise IncidentError(f"operation field {field!r} must be a number")
    if "client_id" in op and not isinstance(op["client_id"], str):
        raise IncidentError("operation 'client_id' must be a string")


def load_op_result(op: Mapping[str, Any]) -> OpResult:
    """Validate and build a bounded :class:`OpResult`."""
    validate_op_result(op)
    verdict = _coerce_verdict(op["verdict"], "verdict")
    assert verdict is not None  # validate_op_result already rejected a None verdict
    observed = tuple(
        (item if isinstance(item, str) else str(item))[:OBSERVED_VALUE_MAX_CHARS]
        for item in (op.get("observed") or ())
    )
    return OpResult(
        op_id=op["op_id"],
        kind=op["kind"],
        verdict=verdict,
        expected=op["expected"],
        observed=observed,
        evidence=op.get("evidence", "")[:EVIDENCE_REF_MAX_CHARS],
        started_at=float(op.get("started_at", 0.0)),
        ended_at=float(op.get("ended_at", 0.0)),
        epoch=int(op.get("epoch", 0)),
        client_id=op.get("client_id", "") or "",
        exit_status=op.get("exit_status"),
    )


# ---------------------------------------------------------------------------
# Incident validation
# ---------------------------------------------------------------------------

# Closed top-level incident schema: every allowed key, nothing else. Forward
# compat bumps SCHEMA_VERSION together with this allowlist (never silent accept).
_INCIDENT_FIELDS = frozenset(
    {
        # required
        "id",
        "severity",
        "symptom",
        "phase",
        "dedupe_key",
        # optional scalars
        "schema_version",
        "created_at",
        "updated_at",
        "host_id",
        "profile_id",
        "client_id",
        "session_id",
        # references and plans
        "observed",
        "authorization",
        "diagnostic_plan",
        "mutation_plan",
        # counters / claim / proof
        "epoch",
        "claimant",
        "lease",
        "attempts",
        "max_attempts",
        # claim identity / fencing / operation receipt (Task 10)
        "nonce",
        "pid",
        "pid_start_time",
        "lease_expiry",
        "owned_proc",
        "op_id",
        "op_state",
        "op_epoch",
        "op_verdict",
        "proof",
        "notification",
    }
)
_REQUIRED_STR_FIELDS = ("id", "symptom", "phase", "dedupe_key")
_OPTIONAL_STR_FIELDS = (
    "host_id",
    "profile_id",
    "client_id",
    "session_id",
    "claimant",
    "nonce",
    "op_id",
)
_REF_FIELDS = ("observed", "authorization")
_PLAN_FIELDS = ("diagnostic_plan", "mutation_plan")


def validate_incident(record: Mapping[str, Any]) -> None:
    """Validate an incident record; raise :class:`IncidentError` on invalid.

    The top-level schema is closed: unknown fields are rejected (see
    ``_INCIDENT_FIELDS``), mirroring the already-closed ``OpResult``.
    """
    if not isinstance(record, Mapping):
        raise IncidentError("incident record must be a mapping")

    forbidden = _first_forbidden(record)
    if forbidden is not None:
        key, category = forbidden
        if category == "authority":
            raise IncidentError(
                f"incident author cannot assert kill/exec authority: "
                f"forbidden field {key!r}"
            )
        raise IncidentError(
            f"incident must not carry command/executable fields (fixed handler + "
            f"enumerated params only): forbidden field {key!r}"
        )

    unknown = sorted((k for k in record if k not in _INCIDENT_FIELDS), key=repr)
    if unknown:
        raise IncidentError(
            f"incident has unknown top-level field(s) {unknown!r}; the incident "
            f"schema is closed — forward-compat requires bumping SCHEMA_VERSION "
            f"together with the explicit allowlist"
        )

    for field in _REQUIRED_STR_FIELDS:
        if field not in record:
            raise IncidentError(f"incident is missing required field {field!r}")
        value = record[field]
        if not isinstance(value, str) or not value.strip():
            raise IncidentError(
                f"incident field {field!r} must be a non-empty string, got {value!r}"
            )

    if "severity" not in record:
        raise IncidentError("incident is missing required field 'severity'")
    if record["severity"] not in SEVERITIES:
        raise IncidentError(
            f"incident severity {record['severity']!r} is invalid; "
            f"must be one of {sorted(SEVERITIES)}"
        )

    _bound_reject(record["symptom"], SYMPTOM_MAX_CHARS, "symptom")

    if record["phase"] not in LIFECYCLE_PHASES:
        raise IncidentError(
            f"incident phase {record['phase']!r} is invalid; "
            f"must be one of {sorted(LIFECYCLE_PHASES)}"
        )

    if "schema_version" in record and not _is_number(record["schema_version"]):
        raise IncidentError("incident 'schema_version' must be a number")
    for field in ("created_at", "updated_at"):
        if field in record and not _is_number(record[field]):
            raise IncidentError(f"incident field {field!r} must be a number")

    for field in _OPTIONAL_STR_FIELDS:
        if field in record and record[field] is not None:
            value = record[field]
            if not isinstance(value, str) or not value.strip():
                raise IncidentError(
                    f"incident field {field!r} must be a non-empty string, got {value!r}"
                )

    for field in ("epoch", "lease", "attempts", "max_attempts"):
        if field in record:
            _nonneg_int(record[field], field)

    attempts = record.get("attempts", 0)
    max_attempts = record.get("max_attempts", DEFAULT_MAX_ATTEMPTS)
    if attempts > max_attempts:
        raise IncidentError(
            f"incident attempts ({attempts}) exceeds max_attempts ({max_attempts})"
        )

    for field in ("pid", "op_epoch"):
        if field in record and not _is_nonneg_int(record[field]):
            raise IncidentError(
                f"incident field {field!r} must be a non-negative int, got {record[field]!r}"
            )
    for field in ("pid_start_time", "lease_expiry"):
        if field in record:
            value = record[field]
            if not _is_number(value) or value < 0:
                raise IncidentError(
                    f"incident field {field!r} must be a non-negative number, got {value!r}"
                )
    if "owned_proc" in record and not isinstance(record["owned_proc"], bool):
        raise IncidentError("incident field 'owned_proc' must be a boolean")
    if "op_state" in record and record["op_state"] not in ("", *RECEIPT_STATES):
        raise IncidentError(
            f"incident field 'op_state' must be empty or one of "
            f"{sorted(RECEIPT_STATES)}; got {record['op_state']!r}"
        )
    if "op_verdict" in record and record["op_verdict"] not in (None, ""):
        _coerce_verdict(record["op_verdict"], "op_verdict")

    for field in _REF_FIELDS:
        if field in record and record[field] is not None:
            value = record[field]
            if not isinstance(value, (list, tuple)):
                raise IncidentError(f"incident field {field!r} must be a list")
            for item in value:
                if not isinstance(item, str) or not item.strip():
                    raise IncidentError(
                        f"incident field {field!r} entries must be non-empty strings"
                    )

    for field in _PLAN_FIELDS:
        if field in record and record[field] is not None:
            value = record[field]
            if not isinstance(value, (list, tuple)):
                raise IncidentError(
                    f"incident field {field!r} must be a list of operations"
                )
            for op in value:
                validate_op_result(op)

    proof = _coerce_verdict(record.get("proof"), "proof")

    notification = record.get("notification", "")
    if notification is not None and not isinstance(notification, str):
        raise IncidentError("incident field 'notification' must be a string")
    if isinstance(notification, str):
        _bound_reject(notification, NOTIFICATION_MAX_CHARS, "notification")

    # No empty repair resolution: a `resolved` incident must actually be proven
    # by a PASS incident-level proof AND a mutation plan whose EVERY op PASSes.
    if record["phase"] == PHASE_RESOLVED:
        if proof is not Verdict.PASS:
            raise IncidentError(
                f"resolved incident requires a conclusive PASS proof; got {proof!r}"
            )
        mutation_plan = record.get("mutation_plan")
        if not mutation_plan:
            raise IncidentError("resolved incident requires a non-empty mutation plan")
        for op in mutation_plan:
            if _coerce_verdict(op["verdict"], "verdict") is not Verdict.PASS:
                raise IncidentError(
                    f"resolved incident requires every mutation op to PASS; "
                    f"op {op.get('op_id')!r} is {op['verdict']!r}"
                )


def load_incident(record: Mapping[str, Any]) -> Incident:
    """Validate and build a bounded :class:`Incident`."""
    validate_incident(record)
    observed = tuple(
        item[:EVIDENCE_REF_MAX_CHARS] for item in (record.get("observed") or ())
    )
    authorization = tuple(
        item[:EVIDENCE_REF_MAX_CHARS] for item in (record.get("authorization") or ())
    )
    diagnostic_plan = tuple(
        load_op_result(op) for op in (record.get("diagnostic_plan") or ())
    )
    mutation_plan = tuple(
        load_op_result(op) for op in (record.get("mutation_plan") or ())
    )
    return Incident(
        id=record["id"],
        severity=record["severity"],
        symptom=record["symptom"],
        phase=record["phase"],
        dedupe_key=record["dedupe_key"],
        schema_version=int(record.get("schema_version", SCHEMA_VERSION)),
        created_at=float(record.get("created_at", 0.0)),
        updated_at=float(record.get("updated_at", 0.0)),
        host_id=record.get("host_id", "") or "",
        profile_id=record.get("profile_id", "") or "",
        client_id=record.get("client_id", "") or "",
        session_id=record.get("session_id", "") or "",
        observed=observed,
        diagnostic_plan=diagnostic_plan,
        mutation_plan=mutation_plan,
        epoch=int(record.get("epoch", 0)),
        claimant=record.get("claimant", "") or "",
        lease=int(record.get("lease", 0)),
        attempts=int(record.get("attempts", 0)),
        max_attempts=int(record.get("max_attempts", DEFAULT_MAX_ATTEMPTS)),
        authorization=authorization,
        proof=_coerce_verdict(record.get("proof"), "proof"),
        notification=record.get("notification", "") or "",
        nonce=record.get("nonce", "") or "",
        pid=int(record.get("pid", 0)),
        pid_start_time=float(record.get("pid_start_time", 0.0)),
        lease_expiry=float(record.get("lease_expiry", 0.0)),
        owned_proc=bool(record.get("owned_proc", False)),
        op_id=record.get("op_id", "") or "",
        op_state=record.get("op_state", "") or "",
        op_epoch=int(record.get("op_epoch", 0)),
        op_verdict=record.get("op_verdict", "") or "",
    )


# ---------------------------------------------------------------------------
# Lossless dataclass <-> dict serialization (leaf 9b)
# ---------------------------------------------------------------------------
#
# ``to_dict`` emits a JSON-serializable mapping (Verdict -> its string value,
# tuples -> lists, OpResult -> dict); ``from_dict`` rebuilds the dataclass
# through the existing validators, so a round-trip is lossless AND re-validated.
# Empty optional-string fields (host_id/profile_id/client_id/session_id/
# claimant) are OMITTED rather than emitted as "" so the closed schema accepts
# the output directly (a present-but-empty optional string is rejected).


def op_result_to_dict(op: OpResult) -> dict:
    """Serialize one :class:`OpResult` to a JSON-safe dict (lossless)."""
    return {
        "op_id": op.op_id,
        "kind": op.kind,
        "verdict": op.verdict.value if op.verdict is not None else None,
        "expected": op.expected,
        "observed": list(op.observed),
        "evidence": op.evidence,
        "started_at": op.started_at,
        "ended_at": op.ended_at,
        "epoch": op.epoch,
        "client_id": op.client_id,
        "exit_status": op.exit_status,
    }


def op_result_from_dict(data: Mapping[str, Any]) -> OpResult:
    """Rebuild a validated :class:`OpResult` from ``op_result_to_dict`` output."""
    return load_op_result(data)


def incident_to_dict(inc: Incident) -> dict:
    """Serialize an :class:`Incident` to a JSON-safe dict (lossless)."""
    data = {
        "id": inc.id,
        "severity": inc.severity,
        "symptom": inc.symptom,
        "phase": inc.phase,
        "dedupe_key": inc.dedupe_key,
        "schema_version": inc.schema_version,
        "created_at": inc.created_at,
        "updated_at": inc.updated_at,
        "observed": list(inc.observed),
        "diagnostic_plan": [op_result_to_dict(op) for op in inc.diagnostic_plan],
        "mutation_plan": [op_result_to_dict(op) for op in inc.mutation_plan],
        "epoch": inc.epoch,
        "lease": inc.lease,
        "attempts": inc.attempts,
        "max_attempts": inc.max_attempts,
        "authorization": list(inc.authorization),
        "proof": inc.proof.value if inc.proof is not None else None,
        "notification": inc.notification,
        "pid": inc.pid,
        "pid_start_time": inc.pid_start_time,
        "lease_expiry": inc.lease_expiry,
        "owned_proc": inc.owned_proc,
        "op_epoch": inc.op_epoch,
    }
    # Empty optional-string fields are omitted: load_incident defaults them to
    # "" and the closed schema rejects a present-but-empty value.
    for field in (
        "host_id",
        "profile_id",
        "client_id",
        "session_id",
        "claimant",
        "nonce",
        "op_id",
        "op_state",
        "op_verdict",
    ):
        value = getattr(inc, field)
        if value:
            data[field] = value
    return data


def incident_from_dict(data: Mapping[str, Any]) -> Incident:
    """Rebuild a validated :class:`Incident` from ``incident_to_dict`` output."""
    return load_incident(data)
