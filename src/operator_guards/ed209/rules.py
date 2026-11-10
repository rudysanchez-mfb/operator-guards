"""Minimal schema loader for ED-209 rules documents.

This module validates and loads a rules document. Matching, capability
binding, and engine logic are intentionally out of scope here and belong to
later tasks, which will extend this module in place.

Rules document shape (see docs/rule-migration.md for provenance):

    {
      "version": 1,
      "reviewer": {"chain": [...], "model": "...", "timeout_s": 50},
      "limits": {...},
      "rules": [
        {
          "id", "surface", "class", "action", "pattern",  # required
          "reason", "origin",                             # required
          "enabled",                                      # optional, defaults True
          "tools", "exempt", "memory", "check",           # optional
          "requires", "cwd", "overridable",               # optional
        }
      ]
    }
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, FrozenSet, Iterable, List, Mapping, Optional, Tuple

REQUIRED_RULE_FIELDS = (
    "id",
    "surface",
    "class",
    "action",
    "pattern",
    "reason",
    "origin",
)


class RulesError(ValueError):
    """Raised when a rules document fails schema validation."""


@dataclass
class Rule:
    id: str
    surface: str
    rule_class: str  # schema key is "class", a Python keyword
    action: str
    pattern: str
    reason: str
    origin: str
    enabled: bool = True
    tools: Any = None
    exempt: Any = None
    memory: Any = None
    check: Any = None
    requires: Any = None
    cwd: Any = None
    overridable: bool = False


def load_rules(doc: Mapping[str, Any]) -> List[Rule]:
    """Validate a rules document and return its rules.

    Raises RulesError on: a missing/non-list ``rules`` key, a rule missing a
    required field, a required field whose value is not a string, a duplicate
    rule id, or a rule whose ``pattern`` is not a valid Python regular
    expression.

    An empty ``rules`` list is schema-valid and loads to ``[]``, meaning no
    deterministic rules are configured. Policy-completeness warnings (e.g. an
    empty or all-disabled rulepack) are the responsibility of the sanctioned
    CLI layer added later, not this loader. Likewise an empty-string pattern
    ``""`` is a valid (if dangerous) regular expression and is accepted.
    """
    if not isinstance(doc, Mapping):
        raise RulesError("rules document must be a mapping")

    raw_rules = doc.get("rules")
    if not isinstance(raw_rules, list):
        raise RulesError("rules document must contain a 'rules' list")

    rules: List[Rule] = []
    seen_ids = set()

    for raw in raw_rules:
        rule = _load_rule(raw)
        if rule.id in seen_ids:
            raise RulesError(f"duplicate rule id: {rule.id!r}")
        seen_ids.add(rule.id)
        rules.append(rule)

    return rules


def _load_rule(raw: Any) -> Rule:
    if not isinstance(raw, Mapping):
        raise RulesError("each rule must be a mapping")

    missing = [f for f in REQUIRED_RULE_FIELDS if f not in raw]
    if missing:
        raise RulesError(f"rule is missing required field(s): {', '.join(missing)}")

    # `id` is type-checked first so a non-str id cannot reach the seen_ids
    # set in load_rules (which would raise an unhashable TypeError).
    rule_id = raw["id"]
    if not isinstance(rule_id, str):
        raise RulesError(
            f"rule 'id' field must be a string, got {type(rule_id).__name__}"
        )

    for field in ("pattern", "surface", "class", "action", "reason", "origin"):
        value = raw[field]
        if not isinstance(value, str):
            raise RulesError(
                f"rule {rule_id!r}: field {field!r} must be a string, "
                f"got {type(value).__name__}"
            )

    # NOTE: compiled here for VALIDATION only — the raw pattern string is
    # stored and compiled again at match time (matching is a later task).
    # Patterns come from a trusted local rules file.
    try:
        re.compile(raw["pattern"])
    except re.error as exc:
        raise RulesError(
            f"invalid regex pattern for rule {raw['id']!r}: {exc}"
        ) from exc

    # Absent `enabled` defaults to True; only an explicit False disables
    # (upstream semantics: `r.get("enabled", True) is False`).
    enabled = raw.get("enabled", True) is not False

    return Rule(
        id=raw["id"],
        surface=raw["surface"],
        rule_class=raw["class"],
        action=raw["action"],
        pattern=raw["pattern"],
        reason=raw["reason"],
        origin=raw["origin"],
        enabled=enabled,
        tools=raw.get("tools"),
        exempt=raw.get("exempt"),
        memory=raw.get("memory"),
        check=raw.get("check"),
        requires=raw.get("requires"),
        cwd=raw.get("cwd"),
        overridable=raw.get("overridable", False),
    )


# ---------------------------------------------------------------------------
# Compiled representation
#
# compile_rules() turns (re-)validated Rule objects into match-ready form: the
# regex is compiled once, tools/exempt/requires are normalized to frozensets,
# and cwd paths are resolved ONCE at compile time via a read-only realpath
# (symlinks resolved, alternate spellings collapsed) so evaluation is genuinely
# I/O-free — it only compares a lexically-normalized context cwd against these
# pre-resolved paths. The revision hashes the *resolved* cwd paths so a symlink
# retarget yields a new revision and cached callers re-compile.
# ---------------------------------------------------------------------------

# Valid surface/action vocabulary (ED-209-HANDOFF.md §4). The loader above
# validates types only; this documents the vocabulary the engine understands.
SUPPORTED_SURFACES = ("tool", "reply")
SUPPORTED_ACTIONS = ("deny", "check", "inject", "memory-first", "escalate", "block", "log")


@dataclass(frozen=True)
class CompiledRule:
    """A single rule prepared for matching (regex pre-compiled, fields normalized)."""

    rule: Rule
    regex: "re.Pattern"
    tools: Optional[FrozenSet[str]]
    exempt: Optional[FrozenSet[str]]
    requires: FrozenSet[str]
    cwd_paths: Tuple[str, ...]


@dataclass(frozen=True)
class CompiledRules:
    """A frozen, revision-addressed collection of CompiledRule."""

    revision: str
    rules: Tuple[CompiledRule, ...]


def _as_frozenset(value: Any) -> Optional[FrozenSet[str]]:
    """Normalize a tools/exempt field to a frozenset of specifiers.

    ``None`` and an empty list both mean "no restriction" (None). A bare string
    is coerced to a single-element set. Non-string entries are dropped.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return frozenset({value})
    if isinstance(value, Iterable):
        result = frozenset(v for v in value if isinstance(v, str))
        return result if result else None
    return None


def _as_reqset(value: Any) -> FrozenSet[str]:
    """Normalize a requires field to a frozenset of requirement names."""
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset({value})
    if isinstance(value, Iterable):
        return frozenset(v for v in value if isinstance(v, str))
    return frozenset()


def _as_paths(value: Any) -> Tuple[str, ...]:
    """Normalize a cwd field to a tuple of realpath'd protected paths.

    Performed at COMPILE time only: each non-empty path is resolved with a
    read-only ``realpath`` (symlinks resolved, alternate spellings collapsed).
    An explicit empty or whitespace-only cwd is invalid and raises RulesError;
    an absent/None cwd means "no restriction" and yields ``()``. A cwd of
    ``"/"`` intentionally protects all absolute paths.
    """
    if value is None:
        return ()
    if isinstance(value, str):
        if not value.strip():
            raise RulesError("cwd must be a non-empty path (empty/whitespace cwd is invalid)")
        value = [value]
    elif not isinstance(value, Iterable):
        return ()
    from .capabilities import normalize_path  # local import: avoids any cycle

    paths: List[str] = []
    for p in value:
        if not isinstance(p, str):
            continue
        if not p.strip():
            raise RulesError("cwd entries must be non-empty paths")
        paths.append(normalize_path(p))
    return tuple(paths)


def _revision(compiled: Iterable[CompiledRule]) -> str:
    """Content hash of the compiled rule set, for revision-addressed caching.

    Hashes the *resolved* cwd paths (not the raw cwd strings) so a symlink
    retarget that changes what a cwd resolves to produces a new revision.
    """
    payload = repr(
        tuple(
            (
                cr.rule.id,
                cr.rule.surface,
                cr.rule.rule_class,
                cr.rule.action,
                cr.rule.pattern,
                cr.rule.reason,
                cr.rule.origin,
                cr.rule.enabled,
                cr.rule.tools,
                cr.rule.exempt,
                cr.rule.memory,
                cr.rule.check,
                cr.rule.requires,
                cr.cwd_paths,
                cr.rule.overridable,
            )
            for cr in compiled
        )
    )
    return sha256(payload.encode("utf-8")).hexdigest()[:16]


def _validate_rule_fields(r: Rule) -> None:
    """Re-validate a (possibly hand-built) Rule's required fields.

    ``load_rules`` already type-checks, but ``compile_rules`` is the documented
    matching boundary and may receive Rule objects built directly. Evaluation
    assumes these invariants, so a bad Rule must fail here (RulesError), never
    mid-evaluation.
    """
    for field, value in (
        ("id", r.id),
        ("surface", r.surface),
        ("class", r.rule_class),
        ("action", r.action),
        ("pattern", r.pattern),
        ("reason", r.reason),
        ("origin", r.origin),
    ):
        if not isinstance(value, str):
            raise RulesError(
                f"rule {r.id!r}: field {field!r} must be a string, "
                f"got {type(value).__name__}"
            )
    if r.action not in SUPPORTED_ACTIONS:
        raise RulesError(
            f"rule {r.id!r}: unsupported action {r.action!r}; "
            f"must be one of {SUPPORTED_ACTIONS}"
        )


def compile_rules(rules: Iterable[Rule]) -> CompiledRules:
    """Compile Rule objects into a frozen CompiledRules.

    Re-validates required fields (id/pattern/surface/class/action/reason/origin
    must be str; action must be a supported action) so a hand-built Rule cannot
    crash mid-evaluation, raising RulesError otherwise. Compilation performs a
    read-only ``realpath`` on cwd paths (see ``_as_paths``); evaluation performs
    no I/O. Identical rule sets — including identical *resolved* cwd paths —
    yield identical ``revision`` hashes, so callers can compile once and
    re-evaluate many contexts against the same instance.
    """
    rule_list = list(rules)
    compiled: List[CompiledRule] = []
    for r in rule_list:
        _validate_rule_fields(r)
        try:
            regex = re.compile(r.pattern)
        except re.error as exc:
            raise RulesError(f"rule {r.id!r}: invalid regex pattern: {exc}") from exc
        compiled.append(
            CompiledRule(
                rule=r,
                regex=regex,
                tools=_as_frozenset(r.tools),
                exempt=_as_frozenset(r.exempt),
                requires=_as_reqset(r.requires),
                cwd_paths=_as_paths(r.cwd),
            )
        )
    compiled_tuple = tuple(compiled)
    return CompiledRules(revision=_revision(compiled_tuple), rules=compiled_tuple)
