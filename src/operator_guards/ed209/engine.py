"""Deterministic ED-209 evaluation engine.

Compile rules once into a :class:`~operator_guards.ed209.rules.CompiledRules`;
evaluate each per-call :class:`EvaluationContext` against it; return an
immutable :class:`Decision`. Evaluation is pure — no I/O, no reviewer calls, no
ledger writes. Side-effecting actions (deny → block directive, inject → context
attachment, escalate → reviewer verdict) are *classified* here and executed by
later adapters/plugins (Task 4+).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from . import capabilities
from .rules import CompiledRule, CompiledRules

# Action vocabulary (ED-209-HANDOFF.md §4).
ACTION_DENY = "deny"
ACTION_CHECK = "check"
ACTION_INJECT = "inject"
ACTION_MEMORY_FIRST = "memory-first"
ACTION_ESCALATE = "escalate"
ACTION_BLOCK = "block"
ACTION_LOG = "log"
ACTION_ALLOW = "allow"
# A sourced override of a single matched overridable deny rule (plan §4 Task 14).
# It is a hit OUTCOME, not an action in ACTION_PRIORITY: it lifts exactly one
# overridable deny for exactly one matching tool call, never a protected rule,
# and it is NOT independent kill authority.
ACTION_OVERRIDE = "override"

# Deterministic precedence when several actions match. The handoff is silent on
# non-deny precedence; this is a documented choice. deny always dominates
# (handled before this tuple is consulted), then block, then escalate/check/
# inject/memory-first/log. Non-denying actions can never out-rank a deny.
ACTION_PRIORITY = (
    ACTION_DENY,
    ACTION_BLOCK,
    ACTION_ESCALATE,
    ACTION_CHECK,
    ACTION_INJECT,
    ACTION_MEMORY_FIRST,
    ACTION_LOG,
)

# Bounds for counted-fact templating and context attachment (flattening bound).
MATCH_TEXT_MAX_CHARS = 200
COUNTED_FACT_MAX_CHARS = 500
CONTEXT_MAX_CHARS = 2000

# Status values for check/reviewer (adapters land in Task 4).
STATUS_DEFERRED = "deferred"
STATUS_UNAVAILABLE = "unavailable"

# Context-interface names consulted via EvaluationContext.available.
IFACE_MEMORY = "memory"
IFACE_GH = "gh"
IFACE_REVIEWER = "reviewer"


@dataclass(frozen=True)
class EvaluationContext:
    """Immutable per-call evaluation snapshot. Side-effect free by construction.

    ``surface`` selects the evaluated subject: ``"tool"`` uses ``payload`` (the
    bounded canonical tool arguments), ``"reply"`` uses ``candidate_text``. The
    engine never consults tool *output* — only these fields — so a safe payload
    cannot match merely because unrelated output text mentions a banned phrase.

    ``capabilities`` are the resolved capabilities of ``tool_name`` (already
    unwrapped from any deferred wrapper). ``available`` names the context
    interfaces present for this call (memory/gh/reviewer); their absence makes a
    matched non-denying action's outcome ``unavailable``, never a deny.
    """

    profile_home: str
    client_id: str
    session_id: str
    turn_id: str
    task_id: str | None = None
    parent_id: str | None = None
    surface: str = "tool"
    tool_name: str | None = None
    capabilities: frozenset[str] = frozenset()
    payload: str | None = None
    candidate_text: str | None = None
    cwd: str | None = None
    tool_count: int = 0
    denial_count: int = 0
    read_count: int = 0
    reviewer_depth: int = 0
    available: frozenset[str] = frozenset()
    timestamp: float = 0.0


@dataclass(frozen=True)
class Decision:
    """Immutable evaluation result. ``degraded`` carries coverage warnings.

    ``unavailable`` records interfaces a matched non-denying action needed but
    that were absent; it is separately observable from ``degraded`` and never
    coerces inject/memory-first into deny/block/escalate.
    """

    action: str
    matched_rule_ids: tuple[str, ...] = ()
    counted_fact: str = ""
    context: tuple[str, ...] = ()
    check_status: str | None = None
    reviewer_status: str | None = None
    unavailable: tuple[str, ...] = ()
    degraded: tuple[str, ...] = ()
    overridden_rule_id: str | None = None


def evaluate(compiled: CompiledRules, ctx: EvaluationContext) -> Decision:
    """Evaluate one immutable context against compiled rules; return a Decision.

    Pure: no side effects. Deterministic: deny wins; otherwise the
    highest-priority matched action per ACTION_PRIORITY.
    """
    matches: list[tuple[CompiledRule, str]] = []
    subject = _subject(ctx)
    for cr in compiled.rules:
        rule = cr.rule
        if not rule.enabled:
            continue
        if rule.surface != ctx.surface:
            continue
        if not _tool_applies(cr, ctx):
            continue
        if not _requires_satisfied(cr, ctx):
            continue
        if not _cwd_applies(cr, ctx):
            continue
        m = cr.regex.search(subject)
        if m is None:
            continue
        matches.append((cr, m.group(0)))

    degraded = _coverage_warnings(ctx)

    if not matches:
        return Decision(action=ACTION_ALLOW, degraded=degraded)

    matched_ids = tuple(cr.rule.id for cr, _ in matches)

    # Deterministic deny wins: any matched deny rule makes the decision deny,
    # UNLESS every matched deny rule is overridable and the call carries a valid
    # ``# ed209-override: <rule-id> <reason>`` directive naming one of them.
    deny_matches = [(cr, mt) for cr, mt in matches if cr.rule.action == ACTION_DENY]
    if deny_matches:
        overridden = _resolve_override(subject, deny_matches, matched_ids, degraded)
        if overridden is not None:
            return overridden
        cr, mt = deny_matches[0]
        return Decision(
            action=ACTION_DENY,
            matched_rule_ids=matched_ids,
            counted_fact=_render_counted_fact(cr.rule, mt, ctx),
            degraded=degraded,
        )

    # No deny: pick the highest-priority matched action, deterministically.
    winning: tuple[CompiledRule, str] | None = None
    for action in ACTION_PRIORITY:
        for cr, mt in matches:
            if cr.rule.action == action:
                winning = (cr, mt)
                break
        if winning is not None:
            break

    if winning is None:
        # A matched rule carried an action outside the documented set; treat as
        # record-only (log) — never deny on an action we cannot interpret.
        return Decision(
            action=ACTION_LOG, matched_rule_ids=matched_ids, degraded=degraded
        )

    cr, mt = winning
    rule = cr.rule
    fact = _render_counted_fact(rule, mt, ctx)

    if rule.action in (ACTION_INJECT, ACTION_MEMORY_FIRST):
        unavailable = () if IFACE_MEMORY in ctx.available else (IFACE_MEMORY,)
        context = _bounded_context(rule) if not unavailable else ()
        # Never coerced into deny/block/escalate: action stays non-denying.
        return Decision(
            action=rule.action,
            matched_rule_ids=matched_ids,
            counted_fact=fact,
            context=context,
            unavailable=unavailable,
            degraded=degraded,
        )

    if rule.action == ACTION_CHECK:
        status = STATUS_UNAVAILABLE if IFACE_GH not in ctx.available else STATUS_DEFERRED
        return Decision(
            action=ACTION_CHECK,
            matched_rule_ids=matched_ids,
            counted_fact=fact,
            check_status=status,
            degraded=degraded,
        )

    if rule.action == ACTION_ESCALATE:
        status = (
            STATUS_UNAVAILABLE if IFACE_REVIEWER not in ctx.available else STATUS_DEFERRED
        )
        return Decision(
            action=ACTION_ESCALATE,
            matched_rule_ids=matched_ids,
            counted_fact=fact,
            reviewer_status=status,
            degraded=degraded,
        )

    # block / log
    return Decision(
        action=rule.action,
        matched_rule_ids=matched_ids,
        counted_fact=fact,
        degraded=degraded,
    )


def _subject(ctx: EvaluationContext) -> str:
    if ctx.surface == "tool":
        return ctx.payload or ""
    return ctx.candidate_text or ""


# Sourced override comment syntax (plan §4): ``# ed209-override: <rule-id> <reason>``.
# The directive only counts when it is an ACTUAL COMMENT LINE — a ``#`` at the
# start of a line, preceded only by optional whitespace — so a token smuggled
# inside a quoted/string argument (mid-line) NEVER overrides. The reason must be
# NONEMPTY. A directive only lifts a deny for the ONE tool call whose payload
# carries it; it is never blanket policy-off and it is NOT independent kill
# authority (grants are the only kill authority, and they are a separate,
# operator-only mechanism).
_OVERRIDE_RE = re.compile(
    r"(?m)^[ \t]*#[ \t]*ed209-override[ \t]*:[ \t]*([A-Za-z0-9_.-]+)[ \t]+(\S[^\n]*)"
)


def _parse_override_directives(subject: str) -> list[tuple[str, str]]:
    """Return ``[(rule_id, reason), ...]`` for each valid nonempty-reason directive."""
    out: list[tuple[str, str]] = []
    for m in _OVERRIDE_RE.finditer(subject):
        reason = m.group(2).strip()
        if reason:  # a blank reason never overrides
            out.append((m.group(1), reason))
    return out


def _resolve_override(subject, deny_matches, matched_ids, degraded) -> Decision | None:
    """Resolve a sourced override of a matched overridable deny, else None.

    * ANY non-overridable (protected) deny among the matches blocks the override
      entirely — the protected rule's deny stands.
    * Otherwise the directive must name one of the matched (overridable) deny
      rules; only then is the deny lifted for this one call (outcome override).
    """
    directives = _parse_override_directives(subject)
    if not directives:
        return None
    for cr, _ in deny_matches:
        if not cr.rule.overridable:
            return None
    overridable_ids = {cr.rule.id for cr, _ in deny_matches}
    for rule_id, reason in directives:
        if rule_id not in overridable_ids:
            continue  # names a rule that did not match this call: no effect
        return Decision(
            action=ACTION_OVERRIDE,
            matched_rule_ids=matched_ids,
            counted_fact=_flatten(f"override {rule_id}: {reason}", COUNTED_FACT_MAX_CHARS),
            overridden_rule_id=rule_id,
            degraded=degraded,
        )
    return None


def _tool_identity_set(ctx: EvaluationContext) -> set[str]:
    s = set(ctx.capabilities)
    if ctx.tool_name:
        s.add(ctx.tool_name)
    return s


def _expand_specifiers(specs: frozenset[str]) -> set[str]:
    """Expand tools/exempt specifiers: a known tool name expands to its
    capabilities (so "Bash" covers the MCP shell tool); otherwise it is matched
    as a literal tool or capability name."""
    out: set[str] = set()
    for spec in specs:
        caps = capabilities.capabilities_for(spec)
        if caps:
            out |= set(caps)
        else:
            out.add(spec)
    return out


def _tool_applies(cr: CompiledRule, ctx: EvaluationContext) -> bool:
    # tools/exempt bind tool calls only; reply-surface rules ignore them.
    if ctx.surface != "tool":
        return True
    identity = _tool_identity_set(ctx)
    if cr.tools is not None:
        if not (identity & _expand_specifiers(cr.tools)):
            return False
    if cr.exempt is not None:
        if identity & _expand_specifiers(cr.exempt):
            return False
    return True


def _requires_satisfied(cr: CompiledRule, ctx: EvaluationContext) -> bool:
    return cr.requires.issubset(ctx.available)


def _cwd_applies(cr: CompiledRule, ctx: EvaluationContext) -> bool:
    # cwd gates tool calls only (it is a working-directory property).
    if ctx.surface != "tool":
        return True
    if not cr.cwd_paths:
        return True
    if not ctx.cwd:
        return False
    # Lexical-only normalization: cwd paths were resolved (realpath) at compile
    # time, so evaluation must not touch the filesystem (no realpath here).
    norm = _normalize_lexical(ctx.cwd)
    for protected in cr.cwd_paths:
        if norm == protected:
            return True
        if norm.startswith(protected.rstrip(os.sep) + os.sep):
            return True
    return False


def _normalize_lexical(path: str) -> str:
    """Collapse a cwd to a comparable form without touching the filesystem.

    ``expanduser`` + ``normpath`` only — deliberately NO ``realpath``, so
    evaluation stays I/O-free. Symlinks in the context cwd are therefore not
    resolved at evaluation time; the caller should re-compile if the filesystem
    changes (the revision hash covers resolved paths).
    """
    return os.path.normpath(os.path.expanduser(path))


def _flatten(text: str, limit: int) -> str:
    # Truncate FIRST so the regex whitespace-collapse never runs over huge
    # matches beyond what we will keep.
    if len(text) > limit:
        text = text[:limit]
    return re.sub(r"\s+", " ", text)


def _render_counted_fact(rule: Any, match_text: str, ctx: EvaluationContext) -> str:
    bounded_match = _flatten(match_text, MATCH_TEXT_MAX_CHARS)
    values = {
        "match": bounded_match,
        "n_tools": str(ctx.tool_count),
        "n_denied": str(ctx.denial_count),
        "n_read_payload": str(ctx.read_count),
        "rule_id": rule.id,
    }
    rendered = rule.reason
    for name, value in values.items():
        rendered = rendered.replace("{" + name + "}", value)
    return _flatten(rendered, COUNTED_FACT_MAX_CHARS)


def _bounded_context(rule: Any) -> tuple[str, ...]:
    mem = rule.memory
    if isinstance(mem, str):
        mem = [mem]
    elif not isinstance(mem, (list, tuple)):
        mem = []
    entries: list[str] = []
    total = 0
    for item in mem:
        if not isinstance(item, str):
            continue
        flat = _flatten(item, CONTEXT_MAX_CHARS)
        if total + len(flat) > CONTEXT_MAX_CHARS:
            break
        entries.append(flat)
        total += len(flat)
    return tuple(entries)


def _coverage_warnings(ctx: EvaluationContext) -> tuple[str, ...]:
    """Surface unbound tool names as a coverage warning (degraded), never silent
    pass-as-safe. Only the tool surface has a tool to bind; a tool with no
    resolved capabilities cannot be covered by capability-bound deny rules. An
    unbound name whose hints suggest mutation is additionally flagged as
    mutating — a higher-severity coverage gap."""
    if ctx.surface == "tool" and ctx.tool_name and not ctx.capabilities:
        warnings = [f"unbound_tool:{ctx.tool_name}"]
        if capabilities.looks_mutating(ctx.tool_name):
            warnings.append(f"unbound_mutating:{ctx.tool_name}")
        return tuple(warnings)
    return ()
