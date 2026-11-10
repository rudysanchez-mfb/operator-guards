"""ED-209 Hermes plugin: mechanical behaviour enforcement.

Wires four real Hermes hooks to the standalone :mod:`operator_guards.ed209`
engine, with no provider call at startup and the active profile home resolved
per callback (never at import time):

* ``pre_tool_call``     — deterministic deny maps to Hermes's block directive
  ``{"action": "block", "message": <counted fact>}``; the reviewer runs only
  after a matched ``escalate`` rule (bounded by the host-fitting adapter).
* ``post_tool_call``    — bounded evidence: a matched ``log`` rule records one
  hit carrying the tool's completion status.
* ``pre_final_response``— reply-surface policy: a matched ``deny``/``block``
  returns ``{"action": "continue", "message": <fact>}`` to reject the candidate
  and continue the turn (works on no-edit turns). **Runtime-dependent**: this
  hook is a member of ``VALID_HOOKS`` (and has a fire site) only in the Hermes
  checkout that carries the completion-policy gate (branch
  ``local/verification-proof``, commit ``e2f6e2a944``). On the DEPLOYED
  runtime (``bd9bb4deee``) it is absent, so ``register()`` does NOT register it
  and surfaces it as unsupported via ``registration_status()`` (never a silent
  inert registration).
* ``pre_llm_call``      — non-denying context attachment: a matched
  ``inject``/``memory-first`` rule injects its bounded memory into the current
  turn's user message once per session. Never coerced into deny/block; if no
  model-visible context carrier existed the outcome is recorded ``unavailable``
  and the call fails open.

Hook registration is GUARDED: each declared hook is registered only when the
runtime actually supports it (``hermes_cli.plugins.VALID_HOOKS``). A hook the
runtime lacks would otherwise be stored-but-inert (Hermes warns and still
stores), silently shipping a dead capability; instead it is not registered,
logged as a clear warning, and exposed via :func:`registration_status`.

**Enforcement requires a seeded runtime rules doc.** Every hook reads the active
profile's ``<home>/ed209/rules.json`` (resolved per callback). When that file is
ABSENT, there are no rules to enforce and every hook fails open — and the plugin
logs a LOUD, precise warning (deduplicated, not spammy) naming the missing path
and stating enforcement is INERT. There is NO silent fallback to the bundled
``documented-initial`` rulepack here: the runtime doc is the source of truth,
and seeding it is the installer's job (``deploy/install.py`` copies the bundled
pack to ``<home>/ed209/rules.json`` on first install).

This module imports only the stdlib and ``operator_guards`` (no ``hermes_cli``)
so it stays import-safe under the standalone test venv.
"""

from __future__ import annotations

import functools
import json
import logging
import os
import threading
import time
from pathlib import Path

from operator_guards.ed209.capabilities import resolve_tool
from operator_guards.ed209.engine import (
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_CHECK,
    ACTION_DENY,
    ACTION_ESCALATE,
    ACTION_INJECT,
    ACTION_LOG,
    ACTION_MEMORY_FIRST,
    ACTION_OVERRIDE,
    COUNTED_FACT_MAX_CHARS,
    EvaluationContext,
    evaluate,
)
from operator_guards.ed209.ledger import HitLedger
from operator_guards.ed209.reviewer import (
    Reviewer,
    ReviewerContext,
    ReviewerRoute,
    resolve_review,
    sanitize_context,
)
from operator_guards.ed209.rules import compile_rules, load_rules
from operator_guards.ed209.state import SessionStateStore

logger = logging.getLogger("ed209")

# Bounded canonical tool payload sent to the evaluator (engine flattens further).
_PAYLOAD_MAX_CHARS = 8000

# Default profile home used only when HERMES_HOME is unset (e.g. a bare probe).
_DEFAULT_HOME = str(Path.home() / ".hermes")

# ---------------------------------------------------------------------------
# Reviewer seam (unconfigured by default -> escalate is `unavailable`, fail-open)
# ---------------------------------------------------------------------------

_reviewer_transport = None  # callable(payload: str) -> str | None
_reviewer_route: ReviewerRoute | None = None
_reviewer_parent_family = ""


def configure_reviewer(transport, *, family, model, timeout_s, parent_family=""):
    """Wire the (test/local) reviewer transport. Default state is *unconfigured*.

    This is the only way to make ``escalate`` rules reach a reviewer; a missing
    transport keeps escalate ``unavailable`` under the source's fail-open
    contract. The adapter is already host-deadline bounded (``Reviewer``).
    """
    global _reviewer_transport, _reviewer_route, _reviewer_parent_family
    _reviewer_transport = transport
    _reviewer_route = ReviewerRoute(family=family, model=model, transport="local", timeout_s=float(timeout_s))
    _reviewer_parent_family = parent_family


# ---------------------------------------------------------------------------
# Registration (local, no provider call)
# ---------------------------------------------------------------------------


# The hook names this plugin DECLARES (the fallback when the runtime cannot be
# introspected, e.g. the standalone test venv where register() is never called
# by a real runtime anyway).
_DECLARED_HOOKS = frozenset(
    {"pre_tool_call", "post_tool_call", "pre_final_response", "pre_llm_call"}
)

_registration_status = {"supported": (), "unsupported": ()}


def _runtime_supported_hooks(ctx) -> frozenset:
    """The hook names THIS runtime actually supports (never guessed).

    ``register()`` is only ever invoked by the real Hermes PluginManager, so
    ``hermes_cli.plugins.VALID_HOOKS`` is authoritative there: a name absent
    from it would be registered INERT (Hermes warns but still stores) and never
    fired. An explicitly set ``ctx.supported_hooks`` (a test/consumer
    simulation) overrides introspection. When ``hermes_cli`` is not importable
    (the standalone test venv), all declared hooks are treated as supported
    (there is no runtime to be inert against).
    """
    supported = getattr(ctx, "supported_hooks", None)
    if supported is not None:
        return frozenset(supported)
    try:
        from hermes_cli.plugins import VALID_HOOKS
    except Exception:  # noqa: BLE001 — standalone venv / no Hermes runtime
        return frozenset(_DECLARED_HOOKS)
    return frozenset(VALID_HOOKS)


def register(ctx):
    """Register each declared hook ONLY if this runtime supports it.

    A hook the runtime does not support would be stored-but-inert by Hermes's
    ``register_hook`` (it warns and still stores the callback with no fire
    site), so registering it unconditionally would silently ship a dead
    capability. Supported hooks are registered; unsupported ones are NOT
    registered, are logged as a clear warning, and are exposed via
    :func:`registration_status`. Local only — no provider/network call.
    """
    hooks = (
        ("pre_tool_call", _pre_tool_call),
        ("post_tool_call", _post_tool_call),
        ("pre_final_response", _pre_final_response),
        ("pre_llm_call", _pre_llm_call),
    )
    supported = _runtime_supported_hooks(ctx)
    registered = []
    unsupported = []
    for name, callback in hooks:
        if name in supported:
            ctx.register_hook(name, callback)
            registered.append(name)
        else:
            unsupported.append(name)
    for name in unsupported:
        logger.warning(
            "ED-209: hook %r is not supported by this Hermes runtime; the "
            "declared capability would be INERT and was NOT registered", name,
        )
    _registration_status["supported"] = tuple(registered)
    _registration_status["unsupported"] = tuple(unsupported)
    return dict(_registration_status)


def registration_status() -> dict:
    """The last registration's supported/unsupported hook names.

    A declared-but-unsupported hook is surfaced here so a consumer
    (status/doctor/tests) can detect a silently-dead capability — never silent.
    """
    return dict(_registration_status)


# ---------------------------------------------------------------------------
# Home / rule resolution (per callback)
# ---------------------------------------------------------------------------

_rules_lock = threading.Lock()
_rules_cache = {}  # path -> (stat_key, (CompiledRules, limits dict))

# Paths already warned-about for a missing runtime rules doc. Deduplicates the
# LOUD degraded warning across per-callback loads (loud, not spammy).
_missing_rules_warned: set = set()


def _resolve_home() -> str:
    """Current profile home, read at call time (never cached at import)."""
    home = (
        os.environ.get("OPERATOR_GUARDS_HOME", "").strip()
        or os.environ.get("HERMES_HOME", "").strip()
    )
    return home or _DEFAULT_HOME


def _rules_file(home: str) -> str:
    return os.path.join(home, "ed209", "rules.json")


def _load_compiled(home: str):
    """Load + compile the home's rules, cached by file stat. ``(None, None)`` on
    a missing/unparseable rules file (no rules -> no enforcement, fail-open). A
    MISSING file logs a LOUD, deduplicated warning (enforcement is inert until
    the runtime doc is seeded); an unreadable/invalid file logs its own warning.

    Staleness caveat: the cache key is ``(path, st_mtime_ns, st_size)``. An edit
    that preserves both the size and the mtime (e.g. a script that rewrites the
    file and restores its mtime) would be served stale within a long-lived
    process. The stat is also read before the cache lock, so there is a benign
    TOCTOU window between stat and read — worst case it re-reads/re-compiles the
    file, never serves a torn parse (the open/parse path fails open).
    """
    path = _rules_file(home)
    try:
        st = os.stat(path)
        stat_key = (path, st.st_mtime_ns, st.st_size)
    except OSError:
        if path not in _missing_rules_warned:
            _missing_rules_warned.add(path)
            logger.warning(
                "ED-209: no runtime rules document at %s — enforcement is INERT "
                "(no rules loaded, fail-open). Seed it at install "
                "(deploy/install.py copies the bundled documented-initial "
                "rulepack to this path) or author rules via `ed209 add`. The "
                "runtime doc is the source of truth; there is NO silent fallback "
                "to the bundled pack.",
                path,
            )
        return None, None

    with _rules_lock:
        cached = _rules_cache.get(path)
        if cached is not None and cached[0] == stat_key:
            return cached[1]

    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        logger.warning("ED-209: cannot read rules at %s: %s", path, exc)
        return None, None

    try:
        rules = load_rules(doc)
        compiled = compile_rules(rules)
    except Exception as exc:
        logger.warning("ED-209: invalid rules at %s: %s", path, exc)
        return None, None

    limits = doc.get("limits") if isinstance(doc.get("limits"), dict) else {}
    result = (compiled, limits)
    with _rules_lock:
        _rules_cache[path] = (stat_key, result)
    return result


def _ledger(home: str) -> HitLedger:
    return HitLedger(os.path.join(home, "ed209", "hits.db"))


def _state_store(home: str, limits: dict | None) -> SessionStateStore:
    limits = limits or {}
    max_blocks = limits.get("max_blocks_per_session")
    max_reviewer = limits.get("max_reviewer_calls_per_session")
    kwargs = {}
    if isinstance(max_blocks, int):
        kwargs["max_blocks"] = max_blocks
    if isinstance(max_reviewer, int):
        kwargs["max_reviewer_calls"] = max_reviewer
    return SessionStateStore(os.path.join(home, "ed209", "state"), **kwargs)


def _record(home, *, rule_id, session_id, outcome, counted_fact, surface, client_id="", turn_id="", task_id="", parent_id=""):
    """Record a hit; a ledger write failure is visible (degraded) and never
    suppresses a deny (the caller's decision already stands)."""
    rec = _ledger(home).record_hit(
        rule_id=rule_id, session_id=session_id, outcome=outcome, counted_fact=counted_fact,
        surface=surface, client_id=client_id, turn_id=turn_id, task_id=task_id, parent_id=parent_id,
    )
    if not rec.ok:
        logger.warning("ED-209: ledger write degraded: %s", rec.degraded)


def _payload_bounded(args) -> str:
    if isinstance(args, dict):
        try:
            text = json.dumps(args, sort_keys=True, default=str)
        except (TypeError, ValueError):
            text = repr(args)
    elif args is None:
        text = ""
    else:
        text = str(args)
    return text[:_PAYLOAD_MAX_CHARS]


def _cwd_from_args(args) -> str | None:
    # cwd gating trusts the model-supplied ``workdir``/``cwd`` arg. This is
    # lexical defence-in-depth only: the value is whatever the tool call claims,
    # and evaluation normalizes it lexically (no realpath), so it is not an OS
    # security boundary — a same-UID process can retarget symlinks after
    # compile time (see engine._cwd_applies / capabilities.normalize_path).
    if isinstance(args, dict):
        for key in ("workdir", "cwd"):
            value = args.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def _base_context(home, *, surface, session_id, turn_id, task_id, tool_name, capabilities, payload, candidate_text, cwd, tool_count, available):
    return EvaluationContext(
        profile_home=home,
        client_id="",
        session_id=session_id or "",
        turn_id=turn_id or "",
        task_id=task_id or "",
        surface=surface,
        tool_name=tool_name,
        capabilities=capabilities,
        payload=payload,
        candidate_text=candidate_text,
        cwd=cwd,
        tool_count=tool_count,
        available=available,
        timestamp=time.time(),
    )


def _reviewer_available() -> bool:
    return _reviewer_transport is not None and _reviewer_route is not None


def _run_reviewer(home, decision, *, ctx, session_id, turn_id, task_id, limits=None):
    """Invoke the host-deadline-bounded reviewer for a matched escalate rule.

    Returns the resolved outcome action (deny/allow/unavailable). The reviewer
    is consulted ONLY here, and only after ``decision.action == escalate``.
    ``limits`` is the rules doc's ``limits`` mapping; it binds the per-session
    reviewer budget (``max_reviewer_calls_per_session``), falling back to the
    store's default when unset.
    """
    if _reviewer_route is None or _reviewer_transport is None:
        return None  # unconfigured -> unavailable -> fail-open
    state = _state_store(home, limits)
    if not state.consume_reviewer(session_id):
        logger.warning("ED-209: reviewer budget exhausted for session %s", session_id)
        return None  # unavailable -> fail-open

    try:
        reviewer = Reviewer(
            _reviewer_route, _reviewer_transport, parent_family=_reviewer_parent_family,
        )
        result = reviewer.review(
            ReviewerContext(
                surface=ctx.surface, tool_name=ctx.tool_name or "", payload=ctx.payload or "",
                candidate_text=ctx.candidate_text or "", counted_fact=decision.counted_fact,
                reviewer_depth=ctx.reviewer_depth,
            )
        )
    except Exception as exc:
        logger.warning("ED-209: reviewer construction failed: %s", exc)
        return None

    return resolve_review(False, result)


# ---------------------------------------------------------------------------
# Hot-path containment + fact redaction
# ---------------------------------------------------------------------------


def _fail_open(func):
    """Guard a hook callback so it can NEVER raise into Hermes.

    An exception means no determined deny was computed, so fail-open (return
    None = no directive / no context) is correct: the tool proceeds, no context
    is injected. A determined deny itself is still returned when computed —
    recording that deny happens inside ``_block_directive``'s own try/except, so
    a later step failing (e.g. the ledger) cannot suppress the block.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 — hot path must never raise
            logger.warning("ED-209: hook %s degraded (fail-open): %s", func.__name__, exc)
            return None

    return wrapper


def _redact_fact(fact: str) -> str:
    """Redact secret-shaped assignments from a counted fact before it reaches
    the model or ledger — the same sanitization the reviewer path applies
    (``sanitize_context``). A matched secret (e.g. ``api_key=...`` echoed by the
    rule's ``reason`` template) must never leak back to the caller."""
    return sanitize_context(fact, max_chars=COUNTED_FACT_MAX_CHARS)


def _winning_rule_id(compiled, decision) -> str | None:
    """Return the id of the single matched rule whose context the engine attached.

    ``matched_rule_ids`` mirrors compiled-rule order, and the engine picks the
    first matched rule whose action equals the winning action — so the winning
    id is the first matched id whose compiled action matches ``decision.action``.
    This re-derives the winner locally rather than exposing a new field on
    ``Decision`` (which would ripple into the engine's public API).
    """
    action_by_id = {cr.rule.id: cr.rule.action for cr in compiled.rules}
    for rid in decision.matched_rule_ids:
        if action_by_id.get(rid) == decision.action:
            return rid
    return None


def _block_directive(home, decision, *, outcome, session_id, turn_id, task_id, surface):
    """Build the Hermes block directive for a determined deny/block.

    The message is secret-redacted (reviewer-path sanitization). The hit is
    recorded best-effort: a ledger write failure is logged (visible, degraded)
    but the block directive is still returned — a determined deny must never be
    suppressed by a failed write.
    """
    redacted = _redact_fact(decision.counted_fact)
    try:
        _record(
            home, rule_id=decision.matched_rule_ids[0], session_id=session_id,
            outcome=outcome, counted_fact=redacted, surface=surface,
            turn_id=turn_id, task_id=task_id,
        )
    except Exception as exc:  # noqa: BLE001 — never suppress a determined deny
        logger.warning("ED-209: ledger record degraded during %s (deny stands): %s", outcome, exc)
    return {"action": "block", "message": redacted}


# ---------------------------------------------------------------------------
# pre_tool_call — deterministic veto
# ---------------------------------------------------------------------------


@_fail_open
def _pre_tool_call(tool_name=None, args=None, session_id="", turn_id="", task_id="", tool_call_id="", **kwargs):
    home = _resolve_home()
    compiled, limits = _load_compiled(home)
    if compiled is None:
        return None  # no rules -> fail-open

    real_name, capabilities = resolve_tool(tool_name, args)
    available = frozenset({"reviewer"}) if _reviewer_available() else frozenset()
    ctx = _base_context(
        home, surface="tool", session_id=session_id, turn_id=turn_id, task_id=task_id,
        tool_name=real_name, capabilities=capabilities, payload=_payload_bounded(args),
        candidate_text=None, cwd=_cwd_from_args(args) or os.getcwd(), tool_count=0,
        available=available,
    )
    decision = evaluate(compiled, ctx)

    # Determined deny/block (block is the defensive completion-policy action on
    # the tool surface): build the block directive via _block_directive so the
    # hit is recorded best-effort and a ledger failure can never suppress it.
    if decision.action in (ACTION_DENY, ACTION_BLOCK):
        outcome = "deny" if decision.action == ACTION_DENY else "block"
        return _block_directive(
            home, decision, outcome=outcome, session_id=session_id, turn_id=turn_id,
            task_id=task_id, surface="tool",
        )

    # A sourced override of a single matched overridable deny rule: the deny is
    # lifted for THIS ONE tool call and the hit is recorded as `override` — the
    # tool proceeds, but the override is durable and queryable (never silent).
    if decision.action == ACTION_OVERRIDE:
        _record(
            home, rule_id=decision.overridden_rule_id or decision.matched_rule_ids[0],
            session_id=session_id, outcome="override", counted_fact=decision.counted_fact,
            surface="tool", turn_id=turn_id, task_id=task_id,
        )
        return None

    if decision.action == ACTION_ESCALATE:
        outcome = _run_reviewer(home, decision, ctx=ctx, session_id=session_id, turn_id=turn_id, task_id=task_id, limits=limits)
        if outcome == ACTION_DENY:
            return _block_directive(
                home, decision, outcome="deny", session_id=session_id, turn_id=turn_id,
                task_id=task_id, surface="tool",
            )
        outcome_name = "allow" if outcome == ACTION_ALLOW else "unavailable"
        _record(home, rule_id=decision.matched_rule_ids[0], session_id=session_id, outcome=outcome_name,
                counted_fact=decision.counted_fact, surface="tool", turn_id=turn_id, task_id=task_id)
        return None  # allow / unavailable -> fail-open

    if decision.action == ACTION_CHECK:
        # No `gh` context is configured by default -> unavailable, fail-open.
        _record(home, rule_id=decision.matched_rule_ids[0], session_id=session_id, outcome="unavailable",
                counted_fact=decision.counted_fact, surface="tool", turn_id=turn_id, task_id=task_id)
        return None

    if decision.action in (ACTION_INJECT, ACTION_MEMORY_FIRST):
        # Tool-surface context has no non-rewrite carrier; record unavailable and
        # fail open — never coerce inject into deny/block.
        _record(home, rule_id=decision.matched_rule_ids[0], session_id=session_id, outcome="unavailable",
                counted_fact=decision.counted_fact, surface="tool", turn_id=turn_id, task_id=task_id)
        return None

    # log: evidence is recorded post-tool (with the actual completion status).
    # allow: nothing to do.
    return None


# ---------------------------------------------------------------------------
# post_tool_call — bounded evidence
# ---------------------------------------------------------------------------


@_fail_open
def _post_tool_call(tool_name=None, args=None, result=None, session_id="", turn_id="", task_id="", tool_call_id="", status=None, error_type=None, error_message=None, **kwargs):
    home = _resolve_home()
    compiled, limits = _load_compiled(home)
    if compiled is None:
        return None

    real_name, capabilities = resolve_tool(tool_name, args)
    ctx = _base_context(
        home, surface="tool", session_id=session_id, turn_id=turn_id, task_id=task_id,
        tool_name=real_name, capabilities=capabilities, payload=_payload_bounded(args),
        candidate_text=None, cwd=_cwd_from_args(args) or os.getcwd(), tool_count=0,
        available=frozenset({"reviewer"}) if _reviewer_available() else frozenset(),
    )
    decision = evaluate(compiled, ctx)

    if decision.action == ACTION_LOG:
        status_text = status or "ok"
        detail = f"tool {real_name} status={status_text}"
        if error_type:
            detail += f" error={error_type}"
        if error_message:
            detail += f" ({str(error_message)[:120]})"
        _record(home, rule_id=decision.matched_rule_ids[0], session_id=session_id, outcome="log",
                counted_fact=detail, surface="tool", turn_id=turn_id, task_id=task_id)
    # Observer: never deny/block from post_tool_call.
    return None


# ---------------------------------------------------------------------------
# pre_final_response — reply policy (no-edit turns included)
# ---------------------------------------------------------------------------


@_fail_open
def _pre_final_response(session_id="", turn_id="", task_id="", final_response="", tool_count=0, **kwargs):
    home = _resolve_home()
    compiled, limits = _load_compiled(home)
    if compiled is None:
        return None

    available = frozenset({"reviewer"}) if _reviewer_available() else frozenset()
    ctx = _base_context(
        home, surface="reply", session_id=session_id, turn_id=turn_id, task_id=task_id,
        tool_name=None, capabilities=frozenset(), payload=None, candidate_text=final_response or "",
        cwd=None, tool_count=tool_count, available=available,
    )
    decision = evaluate(compiled, ctx)

    if decision.action in (ACTION_DENY, ACTION_BLOCK):
        state = _state_store(home, limits)
        if not state.consume_block(session_id):
            logger.warning("ED-209: reply block budget exhausted for session %s", session_id)
            return None  # exhaustion ends the turn rather than looping forever
        redacted = _redact_fact(decision.counted_fact)
        _record(home, rule_id=decision.matched_rule_ids[0], session_id=session_id, outcome="block",
                counted_fact=redacted, surface="reply", turn_id=turn_id, task_id=task_id)
        return {"action": "continue", "message": redacted}

    if decision.action == ACTION_ESCALATE:
        outcome = _run_reviewer(home, decision, ctx=ctx, session_id=session_id, turn_id=turn_id, task_id=task_id, limits=limits)
        if outcome == ACTION_DENY:
            state = _state_store(home, limits)
            if not state.consume_block(session_id):
                return None
            redacted = _redact_fact(decision.counted_fact)
            _record(home, rule_id=decision.matched_rule_ids[0], session_id=session_id, outcome="block",
                    counted_fact=redacted, surface="reply", turn_id=turn_id, task_id=task_id)
            return {"action": "continue", "message": redacted}
        return None  # allow / unavailable -> fail-open

    if decision.action in (ACTION_INJECT, ACTION_MEMORY_FIRST):
        # Context cannot attach to an already-settled candidate; record and fail open.
        _record(home, rule_id=decision.matched_rule_ids[0], session_id=session_id, outcome="unavailable",
                counted_fact=decision.counted_fact, surface="reply", turn_id=turn_id, task_id=task_id)
        return None

    if decision.action == ACTION_LOG:
        _record(home, rule_id=decision.matched_rule_ids[0], session_id=session_id, outcome="log",
                counted_fact=decision.counted_fact, surface="reply", turn_id=turn_id, task_id=task_id)
        return None

    return None


# ---------------------------------------------------------------------------
# pre_llm_call — non-denying context attachment (once per session per rule)
# ---------------------------------------------------------------------------


@_fail_open
def _pre_llm_call(session_id="", turn_id="", task_id="", user_message="", **kwargs):
    home = _resolve_home()
    compiled, limits = _load_compiled(home)
    if compiled is None:
        return None

    ctx = _base_context(
        home, surface="reply", session_id=session_id, turn_id=turn_id, task_id=task_id,
        tool_name=None, capabilities=frozenset(), payload=None, candidate_text=user_message or "",
        cwd=None, tool_count=0, available=frozenset({"memory"}),
    )
    decision = evaluate(compiled, ctx)

    # Only the non-denying inject/memory-first actions attach context here; a
    # deny/block/escalate decision is the final-response gate's concern, never
    # this hook's (never block from pre_llm_call).
    if decision.action not in (ACTION_INJECT, ACTION_MEMORY_FIRST):
        return None
    if not decision.context:
        return None

    # The engine attaches context for a SINGLE winning rule; matched_rule_ids
    # also lists matched losers. Mark only the rule whose context is actually
    # attached so a loser's memory isn't dropped yet permanently marked.
    winning_id = _winning_rule_id(compiled, decision)
    if winning_id is None:
        return None

    state = _state_store(home, limits)
    if not state.try_mark_injected(session_id, winning_id):
        return None  # already injected this session: no duplicate context

    return {"context": "\n".join(decision.context)}
