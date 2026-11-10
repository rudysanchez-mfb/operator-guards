"""ED-209 Hermes plugin tests (plan Task 7).

Two layers, one file:

1. **Contract tests** (run under G/.venv with no Hermes installed) exercise the
   plugin module's handler functions against Hermes's *documented* dispatch
   semantics — the ``{"action": "block", "message": <counted fact>}`` pre-tool
   directive, the ``{"action": "continue", "message": <fact>}`` pre-final
   directive, and the ``{"context": ...}`` pre-llm context injection — without
   importing ``hermes_cli``.

2. **Real-dispatch tests** (skip unless the Hermes source checkout is importable)
   load the actual plugin through Hermes's real ``PluginManager`` against a
   temporary ``HERMES_HOME`` and drive a safe sentinel tool through the real
   ``model_tools.handle_function_call`` / directive resolvers.

Run the real-dispatch layer with the documented runner::

    G/scripts/run_plugin_tests.sh

(equivalent: ``PYTHONPATH=H:G/src H/venv/bin/python -m pytest
G/tests/test_ed209_plugin.py``).
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "plugins" / "ed209"

# ---------------------------------------------------------------------------
# Hermes availability probe (import-safe in both environments)
# ---------------------------------------------------------------------------

HERMES_AVAILABLE = False
try:
    import hermes_cli.plugins  # noqa: F401

    HERMES_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only under G/.venv
    pass

requires_hermes = pytest.mark.skipif(
    not HERMES_AVAILABLE,
    reason="Hermes source not importable; run via G/scripts/run_plugin_tests.sh",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fresh_plugin():
    """Load a *fresh* plugin module (isolated globals) without importing hermes."""
    spec = importlib.util.spec_from_file_location(
        "ed209_plugin_under_test", PLUGIN_DIR / "__init__.py"
    )
    assert spec is not None and spec.loader is not None, "plugin __init__.py missing"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeCtx:
    """Minimal ctx implementing the two surfaces the plugin uses.

    ``supported_hooks`` (optional) simulates a runtime's ``VALID_HOOKS`` set so
    the unsupported-hook guard is exercisable under the standalone venv (where
    ``hermes_cli`` is not importable).
    """

    def __init__(self, supported_hooks=None):
        self.hooks = {}
        self.supported_hooks = supported_hooks

    def register_hook(self, name, callback):
        self.hooks.setdefault(name, []).append(callback)


def _write_rules(home, rules, limits=None):
    doc = {"version": 1, "rules": rules}
    if limits is not None:
        doc["limits"] = limits
    (home / "ed209").mkdir(parents=True, exist_ok=True)
    (home / "ed209" / "rules.json").write_text(json.dumps(doc))


def _register(mod, supported_hooks=None):
    ctx = FakeCtx(supported_hooks=supported_hooks)
    mod.register(ctx)
    return ctx


def _invoke(ctx, hook, **kwargs):
    callbacks = ctx.hooks[hook]
    assert len(callbacks) == 1, f"expected one {hook} callback"
    return callbacks[0](**kwargs)


def _deny_rule(rule_id="deny-sentinel", pattern="SECRET_DENY_TOKEN"):
    return {
        "id": rule_id,
        "surface": "tool",
        "class": "known-bad",
        "action": "deny",
        "pattern": pattern,
        "reason": "denied '{match}'",
        "origin": "test",
    }


def _escalate_rule(rule_id="escalate-one", pattern="ESCALATE_ME"):
    return {
        "id": rule_id,
        "surface": "tool",
        "class": "needs-review",
        "action": "escalate",
        "pattern": pattern,
        "reason": "escalated '{match}'",
        "origin": "test",
    }


def _inject_rule(rule_id="inject-once", pattern="HELLO_ED209", memory="ED209_MEMORY_ONCE"):
    return {
        "id": rule_id,
        "surface": "reply",
        "class": "context",
        "action": "inject",
        "pattern": pattern,
        "reason": "inject context for '{match}'",
        "origin": "test",
        "memory": [memory],
    }


# ---------------------------------------------------------------------------
# Contract tests (no Hermes needed)
# ---------------------------------------------------------------------------


def test_register_registers_supported_hooks_and_makes_no_provider_call(monkeypatch):
    mod = _fresh_plugin()
    # Fail fast if any network / provider path is touched during register().
    import socket

    def _deny(*_a, **_k):
        raise AssertionError("register() must not make any provider/network call")

    monkeypatch.setattr(socket, "create_connection", _deny)
    monkeypatch.setattr(socket.socket, "connect", _deny)

    ctx = _register(mod)

    # Under the standalone venv (no hermes_cli) every declared hook is treated as
    # supported; under a real runtime the set is exactly VALID_HOOKS ∩ declared.
    declared = {"pre_tool_call", "post_tool_call", "pre_final_response", "pre_llm_call"}
    status = mod.registration_status()
    assert set(ctx.hooks) == set(status["supported"])
    assert set(status["supported"]) | set(status["unsupported"]) == declared
    assert not (set(ctx.hooks) & set(status["unsupported"]))
    # register() returns the status dict and only touched register_hook on the ctx.
    assert ctx.hooks["pre_tool_call"][0].__name__ == "_pre_tool_call"


def test_register_reports_unsupported_hook_without_inert_registration():
    mod = _fresh_plugin()
    # Simulate a runtime that LACKS pre_final_response (the deployed runtime):
    # the plugin must NOT register it (no silent inert registration) and must
    # REPORT it via registration_status().
    ctx = _register(
        mod, supported_hooks={"pre_tool_call", "post_tool_call", "pre_llm_call"}
    )
    assert set(ctx.hooks) == {"pre_tool_call", "post_tool_call", "pre_llm_call"}
    assert "pre_final_response" not in ctx.hooks  # never inert
    status = mod.registration_status()
    assert set(status["supported"]) == {"pre_tool_call", "post_tool_call", "pre_llm_call"}
    assert status["unsupported"] == ("pre_final_response",)


def test_home_resolved_per_callback(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home_a = tmp_path / "a"
    home_b = tmp_path / "b"
    _write_rules(home_a, [_deny_rule("rule-a")])
    _write_rules(home_b, [_deny_rule("rule-b")])

    ctx = _register(mod)

    monkeypatch.setenv("HERMES_HOME", str(home_a))
    res_a = _invoke(
        ctx, "pre_tool_call", tool_name="Bash", args={"command": "SECRET_DENY_TOKEN"},
        session_id="sess", turn_id="t", task_id="task", tool_call_id="c1",
    )
    assert res_a == {"action": "block", "message": "denied 'SECRET_DENY_TOKEN'"}

    monkeypatch.setenv("HERMES_HOME", str(home_b))
    res_b = _invoke(
        ctx, "pre_tool_call", tool_name="Bash", args={"command": "SECRET_DENY_TOKEN"},
        session_id="sess", turn_id="t", task_id="task", tool_call_id="c2",
    )
    assert res_b == {"action": "block", "message": "denied 'SECRET_DENY_TOKEN'"}

    from operator_guards.ed209.ledger import HitLedger

    assert [r["rule_id"] for r in HitLedger(str(home_a / "ed209" / "hits.db")).query_by_outcome("deny")] == ["rule-a"]
    assert [r["rule_id"] for r in HitLedger(str(home_b / "ed209" / "hits.db")).query_by_outcome("deny")] == ["rule-b"]


def test_deny_maps_to_block_directive_and_records_deny_hit(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"
    _write_rules(home, [_deny_rule()])
    monkeypatch.setenv("HERMES_HOME", str(home))
    ctx = _register(mod)

    res = _invoke(
        ctx, "pre_tool_call", tool_name="Bash", args={"command": "rm SECRET_DENY_TOKEN"},
        session_id="sess", turn_id="t", task_id="task", tool_call_id="c1",
    )

    assert res == {"action": "block", "message": "denied 'SECRET_DENY_TOKEN'"}

    from operator_guards.ed209.ledger import HitLedger

    ledger = HitLedger(str(home / "ed209" / "hits.db"))
    rows = ledger.query_by_outcome("deny")
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "deny-sentinel"
    assert rows[0]["session_id"] == "sess"


def test_deny_is_synchronous_and_does_not_invoke_reviewer(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"
    _write_rules(home, [_deny_rule()])
    monkeypatch.setenv("HERMES_HOME", str(home))

    calls = []
    mod.configure_reviewer(
        lambda payload: calls.append(payload) or json.dumps(
            {"verdict": "allow", "counted_fact": "ok", "correction": ""}
        ),
        family="reviewer-family",
        model="reviewer-model",
        timeout_s=1.0,
    )

    ctx = _register(mod)
    res = _invoke(
        ctx, "pre_tool_call", tool_name="Bash", args={"command": "SECRET_DENY_TOKEN"},
        session_id="sess", turn_id="t", task_id="task", tool_call_id="c1",
    )

    assert res == {"action": "block", "message": "denied 'SECRET_DENY_TOKEN'"}
    assert calls == []  # deterministic deny: reviewer never consulted


def test_escalate_invokes_reviewer_only_after_match(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"
    _write_rules(home, [_escalate_rule()])
    monkeypatch.setenv("HERMES_HOME", str(home))

    calls = []
    mod.configure_reviewer(
        lambda payload: calls.append(payload) or json.dumps(
            {"verdict": "allow", "counted_fact": "fine", "correction": ""}
        ),
        family="reviewer-family",
        model="reviewer-model",
        timeout_s=1.0,
    )
    ctx = _register(mod)

    # Non-matching payload: reviewer must NOT be called.
    _invoke(
        ctx, "pre_tool_call", tool_name="Bash", args={"command": "echo safe"},
        session_id="sess", turn_id="t", task_id="task", tool_call_id="c1",
    )
    assert calls == []

    # Matching escalate payload: reviewer called exactly once.
    res = _invoke(
        ctx, "pre_tool_call", tool_name="Bash", args={"command": "ESCALATE_ME"},
        session_id="sess", turn_id="t", task_id="task", tool_call_id="c2",
    )
    assert res is None  # reviewer allowed -> fail-open, tool proceeds
    assert len(calls) == 1


def test_engine_deny_precedence_over_reviewer(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"
    # Both a deny and an escalate rule match the same payload.
    _write_rules(home, [_escalate_rule(pattern="SECRET_DENY_TOKEN"), _deny_rule()])
    monkeypatch.setenv("HERMES_HOME", str(home))

    calls = []
    mod.configure_reviewer(
        lambda payload: calls.append(payload) or json.dumps(
            {"verdict": "block", "counted_fact": "block", "correction": "do otherwise"}
        ),
        family="reviewer-family",
        model="reviewer-model",
        timeout_s=1.0,
    )
    ctx = _register(mod)

    res = _invoke(
        ctx, "pre_tool_call", tool_name="Bash", args={"command": "SECRET_DENY_TOKEN"},
        session_id="sess", turn_id="t", task_id="task", tool_call_id="c1",
    )

    # Deterministic deny wins over the reviewer verdict; reviewer never consulted.
    assert res == {"action": "block", "message": "denied 'SECRET_DENY_TOKEN'"}
    assert calls == []


def test_context_attachment_is_non_denying_and_once_per_session(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"
    _write_rules(home, [_inject_rule()])
    monkeypatch.setenv("HERMES_HOME", str(home))
    ctx = _register(mod)

    first = _invoke(
        ctx, "pre_llm_call", session_id="sess", turn_id="t1", user_message="HELLO_ED209 please",
    )
    # Non-denying: it returns context (never a block/continue directive).
    assert first == {"context": "ED209_MEMORY_ONCE"}

    second = _invoke(
        ctx, "pre_llm_call", session_id="sess", turn_id="t2", user_message="HELLO_ED209 again",
    )
    # Once per session: already injected, so nothing more reaches the model.
    assert second is None


def test_reply_phrase_block_directive_without_edits(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"
    _write_rules(
        home,
        [
            {
                "id": "reply-phrase",
                "surface": "reply",
                "class": "offload",
                "action": "block",
                "pattern": r"\bI can do that if you want\b",
                "reason": "policy-blocked '{match}'",
                "origin": "test",
            }
        ],
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    # This contract test exercises the HANDLER logic (not registration), so it
    # declares the full hook set explicitly — independent of the ambient runtime.
    ctx = _register(
        mod,
        supported_hooks={"pre_tool_call", "post_tool_call", "pre_final_response", "pre_llm_call"},
    )

    # tool_count=0 -> a turn with no tool work and no file edits.
    res = _invoke(
        ctx, "pre_final_response", session_id="sess", turn_id="t", final_response="I can do that if you want.",
        tool_count=0,
    )
    assert res == {"action": "continue", "message": "policy-blocked 'I can do that if you want'"}


# ---------------------------------------------------------------------------
# Hot-path containment: the plugin must never raise into Hermes
# ---------------------------------------------------------------------------


def test_hot_path_evaluate_raise_fails_open(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"
    _write_rules(home, [_deny_rule()])
    monkeypatch.setenv("HERMES_HOME", str(home))
    ctx = _register(mod)

    def boom(*_a, **_k):
        raise RuntimeError("engine exploded")

    monkeypatch.setattr(mod, "evaluate", boom)

    # No exception escapes; fail-open (no directive) so the tool proceeds.
    res = _invoke(
        ctx, "pre_tool_call", tool_name="Bash", args={"command": "SECRET_DENY_TOKEN"},
        session_id="sess", turn_id="t", task_id="task", tool_call_id="c1",
    )
    assert res is None


def test_hot_path_os_getcwd_raise_fails_open(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"
    _write_rules(home, [_deny_rule()])
    monkeypatch.setenv("HERMES_HOME", str(home))
    ctx = _register(mod)

    def boom():
        raise OSError("cwd gone")

    monkeypatch.setattr(os, "getcwd", boom)

    res = _invoke(
        ctx, "pre_tool_call", tool_name="Bash", args={"command": "SECRET_DENY_TOKEN"},
        session_id="sess", turn_id="t", task_id="task", tool_call_id="c1",
    )
    assert res is None


# ---------------------------------------------------------------------------
# Reviewer budget must honor the rules doc's max_reviewer_calls_per_session
# ---------------------------------------------------------------------------


def test_reviewer_budget_honors_rules_doc_limit(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"
    _write_rules(home, [_escalate_rule()], limits={"max_reviewer_calls_per_session": 1})
    monkeypatch.setenv("HERMES_HOME", str(home))

    calls = []
    mod.configure_reviewer(
        lambda payload: calls.append(payload) or json.dumps(
            {"verdict": "allow", "counted_fact": "fine", "correction": ""}
        ),
        family="reviewer-family",
        model="reviewer-model",
        timeout_s=1.0,
    )
    ctx = _register(mod)

    # First escalate consumes the single configured reviewer slot.
    r1 = _invoke(
        ctx, "pre_tool_call", tool_name="Bash", args={"command": "ESCALATE_ME"},
        session_id="sess", turn_id="t1", task_id="task", tool_call_id="c1",
    )
    assert r1 is None
    assert len(calls) == 1

    # A second escalate is budget-capped: reviewer never invoked, fail-open.
    r2 = _invoke(
        ctx, "pre_tool_call", tool_name="Bash", args={"command": "ESCALATE_ME"},
        session_id="sess", turn_id="t2", task_id="task", tool_call_id="c2",
    )
    assert r2 is None
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# Inject over-marking: only the rule whose context is actually attached is
# marked injected (the loser's memory must not be dropped-yet-permanently-marked)
# ---------------------------------------------------------------------------


def test_inject_marks_only_attached_rule(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"
    _write_rules(
        home,
        [
            _inject_rule(rule_id="inject-a", memory="MEM_A"),
            _inject_rule(rule_id="inject-b", memory="MEM_B"),
        ],
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    ctx = _register(mod)

    first = _invoke(
        ctx, "pre_llm_call", session_id="sess", turn_id="t1",
        user_message="HELLO_ED209 please",
    )
    # First rule in order wins and its context attaches.
    assert first == {"context": "MEM_A"}

    from operator_guards.ed209.state import SessionStateStore

    injected = SessionStateStore(str(home / "ed209" / "state")).load("sess").injected
    assert "inject-a" in injected
    assert "inject-b" not in injected


# ---------------------------------------------------------------------------
# Deterministic-deny message redaction (mirror the reviewer path's sanitization)
# ---------------------------------------------------------------------------


def test_deterministic_deny_redacts_secret_in_counted_fact(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"
    _write_rules(home, [_deny_rule(pattern=r"api_key=\S+")])
    monkeypatch.setenv("HERMES_HOME", str(home))
    ctx = _register(mod)

    res = _invoke(
        ctx, "pre_tool_call", tool_name="Bash",
        args={"command": "run with api_key=supersecret123"},
        session_id="sess", turn_id="t", task_id="task", tool_call_id="c1",
    )

    assert res["action"] == "block"
    assert "supersecret123" not in res["message"]
    assert "[REDACTED]" in res["message"]


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_missing_rules_file_fail_open(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"  # no ed209/ dir at all
    monkeypatch.setenv("HERMES_HOME", str(home))
    ctx = _register(mod)

    res = _invoke(
        ctx, "pre_tool_call", tool_name="Bash", args={"command": "SECRET_DENY_TOKEN"},
        session_id="sess", turn_id="t", task_id="task", tool_call_id="c1",
    )
    assert res is None  # no rules -> fail-open, no raise


def test_missing_rules_logs_loud_degraded_warning(monkeypatch, tmp_path, caplog):
    import logging

    mod = _fresh_plugin()
    home = tmp_path / "home"  # no ed209/ dir at all
    monkeypatch.setenv("HERMES_HOME", str(home))
    ctx = _register(mod)

    with caplog.at_level(logging.WARNING, logger="ed209"):
        r1 = _invoke(
            ctx, "pre_tool_call", tool_name="Bash", args={"command": "SECRET_DENY_TOKEN"},
            session_id="sess", turn_id="t", task_id="task", tool_call_id="c1",
        )
        r2 = _invoke(
            ctx, "pre_tool_call", tool_name="Bash", args={"command": "SECRET_DENY_TOKEN"},
            session_id="sess", turn_id="t2", task_id="task", tool_call_id="c2",
        )

    assert r1 is None and r2 is None  # still fail-open
    warns = [r for r in caplog.records if r.levelno == logging.WARNING]
    missing = [
        r for r in warns
        if "INERT" in r.getMessage() and "rules document" in r.getMessage()
    ]
    # Loud (a real warning) and deduplicated (one per path, not one per call).
    assert len(missing) == 1, f"expected one deduplicated missing-rules warning, got {len(missing)}"
    assert str(home / "ed209" / "rules.json") in missing[0].getMessage()


def test_corrupt_rules_file_fail_open(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"
    (home / "ed209").mkdir(parents=True)
    (home / "ed209" / "rules.json").write_text("{ not valid json")
    monkeypatch.setenv("HERMES_HOME", str(home))
    ctx = _register(mod)

    res = _invoke(
        ctx, "pre_tool_call", tool_name="Bash", args={"command": "SECRET_DENY_TOKEN"},
        session_id="sess", turn_id="t", task_id="task", tool_call_id="c1",
    )
    assert res is None  # corrupt rules -> fail-open, no raise


def test_ledger_write_failure_deny_still_blocks(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"
    _write_rules(home, [_deny_rule()])
    monkeypatch.setenv("HERMES_HOME", str(home))
    ctx = _register(mod)

    def boom(*_a, **_k):
        raise RuntimeError("ledger disk gone")

    monkeypatch.setattr(mod, "_record", boom)

    # A determined deny still blocks even though recording the hit failed.
    res = _invoke(
        ctx, "pre_tool_call", tool_name="Bash", args={"command": "SECRET_DENY_TOKEN"},
        session_id="sess", turn_id="t", task_id="task", tool_call_id="c1",
    )
    assert res == {"action": "block", "message": "denied 'SECRET_DENY_TOKEN'"}


def test_empty_counted_fact_no_exception(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"
    _write_rules(home, [_deny_rule(rule_id="empty-fact", pattern="SECRET_DENY_TOKEN")])
    # Force an empty rendered fact via an empty reason template.
    rules_path = home / "ed209" / "rules.json"
    doc = json.loads(rules_path.read_text())
    doc["rules"][0]["reason"] = ""
    rules_path.write_text(json.dumps(doc))

    monkeypatch.setenv("HERMES_HOME", str(home))
    ctx = _register(mod)

    res = _invoke(
        ctx, "pre_tool_call", tool_name="Bash", args={"command": "SECRET_DENY_TOKEN"},
        session_id="sess", turn_id="t", task_id="task", tool_call_id="c1",
    )
    assert res == {"action": "block", "message": ""}


def test_concurrent_tool_calls_deny_correct(monkeypatch, tmp_path):
    import threading as _th

    mod = _fresh_plugin()
    home = tmp_path / "home"
    _write_rules(home, [_deny_rule()])
    monkeypatch.setenv("HERMES_HOME", str(home))
    ctx = _register(mod)

    results = []
    errors = []

    def worker(i):
        try:
            r = _invoke(
                ctx, "pre_tool_call", tool_name="Bash",
                args={"command": "SECRET_DENY_TOKEN"},
                session_id="sess", turn_id=f"t{i}", task_id="task", tool_call_id=f"c{i}",
            )
            results.append(r)
        except Exception as exc:  # noqa: BLE001 — capture any concurrent crash
            errors.append(exc)

    threads = [_th.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert results == [
        {"action": "block", "message": "denied 'SECRET_DENY_TOKEN'"} for _ in range(16)
    ]


# ---------------------------------------------------------------------------
# Real-dispatch tests (skip unless Hermes is importable)
# ---------------------------------------------------------------------------


@requires_hermes
def _real_fixture(tmp_path, monkeypatch, rules_doc):
    """Load the real plugin through Hermes against a temp home; return (home, manager)."""
    import hermes_cli.plugins as plugins_mod

    home = tmp_path / "hermes-home"
    (home / "ed209").mkdir(parents=True)
    (home / "ed209" / "rules.json").write_text(json.dumps(rules_doc))

    dst = home / "plugins" / "ed209"
    shutil.copytree(
        str(PLUGIN_DIR), str(dst), ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
    )
    (home / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - ed209\n  isolation: in_process\n"
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    empty_bundled = tmp_path / "bundled"
    empty_bundled.mkdir()
    monkeypatch.setattr(plugins_mod, "get_bundled_plugins_dir", lambda: empty_bundled)
    plugins_mod._reset_plugin_managers_for_tests()
    manager = plugins_mod.get_plugin_manager()
    manager.discover_and_load()
    assert manager._plugins.get("ed209") is not None
    assert manager._plugins["ed209"].error is None
    return home, manager


@requires_hermes
def _register_sentinel(calls):
    from tools.registry import registry

    def handler(args, **kw):
        calls.append(args)
        return json.dumps({"sentinel": True})

    registry.register(
        name="ed209_sentinel",
        toolset="test",
        schema={
            "name": "ed209_sentinel",
            "description": "safe sentinel tool for ED-209 plugin tests",
            "parameters": {"type": "object", "properties": {}},
        },
        handler=handler,
    )


@requires_hermes
def test_denied_sentinel_never_executes(tmp_path, monkeypatch):
    from model_tools import handle_function_call
    from operator_guards.ed209.ledger import HitLedger

    _real_fixture(
        tmp_path, monkeypatch,
        {"version": 1, "rules": [_deny_rule()]},
    )
    calls = []
    _register_sentinel(calls)

    result = handle_function_call(
        "ed209_sentinel", {"marker": "SECRET_DENY_TOKEN"},
        session_id="sess", turn_id="t1", tool_call_id="c1",
    )

    # The tool body never ran.
    assert calls == []
    # The block message (counted fact) reached the model as the tool result.
    assert "denied" in result

    home = tmp_path / "hermes-home"
    rows = HitLedger(str(home / "ed209" / "hits.db")).query_by_outcome("deny")
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "deny-sentinel"


@requires_hermes
def test_allowed_sentinel_executes_once(tmp_path, monkeypatch):
    from model_tools import handle_function_call

    _real_fixture(
        tmp_path, monkeypatch,
        {"version": 1, "rules": [_deny_rule()]},
    )
    calls = []
    _register_sentinel(calls)

    handle_function_call(
        "ed209_sentinel", {"marker": "SAFE_MARKER"},
        session_id="sess", turn_id="t1", tool_call_id="c1",
    )

    assert calls == [{"marker": "SAFE_MARKER"}]  # exactly one invocation


@requires_hermes
def test_reply_phrase_rejection_on_no_edit_turn(tmp_path, monkeypatch):
    from hermes_cli.plugins_directives import get_pre_final_response_continue_message

    _real_fixture(
        tmp_path, monkeypatch,
        {
            "version": 1,
            "rules": [
                {
                    "id": "reply-phrase",
                    "surface": "reply",
                    "class": "offload",
                    "action": "block",
                    "pattern": r"\bI can do that if you want\b",
                    "reason": "policy-blocked '{match}'",
                    "origin": "test",
                }
            ],
        },
    )

    # tool_count=0 -> no tool work / no file edits this turn.
    msg = get_pre_final_response_continue_message(
        session_id="sess", final_response="I can do that if you want.", tool_count=0,
    )
    assert msg is not None
    assert "policy-blocked" in msg


@requires_hermes
def test_context_attachment_reaches_current_turn_once(tmp_path, monkeypatch):
    from hermes_cli.lifecycle import invoke_hook

    _real_fixture(
        tmp_path, monkeypatch,
        {"version": 1, "rules": [_inject_rule()]},
    )

    results = invoke_hook(
        "pre_llm_call", session_id="sess", turn_id="t1", user_message="HELLO_ED209 please",
    )
    contexts = [r for r in results if isinstance(r, dict) and "context" in r]
    assert len(contexts) == 1
    assert contexts[0]["context"] == "ED209_MEMORY_ONCE"
    # Never a block/continue directive from the context hook.
    assert not any(isinstance(r, dict) and r.get("action") in ("block", "continue") for r in results)

    # Once per session: a second turn in the same session injects nothing.
    results2 = invoke_hook(
        "pre_llm_call", session_id="sess", turn_id="t2", user_message="HELLO_ED209 again",
    )
    contexts2 = [r for r in results2 if isinstance(r, dict) and "context" in r]
    assert contexts2 == []
