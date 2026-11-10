"""ED-209 execution-path coverage (plan Task 8 / §6 "Nested/child gates").

Prove, through *real Hermes dispatch* (the runner env), that the ED-209 veto
holds across every tool-execution path, asserting for each mutating path that
(a) the protected sentinel did NOT execute and (b) a ledger hit with
``outcome=deny`` was recorded against the real SQLite DB.

Covered paths
-------------
1. ordinary tool call            — ``model_tools.handle_function_call``
2. deferred ``tool_call``        — bridge unwrap to the underlying tool identity
3. inline agent-level tool       — agent-loop ``_pre_tool_block`` seam (the path
                                   ``delegate_task`` / ``todo_list`` / ``memory``
                                   take, which bypass ``handle_function_call``)
4. nested execute_code RPC       — ``code_execution_rpc._handle_rpc_request``
                                   with the default ``handle_function_call`` dispatch
5. persistent execute_code kernel— ``code_kernel.CellAuthority.dispatch``
6. plugin/MCP tool               — ``mcp__…``-named tool through real dispatch
7. parallel tool calls           — N concurrent real dispatches, N deny hits, none run
8. two isolated homes A→B→A       — separate DB/rules/state per home, real imports
Plus: block>approve precedence is registration-order independent, and the
``verification_proof`` schema requirement is preserved.

Honest limits (documented, NOT claimed as coverage)
---------------------------------------------------
* **Lexical-only, not an OS sandbox.**  ED-209 scans the *outer* tool payload —
  the JSON-encoded argument string — and regex-matches it.  Raw Python inside
  ``execute_code``'s ``code`` argument, or a subprocess it spawns, is visible
  ONLY as the literal code/payload text.  A deny rule matches the code string
  when it lexically contains the pattern; it cannot see what a child process,
  ``os.system``, an imported module, or a dynamically-constructed string does at
  runtime.  This is procedural defence-in-depth for a same-UID agent, NOT a
  security sandbox.  Do not claim coverage the lexical scan cannot deliver.
* **Nested RPC / persistent-kernel identity.**  ``_default_dispatch`` and
  ``CellAuthority._invoke`` thread only ``task_id`` into ``handle_function_call``;
  ``session_id``/``turn_id`` arrive empty, so the deny *still fires* (it matches
  on payload) but those ledger rows record ``session_id=""``/``turn_id=""``.
  The veto is unaffected; per-session identity for RPC/kernel-originated hits is
  a known gap, asserted below rather than silently papered over.
* **Delegated child / grandchild end-to-end.**  Hermes children are constructed
  in-process (``run_agent.AIAgent``) and share the process-global ``PluginManager``
  keyed on ``HERMES_HOME``, so the plugin is registered for children by
  construction — asserted structurally here.  A full end-to-end child that makes
  a *live* tool call needs a real model turn and is not deterministic, so it is
  reported as a coverage limit, not faked.
* **Parallel connector batch.**  ``tool_call``-with-``calls`` batching only
  dispatches *remote connector* tools (local entries are refused with a batch
  error); exercising it needs a real remote connector.  Parallel denial is proven
  instead via N concurrent real dispatches through the same choke point.

Run with the documented runner: ``G/scripts/run_plugin_tests.sh`` (or
``PYTHONPATH=H:G/src H/venv/bin/python -m pytest G/tests/test_execution_paths.py``).
"""

from __future__ import annotations

import json
import os
import shutil
import threading
import types
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "plugins" / "ed209"

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

# Protected sentinel marker: a deny rule matches this token in the tool payload.
DENY_TOKEN = "SECRET_DENY_TOKEN"
SAFE_TOKEN = "SAFE_MARKER"


def _deny_rule(rule_id="deny-sentinel", pattern=DENY_TOKEN):
    return {
        "id": rule_id,
        "surface": "tool",
        "class": "known-bad",
        "action": "deny",
        "pattern": pattern,
        "reason": "denied '{match}'",
        "origin": "test",
    }


# ---------------------------------------------------------------------------
# Fixtures: load the real plugin through Hermes against a temp home.
# ---------------------------------------------------------------------------


@requires_hermes
def _load_manager(tmp_path, monkeypatch, rules_doc, *, home_name="hermes-home"):
    import hermes_cli.plugins as plugins_mod

    home = tmp_path / home_name
    (home / "ed209").mkdir(parents=True)
    (home / "ed209" / "rules.json").write_text(json.dumps(rules_doc))

    dst = home / "plugins" / "ed209"
    shutil.copytree(str(PLUGIN_DIR), str(dst), ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

    (home / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - ed209\n  isolation: in_process\n"
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    empty_bundled = tmp_path / ("bundled-" + home_name)
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
def _register_mcp_named_sentinel(calls):
    """A sentinel whose name follows the MCP/plugin tool convention.

    ``mcp__testsrv__run_command`` resolves to the ``shell`` capability via
    ``resolve_tool``, so a capability-bound deny rule would cover it; here the
    deny rule matches on payload, and the point is that the MCP-shaped name
    still travels the same pre_tool_call seam.
    """
    from tools.registry import registry

    def handler(args, **kw):
        calls.append(args)
        return json.dumps({"sentinel": True})

    registry.register(
        name="mcp__testsrv__run_command",
        toolset="mcp-testsrv",
        schema={
            "name": "mcp__testsrv__run_command",
            "description": "MCP-shaped sentinel tool",
            "parameters": {"type": "object", "properties": {}},
        },
        handler=handler,
    )


def _deny_rows(home):
    from operator_guards.ed209.ledger import HitLedger

    return HitLedger(str(home / "ed209" / "hits.db")).query_by_outcome("deny")


# ---------------------------------------------------------------------------
# 1. Ordinary tool call
# ---------------------------------------------------------------------------


@requires_hermes
def test_ordinary_tool_call_denied(tmp_path, monkeypatch):
    from model_tools import handle_function_call

    home, _ = _load_manager(tmp_path, monkeypatch, {"version": 1, "rules": [_deny_rule()]})
    calls = []
    _register_sentinel(calls)

    result = handle_function_call(
        "ed209_sentinel", {"marker": DENY_TOKEN},
        session_id="sess", turn_id="t1", tool_call_id="c1",
    )

    assert calls == []                       # (a) sentinel never executed
    assert "denied" in result
    rows = _deny_rows(home)
    assert len(rows) == 1                    # (b) ledger hit present
    assert rows[0]["rule_id"] == "deny-sentinel"
    assert rows[0]["session_id"] == "sess"   # identity carried on the ordinary path
    assert rows[0]["turn_id"] == "t1"


# ---------------------------------------------------------------------------
# 2. Deferred tool_call — must unwrap to the underlying tool identity.
# ---------------------------------------------------------------------------


@requires_hermes
def test_deferred_tool_call_unwraps_to_underlying_identity(tmp_path, monkeypatch):
    from model_tools import _dispatch_bridge_tool, handle_function_call

    home, _ = _load_manager(tmp_path, monkeypatch, {"version": 1, "rules": [_deny_rule()]})
    calls = []
    _register_sentinel(calls)

    # Direct proof of the unwrap: the bridge resolves the deferred wrapper to
    # the UNDERLYING tool identity before any downstream hook fires.
    bridge_result, underlying = _dispatch_bridge_tool(
        "tool_call",
        {"name": "ed209_sentinel", "arguments": {"marker": DENY_TOKEN}},
        None,
        None,
    )
    assert bridge_result is None
    assert underlying == ("ed209_sentinel", {"marker": DENY_TOKEN})

    result = handle_function_call(
        "tool_call",
        {"name": "ed209_sentinel", "arguments": {"marker": DENY_TOKEN}},
        session_id="sess", turn_id="t2", tool_call_id="c2",
    )

    # The veto must fire on the UNDERLYING identity, not the "tool_call" wrapper.
    assert calls == []
    assert "denied" in result
    rows = _deny_rows(home)
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "deny-sentinel"


# ---------------------------------------------------------------------------
# 3. Inline agent-level tool (the delegate_task / todo_list / memory seam).
# ---------------------------------------------------------------------------


@requires_hermes
def test_inline_agent_level_tool_denied(tmp_path, monkeypatch):
    from agent.tool_executor import _ToolCallRef, _pre_tool_block

    home, _ = _load_manager(tmp_path, monkeypatch, {"version": 1, "rules": [_deny_rule()]})

    agent = types.SimpleNamespace(
        session_id="sess", _current_turn_id="t3", _current_api_request_id="req3",
    )
    # delegate_task is an inline/agent-loop tool: it bypasses handle_function_call
    # but still passes through the agent loop's pre_tool_call seam.
    ref = _ToolCallRef("delegate_task", {"goal": DENY_TOKEN}, "task3", "c3", [])

    block_msg, final_args = _pre_tool_block(agent, ref)

    assert block_msg is not None
    assert "denied" in block_msg
    rows = _deny_rows(home)
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "deny-sentinel"
    assert rows[0]["session_id"] == "sess"   # agent-loop seam carries identity


# ---------------------------------------------------------------------------
# 4. Nested execute_code RPC path.
# ---------------------------------------------------------------------------


@requires_hermes
def test_nested_execute_code_rpc_denied(tmp_path, monkeypatch):
    from tools.code_execution_rpc import _default_dispatch, _handle_rpc_request

    home, _ = _load_manager(tmp_path, monkeypatch, {"version": 1, "rules": [_deny_rule()]})
    calls = []
    _register_sentinel(calls)

    result = _handle_rpc_request(
        {"tool": "ed209_sentinel", "args": {"marker": DENY_TOKEN}},
        allowed_tools=frozenset({"ed209_sentinel"}),
        tool_call_counter=[0],
        max_tool_calls=10,
        dispatch=_default_dispatch("task-rpc"),
        tool_call_log=[],
        call_start=0.0,
        where="sandbox",
    )

    assert calls == []                       # sentinel never executed
    assert "denied" in result
    rows = _deny_rows(home)
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "deny-sentinel"
    # Identity gap: only task_id is threaded; session/turn arrive empty.
    assert rows[0]["task_id"] == "task-rpc"
    assert rows[0]["session_id"] == ""
    assert rows[0]["turn_id"] == ""


# ---------------------------------------------------------------------------
# 5. Persistent execute_code kernel path.
# ---------------------------------------------------------------------------


@requires_hermes
def test_persistent_kernel_denied(tmp_path, monkeypatch):
    from tools.code_kernel import CellAuthority

    home, _ = _load_manager(tmp_path, monkeypatch, {"version": 1, "rules": [_deny_rule()]})
    calls = []
    _register_sentinel(calls)

    authority = CellAuthority("task-kernel")
    result = authority.dispatch("ed209_sentinel", {"marker": DENY_TOKEN})
    authority.retire()

    assert calls == []
    assert "denied" in result
    rows = _deny_rows(home)
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "deny-sentinel"
    assert rows[0]["task_id"] == "task-kernel"
    assert rows[0]["session_id"] == ""       # same identity gap as the RPC path


# ---------------------------------------------------------------------------
# 6. Plugin / MCP tool path.
# ---------------------------------------------------------------------------


@requires_hermes
def test_plugin_mcp_tool_denied(tmp_path, monkeypatch):
    from model_tools import handle_function_call
    from operator_guards.ed209.capabilities import resolve_tool

    home, _ = _load_manager(tmp_path, monkeypatch, {"version": 1, "rules": [_deny_rule()]})
    calls = []
    _register_mcp_named_sentinel(calls)

    # The MCP-shaped name resolves to a real capability (not "unbound").
    real, caps = resolve_tool("mcp__testsrv__run_command", {"command": DENY_TOKEN})
    assert real == "mcp__testsrv__run_command"
    assert "shell" in caps

    result = handle_function_call(
        "mcp__testsrv__run_command", {"command": DENY_TOKEN},
        session_id="sess", turn_id="t6", tool_call_id="c6",
    )

    assert calls == []
    assert "denied" in result
    rows = _deny_rows(home)
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "deny-sentinel"


# ---------------------------------------------------------------------------
# 7. Parallel tool calls — multiple denials, all recorded, none execute.
# ---------------------------------------------------------------------------


@requires_hermes
def test_parallel_tool_calls_all_denied(tmp_path, monkeypatch):
    from model_tools import handle_function_call

    home, _ = _load_manager(tmp_path, monkeypatch, {"version": 1, "rules": [_deny_rule()]})
    calls = []
    _register_sentinel(calls)

    n = 12
    results = []
    errors = []

    def worker(i):
        try:
            r = handle_function_call(
                "ed209_sentinel", {"marker": DENY_TOKEN},
                session_id="sess", turn_id=f"t{i}", tool_call_id=f"c{i}",
            )
            results.append(r)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert calls == []                       # none of the N calls executed
    assert all("denied" in r for r in results)
    rows = _deny_rows(home)
    assert len(rows) == n                    # all N denials recorded


# ---------------------------------------------------------------------------
# 8. Two isolated homes A -> B -> A (real imports; no real profile touched).
# ---------------------------------------------------------------------------


@requires_hermes
def test_two_isolated_homes_a_b_a(tmp_path, monkeypatch):
    from model_tools import handle_function_call
    from operator_guards.ed209.ledger import HitLedger

    home_a = tmp_path / "home-a"
    home_b = tmp_path / "home-b"
    for home, rule_id in ((home_a, "rule-a"), (home_b, "rule-b")):
        (home / "ed209").mkdir(parents=True)
        (home / "ed209" / "rules.json").write_text(
            json.dumps({"version": 1, "rules": [_deny_rule(rule_id=rule_id)]})
        )
        dst = home / "plugins" / "ed209"
        shutil.copytree(str(PLUGIN_DIR), str(dst), ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (home / "config.yaml").write_text(
            "plugins:\n  enabled:\n    - ed209\n  isolation: in_process\n"
        )

    # Load the plugin manager once (home A is the ambient HERMES_HOME); the
    # plugin resolves HERMES_HOME per callback, so flipping the env re-targets
    # the rules + ledger without re-importing anything.
    import hermes_cli.plugins as plugins_mod

    monkeypatch.setenv("HERMES_HOME", str(home_a))
    empty_bundled = tmp_path / "bundled-ab"
    empty_bundled.mkdir()
    monkeypatch.setattr(plugins_mod, "get_bundled_plugins_dir", lambda: empty_bundled)
    plugins_mod._reset_plugin_managers_for_tests()
    plugins_mod.get_plugin_manager().discover_and_load()

    calls = []
    _register_sentinel(calls)

    def dispatch():
        return handle_function_call(
            "ed209_sentinel", {"marker": DENY_TOKEN},
            session_id="sess", turn_id="t", tool_call_id="c",
        )

    # A
    monkeypatch.setenv("HERMES_HOME", str(home_a))
    assert "denied" in dispatch()
    # B
    monkeypatch.setenv("HERMES_HOME", str(home_b))
    assert "denied" in dispatch()
    # A again
    monkeypatch.setenv("HERMES_HOME", str(home_a))
    assert "denied" in dispatch()

    assert calls == []  # sentinel never ran in any home

    ledger_a = HitLedger(str(home_a / "ed209" / "hits.db"))
    ledger_b = HitLedger(str(home_b / "ed209" / "hits.db"))

    a_rows = ledger_a.query_by_outcome("deny")
    b_rows = ledger_b.query_by_outcome("deny")
    assert [r["rule_id"] for r in a_rows] == ["rule-a", "rule-a"]  # 2 hits in A
    assert [r["rule_id"] for r in b_rows] == ["rule-b"]            # 1 hit in B

    # Separate DB files and no cross-contamination.
    assert (home_a / "ed209" / "hits.db").resolve() != (home_b / "ed209" / "hits.db").resolve()
    assert ledger_a.count() == 2
    assert ledger_b.count() == 1


# ---------------------------------------------------------------------------
# Nested + delegated denial (the required §6 test name).
# ---------------------------------------------------------------------------


@requires_hermes
def test_nested_and_delegated_denial(tmp_path, monkeypatch):
    """One test proving veto across RPC, kernel, deferred, and inline/delegated seams.

    The inline ``delegate_task`` seam is the exact dispatch a delegated child
    uses for agent-level tools; children share this process-global plugin manager
    (Hermes delegation constructs in-process ``AIAgent`` objects).
    """
    from model_tools import handle_function_call
    from agent.tool_executor import _ToolCallRef, _pre_tool_block
    from tools.code_execution_rpc import _default_dispatch, _handle_rpc_request
    from tools.code_kernel import CellAuthority

    home, _ = _load_manager(tmp_path, monkeypatch, {"version": 1, "rules": [_deny_rule()]})
    calls = []
    _register_sentinel(calls)

    # nested execute_code RPC
    r_rpc = _handle_rpc_request(
        {"tool": "ed209_sentinel", "args": {"marker": DENY_TOKEN}},
        allowed_tools=frozenset({"ed209_sentinel"}), tool_call_counter=[0],
        max_tool_calls=10, dispatch=_default_dispatch("task-rpc"),
        tool_call_log=[], call_start=0.0, where="sandbox",
    )
    assert "denied" in r_rpc

    # persistent kernel
    authority = CellAuthority("task-kernel")
    r_kernel = authority.dispatch("ed209_sentinel", {"marker": DENY_TOKEN})
    authority.retire()
    assert "denied" in r_kernel

    # deferred tool_call
    r_deferred = handle_function_call(
        "tool_call", {"name": "ed209_sentinel", "arguments": {"marker": DENY_TOKEN}},
        session_id="sess", turn_id="t", tool_call_id="cd",
    )
    assert "denied" in r_deferred

    # inline / delegated seam (delegate_task is an agent-level tool)
    agent = types.SimpleNamespace(
        session_id="sess", _current_turn_id="t", _current_api_request_id="req",
    )
    block_msg, _ = _pre_tool_block(
        agent, _ToolCallRef("delegate_task", {"goal": DENY_TOKEN}, "task-d", "cd2", [])
    )
    assert block_msg is not None and "denied" in block_msg

    # Sentinel never executed on any path; every path recorded a deny hit.
    assert calls == []
    rows = _deny_rows(home)
    assert len(rows) == 4
    assert {r["rule_id"] for r in rows} == {"deny-sentinel"}

    # Plugin registered for in-process children: the process-global manager that
    # children share has the hook loaded.
    from hermes_cli.lifecycle import has_hook
    assert has_hook("pre_tool_call")


# ---------------------------------------------------------------------------
# block > approve is registration-order independent.
# ---------------------------------------------------------------------------

_APPROVE_PLUGIN = '''\
import os


def register(ctx):
    def pre_tool_call(tool_name=None, args=None, **kw):
        if tool_name == "ed209_sentinel":
            _mark_fired()
            return {"action": "approve", "message": "needs human approval",
                    "rule_key": "ed209_sentinel"}
        return None
    ctx.register_hook("pre_tool_call", pre_tool_call)


def _mark_fired():
    home = os.environ.get("HERMES_HOME", "")
    if home:
        try:
            with open(os.path.join(home, "approve_probe.fired"), "w", encoding="utf-8") as fh:
                fh.write("fired")
        except OSError:
            pass
'''


# A directory plugin is only discovered when it ships a ``plugin.yaml`` manifest
# (``hermes_cli.plugins.scan_directory``); a bare ``__init__.py`` is never imported,
# so an approve hook with no manifest would silently never register — the exact
# false-confidence this test used to have.
_APPROVE_MANIFEST = '''\
name: approve_probe
version: 0.1.0
description: test probe returning an approve directive for ed209_sentinel
kind: standalone
provides_hooks:
  - pre_tool_call
'''


@requires_hermes
@pytest.mark.parametrize("order", [["ed209", "approve_probe"], ["approve_probe", "ed209"]])
def test_block_beats_approve_registration_order_independent(tmp_path, monkeypatch, order):
    from model_tools import handle_function_call

    home, _ = _load_manager(tmp_path, monkeypatch, {"version": 1, "rules": [_deny_rule()]})

    # Register a REAL approve-returning plugin (module + manifest) so discovery
    # actually loads it and its pre_tool_call hook actually registers and fires.
    probe_dir = home / "plugins" / "approve_probe"
    probe_dir.mkdir(parents=True)
    (probe_dir / "__init__.py").write_text(_APPROVE_PLUGIN)
    (probe_dir / "plugin.yaml").write_text(_APPROVE_MANIFEST)

    # Rewrite config.yaml with the requested registration order, reload fresh.
    import hermes_cli.plugins as plugins_mod

    (home / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - " + "\n    - ".join(order) + "\n  isolation: in_process\n"
    )
    plugins_mod._reset_plugin_managers_for_tests()
    manager = plugins_mod.get_plugin_manager()
    manager.discover_and_load()

    # The approve plugin must have actually loaded (not just been requested) —
    # the assertion that used to pass vacuously.
    assert manager._plugins.get("approve_probe") is not None
    assert manager._plugins["approve_probe"].error is None

    calls = []
    _register_sentinel(calls)

    result = handle_function_call(
        "ed209_sentinel", {"marker": DENY_TOKEN},
        session_id="sess", turn_id="t", tool_call_id="c",
    )

    # (a) protected sentinel did NOT execute
    assert calls == []
    # (b) a deny hit was recorded against the real DB
    rows = _deny_rows(home)
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "deny-sentinel"
    # (d) block wins in BOTH orders — the deterministic deny beats the approve.
    assert "denied" in result
    # (c) the approve hook DID fire (it writes a marker on every call), so this
    # test cannot pass vacuously with an approve plugin that never loaded.
    assert (home / "approve_probe.fired").exists()


# ---------------------------------------------------------------------------
# verification_proof schema requirement preserved.
# ---------------------------------------------------------------------------


@requires_hermes
def test_verification_proof_schema_requirement_intact(tmp_path, monkeypatch):
    from tools.code_execution_tool import EXECUTE_CODE_SCHEMA

    required = EXECUTE_CODE_SCHEMA.get("parameters", {}).get("required", [])
    assert "verification_proof" in required

    # Loading the ED-209 plugin must not strip the requirement.
    _load_manager(tmp_path, monkeypatch, {"version": 1, "rules": [_deny_rule()]})
    from tools.code_execution_tool import EXECUTE_CODE_SCHEMA as schema_after
    assert "verification_proof" in schema_after.get("parameters", {}).get("required", [])

    # End-to-end: a REAL dispatch that omits ``verification_proof`` is still
    # rejected by the execute_code handler itself (independent of the plugin —
    # the plugin only vetoes its own deny rules and must not change this).
    from model_tools import handle_function_call
    result = handle_function_call(
        "execute_code", {"code": "print('hi')"},
        session_id="sess", turn_id="t", tool_call_id="c",
    )
    assert "TOOL CALL REJECTED" in result
    assert "verification_proof" in result
