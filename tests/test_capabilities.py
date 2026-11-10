"""Capability binding + deterministic matching/classification (Task 2).

Covers the Task 2 contract: capability alias mapping, unknown-capability
coverage warnings, deferred-name unwrap, surface gating, deny-wins precedence,
enabled/exempt/tools/requires/cwd gating (incl. symlink + alternate-spelling
path normalization), inject/memory-first never deny/escalate when the memory
interface is missing, safe-payload-not-matched-by-unrelated-text, and
counted-fact substitution with bounded flattening.

All fixtures are synthetic; no production rule content is fabricated.
"""

import os
from dataclasses import FrozenInstanceError

import pytest

from operator_guards.ed209.capabilities import (
    SHELL,
    FILE_READ,
    FILE_WRITE,
    FILE_PATCH,
    EXECUTE_CODE,
    DELEGATE,
    MUTATING_CAPABILITIES,
    capabilities_for,
    is_deferred_wrapper,
    unwrap_tool_identity,
    resolve_tool,
    normalize_path,
)
from operator_guards.ed209.rules import Rule, compile_rules
from operator_guards.ed209.engine import (
    EvaluationContext,
    evaluate,
    ACTION_DENY,
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_ESCALATE,
    ACTION_INJECT,
    ACTION_MEMORY_FIRST,
    COUNTED_FACT_MAX_CHARS,
)


def make_rule(
    id="r1",
    surface="tool",
    action="deny",
    pattern=r"\bsecret\b",
    reason="matched '{match}'",
    origin="test",
    rule_class="known-bad",
    **kw,
):
    return Rule(
        id=id,
        surface=surface,
        rule_class=rule_class,
        action=action,
        pattern=pattern,
        reason=reason,
        origin=origin,
        **kw,
    )


def tool_ctx(payload, tool="Bash", capabilities=None, cwd=None, available=frozenset(), **kw):
    if capabilities is None:
        capabilities = capabilities_for(tool)
    return EvaluationContext(
        profile_home="/home/u",
        client_id="client",
        session_id="sess",
        turn_id="turn",
        surface="tool",
        tool_name=tool,
        capabilities=capabilities,
        payload=payload,
        cwd=cwd,
        available=available,
        timestamp=0.0,
        **kw,
    )


def reply_ctx(text, available=frozenset(), **kw):
    return EvaluationContext(
        profile_home="/home/u",
        client_id="client",
        session_id="sess",
        turn_id="turn",
        surface="reply",
        candidate_text=text,
        available=available,
        timestamp=0.0,
        **kw,
    )


# --- capability binding -----------------------------------------------------

def test_shell_aliases():
    for name in ("Bash", "terminal", "mcp__serena__execute_shell_command"):
        assert SHELL in capabilities_for(name)


def test_file_capabilities():
    assert capabilities_for("write_file") == frozenset({FILE_WRITE})
    assert capabilities_for("patch") == frozenset({FILE_PATCH})
    assert capabilities_for("read_file") == frozenset({FILE_READ})


def test_execute_code_capability():
    assert capabilities_for("execute_code") == frozenset({EXECUTE_CODE})


def test_delegation_capability():
    assert DELEGATE in capabilities_for("delegate_task")


def test_mcp_file_aliases():
    assert FILE_WRITE in capabilities_for("mcp__serena__write_file")
    assert FILE_READ in capabilities_for("mcp__serena__read_file")
    assert FILE_PATCH in capabilities_for("mcp__serena__edit_file")


def test_unknown_tool_has_no_capabilities():
    assert capabilities_for("mystery_mutator") == frozenset()


def test_mutating_capability_set():
    assert SHELL in MUTATING_CAPABILITIES
    assert FILE_WRITE in MUTATING_CAPABILITIES
    assert FILE_PATCH in MUTATING_CAPABILITIES
    assert EXECUTE_CODE in MUTATING_CAPABILITIES
    assert DELEGATE in MUTATING_CAPABILITIES
    assert FILE_READ not in MUTATING_CAPABILITIES


def test_deferred_wrapper_detection():
    assert is_deferred_wrapper("tool_call")
    assert not is_deferred_wrapper("Bash")


def test_unwrap_deferred_tool_call():
    assert unwrap_tool_identity("tool_call", {"name": "Bash", "arguments": {"command": "ls"}}) == "Bash"


def test_unwrap_passthrough_for_plain_tool():
    assert unwrap_tool_identity("Bash", {"command": "ls"}) == "Bash"


def test_resolve_tool_returns_identity_and_capabilities():
    real, caps = resolve_tool("tool_call", {"name": "Bash", "arguments": {"command": "ls"}})
    assert real == "Bash"
    assert SHELL in caps


# --- path normalization (protected paths) ----------------------------------

def test_normalize_path_collapses_alternate_spellings(tmp_path):
    a = tmp_path / "a"
    a.mkdir()
    spelled = str(a / ".." / "a" / ".") + "/"
    assert normalize_path(spelled) == os.path.realpath(str(a))


def test_normalize_path_resolves_symlink(tmp_path):
    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unsupported here")
    assert normalize_path(str(link)) == os.path.realpath(str(target))


# --- surface gating --------------------------------------------------------

def test_surface_gating():
    tool_rule = make_rule(id="tool-r", surface="tool", pattern=r"\brm\b")
    reply_rule = make_rule(id="reply-r", surface="reply", pattern=r"\brm\b")
    compiled = compile_rules([tool_rule, reply_rule])

    d_tool = evaluate(compiled, tool_ctx("rm -rf /"))
    assert "tool-r" in d_tool.matched_rule_ids
    assert "reply-r" not in d_tool.matched_rule_ids

    d_reply = evaluate(compiled, reply_ctx("rm -rf /"))
    assert "reply-r" in d_reply.matched_rule_ids
    assert "tool-r" not in d_reply.matched_rule_ids


# --- deterministic deny wins ------------------------------------------------

def test_deny_wins_over_every_other_action():
    rules = [
        make_rule(id="inj", action="inject", pattern=r"\bsafe\b", memory=["m"]),
        make_rule(id="esc", action="escalate", pattern=r"\bsafe\b"),
        make_rule(id="deny", action="deny", pattern=r"\bsafe\b", reason="denied '{match}'"),
    ]
    compiled = compile_rules(rules)
    d = evaluate(compiled, tool_ctx("do the safe thing"))
    assert d.action == ACTION_DENY
    assert set(d.matched_rule_ids) == {"inj", "esc", "deny"}
    assert d.counted_fact == "denied 'safe'"


# --- inject / memory-first never deny/escalate on missing interface ---------

def test_inject_missing_memory_never_denies_or_escalates():
    rule = make_rule(id="inj", action="inject", pattern=r"\bfind\b", memory=["m1", "m2"])
    compiled = compile_rules([rule])
    d = evaluate(compiled, tool_ctx("find the file"))  # available defaults to empty
    assert d.action == ACTION_INJECT
    assert d.unavailable == ("memory",)
    assert d.context == ()
    assert d.action not in (ACTION_DENY, ACTION_BLOCK, ACTION_ESCALATE)


def test_memory_first_missing_memory_never_denies():
    rule = make_rule(id="mf", action="memory-first", pattern=r"\bsearch\b")
    compiled = compile_rules([rule])
    d = evaluate(compiled, tool_ctx("search for x"))
    assert d.action == ACTION_MEMORY_FIRST
    assert d.unavailable == ("memory",)
    assert d.action != ACTION_DENY


def test_inject_with_memory_produces_bounded_context():
    rule = make_rule(id="inj", action="inject", pattern=r"\bfind\b", memory=["mem-a", "mem-b"])
    compiled = compile_rules([rule])
    d = evaluate(compiled, tool_ctx("find it", available=frozenset({"memory"})))
    assert d.action == ACTION_INJECT
    assert d.unavailable == ()
    assert "mem-a" in d.context and "mem-b" in d.context


# --- safe payload is not matched by unrelated tool-output text --------------

def test_unrelated_output_text_does_not_match_tool_rule():
    rule = make_rule(id="deny-rm", pattern=r"rm -rf /etc")
    compiled = compile_rules([rule])
    ctx = EvaluationContext(
        profile_home="/home/u",
        client_id="c",
        session_id="s",
        turn_id="t",
        surface="tool",
        tool_name="Bash",
        capabilities=capabilities_for("Bash"),
        payload="ls -la",  # the safe tool arguments
        candidate_text="rm -rf /etc (tool output)",  # unrelated output text
    )
    d = evaluate(compiled, ctx)
    assert d.action == ACTION_ALLOW
    assert d.matched_rule_ids == ()


# --- enabled / tools / exempt / requires / cwd ------------------------------

def test_disabled_rule_never_matches():
    rule = make_rule(id="off", enabled=False, pattern=r"\brm\b")
    compiled = compile_rules([rule])
    d = evaluate(compiled, tool_ctx("rm -rf /"))
    assert d.action == ACTION_ALLOW
    assert d.matched_rule_ids == ()


def test_tools_narrow_by_capability():
    rule = make_rule(id="shell-deny", tools=["shell"], pattern=r"\bsecret\b")
    compiled = compile_rules([rule])
    assert evaluate(compiled, tool_ctx("secret", tool="Bash")).action == ACTION_DENY
    assert evaluate(compiled, tool_ctx("secret", tool="read_file")).action == ACTION_ALLOW


def test_tools_expand_via_alias_cover_mcp_shell():
    # "Bash" is a shell capability specifier; the MCP shell tool must be
    # covered too (the 2026-09-10 bypass the alias map was built to close).
    rule = make_rule(id="shell-deny", tools=["Bash"], pattern=r"\bsecret\b")
    compiled = compile_rules([rule])
    d = evaluate(compiled, tool_ctx("secret", tool="mcp__serena__execute_shell_command"))
    assert d.action == ACTION_DENY


def test_exempt_excludes_matching_tools():
    rule = make_rule(id="not-shell", exempt=["shell"], pattern=r"\bsecret\b")
    compiled = compile_rules([rule])
    assert evaluate(compiled, tool_ctx("secret", tool="Bash")).action == ACTION_ALLOW
    assert evaluate(compiled, tool_ctx("secret", tool="read_file")).action == ACTION_DENY


def test_requires_gates_applicability():
    rule = make_rule(id="needs-gh", requires=["gh"], pattern=r"\bsecret\b")
    compiled = compile_rules([rule])
    assert evaluate(compiled, tool_ctx("secret", available=frozenset({"gh"}))).action == ACTION_DENY
    assert evaluate(compiled, tool_ctx("secret", available=frozenset())).action == ACTION_ALLOW


def test_cwd_gate_protected_tree(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    rule = make_rule(id="prot", cwd=str(protected), pattern=r"\bsecret\b")
    compiled = compile_rules([rule])
    inside = evaluate(compiled, tool_ctx("secret", cwd=str(protected / "sub")))
    assert inside.action == ACTION_DENY
    outside = evaluate(compiled, tool_ctx("secret", cwd=str(tmp_path / "elsewhere")))
    assert outside.action == ACTION_ALLOW


def test_cwd_alternate_spellings_and_trailing_slash(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    rule = make_rule(id="prot", cwd=str(protected) + "/", pattern=r"\bsecret\b")
    compiled = compile_rules([rule])
    spelled = os.path.join(str(protected), "sub", "..", ".") + "/"
    assert evaluate(compiled, tool_ctx("secret", cwd=spelled)).action == ACTION_DENY


def test_cwd_symlink_resolves_at_compile(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(protected, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unsupported here")
    # The RULE's cwd is a symlink; compile resolves it to the real target.
    rule = make_rule(id="prot", cwd=str(link), pattern=r"\bsecret\b")
    compiled = compile_rules([rule])
    assert compiled.rules[0].cwd_paths == (os.path.realpath(str(protected)),)
    # A context cwd inside the resolved target is covered.
    assert evaluate(compiled, tool_ctx("secret", cwd=str(protected / "sub"))).action == ACTION_DENY
    # Evaluation does no realpath: a symlink in the *context* cwd is NOT resolved.
    assert evaluate(compiled, tool_ctx("secret", cwd=str(link))).action == ACTION_ALLOW


# --- unknown capability reporting ------------------------------------------

def test_unknown_capability_produces_coverage_warning():
    rule = make_rule(id="shell-deny", tools=["shell"], pattern=r"\bsecret\b")
    compiled = compile_rules([rule])
    d = evaluate(compiled, tool_ctx("secret", tool="mystery_mutator"))
    assert d.action == ACTION_ALLOW
    assert any("mystery_mutator" in w for w in d.degraded)


def test_known_tool_no_coverage_warning():
    rule = make_rule(id="shell-deny", tools=["shell"], pattern=r"\bsecret\b")
    compiled = compile_rules([rule])
    d = evaluate(compiled, tool_ctx("benign", tool="read_file"))
    assert d.degraded == ()


# --- counted-fact substitution + flattening bound ---------------------------

def test_counted_fact_substitutions():
    rule = make_rule(
        id="count",
        pattern=r"\bhi\b",
        reason="ran {n_tools}, denied {n_denied}, read {n_read_payload}, hit '{match}', rule {rule_id}",
    )
    compiled = compile_rules([rule])
    d = evaluate(compiled, tool_ctx("hi there", tool_count=3, denial_count=1, read_count=2))
    assert d.counted_fact == "ran 3, denied 1, read 2, hit 'hi', rule count"


def test_counted_fact_flattening_bound():
    huge = "A" * 10000
    rule = make_rule(id="big", pattern=r"\b[A]+\b", reason="matched {match}")
    compiled = compile_rules([rule])
    d = evaluate(compiled, tool_ctx(f"prefix {huge} suffix"))
    assert d.action == ACTION_DENY
    assert len(d.counted_fact) <= COUNTED_FACT_MAX_CHARS
    assert d.counted_fact.startswith("matched ")


def test_counted_fact_flattens_newlines():
    rule = make_rule(id="nl", pattern=r"(?s)bad\s+stuff", reason="matched '{match}'")
    compiled = compile_rules([rule])
    d = evaluate(compiled, tool_ctx("line1\nbad\nstuff\nline2"))
    assert d.action == ACTION_DENY
    assert "\n" not in d.counted_fact
    assert d.counted_fact == "matched 'bad stuff'"


# --- supported actions classify --------------------------------------------

@pytest.mark.parametrize(
    "action",
    ["deny", "check", "inject", "memory-first", "escalate", "block", "log"],
)
def test_each_supported_action_classifies(action):
    kw = {}
    if action == "inject":
        kw["memory"] = ["m1"]
    rule = make_rule(id="a-" + action, action=action, pattern=r"\bhit\b", **kw)
    compiled = compile_rules([rule])
    d = evaluate(compiled, tool_ctx("hit", available=frozenset({"memory", "gh", "reviewer"})))
    assert d.action == action
    assert "a-" + action in d.matched_rule_ids


# --- action-specific status ------------------------------------------------

def test_block_action_on_reply_surface():
    rule = make_rule(id="blk", surface="reply", action="block", pattern=r"\bdefers\b")
    compiled = compile_rules([rule])
    d = evaluate(compiled, reply_ctx("this defers the work"))
    assert d.action == ACTION_BLOCK
    assert "blk" in d.matched_rule_ids


def test_escalate_missing_reviewer_recorded_unavailable_not_deny():
    rule = make_rule(id="esc", action="escalate", pattern=r"\bhello\b")
    compiled = compile_rules([rule])
    d = evaluate(compiled, tool_ctx("hello world"))
    assert d.action == ACTION_ESCALATE
    assert d.reviewer_status == "unavailable"
    assert d.action != ACTION_DENY


def test_escalate_with_reviewer_is_deferred():
    rule = make_rule(id="esc", action="escalate", pattern=r"\bhello\b")
    compiled = compile_rules([rule])
    d = evaluate(compiled, tool_ctx("hello world", available=frozenset({"reviewer"})))
    assert d.action == ACTION_ESCALATE
    assert d.reviewer_status == "deferred"


# --- deferred actual name binds the underlying identity ---------------------

def test_deferred_tool_identity_binds_capability_rule():
    rule = make_rule(id="shell-deny", tools=["shell"], pattern=r"\bsecret\b")
    compiled = compile_rules([rule])
    real, caps = resolve_tool("tool_call", {"name": "Bash", "arguments": {"command": "echo secret"}})
    assert real == "Bash"
    d = evaluate(compiled, tool_ctx("echo secret", tool=real, capabilities=caps))
    assert d.action == ACTION_DENY


# --- evaluation is pure, immutable, deterministic ---------------------------

def test_decision_is_frozen():
    d = evaluate(compile_rules([]), tool_ctx("x"))
    with pytest.raises(FrozenInstanceError):
        d.action = "deny"


def test_evaluation_context_is_frozen():
    ctx = tool_ctx("x")
    with pytest.raises(FrozenInstanceError):
        ctx.payload = "y"


def test_evaluation_is_deterministic():
    rule = make_rule(id="r", pattern=r"\bsecret\b")
    compiled = compile_rules([rule])
    d1 = evaluate(compiled, tool_ctx("secret"))
    d2 = evaluate(compiled, tool_ctx("secret"))
    assert d1 == d2


# --- FIX I3: canonical capability names self-bind ---------------------------

def test_canonical_capability_names_self_bind():
    assert capabilities_for("shell") == frozenset({SHELL})
    assert capabilities_for("file_read") == frozenset({FILE_READ})
    assert capabilities_for("file_write") == frozenset({FILE_WRITE})
    assert capabilities_for("file_patch") == frozenset({FILE_PATCH})
    assert capabilities_for("execute_code") == frozenset({EXECUTE_CODE})
    assert capabilities_for("delegate") == frozenset({DELEGATE})


def test_resolve_tool_shell_self_binds_without_warning():
    real, caps = resolve_tool("shell")
    assert real == "shell"
    assert caps == frozenset({SHELL})
    rule = make_rule(id="shell-deny", tools=["shell"], pattern=r"\bsecret\b")
    compiled = compile_rules([rule])
    d = evaluate(compiled, tool_ctx("secret", tool="shell"))
    assert d.action == ACTION_DENY
    assert d.degraded == ()


# --- deterministic fact selection / deny-block interaction ------------------

def test_two_deny_rules_first_in_order_wins_fact():
    r1 = make_rule(id="d1", action="deny", pattern=r"\bsecret\b", reason="first '{match}'")
    r2 = make_rule(id="d2", action="deny", pattern=r"\bsecret\b", reason="second '{match}'")
    compiled = compile_rules([r1, r2])
    d = evaluate(compiled, tool_ctx("secret"))
    assert d.action == ACTION_DENY
    assert d.matched_rule_ids == ("d1", "d2")
    assert d.counted_fact == "first 'secret'"


def test_deny_beats_block():
    rules = [
        make_rule(id="blk", action="block", pattern=r"\bsecret\b"),
        make_rule(id="deny", action="deny", pattern=r"\bsecret\b", reason="denied '{match}'"),
    ]
    compiled = compile_rules(rules)
    d = evaluate(compiled, tool_ctx("secret"))
    assert d.action == ACTION_DENY


# --- empty rules / empty pattern --------------------------------------------

def test_empty_rules_list_evaluates_to_allow():
    d = evaluate(compile_rules([]), tool_ctx("anything", tool="Bash"))
    assert d.action == ACTION_ALLOW
    assert d.matched_rule_ids == ()
    assert d.counted_fact == ""
    assert d.degraded == ()


def test_empty_string_pattern_matches_everything():
    rule = make_rule(id="everything", pattern="", reason="caught '{match}'")
    compiled = compile_rules([rule])
    d = evaluate(compiled, tool_ctx("any payload at all"))
    assert d.action == ACTION_DENY
    assert d.counted_fact == "caught ''"


# --- minor: cwd="/" protects all (documented intentional) -------------------

def test_cwd_root_protects_all():
    rule = make_rule(id="root", cwd="/", pattern=r"\bsecret\b")
    compiled = compile_rules([rule])
    assert evaluate(compiled, tool_ctx("secret", cwd="/etc")).action == ACTION_DENY
    assert evaluate(compiled, tool_ctx("secret", cwd="/tmp/x")).action == ACTION_DENY


# --- minor: unbound mutating-looking tool is distinguished ------------------

def test_unbound_mutating_tool_distinguished_in_warnings():
    rule = make_rule(id="shell-deny", tools=["shell"], pattern=r"\bsecret\b")
    compiled = compile_rules([rule])
    d = evaluate(compiled, tool_ctx("secret", tool="delete_everything_tool"))
    assert "unbound_tool:delete_everything_tool" in d.degraded
    assert "unbound_mutating:delete_everything_tool" in d.degraded
