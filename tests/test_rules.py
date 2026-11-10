"""Schema regression tests for the ED-209 rules loader.

These lock the minimum contract of the loader before any engine/matching
logic exists: absent `enabled` defaults True (only a literal False disables),
duplicate ids are rejected, invalid regex patterns are rejected, malformed
field types raise RulesError (never a raw TypeError), and an empty rules
list is schema-valid.

Task 2 additions cover the compiled representation: `compile_rules` returns
pre-compiled regexes and normalized tools/exempt/requires/cwd, and computes a
stable revision hash for caching.
"""

import os
from typing import Any

import pytest

from operator_guards.ed209.rules import (
    RulesError,
    Rule,
    CompiledRule,
    CompiledRules,
    load_rules,
    compile_rules,
)


def _doc(rules):
    return {
        "version": 1,
        "_about": "test fixture",
        "reviewer": {"chain": ["copilot"], "model": "gpt-5.4", "timeout_s": 50},
        "limits": {"max_blocks_per_session": 12},
        "rules": rules,
    }


def _rule(**overrides):
    rule = {
        "id": "test-rule",
        "surface": "reply",
        "class": "voice",
        "action": "escalate",
        "pattern": r"\bhello\b",
        "reason": "test reason",
        "origin": "test origin",
    }
    rule.update(overrides)
    return rule


# --- existing contract ---

def test_omitted_enabled_defaults_true():
    rule = _rule()
    assert "enabled" not in rule  # sanity: the fixture really omits it
    loaded = load_rules(_doc([rule]))
    assert len(loaded) == 1
    assert loaded[0].enabled is True


def test_duplicate_ids_rejected():
    rules = [_rule(id="dup"), _rule(id="dup")]
    with pytest.raises(RulesError):
        load_rules(_doc(rules))


def test_invalid_regex_rejected():
    rule = _rule(pattern="([unclosed")
    with pytest.raises(RulesError):
        load_rules(_doc([rule]))


# --- FIX 1: type guards route every schema violation through RulesError ---

def test_non_mapping_root_doc_rejected():
    with pytest.raises(RulesError):
        load_rules(["not", "a", "mapping"])  # type: ignore[arg-type]


def test_non_mapping_rule_entry_rejected():
    with pytest.raises(RulesError):
        load_rules(_doc(["not a mapping"]))


def test_missing_required_field_rejected():
    rule = _rule()
    del rule["reason"]
    with pytest.raises(RulesError):
        load_rules(_doc([rule]))


def test_wrong_typed_id_list_raises_rules_error():
    rule = _rule(id=["a"])
    with pytest.raises(RulesError):
        load_rules(_doc([rule]))


def test_wrong_typed_pattern_int_raises_rules_error():
    rule = _rule(pattern=123)
    with pytest.raises(RulesError):
        load_rules(_doc([rule]))


@pytest.mark.parametrize(
    "field,value",
    [
        ("surface", 123),
        ("class", ["x"]),
        ("action", {"k": "v"}),
        ("reason", 3.14),
        ("origin", None),
    ],
)
def test_wrong_typed_string_field_raises_rules_error(field, value):
    rule = _rule(**{field: value})
    with pytest.raises(RulesError):
        load_rules(_doc([rule]))


# --- FIX 5: enabled truthiness semantics ---

def test_explicit_enabled_false_disables():
    loaded = load_rules(_doc([_rule(enabled=False)]))
    assert loaded[0].enabled is False


@pytest.mark.parametrize("value", [0, None, "false"])
def test_truthy_enabled_values_do_not_disable(value):
    # Upstream semantics: only a literal False disables a rule.
    loaded = load_rules(_doc([_rule(enabled=value)]))
    assert loaded[0].enabled is True


# --- FIX 2: empty ruleset is schema-valid ---

def test_empty_rules_list_loads_to_empty_list():
    assert load_rules(_doc([])) == []


# --- Task 2: compiled representation ---------------------------------------

def test_compile_rules_returns_compiled_rules():
    compiled = compile_rules(load_rules(_doc([_rule()])))
    assert isinstance(compiled, CompiledRules)
    assert len(compiled.rules) == 1
    assert isinstance(compiled.rules[0], CompiledRule)
    assert compiled.rules[0].regex.search("hello world") is not None


def test_compile_rules_from_rule_objects():
    rule = Rule(
        id="r",
        surface="reply",
        rule_class="voice",
        action="escalate",
        pattern=r"\bhi\b",
        reason="reason",
        origin="origin",
    )
    compiled = compile_rules([rule])
    assert compiled.rules[0].rule.id == "r"


def test_revision_is_stable_for_identical_rules():
    a = compile_rules(load_rules(_doc([_rule()])))
    b = compile_rules(load_rules(_doc([_rule()])))
    assert a.revision == b.revision


def test_revision_changes_when_rules_change():
    a = compile_rules(load_rules(_doc([_rule()])))
    b = compile_rules(load_rules(_doc([_rule(pattern=r"\bgoodbye\b")])))
    assert a.revision != b.revision


def test_compiled_tools_exempt_requires_normalized():
    compiled = compile_rules(
        load_rules(_doc([_rule(tools=["shell"], exempt=["Bash"], requires=["gh"], cwd="/tmp/x/")]))
    )
    cr = compiled.rules[0]
    assert cr.tools == frozenset({"shell"})
    assert cr.exempt == frozenset({"Bash"})
    assert cr.requires == frozenset({"gh"})
    assert cr.cwd_paths == (os.path.realpath("/tmp/x"),)


def test_compiled_single_string_tools_coerced_to_set():
    compiled = compile_rules(load_rules(_doc([_rule(tools="shell")])))
    assert compiled.rules[0].tools == frozenset({"shell"})


def test_compiled_empty_tools_means_no_restriction():
    compiled = compile_rules(load_rules(_doc([_rule(tools=[])])))
    assert compiled.rules[0].tools is None


def test_compile_includes_disabled_rules():
    compiled = compile_rules(load_rules(_doc([_rule(enabled=False)])))
    assert len(compiled.rules) == 1
    assert compiled.rules[0].rule.enabled is False


# --- FIX I1: compile_rules re-validates hand-built Rule objects -------------

def _rule_obj(**overrides):
    fields: dict[str, Any] = {
        "id": "test-rule",
        "surface": "reply",
        "rule_class": "voice",
        "action": "escalate",
        "pattern": r"\bhello\b",
        "reason": "test reason",
        "origin": "test origin",
    }
    fields.update(overrides)
    return Rule(**fields)


@pytest.mark.parametrize(
    "field", ["id", "surface", "rule_class", "action", "pattern", "reason", "origin"]
)
def test_compile_rejects_non_str_required_field(field):
    rule = _rule_obj(**{field: None})
    with pytest.raises(RulesError):
        compile_rules([rule])


def test_compile_rejects_none_reason():
    rule = _rule_obj(reason=None)
    with pytest.raises(RulesError):
        compile_rules([rule])


def test_compile_rejects_unsupported_action():
    rule = _rule_obj(action="destroy")
    with pytest.raises(RulesError):
        compile_rules([rule])


# --- FIX I2(b): revision covers resolved cwd paths --------------------------

def test_revision_changes_when_cwd_symlink_retargeted(tmp_path):
    target_a = tmp_path / "a"
    target_b = tmp_path / "b"
    target_a.mkdir()
    target_b.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target_a, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unsupported here")
    rule = _rule(cwd=str(link))
    rev_a = compile_rules(load_rules(_doc([rule]))).revision
    link.unlink()
    link.symlink_to(target_b, target_is_directory=True)
    rev_b = compile_rules(load_rules(_doc([rule]))).revision
    assert rev_a != rev_b


# --- minor: cwd empty/whitespace rejected; None means no restriction --------

def test_compile_rejects_empty_cwd():
    rule = _rule_obj(cwd="")
    with pytest.raises(RulesError):
        compile_rules([rule])


def test_compile_rejects_whitespace_cwd():
    rule = _rule_obj(cwd="   ")
    with pytest.raises(RulesError):
        compile_rules([rule])


def test_none_cwd_means_no_restriction():
    compiled = compile_rules([_rule_obj(cwd=None)])
    assert compiled.rules[0].cwd_paths == ()
