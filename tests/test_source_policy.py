"""Source-backed policy provenance tests (ported from the live ED-209 module).

These tests prove the provenance rules the publication claims:

* a proposal cites a GENUINE user message, not an assistant/tool/meta event;
* an exact quote is required, and a paraphrase never activates;
* a changed source message or tampered proposal invalidates the active rule;
* activation is bound to the exact proposal digest;
* observations are never loaded as active policy.

The store and transcripts live under the pytest ``tmp_path``. No live profile,
transcript, database, or policy store is read or written.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from operator_guards.ed209 import source_policy as p


class PolicyTests:
    pass


@pytest.fixture
def policy(tmp_path):
    store = tmp_path / "policy"
    store.mkdir()
    transcript = tmp_path / "source.jsonl"
    rule = {
        "id": "merge",
        "surface": "reply",
        "action": "block",
        "pattern": "manual",
        "reason": "Production is included",
    }
    raw = json.dumps({"rules": [{**rule, "reason": "legacy"}], "reviewer": {}}).encode()
    (store / "baseline.json").write_bytes(raw)
    (store / "baseline.sha256").write_text(hashlib.sha256(raw).hexdigest())
    entry = {"type": "user", "uuid": "original", "message": {"role": "user", "content": "Merge through production"}}
    transcript.write_text(json.dumps(entry) + "\n")
    return store, transcript, rule, entry


def _write(transcript, *entries):
    transcript.write_text("".join(json.dumps(e) + "\n" for e in entries))


def _propose(store, transcript, rule, entry, *, activate=False):
    return p.propose(
        rule,
        transcript,
        "original",
        "Merge through production",
        store=store,
        activate=activate,
    )


def _activate(store, transcript, entry, proposal_id):
    approval = {
        "type": "user",
        "uuid": "approval",
        "message": {"role": "user", "content": f"activate policy {proposal_id}"},
    }
    _write(transcript, entry, approval)
    return p.activate(proposal_id, transcript, "approval", store=store)


def test_proposal_does_not_activate(policy):
    store, transcript, rule, entry = policy
    _propose(store, transcript, rule, entry)
    assert p.load_rules(store=store)["rules"][0]["reason"] == "legacy"


def test_verified_quote_auto_activates(policy):
    store, transcript, rule, entry = policy
    _propose(store, transcript, rule, entry, activate=True)
    config = p.load_rules(store=store)
    assert config["rules"][0]["reason"] == "Production is included"
    assert not config["_policy_errors"]


def test_forged_quote_approval_rejected(policy):
    store, transcript, rule, entry = policy
    _propose(store, transcript, rule, entry, activate=True)
    state = json.loads((store / "active.json").read_text())
    state["active"][0]["approval"]["quote"] = "production stays manual"
    (store / "active.json").write_text(json.dumps(state))
    config = p.load_rules(store=store)
    assert config["_policy_errors"]
    assert config["rules"][0]["reason"] == "legacy"


def test_edited_source_after_auto_activation_rejected(policy):
    store, transcript, rule, entry = policy
    _propose(store, transcript, rule, entry, activate=True)
    entry["message"]["content"] = "Merge through production, except main stays manual"
    _write(transcript, entry)
    assert p.load_rules(store=store)["_policy_errors"]


def test_find_source_locates_user_quote_only(tmp_path):
    root = tmp_path / "projects"
    root.mkdir()
    (root / "s.jsonl").write_text(
        json.dumps({"type": "assistant", "uuid": "a", "message": {"content": "only stage stays manual"}})
        + "\n"
        + json.dumps({"type": "user", "uuid": "u1", "message": {"content": "merge to production"}})
        + "\n"
    )
    assert p.find_source("merge to production", roots=[root])[1] == "u1"
    with pytest.raises(p.PolicyError):
        p.find_source("only stage stays manual", roots=[root])


def test_exact_approval_activates(policy):
    store, transcript, rule, entry = policy
    _activate(store, transcript, entry, _propose(store, transcript, rule, entry))
    config = p.load_rules(store=store)
    assert config["rules"][0]["policy_status"] == "verified-active"
    assert not config["_policy_errors"]


@pytest.mark.parametrize(
    "override",
    [
        {"type": "assistant"},
        {"isMeta": True},
        {"isCompactSummary": True},
        {"isSidechain": True},
        {"message": {"role": "user", "content": [{"type": "tool_result", "content": "Merge through production"}]}},
    ],
)
def test_assistant_tool_meta_summary_rejected(policy, override):
    store, transcript, rule, entry = policy
    _write(transcript, {**entry, **override})
    with pytest.raises(p.PolicyError):
        _propose(store, transcript, rule, entry)


def test_wrong_quote_rejected(policy):
    store, transcript, rule, entry = policy
    with pytest.raises(p.PolicyError):
        p.propose(rule, transcript, "original", "production stays manual", store=store)


def test_authentic_quote_does_not_authorize_interpretation(policy):
    store, transcript, rule, entry = policy
    rule["reason"] = "production stays manual"
    proposal_id = _propose(store, transcript, rule, entry)
    with pytest.raises(p.PolicyError):
        p.activate(proposal_id, transcript, "original", store=store)
    assert p.load_rules(store=store)["rules"][0]["reason"] == "legacy"


def test_quoted_activation_not_approval(policy):
    store, transcript, rule, entry = policy
    proposal_id = _propose(store, transcript, rule, entry)
    _write(
        transcript,
        entry,
        {"type": "user", "uuid": "approval", "message": {"content": f"The agent said activate policy {proposal_id}"}},
    )
    with pytest.raises(p.PolicyError):
        p.activate(proposal_id, transcript, "approval", store=store)


def test_rule_tampering_rejected(policy):
    store, transcript, rule, entry = policy
    proposal_id = _propose(store, transcript, rule, entry)
    _activate(store, transcript, entry, proposal_id)
    path = store / "proposals" / f"{proposal_id}.json"
    item = json.loads(path.read_text())
    item["body"]["rule"]["reason"] = "injected"
    path.write_text(json.dumps(item))
    config = p.load_rules(store=store)
    assert config["_policy_errors"]
    assert config["rules"][0]["reason"] == "legacy"


def test_source_mutation_rejects_active(policy):
    store, transcript, rule, entry = policy
    _activate(store, transcript, entry, _propose(store, transcript, rule, entry))
    entry["message"]["content"] += " actually wait"
    _write(transcript, entry)
    config = p.load_rules(store=store)
    assert config["_policy_errors"]
    assert config["rules"][0]["reason"] == "legacy"


def test_appended_transcript_is_valid(policy):
    store, transcript, rule, entry = policy
    _activate(store, transcript, entry, _propose(store, transcript, rule, entry))
    with transcript.open("a") as stream:
        stream.write(json.dumps({"type": "assistant", "message": {"content": "later"}}) + "\n")
    assert not p.load_rules(store=store)["_policy_errors"]


def test_corrupt_baseline_raises(policy):
    store, transcript, rule, entry = policy
    (store / "baseline.json").write_text("{}")
    with pytest.raises(p.PolicyError):
        p.load_rules(store=store)


def test_codex_user_event(policy):
    store, transcript, rule, entry = policy
    _write(transcript, {"type": "event_msg", "payload": {"type": "user_message", "message": "Merge through production"}})
    receipt, text = p.source(transcript, "line:1", "Merge through production")
    assert text == "Merge through production"
    assert receipt["message_id"] == "line:1"


def test_duplicate_uuid_rejected(policy):
    store, transcript, rule, entry = policy
    _write(transcript, entry, entry)
    with pytest.raises(p.PolicyError):
        _propose(store, transcript, rule, entry)


def test_superseded_policy_not_loaded(policy):
    store, transcript, rule, entry = policy
    first = _propose(store, transcript, rule, entry)
    _activate(store, transcript, entry, first)
    rule["reason"] = "updated exact rule"
    second = _propose(store, transcript, rule, entry)
    _activate(store, transcript, entry, second)
    state = json.loads((store / "active.json").read_text())
    assert state["history"][0]["status"] == "superseded"
    assert p.load_rules(store=store)["rules"][0]["reason"] == "updated exact rule"


def test_observations_are_not_loaded(policy):
    store, transcript, rule, entry = policy
    (store / "observations").mkdir()
    (store / "observations" / "fake.json").write_text(json.dumps(rule))
    assert p.load_rules(store=store)["rules"][0]["reason"] == "legacy"


def test_default_store_is_configurable(monkeypatch):
    assert p.default_store({"OPERATOR_GUARDS_HOME": "/tmp/profile"}) == Path("/tmp/profile/ed209/policy")
    assert p.default_store({"OPERATOR_GUARDS_POLICY_STORE": "/tmp/custom"}) == Path("/tmp/custom")


def test_source_roots_are_configurable(monkeypatch, tmp_path):
    root = tmp_path / "transcripts"
    root.mkdir()
    (root / "s.jsonl").write_text(
        json.dumps({"type": "user", "uuid": "u1", "message": {"content": "a genuine user instruction"}}) + "\n"
    )
    monkeypatch.setenv("OPERATOR_GUARDS_SOURCE_ROOTS", str(root))
    assert p.find_source("a genuine user instruction")[1] == "u1"
