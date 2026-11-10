"""Focused publication tests: observer predicates, quiet-client behaviour, grants.

Every test uses an isolated ``tmp_path`` home/state root. No live profile,
incident store, grant store, transcript, or process is touched.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from operator_guards.ed209.engine import ACTION_DENY
from operator_guards.ed209.ledger import HitLedger
from operator_guards.ed209.rules import load_rules
from operator_guards.r2d2.authz import (
    GrantAlreadyConsumedError,
    GrantExpiredError,
    GrantIdentityMismatchError,
    GrantNonceMismatchError,
    GrantRevokedError,
    GrantScopeError,
    GrantScopeMismatchError,
    GrantStore,
)
from operator_guards.r2d2.executor import Policy
from operator_guards.r2d2.observer import (
    CLASS_LOST_CAPABILITY,
    CLASS_NONE,
    CLASS_PERMISSION_BLOCK,
    CLASS_POLICY_DENIAL,
    CLASS_RECONNECT_IN_PROGRESS,
    CLASS_STALE_CLIENT,
    CLASS_TRANSPORT_DROP,
    CLASS_UNSUPPORTED,
    CLIENT_STALE_SECONDS,
    ClientRecord,
    Observation,
    Observer,
    RaiseIncident,
    classify,
)
from operator_guards.r2d2.store import IncidentStore

REPO = Path(__file__).resolve().parents[1]


def _client(**overrides):
    base = dict(
        client_id="client-1",
        status="registered",
        capabilities=frozenset({"Bash", "mcp:filesystem"}),
        pid=4242,
        pid_start_time=1000.0,
        last_seen=999.0,
    )
    base.update(overrides)
    return ClientRecord(**base)


def _obs(**overrides):
    base = dict(
        kind="post_tool_error",
        client_id="client-1",
        session_id="session-1",
        tool_name="Bash",
        error_type="connection_reset",
        detail="fixture observation",
        ts=1000.0,
    )
    base.update(overrides)
    return Observation(**base)


def test_observer_predicates_with_fixtures():
    client = _client()
    reconnecting = _client(status="reconnecting", reconnect_started=990.0)
    stuck = _client(status="reconnecting", reconnect_started=900.0)
    capability_client = _client(capabilities=frozenset({"mcp:filesystem"}))

    assert classify(_obs(error_type="transport_closed"), reconnecting, 1000.0).kind == CLASS_RECONNECT_IN_PROGRESS
    assert classify(_obs(error_type="transport_closed"), stuck, 1000.0).kind == CLASS_STALE_CLIENT
    assert classify(_obs(error_type="connection_reset"), client, 1000.0).kind == CLASS_TRANSPORT_DROP
    assert (
        classify(
            _obs(error_type="capability_missing", capability="mcp:filesystem"),
            capability_client,
            1000.0,
        ).kind
        == CLASS_LOST_CAPABILITY
    )
    # A capability signal for a capability the client never registered is not a
    # loss (no false incident).
    assert (
        classify(
            _obs(error_type="capability_missing", capability="mcp:other"),
            capability_client,
            1000.0,
        ).kind
        == CLASS_NONE
    )
    assert classify(_obs(error_type="permission_denied"), client, 1000.0).kind == CLASS_PERMISSION_BLOCK
    assert (
        classify(_obs(kind="post_tool_status", status="denied", rule_id="rule-1"), client, 1000.0).kind
        == CLASS_POLICY_DENIAL
    )
    unsupported = classify(_obs(kind="post_tool_status", predicate="takeover_without_send"), client, 1000.0)
    assert unsupported.kind == CLASS_UNSUPPORTED
    assert unsupported.unsupported is True


def test_quiet_but_alive_client_is_not_escalated(tmp_path):
    """The capability-quiet detector must not treat a quiet session as broken."""
    root = str(tmp_path / "r2d2")
    store = IncidentStore(root)
    observer = Observer(root=root, store=store, clock=lambda: 1000.0, proc_start=lambda pid: 1000.0)
    observer.write_client_record(_client(last_seen=999.0))

    assert observer.check_clients() == []
    assert store.list_incidents() == []


def test_stale_or_dead_client_is_escalated(tmp_path):
    root = str(tmp_path / "r2d2")
    store = IncidentStore(root)
    observer = Observer(root=root, store=store, clock=lambda: 1000.0, proc_start=lambda pid: 1000.0)
    observer.write_client_record(_client(last_seen=1000.0 - CLIENT_STALE_SECONDS - 1.0))

    effects = observer.check_clients()
    assert any(isinstance(effect, RaiseIncident) for effect in effects)
    assert len(store.list_incidents()) == 1


def _issue(store, **overrides):
    kwargs = dict(
        incident_id="inc-1",
        scope="session_stop_resume",
        session_id="session-other",
        client_id="client-other",
        pid=12345,
        start_time=1700000000.0,
        issuer="operator",
        ttl_seconds=1800,
    )
    kwargs.update(overrides)
    return store.issue(**kwargs)


def _binding(grant, **overrides):
    binding = dict(
        session_id=grant.session_id,
        client_id=grant.client_id,
        pid=grant.pid,
        start_time=grant.start_time,
        scope=grant.scope,
    )
    binding.update(overrides)
    return binding


def test_grant_is_identity_bound_scoped_and_single_use(tmp_path):
    store = GrantStore(str(tmp_path / "grants"))
    with pytest.raises(GrantScopeError):
        _issue(store, scope="bogus")

    grant = _issue(store)
    with pytest.raises(GrantIdentityMismatchError):
        store.consume(grant.grant_id, grant.nonce, **_binding(grant, session_id="session-other-2"))
    with pytest.raises(GrantIdentityMismatchError):
        store.consume(grant.grant_id, grant.nonce, **_binding(grant, client_id="client-other-2"))
    with pytest.raises(GrantIdentityMismatchError):
        store.consume(grant.grant_id, grant.nonce, **_binding(grant, pid=999))
    with pytest.raises(GrantIdentityMismatchError):
        store.consume(grant.grant_id, grant.nonce, **_binding(grant, start_time=grant.start_time + 1))
    with pytest.raises(GrantScopeMismatchError):
        store.consume(grant.grant_id, grant.nonce, **_binding(grant, scope="other_scope"))
    with pytest.raises(GrantNonceMismatchError):
        store.consume(grant.grant_id, "wrong-nonce", **_binding(grant))

    consumed = store.consume(grant.grant_id, grant.nonce, **_binding(grant))
    assert consumed.consumed is True
    with pytest.raises(GrantAlreadyConsumedError):
        store.consume(grant.grant_id, grant.nonce, **_binding(grant))


def test_grant_ttl_boundary_and_revoke(tmp_path):
    clock = [1000.0]
    store = GrantStore(str(tmp_path / "grants"), clock=lambda: clock[0])
    grant = _issue(store, ttl_seconds=10)
    assert grant.expires_at - grant.issued_at == 10
    clock[0] = grant.issued_at + 10.0  # inclusive boundary: expired
    with pytest.raises(GrantExpiredError):
        store.consume(grant.grant_id, grant.nonce, **_binding(grant))

    grant2 = _issue(store)
    store.revoke(grant2.grant_id, operator="operator")
    with pytest.raises(GrantRevokedError):
        store.consume(grant2.grant_id, grant2.nonce, **_binding(grant2))


def test_protected_rulepack_denies_agent_write_to_grant_state(tmp_path):
    rulepack = REPO / "rulepacks" / "operator-guards-protected.json"
    doc = json.loads(rulepack.read_text(encoding="utf-8"))
    rules = load_rules(doc)
    assert rules
    assert all(rule.action == "deny" and rule.overridable is False for rule in rules)

    db = str(tmp_path / "hits.db")
    policy = Policy(rules_path=str(rulepack), ledger=HitLedger(db))
    payload = json.dumps({"path": str(tmp_path / "r2d2" / "grants" / "g1.json"), "content": "mint authority"})
    decision = policy.check("file_write", payload, capabilities=frozenset({"file_write"}))
    policy.record(decision, tool_name="file_write")

    assert decision.action == ACTION_DENY
    assert "guard-grant-files" in decision.matched_rule_ids
    assert HitLedger(db).outcomes_for_rule("guard-grant-files") == {"deny": 1}


def test_defaults_are_environment_configurable():
    """The published defaults derive from the environment, not a fixed home."""
    code = (
        "from operator_guards.ed209 import cli, ledger, state\n"
        "from operator_guards.r2d2 import store\n"
        "print(cli.DEFAULT_RULES_PATH)\n"
        "print(ledger.DEFAULT_HITS_DB)\n"
        "print(state.DEFAULT_STATE_DIR)\n"
        "print(store.DEFAULT_STATE_ROOT)\n"
    )
    base_env = {
        **os.environ,
        "PYTHONPATH": str(REPO / "src"),
        "OPERATOR_GUARDS_HOME": "/tmp/guards-home",
    }
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        env=base_env,
        check=True,
    )
    assert result.stdout.splitlines() == [
        "/tmp/guards-home/ed209/rules.json",
        "/tmp/guards-home/ed209/hits.db",
        "/tmp/guards-home/ed209/state",
        "/tmp/guards-home/r2d2",
    ]

    specific = {**base_env, "OPERATOR_GUARDS_ED209_RULES": "/tmp/custom-rules.json"}
    result = subprocess.run(
        [sys.executable, "-c", "from operator_guards.ed209 import cli; print(cli.DEFAULT_RULES_PATH)"],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        env=specific,
        check=True,
    )
    assert result.stdout.strip() == "/tmp/custom-rules.json"


def test_published_python_has_no_hardcoded_operator_home():
    offenders = []
    for path in (REPO / "src").rglob("*.py"):
        if "/home/rsanchez" in path.read_text(encoding="utf-8"):
            offenders.append(str(path.relative_to(REPO)))
    assert offenders == []
