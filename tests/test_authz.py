"""Operator grants + notification policy tests (Task 14).

Covers the durable single-use scoped grant contract, the opt-in
notification policy (local-only by default), the ED-209 protected-path
deny for agent writes to grant/authz state, the sourced ``# ed209-override``
enforcement (overridable rules only), and the fact that
``session_stop_resume`` stays DISABLED pending a separate other-session drill
(Task 17).

Grant contract (plan §4): a grant names the exact other-session/client/
process-START identity, the incident/action scope, the issuer, issued/expiry
times, and a single-use nonce. Consumption is durable and one-way — a failed
resume does NOT refund kill authority. Grant creation can never come from an
incident payload or a model tool operation: the issuer's ``issue`` accepts
only explicit typed identity fields and GENERATES the nonce itself. Consumption
ENFORCES the presented identity (session/client/pid/start-time) and scope
against the grant: a grant is not usable for a different target.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from operator_guards.ed209.engine import (
    ACTION_DENY,
    ACTION_OVERRIDE,
    EvaluationContext,
    evaluate,
)
from operator_guards.ed209.ledger import HitLedger
from operator_guards.ed209.rules import compile_rules, load_rules
from operator_guards.r2d2.authz import (
    CHANNEL_LOCAL,
    GrantAlreadyConsumedError,
    GrantExpiredError,
    GrantIdentityMismatchError,
    GrantNonceMismatchError,
    GrantNotFoundError,
    GrantRevokedError,
    GrantScopeError,
    GrantScopeMismatchError,
    GrantStore,
    NotificationPolicy,
)
from operator_guards.r2d2.executor import Policy
from operator_guards.r2d2.handlers import (
    OPERATION_NAMES,
    OP_SESSION_STOP_RESUME,
    UnsupportedHandler,
)

REPO = Path(__file__).resolve().parents[1]
PROTECTED_RULEPACK = REPO / "rulepacks" / "operator-guards-protected.json"


# ---------------------------------------------------------------------------
# notification policy: opt-in belongs to the operator; absence => LOCAL-ONLY
# ---------------------------------------------------------------------------

def test_no_opt_in_means_local_only(tmp_path):
    policy = NotificationPolicy(opt_in_channels=frozenset(), receipts_dir=str(tmp_path / "receipts"))
    # An outbound channel with no operator opt-in resolves LOCAL-ONLY: no outbound.
    decision = policy.resolve("inc-1", "sms")
    assert decision.status == "local_only"
    assert decision.suppression_reason  # a visible suppression reason, never silent
    # No outbound delivery is accepted and no receipt is ever written.
    assert policy.accept_delivery("inc-1", "sms", "receipt-1") is False
    assert policy.read_receipt("inc-1", "sms") == ""
    # The local channel is the default sink and always available.
    local = policy.resolve("inc-1", CHANNEL_LOCAL)
    assert local.status == "opted_in"


def test_opt_in_enables_single_delivery_with_receipt_readback(tmp_path):
    policy = NotificationPolicy(opt_in_channels=frozenset({"sms"}), receipts_dir=str(tmp_path / "receipts"))
    decision = policy.resolve("inc-1", "sms")
    assert decision.status == "opted_in"
    # At most ONE accepted delivery per incident+channel (durable dedupe).
    assert policy.accept_delivery("inc-1", "sms", "receipt-abc") is True
    assert policy.accept_delivery("inc-1", "sms", "receipt-xyz") is False
    # Exact-delivery-receipt readback returns the first accepted receipt.
    assert policy.read_receipt("inc-1", "sms") == "receipt-abc"


def test_never_enable_sms_telegram_by_default():
    # A daemon that simply starts must NOT enable outbound channels.
    policy = NotificationPolicy()  # default construction
    assert policy.opt_in_channels == frozenset()
    assert policy.resolve("inc-1", "sms").status == "local_only"
    assert policy.resolve("inc-1", "telegram").status == "local_only"


# ---------------------------------------------------------------------------
# grant contract: scope / TTL / single-use durable consumption
# ---------------------------------------------------------------------------

def _issue(store, *, ttl_seconds=1800, scope="session_stop_resume", **overrides):
    kwargs = dict(
        incident_id="inc-1",
        scope=scope,
        session_id="sess-other",
        client_id="client-other",
        pid=12345,
        start_time=1700000000.0,
        issuer="rudy",
        ttl_seconds=ttl_seconds,
    )
    kwargs.update(overrides)
    return store.issue(**kwargs)


def _consume_binding(grant, **overrides):
    """Presented identity/scope for a consume call (defaults to the grant's own)."""
    binding = dict(
        session_id=grant.session_id,
        client_id=grant.client_id,
        pid=grant.pid,
        start_time=grant.start_time,
        scope=grant.scope,
    )
    binding.update(overrides)
    return binding


def test_grant_scope_ttl_and_consumption(tmp_path):
    store = GrantStore(str(tmp_path / "grants"))
    # Scope enforced: an unknown scope is rejected at issue time.
    with pytest.raises(GrantScopeError):
        _issue(store, scope="bogus")

    grant = _issue(store)
    assert grant.scope == "session_stop_resume"
    assert grant.grant_id
    assert grant.nonce                       # issuer-generated nonce
    assert grant.expires_at - grant.issued_at == 1800

    # Single-use: the first consume succeeds and durably marks it consumed.
    consumed = store.consume(grant.grant_id, grant.nonce, **_consume_binding(grant))
    assert consumed.consumed is True
    # A reused grant rejects (no refund, no second use).
    with pytest.raises(GrantAlreadyConsumedError):
        store.consume(grant.grant_id, grant.nonce, **_consume_binding(grant))


def test_grant_ttl_expiry(tmp_path):
    now = [1000.0]
    store = GrantStore(str(tmp_path / "grants"), clock=lambda: now[0])
    grant = _issue(store, ttl_seconds=10)
    now[0] = 1000.0 + 10.0 + 0.001  # past expiry
    with pytest.raises(GrantExpiredError):
        store.consume(grant.grant_id, grant.nonce, **_consume_binding(grant))


def test_grant_ttl_boundary_exact(tmp_path):
    now = [1000.0]
    store = GrantStore(str(tmp_path / "grants"), clock=lambda: now[0])
    grant = _issue(store, ttl_seconds=10)
    # Expiry is INCLUSIVE of the boundary: at exactly now == issued_at + ttl the
    # grant is expired (rejected AT the boundary, not only past it).
    now[0] = grant.issued_at + 10.0
    with pytest.raises(GrantExpiredError):
        store.consume(grant.grant_id, grant.nonce, **_consume_binding(grant))

    grant2 = _issue(store, ttl_seconds=10)
    # 1ns before the boundary the grant is still valid.
    now[0] = grant2.issued_at + 10.0 - 1e-9
    consumed = store.consume(grant2.grant_id, grant2.nonce, **_consume_binding(grant2))
    assert consumed.consumed is True


def test_grant_revoke(tmp_path):
    store = GrantStore(str(tmp_path / "grants"))
    grant = _issue(store)
    revoked = store.revoke(grant.grant_id, operator="rudy")
    assert revoked.revoked is True
    with pytest.raises(GrantRevokedError):
        store.consume(grant.grant_id, grant.nonce, **_consume_binding(grant))


def test_grant_nonce_single_use(tmp_path):
    store = GrantStore(str(tmp_path / "grants"))
    grant = _issue(store)
    # Wrong nonce never authorizes.
    with pytest.raises(GrantNonceMismatchError):
        store.consume(grant.grant_id, "wrong-nonce", **_consume_binding(grant))
    # The correct nonce authorizes exactly once.
    store.consume(grant.grant_id, grant.nonce, **_consume_binding(grant))
    # The same (now-consumed) nonce cannot be reused.
    with pytest.raises(GrantAlreadyConsumedError):
        store.consume(grant.grant_id, grant.nonce, **_consume_binding(grant))


def test_grant_consume_enforces_identity_and_scope(tmp_path):
    store = GrantStore(str(tmp_path / "grants"))
    grant = _issue(
        store,
        session_id="sess-A",
        client_id="client-A",
        pid=100,
        start_time=1700000000.0,
        scope="session_stop_resume",
    )
    # A grant names EXACT identity: a wrong session/client/pid/start-time is
    # rejected at consume time, never usable for a different target.
    with pytest.raises(GrantIdentityMismatchError):
        store.consume(grant.grant_id, grant.nonce, **_consume_binding(grant, session_id="sess-B"))
    with pytest.raises(GrantIdentityMismatchError):
        store.consume(grant.grant_id, grant.nonce, **_consume_binding(grant, client_id="client-B"))
    with pytest.raises(GrantIdentityMismatchError):
        store.consume(grant.grant_id, grant.nonce, **_consume_binding(grant, pid=999))
    with pytest.raises(GrantIdentityMismatchError):
        store.consume(grant.grant_id, grant.nonce, **_consume_binding(grant, start_time=1700000001.0))
    # A wrong scope is rejected too.
    with pytest.raises(GrantScopeMismatchError):
        store.consume(grant.grant_id, grant.nonce, **_consume_binding(grant, scope="other_scope"))
    # The exact bound identity + scope consumes exactly once.
    consumed = store.consume(grant.grant_id, grant.nonce, **_consume_binding(grant))
    assert consumed.consumed is True


def test_failed_resume_does_not_refund(tmp_path):
    store = GrantStore(str(tmp_path / "grants"))
    grant = _issue(store)
    # Consume durably BEFORE the one authorized attempt.
    store.consume(grant.grant_id, grant.nonce, **_consume_binding(grant))
    # A failed resume does NOT refund kill authority: there is no unconsume/refund
    # path, and a second consume is still rejected.
    assert not hasattr(store, "refund")
    assert not hasattr(store, "unconsume")
    with pytest.raises(GrantAlreadyConsumedError):
        store.consume(grant.grant_id, grant.nonce, **_consume_binding(grant))


def test_grant_cannot_be_created_from_incident_payload(tmp_path):
    store = GrantStore(str(tmp_path / "grants"))
    # issue() accepts only explicit, keyword-only identity fields — it has NO
    # `nonce`, `record`, or `payload` parameter, so an incident record (with its
    # authorization/nonce fields) can never mint a grant.
    params = set(inspect.signature(GrantStore.issue).parameters)
    assert "nonce" not in params
    assert "record" not in params
    assert "payload" not in params
    # A positional mapping (an incident record) is rejected by the signature.
    incident_record = {
        "id": "inc-1", "severity": "mechanical", "symptom": "x", "phase": "open",
        "dedupe_key": "d", "authorization": ["grant:foo"], "nonce": "n",
    }
    with pytest.raises(TypeError):
        store.issue(incident_record)  # noqa: positional mapping must not be accepted


def test_grant_not_an_executor_operation():
    # Grant creation is NOT exposed as a model tool operation: the executor's
    # closed allowlist has no grant verb.
    assert "grant" not in OPERATION_NAMES
    assert "grant_issue" not in OPERATION_NAMES


def test_session_stop_resume_stays_disabled():
    # The grant exists, but the resume adapter stays UNAVAILABLE until Task 17.
    handler = UnsupportedHandler(
        OP_SESSION_STOP_RESUME, "requires an externally issued scoped single-use TTL grant (Task 14)"
    )
    assert handler.supported is False


# ---------------------------------------------------------------------------
# ED-209 protected-path rules: agent write to grant/authz files is DENIED+ledgered
# ---------------------------------------------------------------------------

def test_ed209_denies_agent_write_to_grant_files(tmp_path):
    # Load the REAL protected rulepack (provenance + non-overridable) and drive
    # the executor's Policy check+record path against a write to a grants dir.
    doc = json.loads(PROTECTED_RULEPACK.read_text(encoding="utf-8"))
    rules = load_rules(doc)
    assert rules, "protected rulepack must not be empty"
    assert all(r.action == "deny" and r.overridable is False for r in rules)

    db = str(tmp_path / "hits.db")
    policy = Policy(rules_path=str(PROTECTED_RULEPACK), ledger=HitLedger(db))
    grant_path = str(tmp_path / "r2d2" / "grants" / "g1.json")
    payload = json.dumps({"path": grant_path, "content": "mint authority"})

    decision = policy.check("file_write", payload, capabilities=frozenset({"file_write"}))
    policy.record(decision, tool_name="file_write")

    assert decision.action == ACTION_DENY
    assert "guard-grant-files" in decision.matched_rule_ids
    # The attempted agent write is LEDGERED (a hit recorded, not silent).
    assert HitLedger(db).outcomes_for_rule("guard-grant-files") == {"deny": 1}


def test_ed209_denies_directory_wide_delete_of_grants(tmp_path):
    # A directory-wide delete of the grants/authz subtree (WITH or WITHOUT a
    # trailing slash) must be denied: the grants DIRECTORY itself is protected,
    # not just files under it.
    doc = json.loads(PROTECTED_RULEPACK.read_text(encoding="utf-8"))
    assert load_rules(doc), "protected rulepack must not be empty"

    db = str(tmp_path / "hits.db")
    policy = Policy(rules_path=str(PROTECTED_RULEPACK), ledger=HitLedger(db))
    grants_dir = str(tmp_path / "r2d2" / "grants")

    for cmd in (f"rm -rf {grants_dir}", f"rm -rf {grants_dir}/"):
        payload = json.dumps({"command": cmd})
        decision = policy.check("shell", payload, capabilities=frozenset({"shell"}))
        policy.record(decision, tool_name="shell")
        assert decision.action == ACTION_DENY, cmd
        assert "guard-grant-files" in decision.matched_rule_ids, cmd

    # Both attempted deletes are LEDGERED.
    assert HitLedger(db).outcomes_for_rule("guard-grant-files") == {"deny": 2}


# ---------------------------------------------------------------------------
# sourced override: only overridable rules; protected rules reject
# ---------------------------------------------------------------------------

def _tool_ctx(payload, tool_name="Bash", capabilities=frozenset({"shell"})):
    return EvaluationContext(
        profile_home="home",
        client_id="client",
        session_id="sess",
        turn_id="turn",
        surface="tool",
        tool_name=tool_name,
        capabilities=capabilities,
        payload=payload,
    )


def _deny_rule(rule_id, *, overridable):
    return {
        "id": rule_id,
        "surface": "tool",
        "class": "scope",
        "action": "deny",
        "pattern": r"\bSECRET\b",
        "reason": "deny {match}",
        "origin": "test",
        "overridable": overridable,
    }


def test_override_only_for_overridable_rules():
    # A valid override directive on a matching, overridable deny rule lifts the
    # deny for THIS ONE tool call (hit outcome: override).
    overridable = compile_rules(load_rules({"version": 1, "rules": [_deny_rule("r1", overridable=True)]}))
    d = evaluate(overridable, _tool_ctx("# ed209-override: r1 operator reason\necho SECRET"))
    assert d.action == ACTION_OVERRIDE
    assert d.overridden_rule_id == "r1"

    # A protected (non-overridable) deny rule REJECTS the override: deny stands.
    protected = compile_rules(load_rules({"version": 1, "rules": [_deny_rule("r2", overridable=False)]}))
    d2 = evaluate(protected, _tool_ctx("# ed209-override: r2 operator reason\necho SECRET"))
    assert d2.action == ACTION_DENY

    # An empty reason never overrides.
    d3 = evaluate(overridable, _tool_ctx("# ed209-override: r1\necho SECRET"))
    assert d3.action == ACTION_DENY

    # No comment (repeated denial) never implicitly overrides.
    d4 = evaluate(overridable, _tool_ctx("echo SECRET"))
    assert d4.action == ACTION_DENY


def test_override_naming_a_non_matched_rule_has_no_effect():
    compiled = compile_rules(load_rules({"version": 1, "rules": [_deny_rule("r1", overridable=True)]}))
    # The directive names a rule that did not match this call: deny stands.
    d = evaluate(compiled, _tool_ctx("# ed209-override: other reason\necho SECRET"))
    assert d.action == ACTION_DENY


def test_override_token_inside_string_does_not_override():
    overridable = compile_rules(load_rules({"version": 1, "rules": [_deny_rule("r1", overridable=True)]}))
    # The override token is inside a quoted string argument — NOT a leading
    # comment line — so it must NOT lift the deny.
    d = evaluate(overridable, _tool_ctx('echo SECRET && echo "# ed209-override: r1 operator reason"'))
    assert d.action == ACTION_DENY
    # A real comment line (optional leading whitespace + '#') still overrides.
    d2 = evaluate(overridable, _tool_ctx("  # ed209-override: r1 operator reason\necho SECRET"))
    assert d2.action == ACTION_OVERRIDE
