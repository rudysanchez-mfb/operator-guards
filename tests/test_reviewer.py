"""Reviewer adapter tests (Task 4).

Locks the C4 contract from the plan and ED-209-HANDOFF.md §4/§7: an
independently-configured reviewer route (NEVER the parent's inherited
delegation model family), a bounded host-fitting deadline (NOT the Mac 50s),
a validated structured {verdict, counted_fact, correction} verdict, a scoped
recursion marker that exempts ONLY reviewer recursion (never deterministic
deny), sanitized/bounded context, deterministic-deny precedence, and a
correction field that is data-only (never executed).

All transports are local deterministic fixtures; no network/paid provider.
"""

import json
import threading
import time
from dataclasses import FrozenInstanceError

import pytest

from operator_guards.ed209.engine import (
    ACTION_ALLOW,
    ACTION_DENY,
    EvaluationContext,
    evaluate,
)
from operator_guards.ed209.reviewer import (
    DEGRADED_DEADLINE_EXCEEDS_HOST,
    DEGRADED_EMPTY,
    DEGRADED_INVALID_TIMEOUT,
    DEGRADED_MALFORMED,
    DEGRADED_RECURSION,
    DEGRADED_TIMEOUT,
    DEGRADED_TRANSPORT_ERROR,
    MAX_HOST_DEADLINE_SECONDS,
    RECURSION_MARKER,
    REVIEWER_VERDICT_ALLOW,
    REVIEWER_VERDICT_BLOCK,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    VALID_REVIEWER_VERDICTS,
    Reviewer,
    ReviewerContext,
    ReviewerError,
    ReviewerRoute,
    ReviewResult,
    is_reviewer_recursion,
    mark_reviewer_recursion,
    resolve_review,
    sanitize_context,
)
from operator_guards.ed209.rules import Rule, compile_rules


# --- fixtures ---------------------------------------------------------------

def _ctx(payload="echo hello", **kw):
    return ReviewerContext(surface="tool", tool_name="Bash", payload=payload, **kw)


def _ok(verdict="block", fact="matched fact", correction="correction"):
    return json.dumps(
        {"verdict": verdict, "counted_fact": fact, "correction": correction}
    )


def _transport(return_value):
    def t(payload):
        t.seen = payload
        return return_value
    return t


def _reviewer(transport, route=None, parent_family="parent", host_deadline=1.0, **kw):
    route = route or ReviewerRoute(
        family="child", model="m", transport="fixture", timeout_s=0.5
    )
    return Reviewer(route, transport, parent_family=parent_family,
                    host_deadline=host_deadline, **kw)


# --- validated structured verdict -------------------------------------------

def test_valid_block_verdict_ok():
    r = _reviewer(_transport(_ok("block")))
    res = r.review(_ctx())
    assert res.status == STATUS_OK
    assert res.verdict == REVIEWER_VERDICT_BLOCK
    assert res.counted_fact == "matched fact"
    assert res.correction == "correction"


def test_valid_allow_verdict_ok_with_empty_correction():
    raw = json.dumps({"verdict": "allow", "counted_fact": "ok", "correction": ""})
    r = _reviewer(_transport(raw))
    res = r.review(_ctx())
    assert res.status == STATUS_OK
    assert res.verdict == REVIEWER_VERDICT_ALLOW


def test_valid_reviewer_verdicts_closed():
    assert VALID_REVIEWER_VERDICTS == frozenset({"block", "allow"})


# --- empty / malformed ⇒ unavailable (NEVER approval) -----------------------

def test_empty_output_unavailable():
    r = _reviewer(_transport(""))
    res = r.review(_ctx())
    assert res.status == STATUS_UNAVAILABLE
    assert res.verdict == ""
    assert DEGRADED_EMPTY in res.degraded


def test_malformed_json_unavailable():
    r = _reviewer(_transport("not json{"))
    res = r.review(_ctx())
    assert res.status == STATUS_UNAVAILABLE
    assert DEGRADED_MALFORMED in res.degraded


def test_malformed_verdict_value_unavailable():
    r = _reviewer(_transport(_ok(verdict="maybe")))
    res = r.review(_ctx())
    assert res.status == STATUS_UNAVAILABLE
    assert DEGRADED_MALFORMED in res.degraded


def test_missing_counted_fact_unavailable():
    raw = json.dumps({"verdict": "block", "correction": "c"})
    res = _reviewer(_transport(raw)).review(_ctx())
    assert res.status == STATUS_UNAVAILABLE


def test_wrong_typed_counted_fact_unavailable():
    raw = json.dumps({"verdict": "block", "counted_fact": 123, "correction": "c"})
    res = _reviewer(_transport(raw)).review(_ctx())
    assert res.status == STATUS_UNAVAILABLE


def test_block_without_correction_unavailable():
    raw = json.dumps({"verdict": "block", "counted_fact": "f", "correction": ""})
    res = _reviewer(_transport(raw)).review(_ctx())
    assert res.status == STATUS_UNAVAILABLE


# --- bounded host-fitting deadline (NOT the Mac 50s) -------------------------

def test_timeout_unavailable():
    def slow(payload):
        time.sleep(1.0)
        return _ok("block")

    route = ReviewerRoute(family="child", model="m", transport="fixture", timeout_s=0.1)
    r = Reviewer(route, slow, parent_family="parent", host_deadline=1.0)
    start = time.monotonic()
    res = r.review(_ctx())
    elapsed = time.monotonic() - start
    assert res.status == STATUS_UNAVAILABLE
    assert DEGRADED_TIMEOUT in res.degraded
    assert elapsed < 2.0  # bounded: never hangs the pre-tool callback


def test_mac_50s_route_does_not_fit_host_budget():
    called = []
    def t(payload):
        called.append(payload)
        return _ok("block")

    route = ReviewerRoute(family="child", model="gpt-5.4", transport="remote",
                          timeout_s=50.0)
    r = Reviewer(route, t, parent_family="parent", host_deadline=5.0)
    res = r.review(_ctx())
    assert res.status == STATUS_UNAVAILABLE
    assert DEGRADED_DEADLINE_EXCEEDS_HOST in res.degraded
    assert called == []  # never attempted within the short pre-tool budget


def test_nonpositive_route_timeout_unavailable():
    route = ReviewerRoute(family="child", model="m", transport="t", timeout_s=0.0)
    r = Reviewer(route, _transport(_ok()), parent_family="parent", host_deadline=1.0)
    res = r.review(_ctx())
    assert res.status == STATUS_UNAVAILABLE
    assert DEGRADED_INVALID_TIMEOUT in res.degraded


def test_host_deadline_hard_capped():
    route = ReviewerRoute(family="c", model="m", transport="t", timeout_s=0.1)
    r = Reviewer(route, _transport(_ok()), parent_family="p", host_deadline=999.0)
    assert r.host_deadline == MAX_HOST_DEADLINE_SECONDS


def test_no_late_result_authorizes_completed_call():
    gate = threading.Event()
    def slow(payload):
        gate.wait(10)  # blocks until released, then returns a late "allow"
        return _ok("allow")

    route = ReviewerRoute(family="child", model="m", transport="fixture", timeout_s=0.1)
    r = Reviewer(route, slow, parent_family="parent", host_deadline=1.0)
    res = r.review(_ctx())
    assert res.status == STATUS_UNAVAILABLE

    gate.set()        # the late "allow" arrives AFTER the call already completed
    time.sleep(0.1)   # let the daemon thread finish writing its (ignored) result
    assert res.status == STATUS_UNAVAILABLE  # unchanged: no late approval
    assert res.verdict == ""


# --- family-independence check ----------------------------------------------

def test_same_family_route_rejected():
    route = ReviewerRoute(family="gpt-5.4", model="m", transport="t", timeout_s=1.0)
    with pytest.raises(ReviewerError):
        Reviewer(route, _transport(_ok()), parent_family="gpt-5.4")


def test_distinct_family_accepted():
    route = ReviewerRoute(family="cursor", model="m", transport="t", timeout_s=1.0)
    r = Reviewer(route, _transport(_ok()), parent_family="gpt-5.4")
    assert r.route.family == "cursor"


# --- recursion marker: scoped to reviewer recursion only ---------------------

def test_recursion_marker_recognition():
    assert is_reviewer_recursion(RECURSION_MARKER) is True
    assert is_reviewer_recursion("") is False
    assert is_reviewer_recursion(None) is False
    # An "off"-style string is NOT a recursion marker and exempts nothing.
    assert is_reviewer_recursion("off") is False
    assert is_reviewer_recursion("ED209=off") is False


def test_mark_reviewer_recursion_sets_marker_and_depth():
    ctx = ReviewerContext(payload="x", reviewer_depth=0)
    marked = mark_reviewer_recursion(ctx)
    assert is_reviewer_recursion(marked.recursion_marker)
    assert marked.reviewer_depth == 1
    assert ctx.reviewer_depth == 0  # original untouched (frozen)


def test_recursion_context_does_not_reescalate():
    called = []
    def t(payload):
        called.append(payload)
        return _ok("block")

    r = _reviewer(t)
    res = r.review(mark_reviewer_recursion(ReviewerContext(payload="x")))
    assert res.status == STATUS_UNAVAILABLE
    assert DEGRADED_RECURSION in res.degraded
    assert called == []  # transport never invoked → no infinite re-escalation


def test_recursion_marker_does_not_disable_deterministic_deny():
    rule = Rule(
        id="d", surface="tool", rule_class="known-bad", action="deny",
        pattern=r"\bSECRET\b", reason="denied '{match}'", origin="t",
    )
    compiled = compile_rules([rule])
    ctx = EvaluationContext(
        profile_home="/h", client_id="c", session_id="s", turn_id="t",
        surface="tool", tool_name="Bash", capabilities=frozenset({"shell"}),
        payload="echo SECRET",
    )
    assert evaluate(compiled, ctx).action == ACTION_DENY
    # The recursion marker scopes ONLY reviewer recursion; there is no
    # agent-controllable "off" switch that disables deterministic deny.
    assert is_reviewer_recursion(RECURSION_MARKER)
    assert not is_reviewer_recursion("off")


# --- sanitized / bounded context --------------------------------------------

def test_sanitized_context_secret_absent():
    secret = "sk-1234567890abcdef"
    seen = {}
    def t(payload):
        seen["payload"] = payload
        return _ok("allow")

    route = ReviewerRoute(family="child", model="m", transport="t", timeout_s=0.5)
    r = Reviewer(route, t, parent_family="parent", host_deadline=1.0, secrets=(secret,))
    res = r.review(ReviewerContext(payload=f"run with {secret} please"))
    assert res.status == STATUS_OK
    assert secret not in seen["payload"]
    assert "[REDACTED]" in seen["payload"]


def test_sanitize_context_redacts_secret_assignment():
    out = sanitize_context("call with password=hunter2 and api_key=abc123")
    assert "hunter2" not in out
    assert "abc123" not in out
    assert "[REDACTED]" in out


def test_sanitize_context_redacts_bearer_authorization():
    # The ENTIRE credential (Bearer + token), not just the "Bearer" word.
    out = sanitize_context("Authorization: Bearer sk-abc123def456")
    assert "sk-abc123def456" not in out
    assert "Bearer" not in out
    assert "[REDACTED]" in out


def test_sanitize_context_redacts_bearer_authorization_equals():
    out = sanitize_context("authorization=Bearer sk-abc123def456")
    assert "sk-abc123def456" not in out
    assert "Bearer" not in out
    assert "[REDACTED]" in out


def test_sanitize_context_redacts_json_object_secrets():
    # Quoted JSON keys ("password", "token", …) with a ": value" must redact.
    out = sanitize_context('{"password": "hunter2", "token": "xyz"}')
    assert "hunter2" not in out
    assert "xyz" not in out
    assert "[REDACTED]" in out


def test_sanitize_context_bounded():
    out = sanitize_context("x" * 10000, max_chars=2000)
    assert len(out) <= 2000


# --- deterministic-deny precedence ------------------------------------------

def test_deterministic_deny_precedence_over_reviewer_verdict():
    allow = ReviewResult(status=STATUS_OK, verdict=REVIEWER_VERDICT_ALLOW,
                         counted_fact="f", correction="c")
    block = ReviewResult(status=STATUS_OK, verdict=REVIEWER_VERDICT_BLOCK,
                         counted_fact="f", correction="c")
    unavail = ReviewResult(status=STATUS_UNAVAILABLE)

    # deterministic deny dominates even a reviewer "allow"
    assert resolve_review(True, allow) == ACTION_DENY
    # reviewer block → deny
    assert resolve_review(False, block) == ACTION_DENY
    # reviewer allow → allow (no deterministic deny)
    assert resolve_review(False, allow) == ACTION_ALLOW
    # unavailable never authorizes
    assert resolve_review(False, unavail) == STATUS_UNAVAILABLE


# --- correction is data-only ------------------------------------------------

def test_correction_never_executed(tmp_path):
    marker = tmp_path / "pwned"
    correction = f"touch {marker}"
    r = _reviewer(_transport(_ok(verdict="block", correction=correction)))
    res = r.review(_ctx())
    assert res.status == STATUS_OK
    assert res.correction == correction  # carried verbatim as data
    assert not marker.exists()  # the prose was never shell-run


# --- never raise out; fail-open ---------------------------------------------

def test_transport_exception_never_raises_out():
    def boom(payload):
        raise RuntimeError("boom")

    res = _reviewer(boom).review(_ctx())
    assert res.status == STATUS_UNAVAILABLE
    assert DEGRADED_TRANSPORT_ERROR in res.degraded


def test_missing_transport_unavailable_route():
    route = ReviewerRoute(family="child", model="m", transport="remote", timeout_s=0.5)
    r = Reviewer(route, None, parent_family="parent", host_deadline=1.0)
    res = r.review(_ctx())
    assert res.status == STATUS_UNAVAILABLE


# --- immutability -----------------------------------------------------------

def test_review_result_is_frozen():
    res = ReviewResult(status=STATUS_OK, verdict="block", counted_fact="f", correction="c")
    with pytest.raises(FrozenInstanceError):
        res.verdict = "allow"
