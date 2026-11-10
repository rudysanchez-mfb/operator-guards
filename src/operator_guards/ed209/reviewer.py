"""Second-family reviewer adapter (Task 4).

Turns an ``escalate`` decision (``reviewer_status == "deferred"``) into a
validated second opinion from an *independently configured* model family.

Contracts honored (plan §2/§4, C4):

* **Independence, not a mirror.** A reviewer route whose family matches the
  parent/inherited delegation model family is REJECTED at construction
  (``ReviewerError``) — the parent's own delegation model can never pass as a
  supposed second opinion. This is *exact-string equality* on the configured
  family ids, not model-lineage resolution: two routes naming different ids
  that resolve to the same underlying model are NOT detected.
* **Bounded host-fitting deadline.** The reviewer runs under a short,
  configurable, hard-capped deadline that fits the actual host pre-tool
  callback budget — NOT the Mac 50s escalate timeout. A route whose timeout
  exceeds the host budget returns ``unavailable`` (it cannot fit), and a
  non-positive timeout is invalid. No late result may authorize a completed
  call: once ``review()`` returns, its verdict is frozen.
* **Validated structured verdict.** ``{verdict, counted_fact, correction}``.
  Malformed / empty / wrong-shaped / timeout / unavailable-route ⇒
  ``status == "unavailable"`` — never approval.
* **Recursion marker.** Reviewer subprocesses carry a scoped recursion marker
  that exempts ONLY reviewer re-escalation (no infinite loop), never
  deterministic protected-path policy (deny/block/cwd). There is no
  agent-controllable ``ED209=off`` escape hatch.
* **Sanitized context.** The payload sent to the reviewer is bounded and
  stripped of configured secrets + secret-shaped assignments.
* **Correction is data.** The reviewer's ``correction`` text is carried as a
  string only; it is never shell-run or otherwise executed.

The transport is pluggable (a callable ``transport(payload) -> str``); no
network client is imported at module import time.
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, replace
from typing import Callable, Iterable

from .engine import (
    ACTION_ALLOW,
    ACTION_DENY,
    CONTEXT_MAX_CHARS,
    COUNTED_FACT_MAX_CHARS,
    STATUS_UNAVAILABLE,
)

STATUS_OK = "ok"

# Bounded reviewer-verdict domain (the handoff: "block ⇒ deny / turn continues").
REVIEWER_VERDICT_BLOCK = "block"
REVIEWER_VERDICT_ALLOW = "allow"
VALID_REVIEWER_VERDICTS = frozenset({REVIEWER_VERDICT_BLOCK, REVIEWER_VERDICT_ALLOW})

# Scoped recursion marker: exempts ONLY reviewer recursion, never deny policy.
RECURSION_MARKER = "reviewer-recursion"

# Host pre-tool callback budget. Short on purpose; NOT the Mac 50s.
DEFAULT_HOST_DEADLINE_SECONDS = 2.0
MAX_HOST_DEADLINE_SECONDS = 5.0

# Bounds (reuse existing bound constants where they exist).
REVIEWER_FACT_MAX_CHARS = COUNTED_FACT_MAX_CHARS  # 500
REVIEWER_CORRECTION_MAX_CHARS = CONTEXT_MAX_CHARS  # 2000

REDACTED = "[REDACTED]"

# Visible degradation markers (never silent).
DEGRADED_EMPTY = "reviewer:empty"
DEGRADED_MALFORMED = "reviewer:malformed"
DEGRADED_TIMEOUT = "reviewer:timeout"
DEGRADED_RECURSION = "reviewer:recursion"
DEGRADED_DEADLINE_EXCEEDS_HOST = "reviewer:deadline_exceeds_host"
DEGRADED_INVALID_TIMEOUT = "reviewer:invalid_timeout"
DEGRADED_TRANSPORT_ERROR = "reviewer:transport_error"
DEGRADED_UNAVAILABLE_ROUTE = "reviewer:unavailable_route"


class ReviewerError(Exception):
    """Raised when a reviewer route is misconfigured (e.g. same-family)."""


class ReviewerTimeout(Exception):
    """Internal: the transport did not answer within the bounded deadline."""


@dataclass(frozen=True)
class ReviewerRoute:
    """An independently configured reviewer route.

    ``family`` is the model family id that must differ (exact-string) from the
    parent's delegation family id; ``timeout_s`` is the route's configured
    timeout and must fit the host's pre-tool budget. Family independence is a
    string-id check, not model-lineage resolution.
    """

    family: str
    model: str
    transport: str
    timeout_s: float


@dataclass(frozen=True)
class ReviewerContext:
    """Bounded, sanitizable snapshot handed to the reviewer.

    ``recursion_marker`` is set only for reviewer subprocesses (see
    :func:`mark_reviewer_recursion`); it scopes reviewer-recursion exemption,
    nothing else.
    """

    surface: str = "tool"
    tool_name: str = ""
    payload: str = ""
    candidate_text: str = ""
    counted_fact: str = ""
    reviewer_depth: int = 0
    recursion_marker: str = ""


@dataclass(frozen=True)
class ReviewResult:
    """Outcome of a reviewer call. ``status`` is ``ok`` or ``unavailable``.

    ``verdict`` / ``counted_fact`` / ``correction`` are only meaningful when
    ``status == "ok"``; ``degraded`` carries visible failure markers.
    """

    status: str
    verdict: str = ""
    counted_fact: str = ""
    correction: str = ""
    degraded: tuple = ()


# ---------------------------------------------------------------------------
# Recursion marker
# ---------------------------------------------------------------------------

def is_reviewer_recursion(marker: str) -> bool:
    """Recognize the scoped reviewer-recursion marker.

    Only reviewer recursion is exempted by this marker. An ``off``-style
    string (``"off"``, ``"ED209=off"``, ``""``, ``None``) is NOT a marker and
    exempts nothing — there is no agent-controllable escape hatch.
    """
    return marker == RECURSION_MARKER


def mark_reviewer_recursion(context: ReviewerContext) -> ReviewerContext:
    """Return a copy of ``context`` marked as a reviewer subprocess."""
    return replace(
        context,
        recursion_marker=RECURSION_MARKER,
        reviewer_depth=context.reviewer_depth + 1,
    )


# ---------------------------------------------------------------------------
# Sanitization / bounding
# ---------------------------------------------------------------------------

_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?P<key>api[_-]?key|token|secret|password|passwd|authorization)\b"
    r"(?P<sep>\s*[\"']?\s*[=:]\s*)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^,\r\n;\"']+)"
)


def _redact_assignment(m: "re.Match") -> str:
    # Redact the ENTIRE credential value (e.g. "Bearer sk-..."), not just the
    # first whitespace-delimited token; preserve the key and separator. Values
    # run to end-of-line / a quote / a delimiter (`,` or `;`). Patterns are
    # fixed literals (never payload- or user-derived), so no ReDoS risk.
    return f"{m.group('key')}{m.group('sep')}[REDACTED]"


def _bound(text: object, limit: int) -> str:
    if not isinstance(text, str):
        text = str(text)
    if len(text) > limit:
        text = text[:limit]
    return re.sub(r"\s+", " ", text)


def sanitize_context(
    text: object,
    *,
    secrets: Iterable[str] = (),
    max_chars: int = CONTEXT_MAX_CHARS,
) -> str:
    """Bound and redact the context sent to the reviewer (no raw secrets)."""
    if not isinstance(text, str):
        text = str(text)
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    text = _SECRET_ASSIGNMENT_RE.sub(_redact_assignment, text)
    if len(text) > max_chars:
        text = text[:max_chars]
    return text


def build_review_payload(
    context: ReviewerContext,
    *,
    secrets: Iterable[str] = (),
    max_chars: int = CONTEXT_MAX_CHARS,
) -> str:
    """Serialize + sanitize the reviewer context into the outbound payload."""
    subject = context.payload if context.surface == "tool" else context.candidate_text
    body = (
        f"surface={context.surface}\n"
        f"tool={context.tool_name}\n"
        f"counted_fact={context.counted_fact}\n"
        f"subject={subject}"
    )
    return sanitize_context(body, secrets=secrets, max_chars=max_chars)


# ---------------------------------------------------------------------------
# Verdict parsing / validation
# ---------------------------------------------------------------------------

def parse_verdict(raw: str):
    """Parse + validate a non-empty reviewer output into (verdict, fact, correction).

    Returns ``None`` on any malformed/wrong-shaped payload. The verdict must be
    in the closed set; ``counted_fact`` must be a non-empty string; a ``block``
    verdict must carry a non-empty ``correction``. Fields are bounded on the
    way out.
    """
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None

    verdict = data.get("verdict")
    fact = data.get("counted_fact")
    correction = data.get("correction")

    if verdict not in VALID_REVIEWER_VERDICTS:
        return None
    if not isinstance(fact, str) or not fact.strip():
        return None
    if not isinstance(correction, str):
        return None
    if verdict == REVIEWER_VERDICT_BLOCK and not correction.strip():
        return None

    return (
        verdict,
        _bound(fact, REVIEWER_FACT_MAX_CHARS),
        _bound(correction, REVIEWER_CORRECTION_MAX_CHARS),
    )


def resolve_review(deterministic_deny: bool, result: ReviewResult) -> str:
    """Resolve a reviewer result into a final outcome, honoring deny precedence.

    Deterministic deny always dominates — a reviewer verdict (even ``allow``)
    can never downgrade it. A reviewer ``block`` denies; ``allow`` allows;
    ``unavailable`` (or any uninterpretable verdict) never authorizes.
    """
    if deterministic_deny:
        return ACTION_DENY
    if result.status != STATUS_OK:
        return STATUS_UNAVAILABLE
    if result.verdict == REVIEWER_VERDICT_BLOCK:
        return ACTION_DENY
    if result.verdict == REVIEWER_VERDICT_ALLOW:
        return ACTION_ALLOW
    return STATUS_UNAVAILABLE


# ---------------------------------------------------------------------------
# Reviewer adapter
# ---------------------------------------------------------------------------

class Reviewer:
    """Independently-configured reviewer with a bounded host-fitting deadline."""

    def __init__(
        self,
        route: ReviewerRoute,
        transport: Callable[[str], str] | None = None,
        *,
        parent_family: str,
        host_deadline: float = DEFAULT_HOST_DEADLINE_SECONDS,
        secrets: Iterable[str] = (),
        clock=time.monotonic,
    ):
        if route.family == parent_family:
            raise ReviewerError(
                f"reviewer route family {route.family!r} matches the parent "
                f"delegation family {parent_family!r}; not an independent "
                f"second opinion"
            )
        self.route = route
        self.transport = transport
        self.parent_family = parent_family
        self.secrets = tuple(s for s in secrets if s)
        self.clock = clock
        self.host_deadline = min(float(host_deadline), MAX_HOST_DEADLINE_SECONDS)

    def review(self, context: ReviewerContext) -> ReviewResult:
        """Return a validated ReviewResult; never raises out of this method."""
        try:
            return self._review(context)
        except ReviewerTimeout:
            return ReviewResult(status=STATUS_UNAVAILABLE, degraded=(DEGRADED_TIMEOUT,))
        except Exception:
            # Fail-open and visible: any internal/transport error becomes
            # unavailable, never an approval.
            return ReviewResult(
                status=STATUS_UNAVAILABLE, degraded=(DEGRADED_TRANSPORT_ERROR,)
            )

    def _review(self, context: ReviewerContext) -> ReviewResult:
        if is_reviewer_recursion(context.recursion_marker):
            # Already a reviewer subprocess: decline rather than re-escalate.
            return ReviewResult(status=STATUS_UNAVAILABLE, degraded=(DEGRADED_RECURSION,))

        if self.transport is None:
            return ReviewResult(
                status=STATUS_UNAVAILABLE, degraded=(DEGRADED_UNAVAILABLE_ROUTE,)
            )

        if self.route.timeout_s <= 0:
            return ReviewResult(
                status=STATUS_UNAVAILABLE, degraded=(DEGRADED_INVALID_TIMEOUT,)
            )
        if self.route.timeout_s > self.host_deadline:
            # The route's timeout cannot fit the host pre-tool budget.
            return ReviewResult(
                status=STATUS_UNAVAILABLE, degraded=(DEGRADED_DEADLINE_EXCEEDS_HOST,)
            )

        payload = build_review_payload(context, secrets=self.secrets)
        raw = self._run_with_deadline(self.transport, payload, self.route.timeout_s)

        if raw is None:
            return ReviewResult(status=STATUS_UNAVAILABLE, degraded=(DEGRADED_EMPTY,))
        if not isinstance(raw, str):
            return ReviewResult(status=STATUS_UNAVAILABLE, degraded=(DEGRADED_MALFORMED,))
        if not raw.strip():
            return ReviewResult(status=STATUS_UNAVAILABLE, degraded=(DEGRADED_EMPTY,))

        parsed = parse_verdict(raw)
        if parsed is None:
            return ReviewResult(status=STATUS_UNAVAILABLE, degraded=(DEGRADED_MALFORMED,))

        verdict, fact, correction = parsed
        return ReviewResult(
            status=STATUS_OK, verdict=verdict, counted_fact=fact, correction=correction
        )

    def _run_with_deadline(self, transport, payload: str, deadline: float) -> str:
        """Call the transport with a hard deadline; raise ReviewerTimeout on expiry.

        A daemon thread runs the transport so a stuck transport can never hang
        the caller; any result arriving after the deadline is discarded (the
        caller has already returned ``unavailable``).
        """
        box: dict = {}

        def worker():
            try:
                box["out"] = transport(payload)
            except BaseException as exc:  # noqa: BLE001 — surface to caller
                box["err"] = exc

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout=deadline)
        if t.is_alive():
            raise ReviewerTimeout(deadline)
        if "err" in box:
            raise box["err"]
        return box.get("out")
