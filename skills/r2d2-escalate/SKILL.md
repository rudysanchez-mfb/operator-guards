---
name: r2d2-escalate
description: Use when an R2-D2 incident needs escalation. Ask bad-decision vs missing-capability, recover once, then raise durably; never a third denied retry.
---

# r2d2-escalate: escalate a capability incident durably

R2-D2 is the capability-recovery guard. When a capability is lost or repeatedly
denied, escalate through this skill. The executor/observer ENFORCE the bounds
(recovery backoff, denial window, no third denied retry); this skill explains
them.

## First: classify the failure

Ask one question: is this a BAD DECISION (policy denied something the operator
actually wants) or a MISSING CAPABILITY (a tool/transport is gone)? They are
handled differently — a missing capability is recovered or escalated; a policy
denial is a diagnosis, not a retry.

## Check the supervisor is alive

`r2d2 watch` reports the supervisor heartbeat (fresh / stale / absent) and each
client's status WITHOUT changing anything — a DRY-RUN, never a mutator.
`r2d2 doctor` reports ED-209 coverage, unsupported adapters, and degraded policy
without modifying state. Use both before acting.

If the supervisor is DEAD (absent or stale): do NOT wait. Emit a LOCAL alert and
state the exact operator action. Waiting for a dead daemon is wasted time.

## Recover ONCE, within native limits

Perform the available in-session recovery ONCE (respecting native reconnect
backoff). Then re-check. Do not loop: a third denied retry is forbidden.

## Raise durably

`r2d2 raise --id <id> --severity <severity> --symptom <symptom>` — the id is
printed only AFTER the incident is durably committed (no silent success id).
`r2d2 status` lists committed incidents; `r2d2 status --id <id>` shows one.
`r2d2 events` lists the committed event log.

Close only with real evidence: `r2d2 done --id <id> --proof PASS` (a structural
PASS verdict — a blank or prose proof cannot authorize closure) or a manual
`--reason`, which ESCALATES (distinct from verified resolution).

## Waiting is a MAXIMUM, not a delay

When the supervisor is ALIVE, bounded observation windows (roughly two minutes
each, at most three) are allowed. They are a MAXIMUM, not a mandatory delay
after resolution — once the incident is resolved, release user interaction
immediately; expose heartbeat/status while waiting.

## Kill authority is operator-only

A scoped, single-use, TTL-bound kill grant is the ONLY kill authority:
`r2d2 grant issue`, `r2d2 grant list`, `r2d2 grant revoke`. These refuse
daemon/model execution; an operator must issue them explicitly.
