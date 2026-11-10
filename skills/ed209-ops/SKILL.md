---
name: ed209-ops
description: Use when operating the ED-209 guard. List/test/hits/replay and sanctioned rule edits; operator-only. Never edit the guard DB mid-task to escape a hit.
---

# ed209-ops: operate the ED-209 guard

ED-209 is the deterministic behaviour guard. This skill is the SANCTIONED way to
inspect and revise it. The plugin ENFORCES the rules at runtime; this skill only
explains how to operate it honestly — enforcement lives in the plugin, never in
prose.

## Inspect (read-only)

- `ed209 list` — show every rule (enabled AND disabled) with its `origin` provenance.
- `ed209 test-reply <text>` — dry-run a reply phrase against the rules. Prints the decision; never writes the ledger, never consumes a reviewer/block budget, never runs a live check.
- `ed209 test-tool <tool> <payload>` — dry-run a tool payload; reports matched rules and the decision.
- `ed209 hits` — query the REAL ledger of live outcomes (dry-run traffic never lands here). `ed209 hits --rule <id>` restricts to one rule.
- `ed209 replay` — deterministic, non-mutating re-read of recorded hits against the current rules.

## When a deny fires: report the fact, never fabricate

A deny is a fact. Report the matched rule id and the counted fact VERBATIM from
the decision. Do not soften it, do not invent a pass, do not "work around" it.
The override below is the ONLY sanctioned way to lift a deny, and it only ever
works for a single preseeded `overridable` rule for a single call.

## Sourced per-rule opt-in override

The ONLY opt-in syntax is a real comment line at the start of the payload:

```
# ed209-override: <rule-id> <reason>
<payload>
```

Exactly TWO fields, in this order: `<rule-id>` then a NONEMPTY `<reason>`,
separated by whitespace. There is NO operator token. The directive lifts exactly
ONE matched `overridable: true` deny for exactly ONE tool call, recorded as the
hit outcome `override` (durable, never silent). It never overrides a protected
(non-overridable) rule, never changes policy, is never a policy-off, and is NOT
kill authority (grants are the only kill authority). A blank reason never
overrides; a token smuggled inside a quoted string argument never overrides.

## Sanctioned rule revisions

- `ed209 add ...` — append a NEW rule (atomic, validated). `add` may only add: it never weakens an enabled deny, never changes limits, and can never mark a rule `overridable`.
- `ed209 disable <rule-id> --operator <marker>` — flip a rule off (the entry is preserved, never deleted); requires an explicit human operator marker.
- `ed209 enable <rule-id> --operator <marker>` — flip a rule back on; same operator gate.

`disable`/`enable`/`add` refuse automatic-agent-recovery markers and record
who/when. Kill authority (scoped, single-use, TTL-bound) is a SEPARATE
operator-only mechanism — `r2d2 grant issue` — never an override, never a CLI
`policy-off`.

## Never

NEVER edit the guard DB / rules document mid-task to escape a hit. A hit is a
signal to escalate or correct through the sanctioned path — not something to
silently delete.
