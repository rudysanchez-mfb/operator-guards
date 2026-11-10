# Rule migration — ED-209 → operator-guards

## Classification: `documented-initial`

The initial rule set is **`documented-initial`**. The handoff bundle contained
no original ED-209 rule export (`rules.json`), so the 161-rule export (118
enabled) described in the handoff is absent.

Consequences, stated plainly:

- This port **cannot** claim `full parity` or `verified-export` for the rule set.
- `documented-initial` means the initial rule set is derived from the written
  schema contract only, not from a migrated `rules.json`.
- Missing disabled rules and missing `origin` fields are **not invented**.

`rulepacks/operator-guards-protected.json` is an additive, documented set of
non-overridable protected-path deny rules. It is not a replacement for the
absent legacy export.

## Rule schema

Top-level shape:

```json
{
  "version": 1,
  "_about": "...",
  "reviewer": { "chain": ["copilot", "cursor"], "model": "gpt-5.4", "timeout_s": 50 },
  "limits": { "max_blocks_per_session": 12, "max_reviewer_calls_per_session": 12 },
  "rules": [ ... ]
}
```

Each rule: `id`, `surface`, `class`, `action`, `pattern` (Python `re`),
`reason`, `origin`, `enabled`; optional `tools`, `exempt`, `memory`, `check`,
`requires`, `cwd`, `overridable`.

Loader contract:

- Omitted `enabled` defaults to **True**.
- Duplicate rule ids are rejected.
- Invalid regex patterns are rejected.
- An empty rules list is schema-valid (no deterministic rules configured).

## Boundary

ED-209 watches behaviour; R2-D2 watches capability. R2-D2 may never route
around ED-209; its one path to a rule is the sanctioned `ed209 add` command with
an origin, ledgered.
