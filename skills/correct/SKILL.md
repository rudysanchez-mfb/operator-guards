---
name: correct
description: Use when Rudy corrects the guard. Preserve the correction verbatim; encode it as the smallest sourced rule via `ed209 correct`.
---

# correct: turn Rudy's correction into a sourced rule

When Rudy corrects the ED-209 guard's behaviour, capture it faithfully and
encode it as the SMALLEST sourced rule — never a broad rewrite, never a silent
weakening of another rule. Enforcement (verbatim origin, deny-weakening guard,
provenance) lives in the `ed209 correct` CLI verb; this skill explains the
deterministic workflow.

## Preserve the correction VERBATIM

`ed209 correct` embeds the correction word-for-word as the rule's `origin`,
with `--operator` (who is acting) and `--date` attribution, so the rule's
provenance traces to exactly what was said. Pass the correction to `--text`
unchanged: do not paraphrase, do not merge corrections, do not invent intent.

## Generate the smallest sourced rule + tests

1. Find the MINIMAL pattern that captures the correction — the narrowest regex
   that matches the corrected behaviour, not a superset that would over-fire.
2. `ed209 correct --text "<Rudy verbatim>" --id <id> --surface tool|reply --class <class> --action <action> --pattern <pattern> --reason <reason> --operator <marker> [--date YYYY-MM-DD]`.
   `ed209 correct` performs the sanctioned `ed209 add` ONLY: it appends a new
   rule, never weakens an enabled deny (a deny may not be superseded by a
   non-deny successor), never changes limits, and can never mark a rule
   `overridable`. A NON-deny rule MAY be superseded via a `-vN` successor id
   (the successor captures the superseded rule's origin). Same inputs
   (including `--date`) produce the same rule — it is deterministic.
3. Write a POSITIVE and a NEGATIVE test with `ed209 test-reply` / `ed209 test-tool`:
   one payload that MUST match and one that MUST NOT. Confirm both before the
   correction is considered landed.
4. Verify with `ed209 list` — the new rule and its verbatim origin must be visible.

## Save provenance + checklist, without weakening others

Record the correction (verbatim), the rule id, and the pass/fail test results in
the correction checklist. Adding a rule must NEVER disable, widen, or supersede
an existing deny — if the correction would weaken a rule, `ed209 correct`
refuses and you must STOP and ask Rudy rather than editing the guard DB.

`ed209 correct` is DETERMINISTIC — the correction is applied exactly as stated.
Automatic correction-phrase detection is SUPPLEMENTAL: it may surface a
candidate, but it MUST NOT fabricate user intent or apply a change Rudy never
made. There is no slash command for corrections; the CLI verb `ed209 correct`
is the deterministic path.
