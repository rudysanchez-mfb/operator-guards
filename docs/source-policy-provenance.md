# Source-backed policy provenance (optional layer)

`operator_guards.ed209.source_policy` is a port of the live ED-209
`ed209_policy.py` module. It guards against agent-invented standing policies; it
does **not** introduce an approval step for merging, deploying, or other
already-authorized task work.

## Contract

- `propose(rule, source_path, message_id, quote, *, store=None, activate=True)`
  records an executable-rule proposal with its original exact user quotation and
  message hash. With `activate=True` (the source default) it also installs the
  proposal under a verified-quote approval.
- `activate(proposal_id, source_path, message_id, *, store=None)` requires a
  genuine user message whose entire stripped text is
  `activate policy <digest>`. This binds acceptance to the executable rule
  content and its original source, not to a paraphrase.
- `load_baseline(*, store=None)` verifies the byte SHA-256 of `baseline.json`
  against `baseline.sha256`. Integrity failure raises `PolicyError`.
- `load_rules(*, store=None)` loads the legacy baseline plus valid active
  policies. Every active receipt is revalidated against its transcript message.
  Any invalid active record rejects the entire active overlay and retains the
  unchanged legacy baseline, reporting `_policy_errors`.

## Transcript adapters

Supported input is JSONL only:

- Claude: `type: "user"` entries with a `message.role == "user"` and string or
  text-block content; identifiers are `uuid`/`id` or `line:N` (one-based).
- Codex: `type: "event_msg"` with `payload.type == "user_message"`; identifier is
  `line:N` when no id exists.

Assistant messages, tool-result blocks, sidechains, meta, synthetic, and
compact-summary messages are rejected. Quotation must be an exact non-empty
substring. Appending later transcript messages is allowed; changing the cited
message invalidates its receipt.

`find_source` searches the newest matching genuine user message across the
configured roots. Set `OPERATOR_GUARDS_SOURCE_ROOTS` (os.pathsep separated) to
change them; the default remains the Claude and Codex transcript locations.

## Store location

The default store is `<OPERATOR_GUARDS_HOME>/ed209/policy` (falling back to
`HERMES_HOME` and then `~/.hermes`). Override it with
`OPERATOR_GUARDS_POLICY_STORE`. Tests pass an explicit temporary store.

`observations/` holds non-authoritative notes and is never loaded as policy.
Proposal bodies are content-addressed. `active.json` contains active records and
explicit superseded history. Activation replaces the active entry for the same
rule ID and retains superseded history. Atomic file replacement and a file lock
serialize cooperating writers.

## What this does NOT establish

A matching quote proves that text exists in the message; it does not establish
that an inferred executable rule follows from the text. Exact digest acceptance
addresses that separate interpretation problem. The store, source receipts,
transcripts, loader, and callers need external protection. A writer able to
replace files and their hashes can forge provenance. This is **not**
cryptographic authentication of user identity and **not** an OS security
boundary. Same-UID processes are not isolated from each other.

This module is **not wired into the Hermes plugin's runtime rule loader**. The
plugin enforces the operator-authored `rules.json` document. The provenance
layer is an optional, separate mechanism.
