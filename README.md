# operator-guards

Standalone Python library and Hermes plugin pair for two operator guards:

- **ED-209** — deterministic behaviour rules for tool calls and final replies.
- **R2-D2** — bounded capability observation, durable incidents, and
  operator-authorized recovery.

```text
┌─────────────────────────────────────────────────────────────┐
│                       AI CODING AGENT                       │
└──────────────┬──────────────────────────────▲───────────────┘
               │ Tool Call                    │ Tool Result / Veto
               ▼                              │
     ┌──────────────────┐                     │
     │  ED-209 ENGINE   │                     │
     │  Pre-Tool Hook   │──[ Deny / Veto ]────┘
     └─────────┬────────┘
               │ Allowed
               ▼
     ┌──────────────────┐
     │ TARGET SUBSYSTEM │ (Shell / Filesystem / MCP / Database)
     └─────────┬────────┘
               │
               ▼
     ┌──────────────────┐
     │  R2-D2 OBSERVER  │ ──► [ Incident Log ]
     │  Supervisor Loop │ ──► [ Grant Ledger ] ──► [ Remediate ]
     └──────────────────┘
```

This is the standalone distribution of the coordinated ED-209 and R2-D2 operator guards under Apache-2.0. No live profile, service, unit, database, transcript, or credential is included.

## Status and scope

| Item | Status |
| :--- | :--- |
| Python library (`src/operator_guards`) | Included, stdlib-only runtime |
| Hermes plugins (`plugins/ed209`, `plugins/r2d2`) | Included |
| Operator skills (`skills/`) | Included |
| Rulepacks (`rulepacks/`) | `documented-initial` + protected additions |
| Installer / rollback / systemd unit (`deploy/`) | Included; **dry-run only here** |
| Package tests (`tests/`) | Included; `627 passed, 23 skipped` in an isolated venv |
| Full 161-rule legacy export | **Not included** (absent from the source handoff) |
| Non-Hermes harness hooks (Claude Code, Codex, Copilot, Cursor) | **Not included** |
| Live installation / service start | **Not performed** |

## What is actually supported

### ED-209 engine

- Surfaces: `tool`, `reply`.
- Actions: `deny`, `block`, `escalate`, `check`, `inject`, `memory-first`,
  `log`.
- Deterministic precedence: any matched `deny` wins; otherwise the highest
  priority matched action is returned.
- Capability binding via the **documented subset** in
  `src/operator_guards/ed209/capabilities.py` (Bash/terminal, read/write/edit
  aliases, a few MCP aliases, deferred wrappers, canonical capability names).
  This table is deliberately not exhaustive. An unknown tool with no resolved
  capabilities is surfaced as `unbound_tool` / `unbound_mutating` degradation —
  **never silently treated as safe**.
- Sourced overrides (`# ed209-override: <rule-id> <reason>`) lift exactly one
  matching **overridable** deny for one call. A protected (non-overridable) deny
  blocks the override. The directive must be an actual comment line with a
  non-empty reason; a token inside a string argument does not count.
- Rule patterns are operator-authored and trusted. Catastrophic regex
  backtracking is a known limitation; matching is bounded but no regex timeout
  is applied.

### Hermes adapter

`plugins/ed209` declares `pre_tool_call`, `post_tool_call`,
`pre_final_response`, and `pre_llm_call`. A hook is registered **only if the
running Hermes runtime lists it as supported**. An unsupported hook is not
registered, is logged, and is exposed by `registration_status()` — it is never
silently inert.

`pre_final_response` is **runtime-dependent**. It exists only in a Hermes
runtime that carries the completion-policy gate; on a runtime without it, reply
policy cannot veto a no-edit final turn through this hook. The plugin reports
that state rather than pretending the capability exists.

`plugins/r2d2` declares `post_tool_call`, `on_session_start`, `on_session_end`,
and `on_session_reset`, with the same supported-only registration rule. Its
periodic heartbeat is driven by the supervisor, not by a declared hook.

### R2-D2 observer predicates

The Linux observer supports:

- `client_process_alive` — `/proc/<pid>/stat` start-time match.
- `heartbeat_fresh` — supervisor heartbeat within 60 s.
- `client_recent` — a quiet-but-alive client is **not** escalated.
- `reconnect_in_progress` — a native reconnect within its window does not summon
  the daemon.
- `transport_drop` — a bounded session-local recovery request.
- `capability_registered` — a registered capability loss raises one incident.
- `permission_block` — diagnosis/escalation only; no mutation plan.
- `policy_denial` — bounded escalation after repeated denials.

`takeover_without_send` is **UNSUPPORTED**. No real takeover/send observer
exists; it is reported unsupported, never fabricated. Reconnect state is
externally populated: the plugin observes transient tool errors but has no real
"the client is reconnecting" signal, so it does not invent one.

### R2-D2 authorization and recovery

- Grants are scoped (`session_stop_resume`), TTL-bounded, nonce-bound,
  identity-bound (session/client/pid/start-time), and consumed **before** the one
  authorized attempt. There is no refund path.
- Grant creation is not an executor operation and cannot be minted from an
  incident payload.
- `rule_add` goes only through the sanctioned ED-209 CLI. `notify_human` is
  bounded. `mcp_reconnect` is **conditional** on a live owning client and
  adapter; without one it reports `unsupported`, never faked.
- `session_stop_resume`, `config_set`, and `takeover_without_send` remain
  **unsupported** adapters.
- Notification channels are local-only unless the operator explicitly opts in.

### Source-backed policy provenance (optional layer)

`operator_guards.ed209.source_policy` is a port of the live provenance module.
It requires a genuine user message and an exact quote, rejects assistant/tool/
meta/sidechain/synthetic messages, and invalidates an active rule when its source
message or proposal content changes. See
[`docs/source-policy-provenance.md`](docs/source-policy-provenance.md).

This layer is **not wired into the Hermes plugin's runtime rule loader**. The
plugin enforces the operator-authored `rules.json`; provenance is a separate,
optional mechanism. A matching quote proves the text exists; it does not prove
the inferred rule follows from it.

## Security boundaries — read this

- **Same-UID is not security isolation.** Every process under the same user can
  read or replace the rules, grants, ledger, policy store, and code. Integrity
  checks detect drift; they do not stop a hostile same-UID writer.
- The guards are procedural defence-in-depth, not an OS sandbox, container, or
  privilege boundary.
- The capability alias table is a documented subset, not complete coverage.
  Unbound tools produce a visible degraded warning; they are not proven safe.
- `# ed209-override` is a per-call, sourced override. It is not independent kill
  authority, and it cannot lift a protected rule.
- Regex rules are trusted operator input; no timeout is applied.
- Provenance receipts are not cryptographic identity authentication.
- A source transcript, rules file, database, or environment credential is never
  published in this tree.

## Safe install (explicit; no live install performed)

Runtime requires Python 3.11–3.14. There are no runtime third-party
dependencies.

```bash
cd operator-guards
uv venv .venv --python 3.12
uv pip install --python .venv/bin/python -e . 'pytest>=8,<10'
```

Or with `venv`/`pip`:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e . pytest
```

Run the tests from the repository root:

```bash
PYTHONPATH=src .venv/bin/python -m pytest -q
```

The deploy tests verify that the rendered systemd unit points at an existing
repo-local `.venv/bin/python`; create `.venv` as shown before running the full
suite. The library and focused provenance/observer/authorization tests do not
need a live profile or service.

The installer is deliberately two-phase. This prints a manifest and changes
nothing:

```bash
.venv/bin/python deploy/install.py --home /tmp/operator-guards-home --repo "$PWD"
```

`--apply` is an operator-gated live action. It was **not** run for this
publication. Do not point `--home` at a real Hermes profile until you have read
`deploy/install.py` and `deploy/rollback.py` and decided the rollout.

The library modules can be exercised directly:

```bash
PYTHONPATH=src .venv/bin/python -m operator_guards.ed209.cli --help
PYTHONPATH=src .venv/bin/python -m operator_guards.r2d2.cli --help
```

## Configuration

Every former hardcoded runtime default is configurable:

| Variable | Meaning | Default |
| :--- | :--- | :--- |
| `OPERATOR_GUARDS_HOME` | profile home | `HERMES_HOME`, else `~/.hermes` |
| `OPERATOR_GUARDS_ED209_RULES` | rules document | `<home>/ed209/rules.json` |
| `OPERATOR_GUARDS_ED209_DB` | hit ledger | `<home>/ed209/hits.db` |
| `OPERATOR_GUARDS_ED209_STATE` | session state dir | `<home>/ed209/state` |
| `OPERATOR_GUARDS_R2D2_STATE` | incident state root | `<home>/r2d2` |
| `OPERATOR_GUARDS_POLICY_STORE` | source-policy store | `<home>/ed209/policy` |
| `OPERATOR_GUARDS_SOURCE_ROOTS` | transcript search roots (os.pathsep) | Claude/Codex defaults |

Tests always pass explicit temporary paths and do not touch a live home.

## Layout

```text
src/operator_guards/       # library (common, ed209, r2d2)
plugins/ed209/             # Hermes ED-209 plugin
plugins/r2d2/              # Hermes R2-D2 plugin + owning-client IPC adapter
skills/                    # operator skills
rulepacks/                 # documented-initial + protected-path rules
deploy/                    # dry-run-first installer, rollback, unit template
tests/                     # package tests + publication-focused tests
docs/                      # provenance and rule-migration notes
provenance/                # source and publication hashes
```

## Known limitations

- The grant-store module retains the upstream missing-file-as-stale lock
  pattern. Grant consumption is identity/scope/nonce/TTL bound and passed
  concurrent stress trials, but a concurrent double-spend has not been proven
  impossible; the publication path could not be patched in-session because a
  live ED-209 hook refused writes to that source path. Fix the same lock race
  there in an operator-approved follow-up before claiming concurrency-safe
  single-use grants.
- Full 161-rule parity is not claimed: the legacy export was absent.
- The bundled seed rulepack resolves relative to the source tree; a wheel does
  not include `rulepacks/`, so set `OPERATOR_GUARDS_RULEPACK` or pass `--rules`.
- Non-Hermes harness hooks and the live install are not included.
- Same-UID processes are not security-isolated.

## License and provenance

Original code is licensed under the Apache License, Version 2.0. See
[`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Source provenance, exclusions, and
known limitations are in [`PUBLICATION-PROVENANCE.md`](PUBLICATION-PROVENANCE.md) and
[`provenance/source-hashes.json`](provenance/source-hashes.json).
