# Publication provenance

This publication is a clean extraction, not a byte-for-byte copy of a live
profile. The machine-readable record is
[`provenance/source-hashes.json`](provenance/source-hashes.json).

## Upstream source

| Fact | Value |
| :--- | :--- |
| Repository | `/home/rsanchez/hermes-operator-guards` |
| Branch | `main` |
| HEAD | `23effad465abd0cc2a709d59ec557dfe1e69d498` |
| Worktree | clean at extraction |
| Deployed release metadata | `/opt/hermes-operator-guards/releases/23effad465abd0cc2a709d59ec557dfe1e69d498/SOURCE.json` |
| Deployed release commit | `23effad465abd0cc2a709d59ec557dfe1e69d498` (same as checkout HEAD) |
| Deployed release archive SHA-256 | `36e6bfedd347573eb13757fcd14d2c291df6e5652ea23774299c73e081a910c4` |
| Deployed release file count | 26 (`pyproject.toml` + `src/` only) |

The deployed `/opt` release is a runtime subset, not the full repository. Its
recorded commit matches the checkout HEAD, and 22 of its 26 file hashes match
this publication exactly. The four differences are the publication edits listed
below; no other source file changed. Do not infer that a checkout always equals
a deployed release: the release metadata was checked explicitly for this
publication.

## Laptop sources (read-only)

| Source | SHA-256 | Disposition |
| :--- | :--- | :--- |
| `~/.claude/ed209/policy/ed209_policy.py` | `02b31ba8…1a8c5b31` | Ported to `src/operator_guards/ed209/source_policy.py` |
| `~/.claude/ed209/policy/policy_cli.py` | `66951970…bed5eda` | Not copied (live-store CLI); the module is tested directly |
| `~/.claude/ed209/hooks/*.py` | see JSON | Not copied (harness-specific live hooks) |
| `~/.claude/r2d2/bin/*.py` and `tests/test_churn.py` | see JSON | Not copied (packaged library is the coordinated implementation) |

The port preserves the source module's semantics. The only changes are:
package-relative imports; `default_store()` / `OPERATOR_GUARDS_POLICY_STORE`;
`OPERATOR_GUARDS_SOURCE_ROOTS`; and optional `store=None` defaults so the module
does not bind a live path at import.

## Publication edits (not in upstream)

1. **Configurable defaults.** `ed209/cli.py`, `ed209/ledger.py`,
   `ed209/state.py`, and `r2d2/store.py` no longer hardcode an operator home.
   New `common/paths.py` resolves `OPERATOR_GUARDS_HOME` → `HERMES_HOME` →
   `~/.hermes`; each default also has a specific override variable. The bundled
   rulepack path has `OPERATOR_GUARDS_RULEPACK`.
2. **Lock race fix.** `ed209/state.py` and `r2d2/store.py` treated a lock file
   that vanished between a failed `O_EXCL` open and the staleness stat as
   "stale", then unlinked the path. Under concurrent callers this could delete a
   NEW holder's lock and allow two critical sections (reproduced as a
   block-budget overspend: 8 acquisitions against a limit of 5). A missing lock
   is now retried without unlinking; an unreadable lock is never broken.
3. **Ported provenance layer + tests.** Added
   `src/operator_guards/ed209/source_policy.py` and
   `tests/test_source_policy.py`.
4. **Publication tests.** Added `tests/test_publication_focused.py` for the
   observer predicates, quiet-but-alive behavior, grant authorization, the
   protected-path rulepack, and configurable defaults.
5. **Docs/licensing.** Added `README.md`, `LICENSE` (Apache-2.0), `NOTICE`,
   `docs/source-policy-provenance.md`, `docs/rule-migration.md`, and this file.

## Known limitations and unresolved issues

- **The grant-store module retains the upstream lock pattern.** The same
  missing-file-as-stale race was not patched in the grant store. A live ED-209
  hook denied writes to any staged path matching the grant-store source path
  (a false positive on the publication path), so the in-session edit was
  refused. The grant consume path is identity/scope/nonce/TTL bound and passed
  500 concurrent stress trials, but a concurrent double-spend has not been
  proven impossible. Apply the same lock fix in an operator-approved follow-up
  before claiming concurrency-safe single-use grants.
- **Full 161-rule parity is not claimed.** The legacy rule export was absent
  from the source handoff. The rulepacks are `documented-initial` plus
  documented protected-path additions.
- **Non-Hermes adapters are not included.** Claude Code, Codex, Copilot, and
  Cursor hooks are live harness-specific code. The Hermes plugin is the only
  adapter in this tree.
- **`pre_final_response` is runtime-dependent.** It is registered only where the
  Hermes runtime provides the hook; otherwise it is reported unsupported.
- **Installed-wheel rulepack resolution.** `ed209/cli.py` resolves the bundled
  seed rulepack relative to the source tree. A wheel does not include
  `rulepacks/`; set `OPERATOR_GUARDS_RULEPACK` or pass `--rules` explicitly.
- **Same-UID is not security isolation.** The store, rules, grants, ledger, and
  code are all writable by the same user. Hashes detect drift, not a hostile
  writer. This is procedural defence-in-depth, not an OS boundary.
- **Linux-specific pieces.** `/proc` liveness checks, `fcntl` locks, and the
  systemd user unit are Unix/Linux-specific. The library is not a Windows port.
- **Regex rules are trusted input.** No regex timeout is applied; catastrophic
  backtracking is a known limitation.

## Exclusions

No `.git` history, virtual environments, caches, backups, live policy artifacts,
hit databases, incident stores, transcripts, source receipts, credentials, or
environment files are included. See the JSON record for the explicit list.
