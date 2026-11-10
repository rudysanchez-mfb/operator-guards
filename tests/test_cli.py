"""Sanctioned ED-209 CLI tests (Task 5).

These drive the *actual* CLI module (`python -m operator_guards.ed209.cli`)
through a subprocess against an isolated temp rules/state/db root, so they
exercise the real entry point rather than an in-process wrapper. The contract
(plan §4 + ED-209-HANDOFF.md §6):

* `list` shows disabled entries with origin/provenance.
* `add` persists a new rule atomically; rejects duplicate ids and invalid
  regex; successor ids (`-v2`/`-v3`) capture the origin they supersede; `add`
  may only add — it never weakens an enabled deny or changes limits.
* `disable`/`enable` flip `enabled` WITHOUT deleting the entry, require an
  explicit operator marker, record who/when, and refuse to present as
  automatic agent recovery.
* `test-reply`/`test-tool` are dry-run only: they never write the ledger,
  never consume a reviewer/block budget, and never run live checks.
* `hits` reads the real ledger (live outcomes), never dry-run traffic.
* `replay` is a deterministic, non-mutating re-read of recorded hits.
* There is no `policy-off` (or limits-changing) verb.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from operator_guards.ed209.ledger import HitLedger
from operator_guards.ed209.rules import load_rules

REPO = Path(__file__).resolve().parents[1]

PHRASE_RULE = {
    "id": "offload-new-phrase",
    "surface": "reply",
    "class": "offload",
    "action": "escalate",
    "pattern": r"\bI can do that if you want\b",
    "reason": "The final reply defers with '{match}'. {n_tools} tool calls ran this turn.",
    "origin": "ED-209-HANDOFF.md:175-178",
}


def _doc(*rules):
    return {
        "version": 1,
        "_about": "test fixture",
        "reviewer": {"chain": ["copilot", "cursor"], "model": "gpt-5.4", "timeout_s": 50},
        "limits": {"max_blocks_per_session": 12, "max_reviewer_calls_per_session": 12},
        "rules": list(rules),
    }


def _write_doc(tmp_path, doc, name="rules.json"):
    path = tmp_path / name
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return str(path)


def _rule(**overrides):
    rule = {
        "id": "test-rule",
        "surface": "reply",
        "class": "voice",
        "action": "escalate",
        "pattern": r"\bhello\b",
        "reason": "reason {match}",
        "origin": "test origin",
    }
    rule.update(overrides)
    return rule


def run_cli(*argv, cwd=REPO):
    """Run the real CLI module in a subprocess; return CompletedProcess."""
    return subprocess.run(
        [sys.executable, "-m", "operator_guards.ed209.cli", *argv],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        env={**os.environ},
    )


# --- list: shows disabled entries with origin/provenance --------------------

def test_list_shows_disabled_entries(tmp_path):
    rules = _write_doc(
        tmp_path,
        _doc(_rule(id="a", enabled=True), _rule(id="b", enabled=False, origin="provenance-b")),
    )
    proc = run_cli("--rules", rules, "list")
    assert proc.returncode == 0, proc.stderr
    assert "a" in proc.stdout
    assert "b" in proc.stdout          # disabled entry is still listed
    assert "provenance-b" in proc.stdout


# --- add: persist, reject duplicates / invalid regex, origin capture --------

def test_add_persists_new_rule(tmp_path):
    rules = _write_doc(tmp_path, _doc())
    proc = run_cli(
        "--rules", rules, "add",
        "--id", "offload-new-phrase",
        "--surface", "reply", "--class", "offload", "--action", "escalate",
        "--pattern", r"\bI can do that if you want\b",
        "--reason", "defers with {match}",
        "--origin", "handoff",
    )
    assert proc.returncode == 0, proc.stderr
    loaded = load_rules(json.loads(Path(rules).read_text(encoding="utf-8")))
    assert [r.id for r in loaded] == ["offload-new-phrase"]
    assert loaded[0].enabled is True


def test_add_rejects_duplicate_id(tmp_path):
    rules = _write_doc(tmp_path, _doc(_rule(id="dup")))
    proc = run_cli(
        "--rules", rules, "add",
        "--id", "dup", "--surface", "reply", "--class", "voice", "--action", "escalate",
        "--pattern", r"\bx\b", "--reason", "r", "--origin", "o",
    )
    assert proc.returncode != 0
    assert "duplicate" in proc.stderr


def test_add_rejects_invalid_regex(tmp_path):
    rules = _write_doc(tmp_path, _doc())
    proc = run_cli(
        "--rules", rules, "add",
        "--id", "bad", "--surface", "reply", "--class", "voice", "--action", "escalate",
        "--pattern", "([unclosed", "--reason", "r", "--origin", "o",
    )
    assert proc.returncode != 0
    assert "invalid regex" in proc.stderr


def test_add_successor_preserves_origin(tmp_path):
    base_origin = "2026-08-26 — Rudy: original phrase"
    rules = _write_doc(
        tmp_path, _doc(_rule(id="foo", origin=base_origin, pattern=r"\bold\b"))
    )
    proc = run_cli(
        "--rules", rules, "add",
        "--id", "foo-v2", "--surface", "reply", "--class", "offload",
        "--action", "escalate", "--pattern", r"\bnew\b",
        "--reason", "r", "--origin", "2026-10-05 operator",
    )
    assert proc.returncode == 0, proc.stderr
    loaded = load_rules(json.loads(Path(rules).read_text(encoding="utf-8")))
    successor = next(r for r in loaded if r.id == "foo-v2")
    assert base_origin in successor.origin  # superseded origin captured
    assert "foo" in successor.origin


def test_add_never_weakens_enabled_deny(tmp_path):
    rules = _write_doc(
        tmp_path,
        _doc(_rule(id="guard", surface="tool", action="deny", pattern=r"\bSECRET\b")),
    )
    proc = run_cli(
        "--rules", rules, "add",
        "--id", "guard-v2", "--surface", "tool", "--class", "known-bad",
        "--action", "escalate", "--pattern", r"\bSECRET\b",
        "--reason", "r", "--origin", "o",
    )
    assert proc.returncode != 0
    assert "deny" in proc.stderr.lower()


def test_add_preserves_limits_and_existing_rules(tmp_path):
    doc = _doc(_rule(id="existing"))
    doc["limits"] = {"max_blocks_per_session": 7, "max_reviewer_calls_per_session": 7}
    rules = _write_doc(tmp_path, doc)
    proc = run_cli(
        "--rules", rules, "add",
        "--id", "new", "--surface", "reply", "--class", "voice", "--action", "escalate",
        "--pattern", r"\bx\b", "--reason", "r", "--origin", "o",
    )
    assert proc.returncode == 0, proc.stderr
    raw = json.loads(Path(rules).read_text(encoding="utf-8"))
    assert raw["limits"] == {"max_blocks_per_session": 7, "max_reviewer_calls_per_session": 7}
    ids = [r["id"] for r in raw["rules"]]
    assert ids == ["existing", "new"]


def test_add_defaults_overridable_false(tmp_path):
    rules = _write_doc(tmp_path, _doc())
    proc = run_cli(
        "--rules", rules, "add",
        "--id", "hard", "--surface", "tool", "--class", "scope", "--action", "deny",
        "--pattern", r"\bX\b", "--reason", "r", "--origin", "o",
    )
    assert proc.returncode == 0, proc.stderr
    loaded = load_rules(json.loads(Path(rules).read_text(encoding="utf-8")))
    assert loaded[0].overridable is False


# --- correct: deterministic verbatim correction via sanctioned add ----------

def _correct_argv(text, operator="rudy", date="2026-10-06", overrides=None):
    args = {
        "--id": "fix-phrase",
        "--surface": "reply",
        "--class": "offload",
        "--action": "escalate",
        "--pattern": r"\bI can do that if you want\b",
        "--reason": "defers with {match}",
    }
    if overrides:
        args.update(overrides)
    argv = ["correct", "--text", text, "--date", date, "--operator", operator]
    for flag, value in args.items():
        argv += [flag, value]
    return argv


def test_correct_writes_verbatim_origin(tmp_path):
    rules = _write_doc(tmp_path, _doc())
    correction = "Never say I can do that if you want; escalate instead."
    proc = run_cli("--rules", rules, *_correct_argv(correction))
    assert proc.returncode == 0, proc.stderr
    raw = json.loads(Path(rules).read_text(encoding="utf-8"))
    assert len(raw["rules"]) == 1
    rule = raw["rules"][0]
    # The correction text is embedded VERBATIM with author + date attribution.
    assert rule["origin"].startswith("rudy: ")
    assert correction in rule["origin"]
    assert "2026-10-06" in rule["origin"]
    assert rule["enabled"] is True
    assert rule.get("overridable", False) is False  # correct never sets overridable


def test_correct_is_deterministic(tmp_path):
    a = _write_doc(tmp_path, _doc(), name="a.json")
    b = _write_doc(tmp_path, _doc(), name="b.json")
    correction = "Some correction text, verbatim."
    argv = _correct_argv(correction)
    p1 = run_cli("--rules", a, *argv)
    p2 = run_cli("--rules", b, *argv)
    assert p1.returncode == 0, p1.stderr
    assert p2.returncode == 0, p2.stderr
    # Identical inputs (pinned --date) produce a byte-identical rules document.
    assert Path(a).read_bytes() == Path(b).read_bytes()


def test_correct_adds_only_and_preserves_existing(tmp_path):
    doc = _doc(_rule(id="existing"))
    doc["limits"] = {"max_blocks_per_session": 7, "max_reviewer_calls_per_session": 7}
    rules = _write_doc(tmp_path, doc)
    proc = run_cli("--rules", rules, *_correct_argv("verbatim correction"))
    assert proc.returncode == 0, proc.stderr
    raw = json.loads(Path(rules).read_text(encoding="utf-8"))
    assert raw["limits"] == {"max_blocks_per_session": 7, "max_reviewer_calls_per_session": 7}
    assert [r["id"] for r in raw["rules"]] == ["existing", "fix-phrase"]


def test_correct_refuses_to_weaken_enabled_deny(tmp_path):
    rules = _write_doc(
        tmp_path,
        _doc(_rule(id="guard", surface="tool", action="deny", pattern=r"\bSECRET\b")),
    )
    proc = run_cli(
        "--rules", rules,
        *_correct_argv(
            "relax the guard",
            overrides={
                "--id": "guard-v2",
                "--surface": "tool",
                "--action": "escalate",
                "--pattern": r"\bSECRET\b",
            },
        ),
    )
    assert proc.returncode != 0
    assert "deny" in proc.stderr.lower()


def test_correct_requires_operator(tmp_path):
    rules = _write_doc(tmp_path, _doc())
    proc = run_cli(
        "--rules", rules, "correct", "--text", "verbatim", "--date", "2026-10-06",
        "--id", "x", "--surface", "reply", "--class", "voice", "--action", "escalate",
        "--pattern", r"\bx\b", "--reason", "r",
    )
    assert proc.returncode != 0  # no --operator -> refused


def test_correct_refuses_recovery_marker(tmp_path):
    rules = _write_doc(tmp_path, _doc())
    proc = run_cli("--rules", rules, *_correct_argv("verbatim", operator="recovery"))
    assert proc.returncode != 0
    assert "recovery" in proc.stderr.lower()


# --- disable / enable: operator-gated, preserve entry, record who/when ------

def test_disable_requires_operator(tmp_path):
    rules = _write_doc(tmp_path, _doc(_rule(id="r1")))
    proc = run_cli("--rules", rules, "disable", "r1")
    assert proc.returncode != 0  # refused without an operator marker


def test_disable_preserves_entry_and_flips_enabled(tmp_path):
    rules = _write_doc(tmp_path, _doc(_rule(id="r1", enabled=True)))
    proc = run_cli("--rules", rules, "disable", "--operator", "rudy", "r1")
    assert proc.returncode == 0, proc.stderr
    raw = json.loads(Path(rules).read_text(encoding="utf-8"))
    assert raw["rules"][0]["id"] == "r1"     # entry preserved, not deleted
    assert raw["rules"][0]["enabled"] is False


def test_disable_records_operator_who_and_when(tmp_path):
    rules = _write_doc(tmp_path, _doc(_rule(id="r1")))
    proc = run_cli("--rules", rules, "disable", "--operator", "rudy", "r1")
    assert proc.returncode == 0, proc.stderr
    raw = json.loads(Path(rules).read_text(encoding="utf-8"))
    actions = raw.get("_operator_actions", [])
    assert any(
        a.get("verb") == "disable" and a.get("rule_id") == "r1" and a.get("operator") == "rudy"
        for a in actions
    )


def test_disable_refuses_automatic_recovery_marker(tmp_path):
    rules = _write_doc(tmp_path, _doc(_rule(id="r1")))
    proc = run_cli("--rules", rules, "disable", "--operator", "recovery", "r1")
    assert proc.returncode != 0
    assert "recovery" in proc.stderr.lower()


def test_disable_refuses_recovery_flag(tmp_path):
    rules = _write_doc(tmp_path, _doc(_rule(id="r1")))
    proc = run_cli("--rules", rules, "disable", "--operator", "rudy", "--recovery", "r1")
    assert proc.returncode != 0


def test_enable_requires_operator_and_flips(tmp_path):
    rules = _write_doc(tmp_path, _doc(_rule(id="r1", enabled=False)))
    # no operator -> refused
    refused = run_cli("--rules", rules, "enable", "r1")
    assert refused.returncode != 0
    # with operator -> flips back on, entry preserved
    proc = run_cli("--rules", rules, "enable", "--operator", "rudy", "r1")
    assert proc.returncode == 0, proc.stderr
    raw = json.loads(Path(rules).read_text(encoding="utf-8"))
    assert raw["rules"][0]["enabled"] is True


# --- test-reply / test-tool: dry-run, non-mutating --------------------------

def test_test_reply_reports_documented_phrase_rule(tmp_path):
    rules = _write_doc(tmp_path, _doc(PHRASE_RULE))
    proc = run_cli("--rules", rules, "test-reply", "I can do that if you want.")
    assert proc.returncode == 0, proc.stderr
    assert "offload-new-phrase" in proc.stdout


def test_test_reply_safe_negative_returns_no_match(tmp_path):
    rules = _write_doc(tmp_path, _doc(PHRASE_RULE))
    proc = run_cli("--rules", rules, "test-reply", "I cannot do that.")
    assert proc.returncode == 0, proc.stderr
    assert "offload-new-phrase" not in proc.stdout
    assert "no match" in proc.stdout


def test_test_tool_dry_run_matches_tool_rule(tmp_path):
    rules = _write_doc(
        tmp_path,
        _doc(_rule(id="secret-deny", surface="tool", action="deny", pattern=r"\bSECRET\b")),
    )
    proc = run_cli("--rules", rules, "test-tool", "Bash", "echo SECRET")
    assert proc.returncode == 0, proc.stderr
    assert "secret-deny" in proc.stdout


def test_dry_run_does_not_mutate_ledger_or_state(tmp_path):
    db = str(tmp_path / "hits.db")
    rules = _write_doc(tmp_path, _doc(PHRASE_RULE))
    proc = run_cli(
        "--rules", rules, "--db", db,
        "test-reply", "I can do that if you want.",
    )
    assert proc.returncode == 0, proc.stderr
    # The CLI never opened (and thus never created) the ledger — dry-run
    # traffic leaves zero durable footprint.
    assert not os.path.exists(db)


# --- hits: real ledger only -------------------------------------------------

def test_hits_queries_real_ledger(tmp_path):
    db = str(tmp_path / "hits.db")
    ledger = HitLedger(db)
    ledger.record_hit(rule_id="r1", session_id="s", outcome="deny", counted_fact="a")
    ledger.record_hit(rule_id="r1", session_id="s", outcome="deny", counted_fact="b")
    ledger.record_hit(rule_id="r2", session_id="s", outcome="block", counted_fact="c")

    proc = run_cli("--db", db, "hits")
    assert proc.returncode == 0, proc.stderr
    assert "r1" in proc.stdout
    assert "r2" in proc.stdout
    assert "deny" in proc.stdout
    assert "block" in proc.stdout
    assert "2" in proc.stdout


def test_hits_excludes_dry_run_traffic(tmp_path):
    db = str(tmp_path / "hits.db")
    rules = _write_doc(tmp_path, _doc(PHRASE_RULE))
    # Dry-run a reply that WOULD match, against an otherwise-empty ledger.
    dry = run_cli(
        "--rules", rules, "--db", db, "test-reply", "I can do that if you want."
    )
    assert dry.returncode == 0, dry.stderr
    # The real ledger must not gain a row from dry-run traffic.
    proc = run_cli("--db", db, "hits")
    assert proc.returncode == 0, proc.stderr
    assert "offload-new-phrase" not in proc.stdout
    # And the ledger is still empty (or absent).
    assert not os.path.exists(db) or HitLedger(db).count() == 0


# --- replay: deterministic, non-mutating ------------------------------------

def test_replay_is_deterministic_and_non_mutating(tmp_path):
    db = str(tmp_path / "hits.db")
    rules = _write_doc(tmp_path, _doc(_rule(id="r1", surface="tool", action="deny")))
    ledger = HitLedger(db)
    ledger.record_hit(rule_id="r1", session_id="s", outcome="deny", counted_fact="a")
    ledger.record_hit(rule_id="r1", session_id="s", outcome="block", counted_fact="b")
    before = ledger.count()

    first = run_cli("--db", db, "--rules", rules, "replay")
    second = run_cli("--db", db, "--rules", rules, "replay")
    assert first.returncode == 0, first.stderr
    assert first.stdout == second.stdout        # deterministic
    assert "r1" in first.stdout
    assert "present=true" in first.stdout       # re-evaluated against current rules
    assert "action=deny" in first.stdout
    assert HitLedger(db).count() == before      # non-mutating


# --- no policy-off / limits-changing verb exists ----------------------------

def test_no_policy_off_verb(tmp_path):
    rules = _write_doc(tmp_path, _doc())
    assert run_cli("--rules", rules, "policy-off").returncode != 0
    assert run_cli("--rules", rules, "limits").returncode != 0
    assert run_cli("--rules", rules, "off").returncode != 0


# --- Important #1: malformed / non-UTF8 rules file errors cleanly -----------

def test_malformed_json_errors_cleanly(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    proc = run_cli("--rules", str(bad), "list")
    assert proc.returncode != 0
    assert "error:" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_non_utf8_rules_file_errors_cleanly(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_bytes(b"\xff\xfe garbage \x00\x01")
    proc = run_cli("--rules", str(bad), "list")
    assert proc.returncode != 0
    assert "error:" in proc.stderr
    assert "Traceback" not in proc.stderr


# --- Important #2: empty / whitespace-only --operator is refused ------------

def test_disable_rejects_empty_operator(tmp_path):
    rules = _write_doc(tmp_path, _doc(_rule(id="r1")))
    for op in ("", "   "):
        proc = run_cli("--rules", rules, "disable", "--operator", op, "r1")
        assert proc.returncode != 0, op
        assert "error:" in proc.stderr


def test_enable_rejects_empty_operator(tmp_path):
    rules = _write_doc(tmp_path, _doc(_rule(id="r1", enabled=False)))
    for op in ("", "   "):
        proc = run_cli("--rules", rules, "enable", "--operator", op, "r1")
        assert proc.returncode != 0, op
        assert "error:" in proc.stderr


# --- Important #3: fresh EXPLICIT path must not seed the bundled rulepack ---

def test_add_to_fresh_explicit_path_only_adds_rule(tmp_path):
    fresh = tmp_path / "fresh.json"
    proc = run_cli(
        "--rules", str(fresh), "add",
        "--id", "only-rule", "--surface", "reply", "--class", "voice",
        "--action", "escalate", "--pattern", r"\bx\b",
        "--reason", "r", "--origin", "o",
    )
    assert proc.returncode == 0, proc.stderr
    raw = json.loads(fresh.read_text(encoding="utf-8"))
    ids = [r["id"] for r in raw["rules"]]
    assert ids == ["only-rule"]


def test_read_only_verb_errors_on_missing_explicit_path(tmp_path):
    missing = tmp_path / "nope.json"
    proc = run_cli("--rules", str(missing), "list")
    assert proc.returncode != 0
    assert "error:" in proc.stderr


# --- cheap correct minors ----------------------------------------------------

def test_add_empty_pattern_warns_but_succeeds(tmp_path):
    rules = _write_doc(tmp_path, _doc())
    proc = run_cli(
        "--rules", rules, "add",
        "--id", "matchall", "--surface", "reply", "--class", "voice",
        "--action", "escalate", "--pattern", "", "--reason", "r", "--origin", "o",
    )
    assert proc.returncode == 0, proc.stderr
    assert "warning" in proc.stderr.lower()
    loaded = load_rules(json.loads(Path(rules).read_text(encoding="utf-8")))
    assert loaded[0].id == "matchall"
    assert loaded[0].pattern == ""


def test_list_validates_and_errors_on_malformed(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps(
            {
                "version": 1,
                "rules": [
                    {
                        "id": "x", "surface": "reply", "class": "voice",
                        "action": "escalate", "pattern": "x", "origin": "o",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    proc = run_cli("--rules", str(bad), "list")
    assert proc.returncode != 0
    assert "error:" in proc.stderr


def test_hits_does_not_create_db_when_absent(tmp_path):
    db = str(tmp_path / "hits.db")
    proc = run_cli("--db", db, "hits")
    assert proc.returncode == 0, proc.stderr
    assert not os.path.exists(db)


def test_replay_does_not_create_db_when_absent(tmp_path):
    db = str(tmp_path / "hits.db")
    rules = _write_doc(tmp_path, _doc())
    proc = run_cli("--db", db, "--rules", rules, "replay")
    assert proc.returncode == 0, proc.stderr
    assert not os.path.exists(db)


# ===========================================================================
# Task 14: operator grants (r2d2 CLI) + sourced override enforcement
# ===========================================================================

def _r2d2_cli(*argv, root, db=None):
    """Run the REAL r2d2 CLI module in a subprocess against an isolated root."""
    cmd = [sys.executable, "-m", "operator_guards.r2d2.cli", "--root", root]
    if db is not None:
        cmd += ["--db", db]
    cmd += list(argv)
    return subprocess.run(
        cmd, capture_output=True, text=True, cwd=str(REPO), env={**os.environ},
    )


def _raise_incident(root):
    proc = _r2d2_cli(
        "raise", "--id", "inc-1", "--severity", "mechanical", "--symptom", "x",
        root=root,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def test_grant_cli_issue_list_revoke(tmp_path):
    root = str(tmp_path / "r2d2")
    _raise_incident(root)

    issue = _r2d2_cli(
        "grant", "issue", "--incident", "inc-1", "--scope", "session_stop_resume",
        "--session", "sess-2", "--client", "client-2", "--pid", "12345",
        "--start-time", "1700000000.0", "--ttl-seconds", "1800",
        "--operator", "rudy", root=root,
    )
    assert issue.returncode == 0, issue.stderr
    grant_id = issue.stdout.strip().split()[0]  # first token is the grant id
    assert grant_id

    listed = _r2d2_cli("grant", "list", "--incident", "inc-1", "--operator", "rudy", root=root)
    assert listed.returncode == 0, listed.stderr
    assert grant_id in listed.stdout

    revoke = _r2d2_cli("grant", "revoke", "--grant", grant_id, "--operator", "rudy", root=root)
    assert revoke.returncode == 0, revoke.stderr


def test_grant_cli_refuses_daemon_model_and_ledgers(tmp_path):
    root = str(tmp_path / "r2d2")
    db = str(tmp_path / "hits.db")
    _raise_incident(root)

    # Daemon/model execution of the grant verbs is DENIED and LEDGERED.
    for marker in ("daemon", "r2d2", "recovery", "agent"):
        proc = _r2d2_cli(
            "grant", "issue", "--incident", "inc-1", "--scope", "session_stop_resume",
            "--session", "sess-2", "--client", "client-2", "--pid", "12345",
            "--start-time", "1700000000.0", "--operator", marker, root=root, db=db,
        )
        assert proc.returncode != 0, marker
    # The --recovery flag is refused even with a valid operator marker.
    proc = _r2d2_cli(
        "grant", "issue", "--incident", "inc-1", "--scope", "session_stop_resume",
        "--session", "sess-2", "--client", "client-2", "--pid", "12345",
        "--start-time", "1700000000.0", "--operator", "rudy", "--recovery",
        root=root, db=db,
    )
    assert proc.returncode != 0

    # The refusal is LEDGERED as a deny hit against the grant-verb guard rule.
    ledger = HitLedger(db)
    assert ledger.outcomes_for_rule("guard-grant-cli-verb").get("deny", 0) >= 1


def test_grant_cli_requires_operator(tmp_path):
    root = str(tmp_path / "r2d2")
    _raise_incident(root)
    proc = _r2d2_cli(
        "grant", "issue", "--incident", "inc-1", "--scope", "session_stop_resume",
        "--session", "sess-2", "--client", "client-2", "--pid", "12345",
        "--start-time", "1700000000.0", root=root,
    )
    assert proc.returncode != 0  # no --operator -> refused


# --- sourced override: only a preset overridable rule, nonempty reason ------

def test_override_requires_preset_overridable_rule_and_reason(tmp_path):
    rules = _write_doc(
        tmp_path,
        _doc(_rule(id="ov", surface="tool", action="deny", pattern=r"\bSECRET\b", overridable=True)),
    )
    # A valid, nonempty-reason override on an overridable rule yields `override`.
    proc = run_cli("--rules", rules, "test-tool", "Bash", "# ed209-override: ov operator reason\necho SECRET")
    assert proc.returncode == 0, proc.stderr
    assert "override" in proc.stdout

    # A protected (non-overridable) rule rejects the override -> deny stands.
    protected = _write_doc(
        tmp_path,
        _doc(_rule(id="prot", surface="tool", action="deny", pattern=r"\bSECRET\b", overridable=False)),
        name="rules2.json",
    )
    proc2 = run_cli("--rules", protected, "test-tool", "Bash", "# ed209-override: prot operator reason\necho SECRET")
    assert proc2.returncode == 0, proc2.stderr
    assert "override" not in proc2.stdout
    assert "decision: deny" in proc2.stdout

    # An empty reason never overrides.
    proc3 = run_cli("--rules", rules, "test-tool", "Bash", "# ed209-override: ov\necho SECRET")
    assert proc3.returncode == 0, proc3.stderr
    assert "override" not in proc3.stdout


def test_override_inside_string_does_not_override(tmp_path):
    rules = _write_doc(
        tmp_path,
        _doc(_rule(id="ov", surface="tool", action="deny", pattern=r"\bSECRET\b", overridable=True)),
    )
    # The override token is smuggled inside a quoted string argument, NOT a
    # leading comment line: it must not lift the deny.
    proc = run_cli("--rules", rules, "test-tool", "Bash", 'echo SECRET "# ed209-override: ov operator reason"')
    assert proc.returncode == 0, proc.stderr
    assert "override" not in proc.stdout
    assert "decision: deny" in proc.stdout


# --- add CLI cannot mark a rule overridable --------------------------------

def test_add_cannot_mark_overridable(tmp_path):
    rules = _write_doc(tmp_path, _doc())
    # There is NO --overridable flag on `add` (argparse rejects the option).
    proc = run_cli(
        "--rules", rules, "add",
        "--id", "x", "--surface", "tool", "--class", "scope", "--action", "deny",
        "--pattern", r"\bX\b", "--reason", "r", "--origin", "o",
        "--overridable", "true",
    )
    assert proc.returncode != 0
    # A normal add always yields overridable=False.
    proc2 = run_cli(
        "--rules", rules, "add",
        "--id", "y", "--surface", "tool", "--class", "scope", "--action", "deny",
        "--pattern", r"\bY\b", "--reason", "r", "--origin", "o",
    )
    assert proc2.returncode == 0, proc2.stderr
    loaded = load_rules(json.loads(Path(rules).read_text(encoding="utf-8")))
    assert next(r for r in loaded if r.id == "y").overridable is False


# ===========================================================================
# Task 15: watch (dry-run observer) + doctor (read-only report) are read-only
# ===========================================================================

def _snapshot_tree(root):
    """Recursively capture every file's bytes under ``root`` ({} if absent)."""
    root = Path(root)
    if not root.exists():
        return {}
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out[str(p.relative_to(root))] = p.read_bytes()
    return out


def test_watch_is_dry_run_and_non_mutating(tmp_path):
    from operator_guards.r2d2.observer import (
        ClientRecord,
        Observation,
        append_observation,
        write_client_record,
        write_heartbeat_file,
    )

    root = str(tmp_path / "r2d2")
    _raise_incident(root)  # durable incident + events + snapshot dirs
    # Populate observable state: a heartbeat, a live client record, one observation.
    write_heartbeat_file(root, ts=1000.0)
    write_client_record(
        root, ClientRecord(client_id="c1", pid=999999, pid_start_time=1.0, last_seen=1000.0)
    )
    append_observation(root, Observation(kind="heartbeat", client_id="c1", detail="probe"))

    before = _snapshot_tree(root)
    proc = _r2d2_cli("watch", root=root)
    after = _snapshot_tree(root)

    assert proc.returncode == 0, proc.stderr
    assert before == after, "watch must not mutate any state (byte-identical tree)"
    # watch reports, it does not act: the stale client is described, not raised.
    assert "c1" in proc.stdout


def test_watch_reports_supervisor_and_clients(tmp_path):
    from operator_guards.r2d2.observer import ClientRecord, write_client_record, write_heartbeat_file

    root = str(tmp_path / "r2d2")
    write_heartbeat_file(root, ts=1000.0)  # monotonic clock; fresh vs injected ts
    write_client_record(
        root, ClientRecord(client_id="c1", pid=999999, pid_start_time=1.0, last_seen=1000.0)
    )
    proc = _r2d2_cli("watch", root=root)
    assert proc.returncode == 0, proc.stderr
    assert "supervisor" in proc.stdout
    assert "c1" in proc.stdout


def test_watch_on_absent_root_is_a_noop(tmp_path):
    root = str(tmp_path / "r2d2")
    before = _snapshot_tree(root)  # {}
    proc = _r2d2_cli("watch", root=root)
    after = _snapshot_tree(root)
    assert proc.returncode == 0, proc.stderr
    assert before == after  # still absent: watch never creates the state root


def test_doctor_reports_coverage_unsupported_degraded_without_mutation(tmp_path):
    rules = _write_doc(
        tmp_path,
        _doc(
            _rule(id="bound", surface="tool", action="deny", pattern=r"\bSECRET\b", tools=["Bash"]),
            _rule(id="unbound-mut", surface="tool", action="deny", pattern=r"\bX\b", tools=["delete_files"]),
            _rule(id="unbound-quiet", surface="tool", action="deny", pattern=r"\bY\b", tools=["totally_unknown_tool_xyz"]),
        ),
    )
    root = str(tmp_path / "r2d2")
    before_rules = Path(rules).read_bytes()

    proc = _r2d2_cli("doctor", "--rules", rules, root=root)

    assert proc.returncode == 0, proc.stderr
    assert Path(rules).read_bytes() == before_rules, "doctor must not modify the rules document"
    assert not Path(root).exists(), "doctor must not create the r2d2 state root"

    out = proc.stdout
    # coverage: bound specifier covered, unbound specifiers surfaced, degraded flagged
    assert "delete_files" in out
    assert "totally_unknown_tool_xyz" in out
    assert "degraded: yes" in out
    # unsupported adapters reported (never faked as available)
    assert "session_stop_resume" in out
    assert "config_set" in out
    assert "takeover_without_send" in out
    # mcp_reconnect is IMPLEMENTED + CONDITIONAL, never misreported "unsupported".
    assert "conditional: mcp_reconnect" in out
    assert "unsupported: mcp_reconnect" not in out


def test_doctor_absent_rules_is_not_an_error(tmp_path):
    root = str(tmp_path / "r2d2")
    missing = str(tmp_path / "nope.json")
    proc = _r2d2_cli("doctor", "--rules", missing, root=root)
    assert proc.returncode == 0, proc.stderr
    assert "absent" in proc.stdout
    assert not Path(root).exists()


def test_doctor_corrupt_rules_is_corrupt_not_absent(tmp_path):
    root = str(tmp_path / "r2d2")
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{ not json", encoding="utf-8")
    proc = _r2d2_cli("doctor", "--rules", str(corrupt), root=root)
    assert proc.returncode == 0, proc.stderr
    assert "corrupt" in proc.stdout          # present-but-unreadable is corrupt...
    assert "absent" not in proc.stdout       # ...never conflated with absent
    assert "degraded: yes" in proc.stdout    # degraded policy is noted
    assert not Path(root).exists()


def test_doctor_non_object_rules_is_corrupt(tmp_path):
    root = str(tmp_path / "r2d2")
    arr = tmp_path / "arr.json"
    arr.write_text('["not", "an", "object"]', encoding="utf-8")
    proc = _r2d2_cli("doctor", "--rules", str(arr), root=root)
    assert proc.returncode == 0, proc.stderr
    assert "corrupt" in proc.stdout
    assert "absent" not in proc.stdout


def test_doctor_schema_invalid_rules_is_invalid_not_corrupt(tmp_path):
    root = str(tmp_path / "r2d2")
    bad = tmp_path / "schema.json"
    bad.write_text(json.dumps({"version": 1, "rules": [{"id": "x"}]}), encoding="utf-8")
    proc = _r2d2_cli("doctor", "--rules", str(bad), root=root)
    assert proc.returncode == 0, proc.stderr
    assert "invalid" in proc.stdout         # valid JSON, invalid schema -> invalid
    assert "degraded: yes" in proc.stdout

