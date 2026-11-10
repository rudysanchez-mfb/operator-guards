"""Installer + user unit + rollback + supervisor (plan Task 16, phase E).

Dry-run only in this leaf: nothing is actually installed into the live
profile. Every test runs against a throwaway ``tmp_path`` home (and a
throwaway unit dir), never ``~/.hermes``.

Contracts under test (plan §6 + Task 16):

* Dry-run manifest is complete and accurate (lists every file it would
  create/modify/back up) and makes NO filesystem changes.
* Install makes NO unrelated-file changes and no OTHER-PROFILE artifacts.
* Existing config comments/keys survive a round-trip (atomic, comment-preserving
  ``plugins.enabled`` edit — never a YAML re-dump).
* No ledger/incident erasure: rollback retains incident/hit evidence.
* Rollback removes/restores ONLY owned changes and keeps the audit record.
* The generated unit file validates with ``systemd-analyze --user verify``
  (skipped cleanly only when systemd-analyze is absent) and uses explicit
  absolute+verified paths.
* The supervisor starts, writes a heartbeat, and shuts down cleanly against a
  TEMP home (no real install), and never kills an unowned process.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from deploy import install, rollback  # noqa: E402
from operator_guards.r2d2 import supervisor  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

CONFIG_WITH_COMMENTS = """\
# Top-level comment that must survive the round-trip.
model:
  provider: custom
  default: deepseek-v4-pro

# A comment guarding the plugins block.
plugins:
  disabled:
    - anthropic-provider  # inline disabled comment
  enabled:
    - council-mcp
    - weather
    - zai-provider

# An unrelated block with UNKNOWN keys that a YAML dump would drop.
my_custom_block:
  unknown_key_1: 42
  nested:
    another_unknown: [a, b]
    deeper:
      - x
      - y

record_sessions: true
"""


def make_home(root: Path) -> Path:
    """A temp profile home with unrelated content + evidence that must survive."""
    home = root / "profile-default"
    (home / "skills" / "unrelated").mkdir(parents=True)
    (home / "skills" / "unrelated" / "SKILL.md").write_text("# unrelated skill\n")
    (home / "plugins" / "some-other-plugin").mkdir(parents=True)
    (home / "plugins" / "some-other-plugin" / "__init__.py").write_text("x = 1\n")
    (home / "r2d2" / "incidents").mkdir(parents=True)
    (home / "r2d2" / "incidents" / "evidence.json").write_text('{"id":"inc-ev"}\n')
    (home / "ed209").mkdir(parents=True)
    (home / "ed209" / "hits.db").write_bytes(b"SQLITE-EVIDENCE-BYTES")
    (home / "config.yaml").write_text(CONFIG_WITH_COMMENTS)
    return home


def tree_state(root: Path) -> dict:
    """Full recursive snapshot: {relpath: ("dir", None) | ("file", bytes)}."""
    out: dict = {}
    if not root.exists():
        return out
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        out[rel] = ("dir", None) if p.is_dir() else ("file", p.read_bytes())
    return out


def owned_relpaths_under_home() -> set:
    """The exact set of owned artifact relpaths the installer creates under home."""
    src_plugins = {
        ("plugins", "ed209"),
        ("plugins", "r2d2"),
    }
    src_skills = {
        ("skills", "ed209-ops"),
        ("skills", "correct"),
        ("skills", "r2d2-escalate"),
    }
    owned: set = set()
    for parts in src_plugins:
        for p in sorted((REPO / Path(*parts)).rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts:
                owned.add(Path(*parts, p.relative_to(REPO / Path(*parts))).as_posix())
    for parts in src_skills:
        for p in sorted((REPO / Path(*parts)).rglob("*")):
            if p.is_file():
                owned.add(Path(*parts, p.relative_to(REPO / Path(*parts))).as_posix())
    owned.add("config.yaml")
    owned.add("operator-guards/install-manifest.json")
    owned.add("ed209/rules.json")
    return owned


# ---------------------------------------------------------------------------
# 1. Dry-run manifest: complete + accurate, zero side effects
# ---------------------------------------------------------------------------

def test_dry_run_manifest_is_complete_and_accurate(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"
    before = tree_state(tmp_path)

    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )

    # Every file it would create/modify/back up is listed.
    listed_targets = {a.target for a in manifest.actions}
    expected = (
        {str(home / rel) for rel in owned_relpaths_under_home()}
        | {str(unit_dir / "r2d2.service")}
        | {str(bin_dir / "ed209"), str(bin_dir / "r2d2")}
    )
    assert listed_targets == expected, (
        f"manifest targets mismatch:\nmissing={sorted(expected - listed_targets)}\n"
        f"extra={sorted(listed_targets - expected)}"
    )

    # The config modification is represented (the only "modify" action).
    config_actions = [a for a in manifest.actions if a.target.endswith("config.yaml")]
    assert config_actions, "manifest must list the config.yaml modification"
    assert {a.kind for a in config_actions} == {"modify"}

    # Every action names an absolute target.
    assert all(os.path.isabs(a.target) for a in manifest.actions)

    # Dry-run build makes NO changes.
    assert tree_state(tmp_path) == before, "build_manifest must not mutate the tree"


def test_dry_run_apply_makes_no_changes(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"
    before = tree_state(tmp_path)

    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    install.apply_manifest(manifest, dry_run=True)

    assert tree_state(tmp_path) == before, "dry-run apply must not mutate the tree"


# ---------------------------------------------------------------------------
# 2. Install: no unrelated changes, no other-profile artifacts
# ---------------------------------------------------------------------------

def test_install_makes_no_unrelated_changes_and_no_other_profile_artifacts(tmp_path):
    home = make_home(tmp_path)
    other_profile = tmp_path / "profile-other"
    other_profile.mkdir()
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"
    other_unit = tmp_path / "config" / "systemd" / "user" / "other.service"
    other_unit.parent.mkdir(parents=True, exist_ok=True)
    other_unit.write_text("[Service]\n")

    unrelated_skill = (home / "skills" / "unrelated" / "SKILL.md").read_bytes()
    unrelated_plugin = (home / "plugins" / "some-other-plugin" / "__init__.py").read_bytes()
    evidence_incident = (home / "r2d2" / "incidents" / "evidence.json").read_bytes()
    evidence_hits = (home / "ed209" / "hits.db").read_bytes()

    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    install.apply_manifest(manifest, dry_run=False)

    # Unrelated files byte-identical.
    assert (home / "skills" / "unrelated" / "SKILL.md").read_bytes() == unrelated_skill
    assert (home / "plugins" / "some-other-plugin" / "__init__.py").read_bytes() == unrelated_plugin
    # Evidence untouched by install.
    assert (home / "r2d2" / "incidents" / "evidence.json").read_bytes() == evidence_incident
    assert (home / "ed209" / "hits.db").read_bytes() == evidence_hits
    # No other-profile artifacts.
    assert list(other_profile.rglob("*")) == [], "install wrote into another profile"
    assert other_unit.read_text() == "[Service]\n", "install touched an unrelated unit"
    # Owned artifacts actually created.
    assert (home / "plugins" / "ed209" / "plugin.yaml").is_file()
    assert (home / "skills" / "correct" / "SKILL.md").is_file()
    assert (unit_dir / "r2d2.service").is_file()
    # Owned CLI launchers actually created (plan §3).
    assert (bin_dir / "ed209").is_file()
    assert (bin_dir / "r2d2").is_file()


# ---------------------------------------------------------------------------
# 3. Config round-trip: comments + unknown keys preserved (atomic writer)
# ---------------------------------------------------------------------------

def test_config_comments_and_unknown_keys_preserved_round_trip():
    text = CONFIG_WITH_COMMENTS
    edited = install.ensure_plugin_enabled(text, ["ed209", "r2d2"])
    # Both names now in the enabled list.
    assert install.enabled_plugins(edited) == {
        "council-mcp",
        "weather",
        "zai-provider",
        "ed209",
        "r2d2",
    }
    # Every original comment + unknown key survives byte-for-byte.
    for marker in (
        "# Top-level comment",
        "# A comment guarding the plugins block.",
        "# inline disabled comment",
        "# An unrelated block with UNKNOWN keys",
        "my_custom_block:",
        "unknown_key_1: 42",
        "another_unknown: [a, b]",
    ):
        assert marker in edited, f"lost marker {marker!r}"

    # Removing the two names yields the EXACT original (lossless round-trip).
    restored = install.remove_plugins_enabled(edited, ["ed209", "r2d2"])
    assert restored == text, "round-trip was not lossless"


def test_config_writer_appends_plugins_section_when_absent():
    minimal = "model:\n  provider: custom\n"
    edited = install.ensure_plugin_enabled(minimal, ["ed209"])
    assert "plugins:" in edited
    assert install.enabled_plugins(edited) == {"ed209"}


def test_config_writer_is_idempotent():
    once = install.ensure_plugin_enabled(CONFIG_WITH_COMMENTS, ["ed209", "r2d2"])
    twice = install.ensure_plugin_enabled(once, ["ed209", "r2d2"])
    assert twice == once


# ---------------------------------------------------------------------------
# 4. Rollback: owned-only, retains evidence + audit
# ---------------------------------------------------------------------------

def test_rollback_preserves_unrelated_files_and_audit(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"

    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    install.apply_manifest(manifest, dry_run=False)

    unrelated_skill = (home / "skills" / "unrelated" / "SKILL.md").read_bytes()
    unrelated_plugin = (home / "plugins" / "some-other-plugin" / "__init__.py").read_bytes()
    evidence_incident = (home / "r2d2" / "incidents" / "evidence.json").read_bytes()
    evidence_hits = (home / "ed209" / "hits.db").read_bytes()
    audit = (home / "operator-guards" / "install-manifest.json").read_bytes()

    rb = rollback.build_rollback_manifest(str(home), unit_dir=str(unit_dir), bin_dir=str(bin_dir))
    # Rollback stops/disables ONLY r2d2 (no hermes/gateway unit touched).
    assert rb.units_to_stop == ("r2d2",)
    rollback.apply_rollback(
        rb, dry_run=False,
        runner=lambda unit: {"unit": unit, "outcome": "disabled", "rc": 0},
    )

    # Owned artifacts removed.
    assert not (home / "plugins" / "ed209").exists()
    assert not (home / "plugins" / "r2d2").exists()
    assert not (home / "skills" / "correct").exists()
    assert not (home / "skills" / "ed209-ops").exists()
    assert not (home / "skills" / "r2d2-escalate").exists()
    assert not (unit_dir / "r2d2.service").exists()
    # Owned CLI launchers removed.
    assert not (bin_dir / "ed209").exists()
    assert not (bin_dir / "r2d2").exists()

    # Config restored: names gone, comments intact.
    restored = (home / "config.yaml").read_text()
    assert install.enabled_plugins(restored) == {
        "council-mcp",
        "weather",
        "zai-provider",
    }
    assert "# Top-level comment" in restored

    # Unrelated files + evidence preserved.
    assert (home / "skills" / "unrelated" / "SKILL.md").read_bytes() == unrelated_skill
    assert (home / "plugins" / "some-other-plugin" / "__init__.py").read_bytes() == unrelated_plugin
    assert (home / "r2d2" / "incidents" / "evidence.json").read_bytes() == evidence_incident
    assert (home / "ed209" / "hits.db").read_bytes() == evidence_hits

    # Audit retained (install manifest preserved; rollback appends its own audit).
    assert (home / "operator-guards" / "install-manifest.json").read_bytes() == audit
    assert (home / "operator-guards" / "rollback-audit.jsonl").is_file()


def test_rollback_restores_owned_changes_only(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"
    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    install.apply_manifest(manifest, dry_run=False)

    rb = rollback.build_rollback_manifest(str(home), unit_dir=str(unit_dir), bin_dir=str(bin_dir))
    # Rollback's removal set is exactly the owned set (plus config restore + unit).
    removed = {a.target for a in rb.actions if a.kind == "remove"}
    # config.yaml is RESTORED (not removed) and install-manifest.json is the
    # retained audit — neither appears in the rollback's remove set.
    owned = {
        str(home / rel)
        for rel in owned_relpaths_under_home()
        if rel not in ("config.yaml", "operator-guards/install-manifest.json")
    }
    owned |= {str(unit_dir / "r2d2.service")}
    owned |= {str(bin_dir / "ed209"), str(bin_dir / "r2d2")}
    assert removed == owned, (
        f"rollback removal set mismatch:\nmissing={sorted(owned - removed)}\n"
        f"extra={sorted(removed - owned)}"
    )


# ---------------------------------------------------------------------------
# 4.5 Runtime ED-209 rules seed (documented-initial -> <home>/ed209/rules.json)
# ---------------------------------------------------------------------------

def test_manifest_includes_rules_seed_create_and_skip(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"

    # Absent rules doc -> a "create" seeded from the bundled rulepack.
    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    rules_target = install.rules_runtime_target(str(home))
    seed_actions = [a for a in manifest.actions if a.target == rules_target]
    assert len(seed_actions) == 1
    assert seed_actions[0].kind == "create"
    assert seed_actions[0].source == install.rules_seed_source(str(REPO))

    # Pre-existing rules doc -> a "skip" (never clobber an operator's doc).
    (home / "ed209" / "rules.json").write_text('{"version": 1, "rules": []}\n')
    manifest2 = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    seed2 = [a for a in manifest2.actions if a.target == rules_target]
    assert len(seed2) == 1
    assert seed2[0].kind == "skip"


def test_install_seeds_rules_doc_with_documented_initial_content(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"

    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    install.apply_manifest(manifest, dry_run=False)

    rules_target = home / "ed209" / "rules.json"
    bundled = REPO / "rulepacks" / "documented-initial.json"
    assert rules_target.is_file()
    assert rules_target.read_bytes() == bundled.read_bytes(), (
        "seeded rules doc must match the bundled documented-initial rulepack byte-for-byte"
    )
    # The record tracks the seed as an owned create.
    record = install.load_record(str(home / "operator-guards" / "install-manifest.json"))
    seed = [a for a in record["owned_actions"] if a["target"] == str(rules_target)]
    assert seed and seed[0]["kind"] == "create" and seed[0]["source"]


def test_install_does_not_create_hits_db(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.yaml").write_text("model:\n  provider: custom\n")
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"

    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    install.apply_manifest(manifest, dry_run=False)

    assert (home / "ed209" / "rules.json").is_file()
    assert not (home / "ed209" / "hits.db").exists(), (
        "installer must NOT create hits.db (the ledger is created on first hit)"
    )


def test_rollback_removes_seeded_rules_doc(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"

    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    install.apply_manifest(manifest, dry_run=False)
    assert (home / "ed209" / "rules.json").is_file()

    rb = rollback.build_rollback_manifest(str(home), unit_dir=str(unit_dir), bin_dir=str(bin_dir))
    rollback.apply_rollback(
        rb, dry_run=False,
        runner=lambda unit: {"unit": unit, "outcome": "disabled", "rc": 0},
    )

    assert not (home / "ed209" / "rules.json").exists()
    # Ledger evidence retained (install never created hits.db; rollback never removes it).
    assert (home / "ed209" / "hits.db").read_bytes() == b"SQLITE-EVIDENCE-BYTES"


def test_reinstall_does_not_clobber_modified_rules(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"

    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    install.apply_manifest(manifest, dry_run=False)

    rules_target = home / "ed209" / "rules.json"
    operator_doc = b'{"version": 1, "rules": [{"id": "operator-rule", "action": "deny"}]}\n'
    rules_target.write_bytes(operator_doc)

    # Re-install: the operator's doc is preserved byte-for-byte (skip, not clobber).
    manifest2 = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    seed2 = [a for a in manifest2.actions if a.target == str(rules_target)]
    assert seed2 and seed2[0].kind == "skip"
    install.apply_manifest(manifest2, dry_run=False)

    assert rules_target.read_bytes() == operator_doc


def test_install_does_not_clobber_pre_existing_rules(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"

    rules_target = home / "ed209" / "rules.json"
    pre = b'{"version": 1, "rules": [{"id": "pre-existing", "action": "deny"}]}\n'
    rules_target.write_bytes(pre)

    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    seed = [a for a in manifest.actions if a.target == str(rules_target)]
    assert seed and seed[0].kind == "skip"
    install.apply_manifest(manifest, dry_run=False)

    assert rules_target.read_bytes() == pre


# ---------------------------------------------------------------------------
# 5. Rollout owner is recorded and selected (not erased)
# ---------------------------------------------------------------------------

def test_rollout_owner_recorded_and_read_back(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"
    owner = {
        "install_root": "/home/rsanchez/.hermes/installs/6edcfbfabf3a46c9",
        "environment": "35033181a63848d29600ead7eac9df36",
    }
    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir), rollout_owner=owner
    )
    install.apply_manifest(manifest, dry_run=False)

    record = install.load_record(str(home / "operator-guards" / "install-manifest.json"))
    assert record["rollout_owner"] == owner
    assert record["launchers"] == [str(bin_dir / "ed209"), str(bin_dir / "r2d2")]

    rb = rollback.build_rollback_manifest(str(home), unit_dir=str(unit_dir), bin_dir=str(bin_dir))
    assert rb.rollout_owner == owner


# ---------------------------------------------------------------------------
# 6. Generated unit: absolute+verified paths, systemd-analyze verify
# ---------------------------------------------------------------------------

def test_unit_paths_are_absolute_and_verified(tmp_path):
    home = make_home(tmp_path)
    rendered = install.render_unit(str(REPO), str(home))
    # No unresolved placeholders.
    assert "__" not in rendered.replace("__pycache__", "")

    def get(prefix):
        return next(ln for ln in rendered.splitlines() if ln.startswith(prefix))[len(prefix):]

    exec_start = get("ExecStart=")
    working_dir = get("WorkingDirectory=")
    home_env = get("Environment=HOME=")
    path_env = get("Environment=PATH=")

    binary = exec_start.split()[0]
    assert os.path.isabs(binary), "ExecStart binary must be absolute"
    assert os.path.isfile(binary), "ExecStart binary must exist (verified)"
    assert binary == str(REPO / ".venv" / "bin" / "python")
    assert "--home" in exec_start and exec_start.split()[-1] == str(home)
    assert os.path.isabs(working_dir) and os.path.isdir(working_dir)
    assert os.path.isabs(home_env)
    assert path_env.startswith(str(REPO / ".venv" / "bin"))


def test_unit_validates_with_systemd_analyze(tmp_path):
    if shutil.which("systemd-analyze") is None:
        pytest.skip("systemd-analyze not installed")
    home = make_home(tmp_path)
    rendered = install.render_unit(str(REPO), str(home))
    unit_file = tmp_path / "r2d2.service"
    unit_file.write_text(rendered)
    proc = subprocess.run(
        ["systemd-analyze", "--user", "verify", str(unit_file)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    # Our unit must produce no error/warning of its own. The environment's
    # OTHER units (whatsapp-bridge, spice-vdagent) emit unrelated warnings, so
    # filter to lines mentioning our unit file only.
    our_lines = [
        ln for ln in proc.stderr.splitlines() if str(unit_file) in ln
    ]
    assert our_lines == [], f"unit has warnings/errors: {our_lines}"
    assert proc.returncode == 0, f"verify failed: {proc.stderr}"


# ---------------------------------------------------------------------------
# 7. Supervisor: heartbeat + clean shutdown against a TEMP home
# ---------------------------------------------------------------------------

def test_supervisor_writes_heartbeat_and_shuts_down_cleanly(tmp_path):
    home = tmp_path / "sup-home"
    hb = home / "r2d2" / "heartbeat"

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "operator_guards.r2d2.supervisor",
            "--home",
            str(home),
            "--tick-seconds",
            "0.2",
        ],
        cwd=str(REPO),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "HERMES_HOME": str(home)},
    )
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not hb.exists():
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        assert hb.exists(), (
            f"supervisor never wrote a heartbeat; rc={proc.poll()}; "
            f"stderr={proc.stderr.read()}"
        )
        # Heartbeat carries a monotonic ts.
        data = json.loads(hb.read_text())
        assert "ts" in data and isinstance(data["ts"], (int, float))
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
    rc = proc.wait(timeout=20)
    assert rc == 0, f"supervisor exited {rc} (expected 0); stderr={proc.stderr.read()}"


def test_supervisor_never_kills_unowned_process(tmp_path):
    home = tmp_path / "sup-home"
    # A disposable unrelated process the supervisor must NEVER terminate.
    victim = subprocess.Popen(["sleep", "30"])
    try:
        # Poison incident: an unregistered (unowned) live claimant.
        inc_dir = home / "r2d2" / "incidents"
        inc_dir.mkdir(parents=True)
        incident = {
            "id": "poison-1",
            "severity": "mechanical",
            "symptom": "poison unowned claimant",
            "phase": "open",
            "dedupe_key": "poison-1",
            "claimant": "other-worker",
            "epoch": 1,
            "nonce": "n",
            "pid": victim.pid,
            "pid_start_time": 0.0,
            "lease_expiry": time.time() - 10.0,  # already expired
            "owned_proc": False,
        }
        (inc_dir / "poison-1.json").write_text(json.dumps(incident) + "\n")

        sup = supervisor.Supervisor(str(home))
        sup.tick()  # must not raise, and must not kill the victim

        assert victim.poll() is None, "supervisor killed an unowned process"
    finally:
        if victim.poll() is None:
            victim.terminate()
            victim.wait(timeout=10)


# ---------------------------------------------------------------------------
# 8. Rollback dry-run makes no changes
# ---------------------------------------------------------------------------

def test_rollback_dry_run_makes_no_changes(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"
    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    install.apply_manifest(manifest, dry_run=False)
    before = tree_state(tmp_path)

    rb = rollback.build_rollback_manifest(str(home), unit_dir=str(unit_dir), bin_dir=str(bin_dir))
    rollback.apply_rollback(rb, dry_run=True)

    assert tree_state(tmp_path) == before, "rollback dry-run must not mutate the tree"


# ---------------------------------------------------------------------------
# 9. Transactional install + recoverable rollback (finding #1)
# ---------------------------------------------------------------------------

def test_crash_between_backup_and_record_is_recoverable(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"
    original_config = (home / "config.yaml").read_bytes()

    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    real_write = install.write_config_atomic

    def crash_on_record(path, text):
        if os.path.abspath(path) == os.path.abspath(manifest.record_path):
            raise RuntimeError("simulated crash before record write")
        real_write(path, text)

    monkeypatch.setattr(install, "write_config_atomic", crash_on_record)
    with pytest.raises(RuntimeError):
        install.apply_manifest(manifest, dry_run=False)

    # Partial install: artifacts copied, config modified, unit written, NO record.
    assert not (home / "operator-guards" / "install-manifest.json").exists()
    assert (home / "plugins" / "ed209" / "plugin.yaml").is_file()
    assert (unit_dir / "r2d2.service").is_file()

    # Rollback WITHOUT a record must recover a clean state from the scoped backup.
    rb = rollback.build_rollback_manifest(str(home), unit_dir=str(unit_dir), bin_dir=str(bin_dir))
    rollback.apply_rollback(
        rb, dry_run=False,
        runner=lambda unit: {"unit": unit, "outcome": "disabled", "rc": 0},
    )

    assert (home / "config.yaml").read_bytes() == original_config
    assert not (home / "plugins" / "ed209").exists()
    assert not (home / "plugins" / "r2d2").exists()
    assert not (home / "skills" / "correct").exists()
    assert not (unit_dir / "r2d2.service").exists()
    # Unrelated content untouched.
    assert (home / "skills" / "unrelated" / "SKILL.md").is_file()
    assert (home / "ed209" / "hits.db").is_file()


# ---------------------------------------------------------------------------
# 10. Symlink-safe artifact copy (finding #2)
# ---------------------------------------------------------------------------

def test_artifact_copy_does_not_write_through_symlink(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"

    (home / "plugins" / "ed209").mkdir(parents=True)
    link_target = tmp_path / "external-bytes.bin"
    link_target.write_bytes(b"PRECIOUS-TARGET-BYTES")
    (home / "plugins" / "ed209" / "plugin.yaml").symlink_to(link_target)

    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    install.apply_manifest(manifest, dry_run=False)

    # The link's target bytes are untouched.
    assert link_target.read_bytes() == b"PRECIOUS-TARGET-BYTES"
    # The symlink was replaced by a regular file, not written through.
    dst = home / "plugins" / "ed209" / "plugin.yaml"
    assert not dst.is_symlink()
    assert dst.read_bytes() == (REPO / "plugins" / "ed209" / "plugin.yaml").read_bytes()


# ---------------------------------------------------------------------------
# 11. Backup stays inside the timestamped dir (finding #3)
# ---------------------------------------------------------------------------

def test_backup_path_stays_inside_timestamped_dir(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"
    unit_dir.mkdir(parents=True, exist_ok=True)
    (unit_dir / "r2d2.service").write_text("[Unit]\n")

    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    backup_dir = os.path.abspath(manifest.backup_dir)
    for a in manifest.actions:
        if a.backup_path:
            assert os.path.abspath(a.backup_path).startswith(backup_dir + os.sep), a.backup_path
    unit_action = next(a for a in manifest.actions if a.target == manifest.unit_path)
    assert unit_action.backup_path is not None
    assert os.path.abspath(unit_action.backup_path).startswith(backup_dir + os.sep)


# ---------------------------------------------------------------------------
# 12. Rollback RESTORES (finding #4)
# ---------------------------------------------------------------------------

def test_rollback_restores_pre_existing_config_byte_exact(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"
    pre = CONFIG_WITH_COMMENTS.replace(
        "    - zai-provider\n", "    - zai-provider\n    - ed209\n    - r2d2\n"
    )
    (home / "config.yaml").write_text(pre)

    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    install.apply_manifest(manifest, dry_run=False)

    rb = rollback.build_rollback_manifest(str(home), unit_dir=str(unit_dir), bin_dir=str(bin_dir))
    rollback.apply_rollback(
        rb, dry_run=False,
        runner=lambda unit: {"unit": unit, "outcome": "disabled", "rc": 0},
    )

    # A pre-existing ed209/r2d2 registration is RESTORED byte-exact, never stripped.
    assert (home / "config.yaml").read_text() == pre


def test_rollback_restores_pre_existing_unit_and_artifact(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"
    unit_dir.mkdir(parents=True, exist_ok=True)
    pre_unit = b"[Unit]\nDescription=my old r2d2 unit\n"
    (unit_dir / "r2d2.service").write_bytes(pre_unit)

    (home / "plugins" / "ed209").mkdir(parents=True)
    pre_artifact = b"# my pre-existing ed209 plugin.yaml\n"
    (home / "plugins" / "ed209" / "plugin.yaml").write_bytes(pre_artifact)

    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    install.apply_manifest(manifest, dry_run=False)
    # Overwritten by install.
    assert (unit_dir / "r2d2.service").read_bytes() != pre_unit
    assert (home / "plugins" / "ed209" / "plugin.yaml").read_bytes() != pre_artifact

    rb = rollback.build_rollback_manifest(str(home), unit_dir=str(unit_dir), bin_dir=str(bin_dir))
    rollback.apply_rollback(
        rb, dry_run=False,
        runner=lambda unit: {"unit": unit, "outcome": "disabled", "rc": 0},
    )

    # Originals restored byte-exact.
    assert (unit_dir / "r2d2.service").read_bytes() == pre_unit
    assert (home / "plugins" / "ed209" / "plugin.yaml").read_bytes() == pre_artifact


# ---------------------------------------------------------------------------
# 13. Real unit stop/disable with truthful audit (finding #5)
# ---------------------------------------------------------------------------

def test_rollback_disables_unit_via_runner_and_audits_truthfully(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"
    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    install.apply_manifest(manifest, dry_run=False)

    calls = []

    def fake_runner(unit):
        calls.append(unit)
        return {"unit": unit, "outcome": "disabled", "rc": 0}

    rb = rollback.build_rollback_manifest(str(home), unit_dir=str(unit_dir), bin_dir=str(bin_dir))
    rollback.apply_rollback(rb, dry_run=False, runner=fake_runner)

    assert calls == ["r2d2"]
    audit_lines = (home / "operator-guards" / "rollback-audit.jsonl").read_text().splitlines()
    last = json.loads(audit_lines[-1])
    assert last["unit_stopped"] == [{"unit": "r2d2", "outcome": "disabled", "rc": 0}]


def test_rollback_skips_systemctl_when_unit_absent(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"
    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    install.apply_manifest(manifest, dry_run=False)
    (unit_dir / "r2d2.service").unlink()  # unit already gone (partial state)

    calls = []
    rb = rollback.build_rollback_manifest(str(home), unit_dir=str(unit_dir), bin_dir=str(bin_dir))
    rollback.apply_rollback(
        rb, dry_run=False,
        runner=lambda unit: calls.append(unit) or {"unit": unit, "outcome": "disabled", "rc": 0},
    )
    assert calls == []
    audit_lines = (home / "operator-guards" / "rollback-audit.jsonl").read_text().splitlines()
    last = json.loads(audit_lines[-1])
    assert last["unit_stopped"] == [{"unit": "r2d2", "outcome": "skipped", "reason": "unit not present"}]


# ---------------------------------------------------------------------------
# 14. Config writer validates output (finding #6) + CRLF (minor #12)
# ---------------------------------------------------------------------------

def test_config_writer_refuses_flow_style_enabled():
    text = "model:\n  provider: custom\nplugins:\n  enabled: [council-mcp, weather]\n"
    edited = install.ensure_plugin_enabled(text, ["ed209"])
    with pytest.raises(install.ConfigEditError):
        install.validate_config_edit(text, edited, ["ed209"])


def test_config_writer_refuses_anchored_enabled():
    text = "plugins:\n  enabled: &e\n    - weather\n"
    edited = install.ensure_plugin_enabled(text, ["ed209"])
    with pytest.raises(install.ConfigEditError):
        install.validate_config_edit(text, edited, ["ed209"])


def test_config_writer_refuses_multi_doc_config():
    text = "plugins:\n  enabled:\n    - weather\n---\nother: true\n"
    edited = install.ensure_plugin_enabled(text, ["ed209"])
    with pytest.raises(install.ConfigEditError):
        install.validate_config_edit(text, edited, ["ed209"])


def test_config_writer_refuses_list_of_maps_enabled():
    text = "plugins:\n  enabled:\n    - name: weather\n      weight: 1\n"
    edited = install.ensure_plugin_enabled(text, ["ed209"])
    with pytest.raises(install.ConfigEditError):
        install.validate_config_edit(text, edited, ["ed209"])


def test_config_writer_handles_quoted_enabled_items():
    text = 'plugins:\n  enabled:\n    - "weather"\n    - \'zai-provider\'\n'
    edited = install.ensure_plugin_enabled(text, ["ed209"])
    install.validate_config_edit(text, edited, ["ed209"])  # must not raise
    assert install.enabled_plugins(edited) == {"weather", "zai-provider", "ed209"}


def test_config_writer_preserves_crlf_line_endings():
    text = "model:\r\n  provider: custom\r\nplugins:\r\n  enabled:\r\n    - weather\r\n"
    edited = install.ensure_plugin_enabled(text, ["ed209"])
    install.validate_config_edit(text, edited, ["ed209"])
    # No mixed endings: every line terminator is exactly CRLF.
    assert "\n" not in edited.replace("\r\n", "")
    assert "\r" not in edited.replace("\r\n", "")
    assert install.enabled_plugins(edited) == {"weather", "ed209"}
    restored = install.remove_plugins_enabled(edited, ["ed209"])
    assert "\n" not in restored.replace("\r\n", "")
    assert "\r" not in restored.replace("\r\n", "")
    assert install.enabled_plugins(restored) == {"weather"}


# ---------------------------------------------------------------------------
# 15. Supervisor containment (minor #7) + unit template (minor #8) + unit dir (minor #11)
# ---------------------------------------------------------------------------

def test_supervisor_contains_corrupt_state_dir_at_startup(tmp_path):
    home = tmp_path / "sup-home"
    home.mkdir()
    (home / "r2d2").write_text("corrupt: not a directory")
    sup = supervisor.Supervisor(str(home), tick_seconds=0.01)
    sup.tick()  # list_incidents() is contained
    sup.request_shutdown()
    sup.run_forever()  # the initial tick() is contained; loop exits immediately


def test_unit_template_has_no_network_target(tmp_path):
    rendered = install.render_unit(str(REPO), str(tmp_path / "home"))
    assert "After=network.target" not in rendered


def test_default_unit_dir_resolved_at_call_time_and_single_source(monkeypatch, tmp_path):
    xdg = tmp_path / "xdg"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    expected = str(xdg / "systemd" / "user")
    assert install.default_unit_dir() == expected
    # rollback reuses install's single source (no duplicate definition).
    assert not hasattr(rollback, "_DEFAULT_UNIT_DIR")
    assert rollback.default_unit_dir() == expected


# ---------------------------------------------------------------------------
# 16. Operator CLI launchers (~/.local/bin/{ed209,r2d2}) + runbook invocations
# ---------------------------------------------------------------------------

def test_default_bin_dir_resolved_at_call_time_and_single_source(monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    expected = str(home / ".local" / "bin")
    assert install.default_bin_dir() == expected
    # rollback reuses install's single source (no duplicate definition).
    assert not hasattr(rollback, "_DEFAULT_BIN_DIR")
    assert rollback.default_bin_dir() == expected


def test_install_creates_executable_launchers_and_they_run_throwaway(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"
    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    install.apply_manifest(manifest, dry_run=False)

    ed209 = bin_dir / "ed209"
    r2d2 = bin_dir / "r2d2"
    assert ed209.is_file() and os.access(ed209, os.X_OK), "ed209 launcher missing/not executable"
    assert r2d2.is_file() and os.access(r2d2, os.X_OK), "r2d2 launcher missing/not executable"
    # The launcher execs the repo venv python with the right module.
    assert str(REPO / ".venv" / "bin" / "python") in ed209.read_text()
    assert "operator_guards.ed209.cli" in ed209.read_text()
    assert "operator_guards.r2d2.cli" in r2d2.read_text()

    # The exact §4 operator commands run against THROWAWAY state only (the
    # global --rules/--db/--root flags precede the verb, matching the CLI).
    rules = tmp_path / "rules.json"
    rules.write_text('{"version": 1, "rules": []}\n')
    p1 = subprocess.run(
        [str(ed209), "--rules", str(rules), "list"], capture_output=True, text=True
    )
    assert p1.returncode == 0, f"ed209 launcher failed: {p1.stderr}"
    p2 = subprocess.run(
        [str(ed209), "--db", str(tmp_path / "hits.db"), "hits"],
        capture_output=True, text=True,
    )
    assert p2.returncode == 0, f"ed209 hits failed: {p2.stderr}"
    p3 = subprocess.run(
        [str(r2d2), "--root", str(tmp_path / "r2d2-state"), "status"],
        capture_output=True, text=True,
    )
    assert p3.returncode == 0, f"r2d2 launcher failed: {p3.stderr}"
    p4 = subprocess.run(
        [str(r2d2), "--root", str(tmp_path / "r2d2-state"), "events", "-n", "20"],
        capture_output=True, text=True,
    )
    assert p4.returncode == 0, f"r2d2 events failed: {p4.stderr}"


def test_rollback_restores_pre_existing_launcher_byte_exact(tmp_path):
    home = make_home(tmp_path)
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    pre_launcher = b"#!/bin/sh\n# my pre-existing ed209 launcher\n"
    (bin_dir / "ed209").write_bytes(pre_launcher)

    manifest = install.build_manifest(
        str(home), str(REPO), unit_dir=str(unit_dir), bin_dir=str(bin_dir)
    )
    install.apply_manifest(manifest, dry_run=False)
    # Overwritten by install (scoped-backed up first).
    assert (bin_dir / "ed209").read_bytes() != pre_launcher

    rb = rollback.build_rollback_manifest(str(home), unit_dir=str(unit_dir), bin_dir=str(bin_dir))
    rollback.apply_rollback(
        rb, dry_run=False,
        runner=lambda unit: {"unit": unit, "outcome": "disabled", "rc": 0},
    )

    # The pre-existing launcher is RESTORED byte-exact; the owned r2d2 launcher
    # (which did NOT pre-exist) is removed.
    assert (bin_dir / "ed209").read_bytes() == pre_launcher
    assert not (bin_dir / "r2d2").exists()


def test_documented_rollback_module_invocation_runs_dry_run(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    unit_dir = tmp_path / "config" / "systemd" / "user"
    bin_dir = tmp_path / "local" / "bin"

    # The EXACT documented form: `python -m deploy.rollback --home ...` run from
    # the repo root (sys.path[0] == REPO so `deploy` is importable).
    proc = subprocess.run(
        [
            sys.executable, "-m", "deploy.rollback",
            "--home", str(home), "--unit-dir", str(unit_dir), "--bin-dir", str(bin_dir),
        ],
        cwd=str(REPO), capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"
    assert "DRY-RUN" in proc.stdout
    assert "dry-run: nothing was changed" in proc.stdout

    # The SCRIPT form (`python deploy/rollback.py`) also works — the __main__
    # sys.path guard keeps `deploy.install` importable either way.
    proc2 = subprocess.run(
        [
            sys.executable, str(REPO / "deploy" / "rollback.py"),
            "--home", str(home), "--unit-dir", str(unit_dir), "--bin-dir", str(bin_dir),
        ],
        cwd=str(REPO), capture_output=True, text=True, timeout=60,
    )
    assert proc2.returncode == 0, f"stderr={proc2.stderr}\nstdout={proc2.stdout}"
    assert "DRY-RUN" in proc2.stdout
