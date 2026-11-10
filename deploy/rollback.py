"""R2-D2 rollback (plan Task 16) — stops/disables ONLY r2d2, restores/removes
ONLY owned changes, and retains incident/hit evidence + the audit record.

Dry-run manifest is produced FIRST (:func:`build_rollback_manifest`); no change
is made unless :func:`apply_rollback` is called with ``dry_run=False``.

Scope (the "owned" set) is derived from the DURABLE install record when present,
and RECONSTRUCTED by scanning the scoped backup dir when the record is missing or
partial (a crashed install — finding #1). The owned set is limited to:

* the plugin/skill artifact files the installer copied,
* the generated systemd user unit (``r2d2.service``),
* the ``plugins.enabled`` config change (RESTORED from the scoped backup, not
  re-computed — so a user's PRE-EXISTING ed209/r2d2 registration is preserved).

The seeded runtime ED-209 rules doc (``<home>/ed209/rules.json``) is rolled back
like other owned artifacts: a doc the installer CREATED (no pre-existing file)
is removed, while a PRE-EXISTING operator-authored doc is left untouched (the
installer reported it as a ``skip``, so it is not in the owned set and never
removed/restored — an operator's rules are never clobbered by rollback). In the
record-less (crashed-install) reconstruction path the seeded doc is deliberately
left in place: without the record it cannot be distinguished from an
operator-authored doc, and leaving a valid rules doc is fail-closed (ED-209
still enforces) whereas deleting it could destroy operator rules.

Rollback RESTORES pre-existing originals (config, unit, artifacts) from the
scoped backup and deletes only files that did NOT pre-exist (finding #4). It
stops/disables ONLY ``r2d2.service`` via ``systemctl --user disable --now``,
guarded to run only when the unit is present, with the runner injectable so
tests use a fake; the audit records the REAL outcome (finding #5).

It deliberately does NOT touch: ``~/.hermes/r2d2/`` (incident evidence),
``~/.hermes/ed209/`` (hit ledger), any unrelated plugin/skill/config file, any
OTHER profile, or the Hermes gateway/service unit. It NEVER restarts Hermes
from inside itself — ``units_to_stop`` is exactly ``("r2d2",)``.

The recorded rollout owner (managed Hermes install root/environment) is READ
BACK and exposed on the manifest so a Hermes-core revert can select the prior
managed version through it; this leaf records/reports it, it does not execute a
``hermes update`` (that is Task 17's gated deploy).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

# Make the repo root importable when this file is run as a SCRIPT
# (`python deploy/rollback.py`): sys.path[0] is then `deploy/`, so the
# `deploy.install` package below would otherwise fail with ModuleNotFoundError.
# As a module (`python -m deploy.rollback` from the repo root) this is a no-op.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from deploy.install import (
    ARTIFACT_REL_DIRS,
    BACKUP_DIR_NAME,
    LAUNCHER_NAMES,
    PHASE_NAME,
    RECORD_DIR,
    RECORD_NAME,
    REGISTERED_PLUGINS,
    FileAction,
    _copy_file,
    _source_files,
    _target_from_backup_rel,
    default_bin_dir,
    default_unit_dir,
    load_record,
    read_phase,
    remove_plugins_enabled,
    validate_config_removal,
    write_config_atomic,
)

ROLLBACK_AUDIT_NAME = "rollback-audit.jsonl"

# The ONLY unit rollback stops/disables. Never the Hermes gateway/service.
UNIT_NAME = "r2d2"


@dataclass(frozen=True)
class RollbackManifest:
    """The rollback dry-run manifest: owned changes to restore/remove."""

    home: str
    unit_dir: str
    config_path: str
    unit_path: str
    record_path: str
    audit_path: str
    rollout_owner: Mapping[str, Any]
    units_to_stop: tuple
    actions: tuple = ()

    def render(self) -> str:
        lines = [
            f"DRY-RUN: rollback operator-guards (R2-D2) from {self.home}",
            f"  stop/disable unit(s): {list(self.units_to_stop)}",
            f"  rollout owner: {json.dumps(dict(self.rollout_owner), sort_keys=True)}",
            "",
            f"Planned actions ({len(self.actions)}):",
        ]
        for a in self.actions:
            lines.append(f"  {a.kind:9} {a.target}")
        lines.append("")
        lines.append("  retained (never removed): incident/hit evidence + install record (audit)")
        return "\n".join(lines)


def _record_path(home: str) -> str:
    return os.path.join(home, RECORD_DIR, RECORD_NAME)


def _default_repo() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _find_backup_dir(home: str, record_backup_dir: str | None) -> str | None:
    """The scoped backup dir to roll back: the record's dir if present, else scan.

    When the record is missing/partial, scan ``operator-guards/backup/`` and
    prefer an ``in-progress`` (crashed) install, else the most recently modified.
    """
    if record_backup_dir and os.path.isdir(record_backup_dir):
        return record_backup_dir
    backup_root = os.path.join(home, RECORD_DIR, BACKUP_DIR_NAME)
    if not os.path.isdir(backup_root):
        return None
    try:
        entries = os.listdir(backup_root)
    except OSError:
        return None
    dirs = [os.path.join(backup_root, e) for e in entries if os.path.isdir(os.path.join(backup_root, e))]
    if not dirs:
        return None
    for d in sorted(dirs):
        if read_phase(d).get("phase") == "in-progress":
            return d
    try:
        return max(dirs, key=os.path.getmtime)
    except OSError:
        return dirs[-1]


def _scan_backup_targets(backup_dir: str, home: str) -> dict[str, str]:
    """Map each backed-up file (skipping the PHASE marker) to its original target."""
    targets: dict[str, str] = {}
    for dirpath, _dirnames, filenames in os.walk(backup_dir):
        for fn in filenames:
            if fn == PHASE_NAME:
                continue
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, backup_dir)
            targets[os.path.abspath(_target_from_backup_rel(rel, home))] = p
    return targets


def build_rollback_manifest(
    home: str,
    *,
    unit_dir: str | None = None,
    bin_dir: str | None = None,
    record_path: str | None = None,
    repo: str | None = None,
) -> RollbackManifest:
    """Compute the rollback manifest (no writes).

    Tolerates a missing/partial install record: when it cannot be loaded, the
    owned set is reconstructed from the repo artifact tree + the scoped backup
    dir scan, so a crashed install still rolls back to a clean state (#1).
    """
    home = os.path.abspath(home)
    unit_dir = os.path.abspath(unit_dir) if unit_dir else default_unit_dir()
    bin_dir = os.path.abspath(bin_dir) if bin_dir else default_bin_dir()
    repo = os.path.abspath(repo) if repo else _default_repo()
    record_path = record_path or _record_path(home)

    record = None
    try:
        record = load_record(record_path)
    except (OSError, ValueError):
        record = None

    backup_dir = _find_backup_dir(home, (record or {}).get("backup_dir"))
    unit_path = (record or {}).get("unit_path") or os.path.join(unit_dir, "r2d2.service")
    config_path = os.path.join(home, "config.yaml")
    rollout_owner = (record or {}).get("rollout_owner") or {}

    # Owned CLI launchers: from the record, else deterministically from bin_dir
    # (a crashed install that lost the record still rolls its launchers back).
    launcher_targets = list(
        (record or {}).get("launchers")
        or [os.path.join(bin_dir, name) for name in LAUNCHER_NAMES]
    )

    # Owned artifact targets: from the record, else the repo artifact tree.
    if record and record.get("owned_actions"):
        artifact_targets = [
            a["target"] for a in record["owned_actions"] if a.get("source")
        ]
    else:
        artifact_targets = [
            os.path.join(home, rel) for _, rel in _source_files(repo, ARTIFACT_REL_DIRS)
        ]

    # Backed-up originals (scan the scoped backup dir).
    backup_targets = _scan_backup_targets(backup_dir, home) if backup_dir else {}

    actions: list[FileAction] = []

    def _restore_or_remove(target: str, reason_restore: str, reason_remove: str) -> None:
        bkp = backup_targets.get(os.path.abspath(target))
        if bkp and os.path.isfile(bkp):
            actions.append(FileAction("restore", target, backup_path=bkp, reason=reason_restore))
        else:
            actions.append(FileAction("remove", target, reason=reason_remove))

    for target in artifact_targets:
        _restore_or_remove(target, "restore original artifact", "remove owned artifact")

    _restore_or_remove(unit_path, "restore original unit", "remove generated unit")

    for target in launcher_targets:
        _restore_or_remove(target, "restore original launcher", "remove owned launcher")

    # Config: restore original bytes when backed up, else unregister owned names.
    bkp_cfg = backup_targets.get(os.path.abspath(config_path))
    if bkp_cfg and os.path.isfile(bkp_cfg):
        actions.append(FileAction("restore", config_path, backup_path=bkp_cfg, reason="restore original config"))
    else:
        actions.append(FileAction("restore", config_path, reason="unregister plugin names from plugins.enabled"))

    return RollbackManifest(
        home=home,
        unit_dir=unit_dir,
        config_path=config_path,
        unit_path=unit_path,
        record_path=record_path,
        audit_path=os.path.join(home, RECORD_DIR, ROLLBACK_AUDIT_NAME),
        rollout_owner=rollout_owner,
        units_to_stop=(UNIT_NAME,),
        actions=tuple(actions),
    )


def _systemctl_disable_now(unit_name: str) -> dict:
    """Real runner: ``systemctl --user disable --now <unit>.service`` (r2d2 ONLY).

    Returns a truthful outcome dict; never touches the Hermes gateway/service.
    """
    unit = f"{unit_name}.service"
    try:
        proc = subprocess.run(
            ["systemctl", "--user", "disable", "--now", unit],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {
            "unit": unit_name,
            "outcome": "disabled" if proc.returncode == 0 else "failed",
            "rc": proc.returncode,
            "stderr": proc.stderr.strip()[:200],
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"unit": unit_name, "outcome": "error", "error": str(exc)}


def _append_audit(path: str, record: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    line = json.dumps(record, sort_keys=True) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def apply_rollback(manifest: RollbackManifest, *, dry_run: bool = False, runner=None) -> None:
    """Apply the rollback (stop/disable r2d2, restore/remove owned changes).

    ``runner`` is the systemctl shim (injectable for tests); it receives the unit
    name (``"r2d2"``) and returns a truthful outcome dict recorded in the audit.
    Retains the install record (audit) and appends a rollback-audit entry.
    NEVER touches incident/hit evidence, unrelated files, or another unit.
    """
    if dry_run:
        return
    runner = runner if runner is not None else _systemctl_disable_now

    # 1. Stop/disable ONLY r2d2 (guarded: only when the unit file is present).
    stop_results: list[dict] = []
    if os.path.isfile(manifest.unit_path):
        for unit in manifest.units_to_stop:
            try:
                stop_results.append(runner(unit))
            except Exception as exc:  # noqa: BLE001 - audit must record the truth
                stop_results.append({"unit": unit, "outcome": "error", "error": str(exc)})
    else:
        stop_results.append(
            {"unit": UNIT_NAME, "outcome": "skipped", "reason": "unit not present"}
        )

    # 2. Restore/remove owned files.
    for a in manifest.actions:
        if a.kind == "remove":
            try:
                if os.path.isfile(a.target) or os.path.islink(a.target):
                    os.remove(a.target)
            except OSError:
                pass
            _prune_empty_parents(a.target, manifest.home)
        elif a.kind == "restore":
            if a.backup_path and os.path.isfile(a.backup_path):
                _copy_file(a.backup_path, a.target)
            else:
                # Unregister owned names (comment-preserving, VALIDATED).
                try:
                    with open(a.target, encoding="utf-8") as f:
                        current = f.read()
                except OSError:
                    continue
                updated = remove_plugins_enabled(current, REGISTERED_PLUGINS)
                if updated != current:
                    validate_config_removal(current, updated, REGISTERED_PLUGINS)
                    write_config_atomic(a.target, updated)

    # 3. Retain audit: the install record stays; append a rollback entry.
    _append_audit(
        manifest.audit_path,
        {
            "rolled_back_at": time.time(),
            "home": manifest.home,
            "unit_stopped": stop_results,
            "rollout_owner": dict(manifest.rollout_owner),
        },
    )


def _prune_empty_parents(path: str, home: str) -> None:
    """Remove now-empty owned parent dirs (e.g. plugins/ed209) up to ``home``.

    Stops at (and never removes) ``home``, ``home/plugins``, or ``home/skills``
    roots — only the specific owned subdirs are pruned. Never touches unrelated
    sibling dirs.
    """
    protected = {
        home,
        os.path.join(home, "plugins"),
        os.path.join(home, "skills"),
    }
    d = os.path.dirname(path)
    while d and d != home and os.path.isdir(d):
        if d in protected:
            break
        try:
            os.rmdir(d)
        except OSError:
            break
        d = os.path.dirname(d)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rollback.py",
        description="Roll back the operator-guards R2-D2 install (dry-run by default).",
    )
    p.add_argument("--home", default=os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes"))
    p.add_argument("--unit-dir", default=None)
    p.add_argument("--bin-dir", default=None)
    p.add_argument("--apply", action="store_true", help="actually apply (default is dry-run only)")
    return p


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    manifest = build_rollback_manifest(args.home, unit_dir=args.unit_dir, bin_dir=args.bin_dir)
    print(manifest.render())
    if args.apply:
        apply_rollback(manifest, dry_run=False)
        print(f"\nAPPLIED rollback into {manifest.home}")
    else:
        print("\n(dry-run: nothing was changed; pass --apply to roll back)")
    return 0


__all__ = [
    "RollbackManifest",
    "UNIT_NAME",
    "build_rollback_manifest",
    "apply_rollback",
    "default_unit_dir",
    "default_bin_dir",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
