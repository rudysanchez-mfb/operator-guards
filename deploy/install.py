"""R2-D2 installer (plan Task 16, phase E) — BUILD + DRY-RUN ONLY.

This leaf does NOT install into the live profile. It provides:

* a **dry-run manifest FIRST** (every file it would create/modify/back up) and a
  **scoped backup** of anything it would overwrite;
* an **atomic, comment-preserving** ``plugins.enabled`` registration (a
  text-level round-trip edit, NOT a YAML re-dump, so comments and unknown keys
  survive byte-for-byte);
* a **generated systemd user unit** with explicit VERIFIED absolute paths
  (resolved at install time — the library never hardcodes the live profile
  home);
* a **seeded runtime ED-209 rules doc** (``<home>/ed209/rules.json``) copied
  from the bundled ``rulepacks/documented-initial.json`` — the enforcement
  source of truth. Idempotent and NON-clobbering: an existing rules.json is an
  operator-authored doc and is never overwritten (reported as a ``skip``);
* a durable **install record** (audit) capturing the owned changes and the
  recorded rollout owner.

The installer copies the package plugin/skill artifacts into the default
profile, preserves unrelated config/skill files, and registers through the
supported Hermes ``plugins.enabled`` config list. Config files are
version-controlled WITHOUT secrets (the deploy scripts live in Git; no secret
is written).

The live profile home is NEVER hardcoded in library code: every path is
resolved from an explicit ``home`` argument (and ``unit_dir``), defaulting to
derived locations (``HERMES_HOME``/``~/.hermes``) only at the CLI boundary.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

# ---------------------------------------------------------------------------
# Owned artifact names (closed allowlist — the installer copies exactly these)
# ---------------------------------------------------------------------------

_PLUGIN_NAMES = ("ed209", "r2d2")
_SKILL_NAMES = ("ed209-ops", "correct", "r2d2-escalate")

# The config change the installer makes: register these plugins as enabled.
REGISTERED_PLUGINS = ("ed209", "r2d2")

# Operator CLI launcher scripts the installer creates in ``~/.local/bin``
# (plan §3 INTENDS these to exist). Each is a tiny executable that execs the
# repo venv python with ``-m <module>``; the module is importable in that venv
# via the editable install. Ordering matters for tests (kept deterministic).
LAUNCHER_MODULES = {
    "ed209": "operator_guards.ed209.cli",
    "r2d2": "operator_guards.r2d2.cli",
}
LAUNCHER_NAMES = tuple(LAUNCHER_MODULES)

# Where the durable install record (audit) lives, relative to the profile home.
RECORD_DIR = "operator-guards"
RECORD_NAME = "install-manifest.json"
BACKUP_DIR_NAME = "backup"

# The bundled rulepack that SEEDS the runtime ED-209 rules doc at first install.
# Single source of truth: the ed209 CLI reads this exact file for its read-only
# pre-deployment seed, and the plugin's runtime path is ``<home>/ed209/rules.json``
# (the plugin has NO silent fallback to this bundle — enforcement requires the
# seeded runtime doc).
RULES_SEED_REL_SOURCE = os.path.join("rulepacks", "documented-initial.json")
RULES_RUNTIME_REL = os.path.join("ed209", "rules.json")

# systemd user unit search path — resolved at CALL time, never import time
# (so a changed XDG_CONFIG_HOME/HOME is honoured and there is one single source).
def default_unit_dir() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "systemd", "user")


# Operator CLI launcher dir — resolved at CALL time (single source, reused by
# rollback). Never hardcoded to the live profile in library code.
def default_bin_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".local", "bin")


def rules_seed_source(repo: str) -> str:
    """Absolute path to the bundled rulepack that seeds the runtime rules doc."""
    return os.path.join(os.path.abspath(repo), RULES_SEED_REL_SOURCE)


def rules_runtime_target(home: str) -> str:
    """Absolute path to the runtime ED-209 rules doc the seed creates."""
    return os.path.join(os.path.abspath(home), RULES_RUNTIME_REL)


# The artifact sub-trees the installer copies (single source for install + rollback).
ARTIFACT_REL_DIRS = tuple(
    os.path.join("plugins", n) for n in _PLUGIN_NAMES
) + tuple(os.path.join("skills", n) for n in _SKILL_NAMES)

# Install phase/commit marker inside the scoped backup dir.
PHASE_NAME = "PHASE"

_TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "r2d2.service")


# ---------------------------------------------------------------------------
# Manifest types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FileAction:
    """One planned filesystem action (a create/modify/overwrite/backup/remove)."""

    kind: str  # "create" | "overwrite" | "modify" | "remove"
    target: str
    source: str | None = None  # source path for copies (plugins/skills)
    reason: str = ""
    backup_path: str | None = None  # scoped backup destination, when a target pre-exists


@dataclass(frozen=True)
class InstallManifest:
    """The dry-run manifest: every file the installer would create/modify/back up."""

    home: str
    repo: str
    unit_dir: str
    unit_path: str
    config_path: str
    record_path: str
    backup_dir: str
    bin_dir: str
    rollout_owner: Mapping[str, Any]
    launcher_paths: tuple = ()  # tuple[(target, module)] for ~/.local/bin launchers
    actions: tuple = ()

    def render(self) -> str:
        """Human-readable dry-run listing (used by ``--dry-run``)."""
        lines = [
            f"DRY-RUN: install operator-guards (R2-D2) into {self.home}",
            f"  repo:        {self.repo}",
            f"  unit:        {self.unit_path}",
            f"  bin:         {self.bin_dir}",
            f"  backup dir:  {self.backup_dir}",
            f"  rollout owner: {json.dumps(dict(self.rollout_owner), sort_keys=True)}",
            "",
            f"Planned actions ({len(self.actions)}):",
        ]
        for a in self.actions:
            src = f" <- {a.source}" if a.source else ""
            bkp = f" (backup {a.backup_path})" if a.backup_path else ""
            lines.append(f"  {a.kind:9} {a.target}{src}{bkp}")
        return "\n".join(lines)

    def record(self, now: float | None = None) -> dict:
        """The durable install record written to ``record_path`` (the audit)."""
        created = tuple(
            {"kind": a.kind, "target": a.target, "source": a.source}
            for a in self.actions
            if a.kind != "skip"
        )
        skipped = tuple(
            {"target": a.target, "source": a.source, "reason": a.reason}
            for a in self.actions
            if a.kind == "skip"
        )
        return {
            "version": 1,
            "installed_at": time.time() if now is None else now,
            "repo": self.repo,
            "home": self.home,
            "unit_path": self.unit_path,
            "backup_dir": self.backup_dir,
            "rollout_owner": dict(self.rollout_owner),
            "launchers": [target for target, _module in self.launcher_paths],
            "owned_actions": created,
            "skipped_actions": skipped,
        }


# ---------------------------------------------------------------------------
# Config text round-trip (comment-preserving, atomic — NOT a YAML dump)
# ---------------------------------------------------------------------------

_ENABLED_ITEM_RE = re.compile(r"^(\s*)-\s+(\S+)(.*)$")

# Shape markers the text editor refuses (never silently corrupts).
_MULTIDOC_LINE_RE = re.compile(r"^(?:---|\.\.\.)\s*$")


class ConfigEditError(ValueError):
    """config.yaml uses a shape the text editor refuses to touch."""


def _nl(text: str) -> str:
    """The file's dominant newline (CRLF-safe insertion)."""
    return "\r\n" if "\r\n" in text else "\n"


def _is_quoted_scalar(s: str) -> bool:
    return len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"')


def _strip_quotes(s: str) -> str:
    return s[1:-1] if _is_quoted_scalar(s) else s


def _iter_enabled_items(text: str) -> list[str]:
    """Ordered ``plugins.enabled`` item names (quotes stripped), text-level."""
    names: list[str] = []
    lines = text.splitlines()
    n = len(lines)
    i = 0
    while i < n:
        if lines[i].startswith("plugins:"):
            break
        i += 1
    else:
        return names
    i += 1
    while i < n:
        line = lines[i]
        if line.strip() == "":
            i += 1
            continue
        if not line.startswith(" "):
            break  # left the plugins block (top-level key)
        if line.startswith("  enabled:"):
            j = i + 1
            while j < n:
                ln = lines[j]
                if ln.strip() == "":
                    j += 1
                    continue
                if not ln.startswith(" "):
                    break
                if ln.startswith("    - "):
                    item = ln[6:].split("#", 1)[0].strip()
                    if item:
                        names.append(_strip_quotes(item))
                elif ln.startswith("  ") and not ln.startswith("    "):
                    break  # sibling 2-space key -> end of enabled list
                j += 1
            return names
        i += 1
    return names


def enabled_plugins(text: str) -> set[str]:
    """Parse the ``plugins.enabled`` list out of raw config text (text-level).

    Only the ``enabled:`` sub-list under the top-level ``plugins:`` key is read;
    everything else (comments, unknown keys, the ``disabled:`` list) is ignored.
    Quoted items (``- "weather"``) are read as their bare name.
    """
    return set(_iter_enabled_items(text))


def ensure_plugin_enabled(text: str, names: Iterable[str]) -> str:
    """Return ``text`` with ``names`` present in ``plugins.enabled``.

    Purely text-level: inserts ``    - <name>`` lines right after the
    ``  enabled:`` key (or appends a whole ``plugins:`` block when absent), so
    every comment and unknown key elsewhere survives byte-for-byte. Idempotent.
    Preserves the file's newline style (LF vs CRLF).
    """
    missing = [n for n in names if n not in enabled_plugins(text)]
    if not missing:
        return text
    nl = _nl(text)
    lines = text.splitlines(keepends=True)
    idx = None
    for i, ln in enumerate(lines):
        if ln.startswith("plugins:"):
            idx = i
            break
    if idx is None:
        block = f"plugins:{nl}  enabled:{nl}" + "".join(f"    - {n}{nl}" for n in missing)
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += nl
        return "".join(lines) + block
    j = idx + 1
    while j < len(lines):
        ln = lines[j]
        if ln.startswith("  enabled:"):
            insertion = "".join(f"    - {n}{nl}" for n in missing)
            lines.insert(j + 1, insertion)
            return "".join(lines)
        if ln.strip() and not ln.startswith(" "):
            break  # no enabled: key yet — insert one under plugins:
        j += 1
    lines.insert(idx + 1, f"  enabled:{nl}")
    lines.insert(idx + 2, "".join(f"    - {n}{nl}" for n in missing))
    return "".join(lines)


def remove_plugins_enabled(text: str, names: Iterable[str]) -> str:
    """Return ``text`` with ``names`` removed from ``plugins.enabled``.

    The exact inverse of :func:`ensure_plugin_enabled` (lossless round-trip);
    drops only the matching ``- name`` lines (quote-insensitive), preserving
    comments and all other keys byte-for-byte.
    """
    nameset = set(names)
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    in_enabled = False
    for ln in lines:
        if not in_enabled:
            out.append(ln)
            if ln.startswith("  enabled:"):
                in_enabled = True
            continue
        if ln.strip() == "":
            out.append(ln)
            continue
        if not ln.startswith(" "):
            in_enabled = False
            out.append(ln)
            continue
        m = _ENABLED_ITEM_RE.match(ln)
        if m and _strip_quotes(m.group(2).strip()) in nameset:
            continue  # drop this owned item line
        if ln.startswith("  ") and not ln.startswith("    "):
            in_enabled = False  # sibling 2-space key ended the enabled list
        out.append(ln)
    return "".join(out)


# -- structural YAML-shape validation (refuse, never corrupt) ---------------


def _validate_item(item: str) -> None:
    body = item.split("#", 1)[0].strip()
    if not body:
        raise ConfigEditError("plugins.enabled has an empty item; refusing to modify")
    if _is_quoted_scalar(body):
        return  # a fully quoted scalar is always a scalar
    if body[0] in "[{":
        raise ConfigEditError("plugins.enabled uses flow/block collection items; refusing to modify")
    if body.startswith(("&", "*", "!")):
        raise ConfigEditError("plugins.enabled uses anchors/aliases/tags; refusing to modify")
    if body.startswith("- "):
        raise ConfigEditError("plugins.enabled uses nested lists; refusing to modify")
    if ":" in body:
        raise ConfigEditError("plugins.enabled uses list-of-maps; refusing to modify")


def _validate_enabled_items(lines: list[str], j: int) -> None:
    while j < len(lines):
        ln = lines[j]
        stripped = ln.strip()
        if stripped == "" or stripped.startswith("#"):
            j += 1
            continue
        if not ln.startswith(" "):
            return  # left the enabled list (top-level key)
        if ln.startswith("    - "):
            _validate_item(ln[6:])
            j += 1
            continue
        if ln.startswith("  ") and not ln.startswith("    "):
            return  # sibling key under plugins (e.g. 'disabled:')
        raise ConfigEditError("plugins.enabled has an unsupported shape; refusing to modify")


def _validate_plugins_block(lines: list[str], start: int) -> None:
    i = start + 1
    while i < len(lines):
        ln = lines[i]
        stripped = ln.strip()
        if stripped == "" or stripped.startswith("#"):
            i += 1
            continue
        if not ln.startswith(" "):
            break  # back to top level
        if ln.startswith("  enabled:"):
            rest = ln[len("  enabled:"):].strip()
            if rest and not rest.startswith("#"):
                raise ConfigEditError(
                    "plugins.enabled must be a block list ('enabled:' followed by '- name' lines); "
                    "flow/anchor/scalar forms are unsupported"
                )
            _validate_enabled_items(lines, i + 1)
            return
        i += 1


def _validate_config_shape(text: str) -> None:
    """Refuse config shapes the text editor cannot modify safely (never corrupt)."""
    lines = text.splitlines()
    for ln in lines:
        if _MULTIDOC_LINE_RE.match(ln):
            raise ConfigEditError("config.yaml is multi-document YAML; refusing to modify")
    for i, ln in enumerate(lines):
        if ln.startswith("plugins:"):
            _validate_plugins_block(lines, i)
            return


def validate_config_edit(original: str, edited: str, added_names: Iterable[str]) -> None:
    """Verify an ``ensure_plugin_enabled`` edit round-trips to a sane structure.

    Raises :class:`ConfigEditError` (refuses) when the original or the edited
    text is unsupported/corrupt — so a bad edit is never written.
    """
    _validate_config_shape(original)
    _validate_config_shape(edited)
    expected = set(_iter_enabled_items(original)) | set(added_names)
    if set(_iter_enabled_items(edited)) != expected:
        raise ConfigEditError("config edit did not round-trip; refusing to write")


def validate_config_removal(original: str, edited: str, removed_names: Iterable[str]) -> None:
    """Verify a ``remove_plugins_enabled`` edit round-trips to a sane structure."""
    _validate_config_shape(original)
    _validate_config_shape(edited)
    expected = set(_iter_enabled_items(original)) - set(removed_names)
    if set(_iter_enabled_items(edited)) != expected:
        raise ConfigEditError("config edit did not round-trip; refusing to write")


# ---------------------------------------------------------------------------
# Atomic write (temp + fsync + replace + parent-dir fsync)
# ---------------------------------------------------------------------------


def _fsync_dir(dirpath: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    dfd = os.open(dirpath, flags)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def write_config_atomic(path: str, text: str) -> None:
    """Atomically replace ``path`` with ``text`` (never a partial write).

    Preserves the prior file's mode (if any) and writes UTF-8 with no newline
    translation, so CRLF/LF content is stored byte-for-byte.
    """
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        mode = None
    fd, tmp = tempfile.mkstemp(prefix=".cfg-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
        _fsync_dir(d)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_text(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Path resolution + artifact discovery
# ---------------------------------------------------------------------------


def _source_files(repo: str, rel_dirs: Iterable[str]) -> list[tuple[str, str]]:
    """Return [(source_abs, target_rel)] for every file under the given rel dirs.

    Skips ``__pycache__`` (version-controlled artifacts only).
    """
    out: list[tuple[str, str]] = []
    for rel in rel_dirs:
        base = os.path.join(repo, rel)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for fn in filenames:
                src = os.path.join(dirpath, fn)
                target_rel = os.path.relpath(src, base)
                out.append((src, os.path.join(rel, target_rel)))
    return out


def resolve_targets(home: str, repo: str, unit_dir: str, bin_dir: str) -> dict:
    """All target paths the installer touches (resolved, absolute)."""
    home = os.path.abspath(home)
    repo = os.path.abspath(repo)
    unit_dir = os.path.abspath(unit_dir)
    bin_dir = os.path.abspath(bin_dir)
    launcher_paths = tuple(
        (os.path.join(bin_dir, name), module)
        for name, module in LAUNCHER_MODULES.items()
    )
    return {
        "home": home,
        "repo": repo,
        "unit_dir": unit_dir,
        "bin_dir": bin_dir,
        "launcher_paths": launcher_paths,
        "unit_path": os.path.join(unit_dir, "r2d2.service"),
        "config_path": os.path.join(home, "config.yaml"),
        "record_path": os.path.join(home, RECORD_DIR, RECORD_NAME),
        "backup_dir": os.path.join(
            home, RECORD_DIR, BACKUP_DIR_NAME, time.strftime("%Y%m%dT%H%M%S")
        ),
    }


def discover_rollout_owner(home: str) -> dict:
    """Best-effort discovery of the managed Hermes rollout owner.

    Reads the PM install metadata (``installs/*/bootstrap/default.json`` for the
    identity, and ``installs/*/facts.json`` ``packages.venv.environment`` for the
    active environment) to find the active install/environment; returns ``{}``
    when the managed layout is absent. NEVER hardcoded in library code —
    resolved at install time from the live home.
    """
    try:
        installs = os.path.join(home, "installs")
        if not os.path.isdir(installs):
            return {}
        for entry in sorted(os.listdir(installs)):
            root = os.path.join(installs, entry)
            bootstrap = os.path.join(root, "bootstrap", "default.json")
            if not os.path.isfile(bootstrap):
                continue
            owner: dict[str, str] = {"install_root": root}
            try:
                with open(bootstrap, encoding="utf-8") as f:
                    meta = json.load(f)
                if isinstance(meta, dict):
                    for key in ("identity", "adopt_blessed_checkout"):
                        if meta.get(key):
                            owner[key] = str(meta[key])
            except (OSError, ValueError):
                pass
            facts = os.path.join(root, "facts.json")
            try:
                with open(facts, encoding="utf-8") as f:
                    fdata = json.load(f)
            except (OSError, ValueError):
                fdata = {}
            env_path = ""
            if isinstance(fdata, dict):
                venv = (fdata.get("packages") or {}).get("venv") if isinstance(fdata.get("packages"), dict) else None
                if isinstance(venv, dict):
                    env_path = venv.get("environment") or ""
            if env_path:
                owner["environment"] = str(env_path)
                m = re.search(r"environments/([^/]+)", str(env_path))
                if m:
                    owner["environment_id"] = m.group(1)
            return owner
    except OSError:
        return {}
    return {}


def load_record(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"install record {path!r} is not a JSON object")
    return data


# ---------------------------------------------------------------------------
# Unit rendering
# ---------------------------------------------------------------------------


def render_unit(repo: str, home: str, user_home: str | None = None) -> str:
    """Render ``deploy/r2d2.service`` with explicit VERIFIED absolute paths."""
    repo = os.path.abspath(repo)
    home = os.path.abspath(home)
    user_home = os.path.abspath(user_home) if user_home else os.path.expanduser("~")
    python = os.path.join(repo, ".venv", "bin", "python")
    venv_bin = os.path.join(repo, ".venv", "bin")
    with open(_TEMPLATE_PATH, encoding="utf-8") as f:
        template = f.read()
    return (
        template.replace("__REPO__", repo)
        .replace("__PYTHON__", python)
        .replace("__VENV_BIN__", venv_bin)
        .replace("__HOME__", home)
        .replace("__USER_HOME__", user_home)
    )


def render_launcher(repo: str, module: str) -> str:
    """Render an executable ``~/.local/bin`` launcher that execs the repo venv.

    ``exec`` (not a fork) so the CLI's exit code + signals pass through
    unchanged. The venv python is resolved from the repo at install time, so
    the launcher stays correct if the repo moves — it never hardcodes the live
    profile home.
    """
    python = os.path.join(os.path.abspath(repo), ".venv", "bin", "python")
    return (
        "#!/bin/sh\n"
        "# Generated by the operator-guards installer (owned). Do not edit.\n"
        f'exec "{python}" -m {module} "$@"\n'
    )


# ---------------------------------------------------------------------------
# Manifest build + apply
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Scoped backup path encoding + install phase marker
# ---------------------------------------------------------------------------


def _backup_rel(target: str, home: str) -> str:
    """Relative path for a target's scoped backup, ALWAYS inside ``backup/<ts>/``.

    In-home targets map to ``home/<rel>``; out-of-home targets (e.g. the systemd
    unit under ``~/.config``) map to ``system/<abs-path-without-leading-slash>``
    — so no backup ever escapes the timestamped dir (finding #3).
    """
    target = os.path.abspath(target)
    home = os.path.abspath(home)
    rel = os.path.relpath(target, home)
    if rel == ".." or rel.startswith(".." + os.sep) or os.path.isabs(rel):
        return os.path.join("system", target.lstrip(os.sep))
    return os.path.join("home", rel)


def _target_from_backup_rel(rel: str, home: str) -> str:
    """Inverse of :func:`_backup_rel` (used by rollback's backup-dir scan)."""
    home = os.path.abspath(home)
    if rel.startswith("system" + os.sep):
        return os.sep + rel[len("system" + os.sep):]
    if rel.startswith("home" + os.sep):
        return os.path.join(home, rel[len("home" + os.sep):])
    # Legacy fallback: pre-encoding backups stored the home-relative path directly.
    return os.path.join(home, rel)


def _phase_path(backup_dir: str) -> str:
    return os.path.join(backup_dir, PHASE_NAME)


def _write_phase(backup_dir: str, phase: str) -> None:
    """Write/update the install PHASE marker (in-progress -> committed)."""
    os.makedirs(backup_dir, exist_ok=True)
    payload = json.dumps({"phase": phase, "ts": time.time()}, sort_keys=True) + "\n"
    write_config_atomic(_phase_path(backup_dir), payload)


def read_phase(backup_dir: str) -> dict:
    """Read the PHASE marker, or ``{}`` when absent/unreadable."""
    try:
        with open(_phase_path(backup_dir), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def build_manifest(
    home: str,
    repo: str,
    *,
    unit_dir: str | None = None,
    bin_dir: str | None = None,
    rollout_owner: Mapping[str, Any] | None = None,
) -> InstallManifest:
    """Compute the dry-run manifest (NO filesystem changes)."""
    t = resolve_targets(home, repo, unit_dir or default_unit_dir(), bin_dir or default_bin_dir())
    actions: list[FileAction] = []
    backup_dir = t["backup_dir"]

    def _backup_path(target: str) -> str:
        return os.path.join(backup_dir, _backup_rel(target, t["home"]))

    # 1. Plugin + skill artifacts (copy the version-controlled tree).
    for src, rel in _source_files(repo, ARTIFACT_REL_DIRS):
        target = os.path.join(t["home"], rel)
        if os.path.exists(target):
            actions.append(
                FileAction("overwrite", target, src, "owned artifact", _backup_path(target))
            )
        else:
            actions.append(FileAction("create", target, src, "owned artifact"))

    # 2. Config registration (always a "modify"; scoped backup if pre-existing).
    config_path = t["config_path"]
    bkp = _backup_path(config_path) if os.path.exists(config_path) else None
    actions.append(
        FileAction(
            "modify",
            config_path,
            None,
            f"register {', '.join(REGISTERED_PLUGINS)} in plugins.enabled",
            bkp,
        )
    )

    # 2.5. Runtime ED-209 rules seed (the enforcement source of truth). IDEMPOTENT
    # and NON-clobbering: an existing rules.json is an operator-authored doc and
    # is NEVER overwritten or backed up — the install reports a `skip` instead
    # (leaving the operator's rules byte-identical). A missing rules.json is a
    # `create` seeded from the bundled documented-initial rulepack. hits.db is
    # deliberately NOT created here (the ledger is created on first hit).
    rules_src = rules_seed_source(repo)
    rules_target = rules_runtime_target(t["home"])
    if os.path.exists(rules_target):
        actions.append(
            FileAction(
                "skip",
                rules_target,
                rules_src,
                "rules seed SKIPPED: existing rules.json preserved (operator-authored)",
            )
        )
    else:
        actions.append(
            FileAction(
                "create",
                rules_target,
                rules_src,
                "seed runtime ED-209 rules from bundled documented-initial rulepack",
            )
        )

    # 3. Generated systemd user unit.
    if os.path.exists(t["unit_path"]):
        actions.append(
            FileAction("overwrite", t["unit_path"], None, "generated unit", _backup_path(t["unit_path"]))
        )
    else:
        actions.append(FileAction("create", t["unit_path"], None, "generated unit"))

    # 3.5. Operator CLI launchers in ~/.local/bin (plan §3). A pre-existing
    # file of the same name is scoped-backed up (never silently clobbered);
    # rollback restores it byte-exact.
    for target, module in t["launcher_paths"]:
        if os.path.exists(target):
            actions.append(
                FileAction("overwrite", target, None, f"CLI launcher ({module})", _backup_path(target))
            )
        else:
            actions.append(FileAction("create", target, None, f"CLI launcher ({module})"))

    # 4. Durable install record (audit).
    if os.path.exists(t["record_path"]):
        actions.append(
            FileAction("overwrite", t["record_path"], None, "install record", _backup_path(t["record_path"]))
        )
    else:
        actions.append(FileAction("create", t["record_path"], None, "install record"))

    owner = dict(rollout_owner) if rollout_owner is not None else discover_rollout_owner(t["home"])
    return InstallManifest(
        home=t["home"],
        repo=t["repo"],
        unit_dir=t["unit_dir"],
        unit_path=t["unit_path"],
        config_path=config_path,
        record_path=t["record_path"],
        backup_dir=backup_dir,
        bin_dir=t["bin_dir"],
        rollout_owner=owner,
        launcher_paths=t["launcher_paths"],
        actions=tuple(actions),
    )


def _copy_file(src: str, dst: str) -> None:
    """Copy ``src`` bytes to ``dst`` atomically and WITHOUT following symlinks.

    Writes to a temp file in ``dst``'s directory, fsyncs, then ``os.replace``
    (which swaps the directory entry), so a pre-existing symlink at ``dst`` is
    REPLACED by a regular file — never written through to the link's target.
    The source file's mode is preserved.
    """
    d = os.path.dirname(dst) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".cp-", dir=d)
    try:
        with open(src, "rb") as fsrc, os.fdopen(fd, "wb") as fdst:
            shutil.copyfileobj(fsrc, fdst)
            fdst.flush()
            os.fsync(fdst.fileno())
        shutil.copymode(src, tmp)
        os.replace(tmp, dst)
        _fsync_dir(d)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def apply_manifest(manifest: InstallManifest, *, dry_run: bool = False) -> None:
    """Apply the manifest transactionally (scoped backup + phase marker).

    Writes an ``in-progress`` PHASE marker FIRST and finalizes it to
    ``committed`` only after the durable install record is written, so a crash
    mid-install leaves a scoped backup dir that rollback can scan and recover
    from (finding #1). ``dry_run=True`` makes NO filesystem changes.
    """
    if dry_run:
        return

    _write_phase(manifest.backup_dir, "in-progress")
    try:
        # Scoped backup first (anything that would be overwritten/modified).
        for a in manifest.actions:
            if a.backup_path and os.path.exists(a.target) and not os.path.isdir(a.target):
                _copy_file(a.target, a.backup_path)

        # Copy artifacts (atomic, symlink-safe).
        for a in manifest.actions:
            if a.kind in ("create", "overwrite") and a.source:
                _copy_file(a.source, a.target)

        # Config registration (atomic, comment-preserving, VALIDATED).
        config_actions = [a for a in manifest.actions if a.kind == "modify"]
        if config_actions:
            config_path = config_actions[0].target
            current = _read_text(config_path) or ""
            updated = ensure_plugin_enabled(current, REGISTERED_PLUGINS)
            if updated != current:
                validate_config_edit(current, updated, REGISTERED_PLUGINS)
                write_config_atomic(config_path, updated)

        # Generated unit (atomic write).
        unit_actions = [
            a for a in manifest.actions
            if a.target == manifest.unit_path and a.kind in ("create", "overwrite")
        ]
        if unit_actions:
            rendered = render_unit(manifest.repo, manifest.home)
            write_config_atomic(manifest.unit_path, rendered)

        # Operator CLI launchers in ~/.local/bin (rendered + executable).
        for target, module in manifest.launcher_paths:
            write_config_atomic(target, render_launcher(manifest.repo, module))
            os.chmod(target, 0o755)

        # Durable install record (atomic write).
        record_data = json.dumps(manifest.record(), indent=2, sort_keys=True) + "\n"
        write_config_atomic(manifest.record_path, record_data)

        _write_phase(manifest.backup_dir, "committed")
    except BaseException:
        # Leave PHASE=in-progress so rollback can detect and recover the partial install.
        raise


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="install.py",
        description="Install the operator-guards R2-D2 unit + plugin/skill artifacts (dry-run by default).",
    )
    p.add_argument("--home", default=None, help="profile home (default: HERMES_HOME or ~/.hermes)")
    p.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]))
    p.add_argument("--unit-dir", default=None, help=f"systemd user unit dir (default: {default_unit_dir()})")
    p.add_argument("--bin-dir", default=None, help=f"CLI launcher dir (default: {default_bin_dir()})")
    p.add_argument("--apply", action="store_true", help="actually apply (default is dry-run only)")
    p.add_argument("--rollout-owner", default=None, help="JSON object overriding rollout-owner discovery")
    return p


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    home = args.home or os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
    owner = json.loads(args.rollout_owner) if args.rollout_owner else None
    manifest = build_manifest(
        home, args.repo, unit_dir=args.unit_dir, bin_dir=args.bin_dir, rollout_owner=owner
    )
    print(manifest.render())
    if args.apply:
        apply_manifest(manifest, dry_run=False)
        print(f"\nAPPLIED into {manifest.home}")
    else:
        print("\n(dry-run: nothing was changed; pass --apply to install)")
    return 0


__all__ = [
    "FileAction",
    "InstallManifest",
    "REGISTERED_PLUGINS",
    "RECORD_DIR",
    "RECORD_NAME",
    "BACKUP_DIR_NAME",
    "PHASE_NAME",
    "RULES_SEED_REL_SOURCE",
    "RULES_RUNTIME_REL",
    "ARTIFACT_REL_DIRS",
    "ConfigEditError",
    "enabled_plugins",
    "ensure_plugin_enabled",
    "remove_plugins_enabled",
    "validate_config_edit",
    "validate_config_removal",
    "write_config_atomic",
    "render_unit",
    "render_launcher",
    "resolve_targets",
    "default_unit_dir",
    "default_bin_dir",
    "rules_seed_source",
    "rules_runtime_target",
    "LAUNCHER_NAMES",
    "discover_rollout_owner",
    "load_record",
    "build_manifest",
    "apply_manifest",
    "_backup_rel",
    "_target_from_backup_rel",
    "_copy_file",
    "_source_files",
    "read_phase",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
