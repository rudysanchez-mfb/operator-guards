"""Task 15: the three Hermes skills load in a FRESH ISOLATED default-shaped
home, carry valid frontmatter (``name`` matches the dir, a self-contained
first-57-char trigger description, no secrets), and reference ONLY commands
that genuinely exist in the ``ed209``/``r2d2`` CLIs.

The skills EXPLAIN behavior; the CLIs/plugins ENFORCE it. A skill may never
instruct an agent to run a nonexistent verb, so this test introspects the real
argparse parsers and cross-checks every command the skills reference.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pytest

from operator_guards.ed209.cli import build_parser as ed209_build_parser
from operator_guards.r2d2.cli import build_parser as r2d2_build_parser

REPO = Path(__file__).resolve().parents[1]
SKILLS_DIR = REPO / "skills"

SKILLS = ("ed209-ops", "correct", "r2d2-escalate")

# Commands each skill MUST reference (a skill omitting its core verbs is not a
# usable skill). Category keys mirror ``_extract_references``: "ed209" (ed209
# top-level verbs), "r2d2" (r2d2 top-level verbs), "r2d2-grant" (grant
# subverbs issue/list/revoke).
REQUIRED_REFERENCES = {
    "ed209-ops": {
        "ed209": {"list", "test-reply", "test-tool", "hits", "replay"},
        "r2d2": set(),
        "r2d2-grant": set(),
    },
    "correct": {
        "ed209": {"add", "list", "test-reply", "test-tool"},
        "r2d2": set(),
        "r2d2-grant": set(),
    },
    "r2d2-escalate": {
        "ed209": set(),
        "r2d2": {"raise", "status", "done", "watch", "events", "doctor"},
        "r2d2-grant": {"issue", "list", "revoke"},
    },
}

# Secret-like tokens that must never appear in a skill (an accidental paste of
# a credential). Kept broad on purpose: skills are plain text, no credential
# belongs in them.
_SECRET_RE = re.compile(
    r"sk-[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{10,}|"
    r"xox[bap]-[A-Za-z0-9-]{10,}|-----BEGIN|api[_-]?key|password|"
    r"access[_-]?token|secret[_-]?token"
)

_COMMAND_RE = {
    "r2d2-grant": re.compile(r"r2d2\s+grant\s+([a-z][a-z0-9-]*)"),
    "r2d2": re.compile(r"r2d2\s+([a-z][a-z0-9-]*)"),
    "ed209": re.compile(r"ed209\s+([a-z][a-z0-9-]*)"),
}


# ---------------------------------------------------------------------------
# Parser introspection: the set of REAL verbs the CLIs actually implement.
# ---------------------------------------------------------------------------

def _top_level_subcommands(parser: argparse.ArgumentParser) -> set[str]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    return set()


def _subparser(parser: argparse.ArgumentParser, name: str):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices.get(name)
    return None


def _real_verbs() -> dict[str, set[str]]:
    ed209 = ed209_build_parser()
    r2d2 = r2d2_build_parser()
    grant = _subparser(r2d2, "grant")
    return {
        "ed209": _top_level_subcommands(ed209),
        "r2d2": _top_level_subcommands(r2d2),
        "r2d2-grant": _top_level_subcommands(grant) if grant is not None else set(),
    }


# ---------------------------------------------------------------------------
# Skill loading + frontmatter parsing (dependency-free: the real format is a
# YAML block; we only need name + description here).
# ---------------------------------------------------------------------------

def _load_skill_text(name: str) -> str:
    path = SKILLS_DIR / name / "SKILL.md"
    assert path.is_file(), f"missing skill file: {path}"
    return path.read_text(encoding="utf-8")


def _frontmatter(text: str) -> tuple[str, str]:
    assert text.startswith("---\n"), "SKILL.md must begin with a YAML frontmatter block"
    parts = text.split("\n---", 1)
    assert len(parts) == 2, "SKILL.md frontmatter must be closed by a --- line"
    name = desc = None
    for line in parts[0].splitlines():
        if line.startswith("name:"):
            name = line[len("name:"):].strip()
        elif line.startswith("description:"):
            desc = line[len("description:"):].strip()
    assert name, "frontmatter is missing `name:`"
    assert desc, "frontmatter is missing `description:`"
    return name, desc


def _extract_references(text: str) -> dict[str, set[str]]:
    """Pull command verbs out of backtick spans, bucketed by CLI context."""
    refs: dict[str, set[str]] = {"ed209": set(), "r2d2": set(), "r2d2-grant": set()}
    for span in re.findall(r"`([^`]+)`", text):
        for category, pattern in _COMMAND_RE.items():
            refs[category] |= set(pattern.findall(span))
    return refs


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", SKILLS)
def test_frontmatter_valid_and_name_matches_dir(name):
    text = _load_skill_text(name)
    fm_name, desc = _frontmatter(text)
    assert fm_name == name, f"frontmatter name {fm_name!r} != dir {name!r}"
    # description is a self-contained trigger: starts with "Use " and its
    # trigger sentence terminates within the first 57 characters.
    assert desc.startswith("Use "), "description must start with 'Use ...'"
    assert "." in desc[:57], (
        "description's first 57 chars must be a self-contained trigger "
        "('Use when <trigger>. <behavior>.')"
    )
    assert len(desc) > len(desc[:57]), "description must carry behavior after the trigger"
    # a body (explanation) must follow the frontmatter
    assert "## " in text, "skill must have markdown sections explaining behavior"


@pytest.mark.parametrize("name", SKILLS)
def test_skill_contains_no_secrets(name):
    text = _load_skill_text(name)
    assert not _SECRET_RE.search(text.lower()), "skill must not contain credential-like tokens"


def test_skills_load_in_fresh_isolated_home(tmp_path):
    """A fresh default-shaped home (`<home>/skills/<name>/SKILL.md`) parses."""
    home = tmp_path / "home"
    for name in SKILLS:
        text = _load_skill_text(name)
        target = home / "skills" / name / "SKILL.md"
        target.parent.mkdir(parents=True)
        target.write_text(text, encoding="utf-8")
        fm_name, desc = _frontmatter(text)
        assert fm_name == name
        assert desc.startswith("Use ")


@pytest.mark.parametrize("name", SKILLS)
def test_skill_references_only_real_commands(name):
    text = _load_skill_text(name)
    refs = _extract_references(text)
    real = _real_verbs()
    for category, referenced in refs.items():
        assert referenced <= real[category], (
            f"{name}: referenced {category} verbs not implemented: "
            f"{sorted(referenced - real[category])} (real: {sorted(real[category])})"
        )


@pytest.mark.parametrize("name", SKILLS)
def test_skill_references_required_commands(name):
    text = _load_skill_text(name)
    refs = _extract_references(text)
    for category, required in REQUIRED_REFERENCES[name].items():
        missing = required - refs[category]
        assert not missing, (
            f"{name}: must reference these {category} commands but does not: {sorted(missing)}"
        )


def test_watch_and_doctor_are_real_r2d2_verbs():
    """The closure verbs exist in the actual r2d2 parser."""
    r2d2 = _top_level_subcommands(r2d2_build_parser())
    assert {"watch", "doctor"} <= r2d2


def test_grant_subverbs_are_real():
    real = _real_verbs()
    assert {"issue", "list", "revoke"} <= real["r2d2-grant"]


def test_correct_verb_is_real_and_skill_references_it_not_slash():
    real = _real_verbs()
    assert "correct" in real["ed209"]  # the deterministic CLI verb exists
    text = _load_skill_text("correct")
    assert "correct" in _extract_references(text)["ed209"]
    assert "/correct" not in text  # no nonexistent slash command is claimed
    assert "SUPPLEMENTAL" in text  # automatic phrase detection is labeled supplemental


def test_override_syntax_matches_real_two_group_regex():
    from operator_guards.ed209.engine import _OVERRIDE_RE

    # The real regex has exactly TWO capture groups: <rule-id> <reason>.
    assert _OVERRIDE_RE.groups == 2
    m = _OVERRIDE_RE.match("# ed209-override: ov-1 some reason here")
    assert m is not None
    assert m.groups() == ("ov-1", "some reason here")

    text = _load_skill_text("ed209-ops")
    # The documented template is exactly the two fields — no operator token.
    assert "# ed209-override: <rule-id> <reason>" in text
    assert "<operator>" not in text
