"""Shared fixtures for operator-guards tests."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def valid_incident():
    """The smallest valid R2-D2 incident record (all optional fields omitted)."""
    return {
        "id": "inc-1",
        "severity": "mechanical",
        "symptom": "service unreachable",
        "phase": "open",
        "dedupe_key": "dedupe-1",
    }


@pytest.fixture
def r2d2_cli(tmp_path):
    """Invoke the REAL r2d2 CLI module in an isolated state root.

    Returns a callable ``run(*argv, root=None)`` that runs the actual
    ``operator_guards.r2d2.cli`` entry point in a subprocess (so the real
    module, not an in-process wrapper, is exercised), captures bounded output,
    and returns the ``subprocess.CompletedProcess``. The default root is
    ``<tmp_path>/r2d2``, shared across the test and the ``committed_incident``
    fixture so a raised incident is visible to later CLI verbs.
    """
    default_root = tmp_path / "r2d2"

    def run(*argv, root=None):
        root = str(root) if root is not None else str(default_root)
        return subprocess.run(
            [sys.executable, "-m", "operator_guards.r2d2.cli", "--root", root, *argv],
            capture_output=True,
            text=True,
            cwd=str(REPO),
            env={**os.environ},
        )

    return run


@pytest.fixture
def committed_incident(r2d2_cli):
    """Raise a real incident through the CLI and return its committed id.

    Calls the actual ``raise`` verb and reads the durable incident id back
    from the CLI's stdout (which the CLI prints only after event and state
    durability are confirmed).
    """
    proc = r2d2_cli(
        "raise",
        "--id", "inc-committed",
        "--severity", "mechanical",
        "--symptom", "fixture incident",
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()
