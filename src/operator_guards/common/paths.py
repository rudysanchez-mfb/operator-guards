"""Configurable default paths for operator-guards.

The original deployment hardcoded a single operator's home directory. The
published package derives every default from the environment instead:

* ``OPERATOR_GUARDS_HOME`` overrides the profile home.
* ``HERMES_HOME`` is used next (the Hermes convention).
* ``~/.hermes`` is the final fallback.

Individual defaults can still be overridden with the specific variables used by
the callers (``OPERATOR_GUARDS_ED209_RULES``, ``OPERATOR_GUARDS_ED209_DB``,
``OPERATOR_GUARDS_ED209_STATE``, ``OPERATOR_GUARDS_R2D2_STATE``,
``OPERATOR_GUARDS_POLICY_STORE``).
"""

from __future__ import annotations

import os


def default_home(environ: dict | None = None) -> str:
    """The default profile home, resolved from the environment at call time."""
    env = os.environ if environ is None else environ
    return (
        (env.get("OPERATOR_GUARDS_HOME") or "").strip()
        or (env.get("HERMES_HOME") or "").strip()
        or os.path.expanduser("~/.hermes")
    )


def env_path(variable: str, default: str, environ: dict | None = None) -> str:
    """Return ``$variable`` when set and non-empty, otherwise ``default``."""
    env = os.environ if environ is None else environ
    return (env.get(variable) or "").strip() or default
