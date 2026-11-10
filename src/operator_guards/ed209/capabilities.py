"""Capability taxonomy and tool-name binding for ED-209.

ED-209 rules bind by *capability*, not exact tool name (ED-209-HANDOFF.md §4,
"Capability binding"). A deny rule bound to shell must also cover
``mcp__serena__execute_shell_command`` or it is bypassable through a different
MCP server.

The alias table below is the *documented subset* of tool names we can bind
today. It is deliberately NOT exhaustive: a tool name we cannot bind resolves
to the empty set, and the engine surfaces that as a coverage warning
(degraded), never as "safe". Canonical capability names bind to themselves,
so a rule bound to ``"shell"`` (etc.) is self-coverable and never "unbound".
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Mapping

# Canonical capability names.
SHELL = "shell"
FILE_READ = "file_read"
FILE_WRITE = "file_write"
FILE_PATCH = "file_patch"
EXECUTE_CODE = "execute_code"
DELEGATE = "delegate"

# Capabilities whose side effects mutate external state (coverage-sensitive).
MUTATING_CAPABILITIES = frozenset(
    {SHELL, FILE_WRITE, FILE_PATCH, EXECUTE_CODE, DELEGATE}
)

# Deferred tool wrappers: these names must be unwrapped to the underlying tool
# identity before capability binding (model_tools.py deferred tool_call).
DEFERRED_WRAPPERS = frozenset({"tool_call", "tool_use"})

# Exact tool name → capabilities. Documented subset; not exhaustive.
_EXACT_CAPABILITIES = {
    # Canonical capability names bind to themselves: a rule bound to a
    # canonical capability (or a tool reporting itself by capability name) must
    # resolve to a non-empty set, never fall through to the unbound warning.
    SHELL: frozenset({SHELL}),
    FILE_READ: frozenset({FILE_READ}),
    FILE_WRITE: frozenset({FILE_WRITE}),
    FILE_PATCH: frozenset({FILE_PATCH}),
    EXECUTE_CODE: frozenset({EXECUTE_CODE}),
    DELEGATE: frozenset({DELEGATE}),
    # shell / terminal
    "Bash": frozenset({SHELL}),
    "bash": frozenset({SHELL}),
    "terminal": frozenset({SHELL}),
    # file read
    "Read": frozenset({FILE_READ}),
    "read_file": frozenset({FILE_READ}),
    # file write
    "Write": frozenset({FILE_WRITE}),
    "write_file": frozenset({FILE_WRITE}),
    "write": frozenset({FILE_WRITE}),
    # file patch / edit
    "Edit": frozenset({FILE_PATCH}),
    "patch": frozenset({FILE_PATCH}),
    "edit_file": frozenset({FILE_PATCH}),
    # delegated work
    "delegate_task": frozenset({DELEGATE}),
    "spawn_agent": frozenset({DELEGATE}),
    "subagent": frozenset({DELEGATE}),
}

# Documented MCP aliases (exact names; source example is the Serena shell tool).
_MCP_EXACT = {
    "mcp__serena__execute_shell_command": frozenset({SHELL}),
    "mcp__serena__write_file": frozenset({FILE_WRITE}),
    "mcp__serena__read_file": frozenset({FILE_READ}),
    "mcp__serena__edit_file": frozenset({FILE_PATCH}),
}

# MCP/plugin tool-name convention: mcp__<server>__<tool> / plugin__<name>__<tool>.
_MCP_TOOL_RE = re.compile(r"^(mcp|plugin)__[^_]+__(.+)$")

_SHELL_HINTS = ("shell", "exec", "command", "bash", "terminal", "subprocess", "run")
_PATCH_HINTS = ("patch", "edit", "modify", "update", "replace")
_WRITE_HINTS = (
    "write",
    "save",
    "create",
    "delete",
    "remove",
    "move",
    "rename",
    "copy",
    "put",
    "upload",
)
_READ_HINTS = (
    "read",
    "get",
    "open",
    "cat",
    "list",
    "ls",
    "find",
    "search",
    "query",
    "view",
    "stat",
    "fetch",
)


def capabilities_for(tool_name: str) -> frozenset[str]:
    """Return the set of capabilities a tool name provides.

    Unknown/unbound tool names return the empty set; callers surface that as a
    coverage warning rather than assuming the tool is safe.
    """
    if not isinstance(tool_name, str):
        return frozenset()
    if tool_name in _EXACT_CAPABILITIES:
        return _EXACT_CAPABILITIES[tool_name]
    if tool_name in _MCP_EXACT:
        return _MCP_EXACT[tool_name]
    return _mcp_capabilities(tool_name)


def _hint_capabilities(tool_name: str) -> frozenset[str]:
    """Scan a tool name's hint substrings for suggested capabilities.

    Pure heuristic used both to bind unrecognized mcp__/plugin__ names and to
    decide whether an unbound name *looks* mutating (for coverage warnings).
    """
    tool = tool_name.lower()
    caps = set()
    if any(h in tool for h in _SHELL_HINTS):
        caps.add(SHELL)
    if any(h in tool for h in _PATCH_HINTS):
        caps.add(FILE_PATCH)
    if any(h in tool for h in _WRITE_HINTS):
        caps.add(FILE_WRITE)
    if any(h in tool for h in _READ_HINTS):
        caps.add(FILE_READ)
    return frozenset(caps)


def _mcp_capabilities(tool_name: str) -> frozenset[str]:
    """Heuristic binding for unrecognized mcp__/plugin__ tool names.

    The final tool-name segment is scanned for unambiguous capability hints.
    This deliberately errs toward binding an unknown MCP tool as *possibly*
    mutating (shell/file-write) when its name suggests it, because a false
    negative here silently leaves a deny rule uncovered.
    """
    m = _MCP_TOOL_RE.match(tool_name)
    if not m:
        return frozenset()
    return _hint_capabilities(m.group(2))


def looks_mutating(tool_name: str) -> bool:
    """Whether an unbound tool name's hints suggest a mutating capability.

    Used by the engine's coverage warning to distinguish "unbound and possibly
    mutating" from merely "unbound" — a higher-severity coverage gap.
    """
    if not isinstance(tool_name, str):
        return False
    return bool(_hint_capabilities(tool_name) & MUTATING_CAPABILITIES)


def is_deferred_wrapper(tool_name: str) -> bool:
    """Whether ``tool_name`` is a deferred wrapper that must be unwrapped."""
    return tool_name in DEFERRED_WRAPPERS


def unwrap_tool_identity(tool_name: str, args: Any = None) -> str:
    """Return the underlying tool name for a deferred wrapper, else ``tool_name``.

    A deferred ``tool_call`` carries its real target in the arguments (``name``,
    or ``calls[0].name``). The wrapper name is never treated as a tool identity.
    """
    if not is_deferred_wrapper(tool_name):
        return tool_name
    name = _extract_name(args)
    return name if name else tool_name


def _extract_name(args: Any) -> str | None:
    if isinstance(args, Mapping):
        name = args.get("name")
        if isinstance(name, str) and name:
            return name
        calls = args.get("calls")
        if isinstance(calls, list) and calls and isinstance(calls[0], Mapping):
            name = calls[0].get("name")
            if isinstance(name, str) and name:
                return name
        return None
    if isinstance(args, str):
        try:
            data = json.loads(args)
        except ValueError:
            return None
        return _extract_name(data)
    return None


def resolve_tool(tool_name: str, args: Any = None) -> tuple[str, frozenset[str]]:
    """Unwrap any deferred wrapper, then bind capabilities to the real name."""
    real = unwrap_tool_identity(tool_name, args)
    return real, capabilities_for(real)


def normalize_path(path: str) -> str:
    """Normalize a filesystem path for protected-path gating.

    Applies ``expanduser`` → ``normpath`` → ``realpath`` (read-only): collapses
    redundant separators, ``.`` and ``..`` segments, and a trailing slash, and
    resolves symlinks to their targets. This is performed at COMPILE time only;
    evaluation never calls it (no I/O during evaluation). Same-UID limitation:
    a same-UID process can create or retarget a symlink after compilation, so
    this is procedural defence-in-depth, not an OS security boundary — callers
    must re-compile (the revision hash changes when a resolved path changes).
    """
    return os.path.realpath(os.path.normpath(os.path.expanduser(path)))
