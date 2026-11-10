"""Fixed R2-D2 handler allowlist (plan §4, Task 11).

Each operation in the closed §4 allowlist is bound to a FIXED handler with
VALIDATED ENUMERATED parameters. Handlers construct ``argv`` arrays INTERNALLY
(``shell=False`` always; incident data is never interpolated into a shell), and
operations outside the allowlist are rejected — there is NO incident-provided
shell command, executable path, arbitrary config key, broad process-pattern
kill, or guard unlock.

The allowlist (only these names exist in ``OPERATION_NAMES``):

* ``shell_diag``  — a FIXED table of read-only, scoped probes (client
  heartbeat/identity, native MCP status, bounded targeted log tail, ED-209
  rules/hits). Mac Teams/Claude probes are UNSUPPORTED and rejected.
* ``mcp_reconnect`` — CONDITIONAL (implemented ``McpReconnectHandler``): executes
  via the OWNING-CLIENT IPC adapter when one is wired in the handler context
  (``mcp_reconnect_adapter``); reports UNSUPPORTED (never faked) when no adapter
  is present. Task 13.
* ``rule_add``     — ONLY via the sanctioned ``ed209`` CLI; ``origin`` required;
  may add evidence-backed RESTRICTIVE (deny/block) rules only, never weaken or
  supersede the triggering denial; does not resolve the original blocked op.
* ``notify_human`` — explicit channel opt-in; permitted scope; at most ONE
  accepted delivery per incident; default LOCAL-ONLY (no outbound).
* ``session_stop_resume`` — UNSUPPORTED (needs an externally issued scoped
  single-use TTL grant, Task 14).
* ``config_set``   — UNSUPPORTED and ABSENT from ``EXECUTABLE_OPERATIONS``.

``EXECUTABLE_OPERATIONS`` is the set of operations with a supported handler;
``config_set`` is deliberately not in it (do not mark the whole set portable by
naming it).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from operator_guards.ed209.ledger import HitLedger
from operator_guards.ed209.rules import SUPPORTED_SURFACES, load_rules
from operator_guards.common.proof import EVIDENCE_REF_MAX_CHARS
from operator_guards.r2d2.schema import NOTIFICATION_MAX_CHARS

# Repository root (for ``python -m operator_guards.ed209.cli`` subprocess cwd).
_REPO_ROOT = Path(__file__).resolve().parents[3]

# ---------------------------------------------------------------------------
# Operation names (the closed §4 allowlist — nothing else)
# ---------------------------------------------------------------------------

OP_SHELL_DIAG = "shell_diag"
OP_MCP_RECONNECT = "mcp_reconnect"
OP_RULE_ADD = "rule_add"
OP_NOTIFY_HUMAN = "notify_human"
OP_SESSION_STOP_RESUME = "session_stop_resume"
OP_CONFIG_SET = "config_set"

OPERATION_NAMES = frozenset(
    {
        OP_SHELL_DIAG,
        OP_MCP_RECONNECT,
        OP_RULE_ADD,
        OP_NOTIFY_HUMAN,
        OP_SESSION_STOP_RESUME,
        OP_CONFIG_SET,
    }
)

# Operations with a SUPPORTED (executable) handler. ``config_set`` and the
# not-yet-implemented adapters are deliberately absent.
EXECUTABLE_OPERATIONS = frozenset({OP_SHELL_DIAG, OP_RULE_ADD, OP_NOTIFY_HUMAN})

# ---------------------------------------------------------------------------
# shell_diag probes (the FIXED read-only table; Mac Teams/Claude are NOT here)
# ---------------------------------------------------------------------------

PROBE_CLIENT_HEARTBEAT = "client_heartbeat"
PROBE_MCP_STATUS = "mcp_status"
PROBE_LOG_TAIL = "log_tail"
PROBE_ED209_RULES = "ed209_rules"
PROBE_ED209_HITS = "ed209_hits"

SHELL_DIAG_PROBES = frozenset(
    {
        PROBE_CLIENT_HEARTBEAT,
        PROBE_MCP_STATUS,
        PROBE_LOG_TAIL,
        PROBE_ED209_RULES,
        PROBE_ED209_HITS,
    }
)

# Bounded log tail (read-only, targeted): at most this many lines.
LOG_TAIL_MAX_LINES = 500

# ---------------------------------------------------------------------------
# Bounded subprocess deadline (Task 11 review: no hung child may block the
# daemon indefinitely)
# ---------------------------------------------------------------------------

# Every handler-spawned subprocess runs under a BOUNDED deadline. ``log_tail``
# (``tail`` on a local file) and ``rule_add`` (the sanctioned ``ed209`` CLI)
# are both local, bounded-work commands that finish in well under a second in
# the healthy case; a child still running past this window is hung (e.g. a
# FIFO with no writer, a wedged filesystem, a stuck CLI). 10s is an order of
# magnitude of headroom over normal runtime — avoiding false-positive kills on
# a loaded box — while still bounding the worst-case daemon stall to ~15s
# (deadline + TERM grace below). On expiry the child is TERM'd, PROVEN dead,
# and the op is recorded FAIL/UNKNOWN (never success, never a blind retry).
HANDLER_SUBPROCESS_TIMEOUT = 10.0

# After SIGTERM, how long to wait before escalating to SIGKILL (the bounded
# "prove dead" window). SIGKILL is uncatchable, so the child is reaped
# promptly and cannot linger as an orphan/zombie.
SUBPROCESS_KILL_GRACE_SECONDS = 5.0

# ---------------------------------------------------------------------------
# notify_human
# ---------------------------------------------------------------------------

CHANNEL_LOCAL = "local"
CHANNELS = frozenset({CHANNEL_LOCAL})
NOTIFY_SCOPES = frozenset({"symptom", "summary", "status"})

# ---------------------------------------------------------------------------
# rule_add: only RESTRICTIVE actions may be added (never weaken a deny)
# ---------------------------------------------------------------------------

RESTRICTIVE_ACTIONS = frozenset({"deny", "block"})

# ---------------------------------------------------------------------------
# Forbidden param keys (defense-in-depth, mirroring schema._COMMAND_TOKENS).
# Any step carrying one of these — at any operation — is rejected before the
# handler is even consulted.
# ---------------------------------------------------------------------------

FORBIDDEN_PARAM_KEYS = frozenset(
    {
        "command", "cmd", "exec", "executable", "argv", "shell", "script",
        "path", "exe", "bash", "zsh",
        "kill", "authority", "authorize", "authorized",
        "unlock", "off", "disable", "enable", "policy_off",
        "hook", "approval", "approve", "config_key", "config", "key",
        "pkill", "process",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class HandlerError(ValueError):
    """Base error for the fixed handler allowlist and the executor."""


class UnsupportedOperationError(HandlerError):
    """An operation is known but has no supported adapter (never faked)."""


class InvalidParamsError(HandlerError):
    """A step's parameters are not valid enumerated parameters for its handler."""


# ---------------------------------------------------------------------------
# Handler context (injected runtime paths; keeps handlers hermetic in tests)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HandlerContext:
    rules_path: str | None = None
    hits_db: str | None = None
    log_targets: Mapping[str, str] = field(default_factory=dict)
    heartbeat_path: str | None = None
    mcp_status_path: str | None = None
    notify_dir: str | None = None
    opt_in_channels: frozenset = frozenset()
    # Bounded deadline for subprocess-spawning handlers; None -> module default
    # (HANDLER_SUBPROCESS_TIMEOUT). Tests inject a short value to exercise the
    # timeout path quickly.
    subprocess_timeout: float | None = None
    # Owning-client IPC adapter (Task 13): when present, ``mcp_reconnect``
    # dispatches over the owning-client socket; when absent it is UNSUPPORTED.
    mcp_reconnect_adapter: Any = None


@dataclass(frozen=True)
class HandlerResult:
    """What a handler observed/executed (``actual`` is a FRESH observation)."""

    actual: Any = None
    observed: tuple = ()
    evidence: str = ""
    exit_status: int | None = None
    performed: bool = True  # False when a mutation did NOT take effect
    timed_out: bool = False  # True when the subprocess deadline was exceeded


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _validate_enumerated_params(name: str, allowed: frozenset, params: Mapping) -> None:
    """Reject forbidden keys and any key outside the handler's enum allowlist."""
    for key in params:
        if key in FORBIDDEN_PARAM_KEYS:
            raise InvalidParamsError(
                f"operation {name!r}: forbidden param key {key!r} "
                f"(fixed handler + enumerated params; no command/path/kill/"
                f"config/hook/authority)"
            )
        if key not in allowed:
            raise InvalidParamsError(
                f"operation {name!r}: unknown param {key!r} "
                f"(allowed: {sorted(allowed)})"
            )


def _read_file(path: str | None) -> str:
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def _safe_basename(value: str) -> str:
    safe = "".join(c if c in _FILENAME_SAFE else "_" for c in value)
    if safe != value or safe in (".", ".."):
        safe = "s_" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
    return safe


_FILENAME_SAFE = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)

_SUCCESSOR_RE = re.compile(r"^(?P<base>.+)-v\d+$")


def _base_rule_id(rule_id: str) -> str | None:
    m = _SUCCESSOR_RE.match(rule_id)
    return m.group("base") if m else None


@dataclass(frozen=True)
class SubprocessResult:
    """Outcome of a bounded handler subprocess run (``run_bounded``)."""

    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    timed_out: bool = False
    pid: int | None = None


def _subprocess_timeout(ctx: HandlerContext) -> float:
    """Resolve the bounded subprocess deadline for a handler context."""
    return ctx.subprocess_timeout if ctx.subprocess_timeout is not None else HANDLER_SUBPROCESS_TIMEOUT


def _terminate_and_prove_dead(proc: subprocess.Popen) -> None:
    """TERM the child, wait bounded, then KILL and reap — prove it dead.

    A child that ignores/exceeds the SIGTERM grace window is escalated to
    SIGKILL (uncatchable), so it is reaped promptly and cannot linger as an
    orphan or zombie. Only the direct child WE spawned is ever signalled; a
    non-owned process is never touched.
    """
    if proc.poll() is not None:
        return
    try:
        proc.terminate()  # SIGTERM
    except OSError:
        pass
    try:
        proc.communicate(timeout=SUBPROCESS_KILL_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()  # SIGKILL — uncatchable
        except OSError:
            pass
        proc.communicate()  # drains + reaps the now-dead child


def run_bounded(
    argv, *, cwd: str | None = None, timeout: float | None = None
) -> SubprocessResult:
    """Run a handler-owned subprocess under a bounded deadline.

    ``shell=False`` always. On deadline: SIGTERM, a bounded wait, then SIGKILL
    and reap — the child is PROVEN dead before this returns, and the caller
    gets ``SubprocessResult(timed_out=True)`` so the op is recorded
    FAIL/UNKNOWN (never success, never a blind retry). Only the direct child
    this function spawned is ever signalled.
    """
    if timeout is None:
        timeout = HANDLER_SUBPROCESS_TIMEOUT
    proc = subprocess.Popen(
        argv,
        shell=False,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_and_prove_dead(proc)
        return SubprocessResult(
            stdout="",
            stderr="",
            returncode=proc.returncode,
            timed_out=True,
            pid=proc.pid,
        )
    return SubprocessResult(
        stdout=stdout or "",
        stderr=stderr or "",
        returncode=proc.returncode,
        timed_out=False,
        pid=proc.pid,
    )


# ---------------------------------------------------------------------------
# Handler base + concrete handlers
# ---------------------------------------------------------------------------

class Handler:
    """A fixed operation handler (one operation -> one handler, fixed params)."""

    name: str = ""
    phase: str = "diagnostic"  # "diagnostic" | "mutation"
    supported: bool = True
    param_keys: frozenset = frozenset()

    def is_supported(self, ctx: HandlerContext) -> bool:
        """Whether the handler is executable for ``ctx`` (dynamic adapters).

        The static ``supported`` flag is the default; a handler whose adapter
        is wired per-context (e.g. ``mcp_reconnect`` needing an owning-client
        IPC adapter) overrides this.
        """
        return self.supported

    def validate(self, params: Mapping) -> None:
        _validate_enumerated_params(self.name, self.param_keys, params)
        self._validate(params)

    def _validate(self, params: Mapping) -> None:
        raise NotImplementedError

    def run(self, params: Mapping, ctx: HandlerContext, incident_id: str) -> HandlerResult:
        raise NotImplementedError

    def verify(self, params: Mapping, ctx: HandlerContext, incident_id: str) -> Any:
        """Fresh post-mutation observation (mutations) or the read (diagnostics)."""
        raise NotImplementedError


class ShellDiagHandler(Handler):
    """Read-only scoped probes (diagnostic). Mac Teams/Claude are unsupported."""

    name = OP_SHELL_DIAG
    phase = "diagnostic"
    param_keys = frozenset({"probe", "target", "lines"})

    def _validate(self, params: Mapping) -> None:
        probe = params.get("probe")
        if not isinstance(probe, str) or probe not in SHELL_DIAG_PROBES:
            raise InvalidParamsError(
                f"shell_diag probe {probe!r} is not a supported read-only probe; "
                f"Mac Teams/Claude probes are UNSUPPORTED (allowed: "
                f"{sorted(SHELL_DIAG_PROBES)})"
            )
        if probe == PROBE_LOG_TAIL:
            lines = params.get("lines", LOG_TAIL_MAX_LINES)
            if not isinstance(lines, int) or isinstance(lines, bool) or not (
                1 <= lines <= LOG_TAIL_MAX_LINES
            ):
                raise InvalidParamsError(
                    f"log_tail lines must be an int in 1..{LOG_TAIL_MAX_LINES}"
                )
            target = params.get("target")
            if not isinstance(target, str) or not target.strip():
                raise InvalidParamsError("log_tail requires a non-empty 'target'")
        else:
            for extra in ("target", "lines"):
                if extra in params:
                    raise InvalidParamsError(
                        f"shell_diag probe {probe!r} does not take param {extra!r}"
                    )

    def run(self, params, ctx, incident_id):
        probe = params["probe"]
        if probe == PROBE_CLIENT_HEARTBEAT:
            return HandlerResult(actual=_read_file(ctx.heartbeat_path), evidence="client_heartbeat")
        if probe == PROBE_MCP_STATUS:
            return HandlerResult(actual=_read_file(ctx.mcp_status_path), evidence="mcp_status")
        if probe == PROBE_LOG_TAIL:
            target = params["target"]
            if target not in ctx.log_targets:
                raise InvalidParamsError(
                    f"log target {target!r} is not an allowed log target "
                    f"(allowed: {sorted(ctx.log_targets)})"
                )
            lines = params.get("lines", LOG_TAIL_MAX_LINES)
            timeout = _subprocess_timeout(ctx)
            # argv constructed internally; shell=False; bounded line count; a
            # fixed path resolved from the enumerated target table; and a
            # BOUNDED deadline — a hung child is TERM'd + proven dead.
            argv = ["tail", "-n", str(lines), ctx.log_targets[target]]
            r = run_bounded(argv, timeout=timeout)
            return HandlerResult(
                actual=r.stdout,
                evidence=(
                    ctx.log_targets[target]
                    if not r.timed_out
                    else f"log_tail timed out after {timeout}s (pid {r.pid})"
                ),
                exit_status=r.returncode,
                timed_out=r.timed_out,
            )
        if probe == PROBE_ED209_RULES:
            return HandlerResult(actual=_read_file(ctx.rules_path), evidence="ed209_rules")
        if probe == PROBE_ED209_HITS:
            return HandlerResult(actual=_hits_summary(ctx.hits_db), evidence="ed209_hits")
        raise UnsupportedOperationError(f"shell_diag probe {probe!r} is unsupported")

    def verify(self, params, ctx, incident_id):
        return self.run(params, ctx, incident_id).actual


class RuleAddHandler(Handler):
    """Add a RESTRICTIVE rule ONLY via the sanctioned ``ed209`` CLI."""

    name = OP_RULE_ADD
    phase = "mutation"
    param_keys = frozenset(
        {"id", "surface", "rule_class", "action", "pattern", "reason", "origin", "tools", "cwd"}
    )

    def _validate(self, params: Mapping) -> None:
        for req in ("id", "surface", "rule_class", "action", "pattern", "reason", "origin"):
            value = params.get(req)
            if not isinstance(value, str) or not value.strip():
                raise InvalidParamsError(f"rule_add requires a non-empty {req!r}")
        if params["surface"] not in SUPPORTED_SURFACES:
            raise InvalidParamsError(
                f"rule_add surface must be one of {sorted(SUPPORTED_SURFACES)}"
            )
        if params["action"] not in RESTRICTIVE_ACTIONS:
            raise InvalidParamsError(
                f"rule_add may only add RESTRICTIVE rules (deny|block); "
                f"got {params['action']!r} — never weaken the triggering denial"
            )
        tools = params.get("tools")
        if tools is not None:
            if not isinstance(tools, (list, tuple)) or not all(
                isinstance(x, str) and x.strip() for x in tools
            ):
                raise InvalidParamsError("rule_add 'tools' must be a list of non-empty strings")
        cwd = params.get("cwd")
        if cwd is not None and (not isinstance(cwd, str) or not cwd.strip()):
            raise InvalidParamsError("rule_add 'cwd' must be a non-empty string")

    def run(self, params, ctx, incident_id):
        rules_path = ctx.rules_path
        if not rules_path:
            raise InvalidParamsError("rule_add requires a rules_path in the handler context")
        self._guard_no_deny_weaken(params, rules_path)

        argv = [
            sys.executable, "-m", "operator_guards.ed209.cli",
            "--rules", rules_path, "add",
            "--id", params["id"],
            "--surface", params["surface"],
            "--class", params["rule_class"],
            "--action", params["action"],
            "--pattern", params["pattern"],
            "--reason", params["reason"],
            "--origin", params["origin"],
        ]
        if params.get("tools"):
            argv += ["--tools", *params["tools"]]
        if params.get("cwd"):
            argv += ["--cwd", params["cwd"]]
        timeout = _subprocess_timeout(ctx)
        r = run_bounded(argv, cwd=str(_REPO_ROOT), timeout=timeout)
        if r.timed_out:
            return HandlerResult(
                actual="",
                evidence=f"rule_add timed out after {timeout}s (pid {r.pid}); child terminated",
                exit_status=None,
                performed=False,
                timed_out=True,
            )
        return HandlerResult(
            actual=r.stdout,
            evidence=(r.stderr or r.stdout or "").strip(),
            exit_status=r.returncode,
            performed=(r.returncode == 0),
        )

    def verify(self, params, ctx, incident_id):
        # fresh re-read of the rules document AFTER the CLI add (post-mutation)
        return _read_file(ctx.rules_path)

    def _guard_no_deny_weaken(self, params, rules_path) -> None:
        """A ``-vN`` successor of an enabled deny may not be downgraded to block."""
        base = _base_rule_id(params["id"])
        if base is None or params["action"] == "deny":
            return
        try:
            with open(rules_path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, ValueError):
            return
        for rule in load_rules(doc):
            if rule.id == base and rule.enabled and rule.action == "deny":
                raise InvalidParamsError(
                    f"rule_add refuses to supersede enabled deny rule {base!r} "
                    f"with action {params['action']!r}: a deny may not be weakened"
                )


class NotifyHumanHandler(Handler):
    """LOCAL-ONLY human notification; at most one accepted delivery per incident."""

    name = OP_NOTIFY_HUMAN
    phase = "mutation"
    param_keys = frozenset({"channel", "scope", "message"})

    def _validate(self, params: Mapping) -> None:
        channel = params.get("channel", CHANNEL_LOCAL)
        if not isinstance(channel, str) or not channel.strip():
            raise InvalidParamsError("notify channel must be a non-empty string")
        scope = params.get("scope", "summary")
        if scope not in NOTIFY_SCOPES:
            raise InvalidParamsError(
                f"notify scope must be one of {sorted(NOTIFY_SCOPES)}; got {scope!r}"
            )
        message = params.get("message")
        if not isinstance(message, str) or not message.strip():
            raise InvalidParamsError("notify requires a non-empty 'message'")
        if len(message) > NOTIFICATION_MAX_CHARS:
            raise InvalidParamsError(
                f"notify message exceeds the {NOTIFICATION_MAX_CHARS}-char bound"
            )

    def run(self, params, ctx, incident_id):
        channel = params.get("channel", CHANNEL_LOCAL)
        if channel != CHANNEL_LOCAL:
            if channel not in ctx.opt_in_channels:
                raise InvalidParamsError(
                    f"notify channel {channel!r} requires explicit opt-in "
                    f"(default is LOCAL-ONLY, no outbound)"
                )
            raise UnsupportedOperationError(
                f"outbound notify channel {channel!r} is not implemented (local-only)"
            )
        if not ctx.notify_dir:
            raise InvalidParamsError("notify_human requires a notify_dir in the context")
        os.makedirs(ctx.notify_dir, exist_ok=True)
        path = os.path.join(ctx.notify_dir, _safe_basename(incident_id) + ".notify")
        body = f"{params.get('scope', 'summary')}: {params['message']}\n"
        try:
            # O_CREAT|O_EXCL: at most ONE accepted delivery per incident.
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            return HandlerResult(
                actual="", evidence="delivery already accepted for this incident",
                performed=False,
            )
        with os.fdopen(fd, "w") as f:
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
        return HandlerResult(actual=body, evidence=path, performed=True)

    def verify(self, params, ctx, incident_id):
        if not ctx.notify_dir:
            return ""
        path = os.path.join(ctx.notify_dir, _safe_basename(incident_id) + ".notify")
        return _read_file(path)


class McpReconnectHandler(Handler):
    """``mcp_reconnect`` via the OWNING-CLIENT IPC adapter (Task 13).

    Unsupported when no adapter is wired (``is_supported`` is False), reported
    as UNSUPPORTED by the executor. With an adapter present, the request is
    dispatched over the owning-client socket; the owning client performs the
    native reconnect and a harmless actual tool call, returning a typed
    ``capability_proof``.
    """

    name = OP_MCP_RECONNECT
    phase = "mutation"
    param_keys = frozenset({"server"})

    def is_supported(self, ctx: HandlerContext) -> bool:
        return ctx.mcp_reconnect_adapter is not None

    def _validate(self, params: Mapping) -> None:
        server = params.get("server")
        if not isinstance(server, str) or not server.strip():
            raise InvalidParamsError("mcp_reconnect requires a non-empty 'server' name")
        if set(params) - {"server"}:
            raise InvalidParamsError("mcp_reconnect takes only the 'server' param")

    def run(self, params, ctx, incident_id):
        adapter = ctx.mcp_reconnect_adapter
        if adapter is None:
            raise UnsupportedOperationError(
                "mcp_reconnect requires an owning-client IPC adapter (Task 13)"
            )
        reply = adapter.request_mcp_reconnect(incident_id, params["server"])
        proof = reply.capability_proof or {}
        return HandlerResult(
            actual=proof.get("verdict", ""),
            observed=(proof.get("server", ""), proof.get("probe_tool", "")),
            evidence=json.dumps(reply.to_dict(), sort_keys=True)[:EVIDENCE_REF_MAX_CHARS],
            performed=(reply.status == "ok"),
        )

    def verify(self, params, ctx, incident_id):
        adapter = ctx.mcp_reconnect_adapter
        if adapter is None:
            raise UnsupportedOperationError(
                "mcp_reconnect requires an owning-client IPC adapter (Task 13)"
            )
        # FRESH durable read: the incident's typed mutation proof (a PASS op of
        # kind ``mcp_status`` appended by the adapter), never the in-memory reply.
        store = getattr(adapter, "store", None)
        if store is not None:
            try:
                store.refresh()
            except Exception:  # noqa: BLE001
                pass
            inc = store.get_incident(incident_id)
            if inc is not None:
                for op in reversed(inc.mutation_plan):
                    if op.kind == "mcp_status":
                        return op.verdict.value
        reply = getattr(adapter, "last_reply", None)
        if reply is not None and reply.capability_proof:
            return reply.capability_proof.get("verdict", "")
        return ""


class UnsupportedHandler(Handler):
    """A known operation with no supported adapter — reported, never faked."""

    phase = "mutation"
    supported = False
    param_keys = frozenset()

    def __init__(self, name: str, reason: str):
        self.name = name
        self.reason = reason

    def _validate(self, params: Mapping) -> None:
        if params:
            raise InvalidParamsError(
                f"operation {self.name!r} is unsupported ({self.reason}) and takes no params"
            )

    def run(self, params, ctx, incident_id):
        raise UnsupportedOperationError(f"operation {self.name!r} is unsupported: {self.reason}")

    def verify(self, params, ctx, incident_id):
        raise UnsupportedOperationError(f"operation {self.name!r} is unsupported: {self.reason}")


HANDLERS: dict[str, Handler] = {
    OP_SHELL_DIAG: ShellDiagHandler(),
    OP_MCP_RECONNECT: McpReconnectHandler(),
    OP_RULE_ADD: RuleAddHandler(),
    OP_NOTIFY_HUMAN: NotifyHumanHandler(),
    OP_SESSION_STOP_RESUME: UnsupportedHandler(
        OP_SESSION_STOP_RESUME, "requires an externally issued scoped single-use TTL grant (Task 14)"
    ),
    OP_CONFIG_SET: UnsupportedHandler(OP_CONFIG_SET, "config_set is not in the executable allowlist"),
}


def get_handler(name: str) -> Handler:
    if name not in OPERATION_NAMES:
        raise InvalidParamsError(
            f"unknown operation {name!r}; not in the §4 allowlist "
            f"({sorted(OPERATION_NAMES)})"
        )
    return HANDLERS[name]


def _hits_summary(hits_db: str | None) -> str:
    if not hits_db or not os.path.exists(hits_db):
        return ""
    ledger = HitLedger(hits_db)
    rows = ledger._query(  # noqa: SLF001 — in-package read path
        "SELECT rule_id, outcome, COUNT(*) AS n FROM hits "
        "GROUP BY rule_id, outcome ORDER BY rule_id, outcome",
        (),
    )
    return "; ".join(f"{r['rule_id']}={r['outcome']}:{r['n']}" for r in rows)


__all__ = [
    "OP_SHELL_DIAG",
    "OP_MCP_RECONNECT",
    "OP_RULE_ADD",
    "OP_NOTIFY_HUMAN",
    "OP_SESSION_STOP_RESUME",
    "OP_CONFIG_SET",
    "OPERATION_NAMES",
    "EXECUTABLE_OPERATIONS",
    "PROBE_CLIENT_HEARTBEAT",
    "PROBE_MCP_STATUS",
    "PROBE_LOG_TAIL",
    "PROBE_ED209_RULES",
    "PROBE_ED209_HITS",
    "SHELL_DIAG_PROBES",
    "CHANNEL_LOCAL",
    "CHANNELS",
    "NOTIFY_SCOPES",
    "RESTRICTIVE_ACTIONS",
    "FORBIDDEN_PARAM_KEYS",
    "HANDLER_SUBPROCESS_TIMEOUT",
    "SUBPROCESS_KILL_GRACE_SECONDS",
    "HandlerError",
    "UnsupportedOperationError",
    "InvalidParamsError",
    "HandlerContext",
    "HandlerResult",
    "SubprocessResult",
    "run_bounded",
    "Handler",
    "ShellDiagHandler",
    "RuleAddHandler",
    "NotifyHumanHandler",
    "McpReconnectHandler",
    "UnsupportedHandler",
    "HANDLERS",
    "get_handler",
]
