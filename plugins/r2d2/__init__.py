"""R2-D2 Hermes plugin: bounded capability observation + heartbeat.

Wires four real Hermes hooks (all REAL members of ``VALID_HOOKS``) to the
standalone :mod:`operator_guards.r2d2.observer` record helpers, with no
provider/network call at startup and the active profile home resolved PER
CALLBACK (never at import time):

* ``post_tool_call``     — emits a bounded ``post_tool_error``/``post_tool_status``
  observation on a failing/denied tool and always refreshes the heartbeat +
  the bounded client record.
* ``on_session_start``   — emits a ``session_start`` observation and writes the
  bounded client record.
* ``on_session_end``     — emits a ``session_end`` observation.
* ``on_session_reset``   — emits a ``session_reset`` observation.

The heartbeat is throttled to ``HEARTBEAT_MIN_INTERVAL_SECONDS`` (the
"periodic" liveness signal), and the client record is a bounded JSON file in
``<HERMES_HOME>/r2d2/clients/``. Every hook body is wrapped fail-open (like the
ed209 plugin): it can NEVER raise into Hermes.

All timestamps written by this plugin (heartbeat ``ts``, client ``last_seen``,
observation ``ts``) are MONOTONIC (``time.monotonic``) so the observer's
staleness checks are immune to wall-clock jumps.

Reconnect state (``ClientRecord.status == "reconnecting"`` and
``reconnect_started``) is NOT populated by this plugin: the four hooks observe
transient tool errors but carry no real "the client is now reconnecting" signal,
and fabricating one would be dishonest. The ``reconnect_in_progress`` predicate
is therefore externally populated — a future transport/session manager that
actually tracks reconnect state must write those fields onto the client record.

This module imports only the stdlib and ``operator_guards`` (no ``hermes_cli``)
so it stays import-safe under the standalone test venv.

Hook registration is GUARDED: each declared hook is registered only when the
runtime supports it (``hermes_cli.plugins.VALID_HOOKS``); an unsupported hook is
NOT registered, is logged, and is exposed via :func:`registration_status` —
never a silent inert registration.

On a real Hermes runtime, ``register()`` also starts the OWNING-CLIENT IPC
server (``ipc_adapter.start_ipc_server``, idempotent + fail-closed) so the
daemon's ``mcp_reconnect`` recovery can reach a live owning client. It is a
no-op under the standalone test venv (no ``hermes_cli``) and never binds a real
socket for a bare probe.
"""

from __future__ import annotations

import functools
import logging
import os
import socket
import threading
import time
from pathlib import Path

from operator_guards.r2d2.claims import proc_start_time
from operator_guards.r2d2.observer import (
    CLIENT_CAPABILITIES_MAX,
    HEARTBEAT_MIN_INTERVAL_SECONDS,
    OBSERVATION_DETAIL_MAX_CHARS,
    ClientRecord,
    Observation,
    append_observation,
    state_root_for,
    write_client_record,
    write_heartbeat_file,
)

logger = logging.getLogger("r2d2")

# Default profile home used only when HERMES_HOME is unset (e.g. a bare probe).
_DEFAULT_HOME = str(Path.home() / ".hermes")

# Per-process client state + heartbeat throttle (bounded, process-local).
_lock = threading.Lock()
_heartbeat_last: dict[str, float] = {}
_client_state: dict[str, ClientRecord] = {}
_pid_start_time: float | None = None

# The hooks this plugin DECLARES (fallback when the runtime can't be introspected).
_DECLARED_HOOKS = frozenset(
    {"post_tool_call", "on_session_start", "on_session_end", "on_session_reset"}
)

_registration_status = {"supported": (), "unsupported": ()}


# ---------------------------------------------------------------------------
# Registration (local, no provider call)
# ---------------------------------------------------------------------------


def _runtime_supported_hooks(ctx) -> frozenset:
    """The hook names THIS runtime actually supports (never guessed)."""
    supported = getattr(ctx, "supported_hooks", None)
    if supported is not None:
        return frozenset(supported)
    try:
        from hermes_cli.plugins import VALID_HOOKS
    except Exception:  # noqa: BLE001 — standalone venv / no Hermes runtime
        return frozenset(_DECLARED_HOOKS)
    return frozenset(VALID_HOOKS)


def _start_ipc_server_if_runtime(ctx) -> str | None:
    """Start the owning-client IPC server, ONLY inside a real Hermes runtime.

    A real Hermes ``PluginContext`` exposes ``_manager``; the standalone
    contract-test ``FakeCtx`` does not, and a bare probe must never bind a real
    Unix socket in the runtime dir. The start is idempotent and fail-closed (a
    failure is logged and ``mcp_reconnect`` stays UNSUPPORTED, never faked).
    """
    if getattr(ctx, "_manager", None) is None:
        return None
    try:
        import hermes_cli  # noqa: F401 — real runtime marker
    except Exception:  # noqa: BLE001
        return None
    try:
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "r2d2_plugin_ipc", str(Path(__file__).with_name("ipc_adapter.py"))
        )
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        path = mod.start_ipc_server()
    except Exception as exc:  # noqa: BLE001 — fail closed, never crash register()
        logger.warning("r2d2: owning-client IPC server start failed: %s", exc)
        return None
    if path is None:
        logger.warning(
            "r2d2: owning-client IPC server did not start (fail-closed); "
            "mcp_reconnect will be UNSUPPORTED"
        )
    return path


def register(ctx):
    """Register supported hooks; start the owning-client IPC server on a real
    runtime. Local only — no provider/network call."""
    hooks = (
        ("post_tool_call", _post_tool_call),
        ("on_session_start", _on_session_start),
        ("on_session_end", _on_session_end),
        ("on_session_reset", _on_session_reset),
    )
    supported = _runtime_supported_hooks(ctx)
    registered = []
    unsupported = []
    for name, callback in hooks:
        if name in supported:
            ctx.register_hook(name, callback)
            registered.append(name)
        else:
            unsupported.append(name)
    for name in unsupported:
        logger.warning(
            "r2d2: hook %r is not supported by this Hermes runtime; the "
            "declared capability would be INERT and was NOT registered", name,
        )
    _registration_status["supported"] = tuple(registered)
    _registration_status["unsupported"] = tuple(unsupported)
    _start_ipc_server_if_runtime(ctx)
    return dict(_registration_status)


def registration_status() -> dict:
    """The last registration's supported/unsupported hook names."""
    return dict(_registration_status)


# ---------------------------------------------------------------------------
# Hot-path containment
# ---------------------------------------------------------------------------


def _fail_open(func):
    """Guard a hook callback so it can NEVER raise into Hermes."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 — hot path must never raise
            logger.warning("r2d2: hook %s degraded (fail-open): %s", func.__name__, exc)
            return None

    return wrapper


# ---------------------------------------------------------------------------
# Home / client / heartbeat resolution (per callback)
# ---------------------------------------------------------------------------


def _resolve_home() -> str:
    home = (
        os.environ.get("OPERATOR_GUARDS_HOME", "").strip()
        or os.environ.get("HERMES_HOME", "").strip()
    )
    return home or _DEFAULT_HOME


def _client_id(home: str) -> str:
    profile = os.path.basename(os.path.normpath(home)) or "default"
    return f"{socket.gethostname()}:{profile}"


def _proc_start() -> float:
    global _pid_start_time
    if _pid_start_time is None:
        _pid_start_time = proc_start_time(os.getpid()) or 0.0
    return _pid_start_time


def _tick(root: str, home: str) -> bool:
    """Touch the heartbeat; True only when the write actually happened."""
    now = time.monotonic()
    with _lock:
        last = _heartbeat_last.get(home, 0.0)
        if now - last < HEARTBEAT_MIN_INTERVAL_SECONDS:
            return False
        _heartbeat_last[home] = now
        write_heartbeat_file(root, ts=now, host=socket.gethostname())
        return True


def _update_client(root: str, home: str, tool_name: str | None = None, *, persist: bool) -> ClientRecord:
    """Update (and, when ``persist``, write) the bounded client record."""
    now = time.monotonic()
    with _lock:
        client = _client_state.get(home)
        if client is None:
            client = ClientRecord(
                client_id=_client_id(home),
                pid=os.getpid(),
                pid_start_time=_proc_start(),
                last_seen=now,
            )
        caps = set(client.capabilities)
        if tool_name and len(caps) < CLIENT_CAPABILITIES_MAX:
            caps.add(tool_name)
        updated = ClientRecord(
            client_id=client.client_id,
            status=client.status,
            capabilities=frozenset(caps),
            pid=client.pid,
            pid_start_time=client.pid_start_time,
            last_seen=now,
            reconnect_started=client.reconnect_started,
        )
        _client_state[home] = updated
        if persist:
            write_client_record(root, updated)
        return updated


def _emit(home: str, root: str, client: ClientRecord, *, kind: str, session_id: str) -> None:
    append_observation(
        root,
        Observation(
            kind=kind,
            client_id=client.client_id,
            session_id=session_id or "",
            ts=time.monotonic(),
        ),
    )


# ---------------------------------------------------------------------------
# post_tool_call — bounded error/status observation
# ---------------------------------------------------------------------------


@_fail_open
def _post_tool_call(
    tool_name=None,
    args=None,
    result=None,
    session_id="",
    turn_id="",
    task_id="",
    tool_call_id="",
    status=None,
    error_type=None,
    error_message=None,
    **kwargs,
):
    home = _resolve_home()
    root = state_root_for(home)
    tick = _tick(root, home)
    client = _update_client(root, home, tool_name=tool_name, persist=tick)

    if error_type or (status and status != "ok"):
        kind = "post_tool_error" if error_type else "post_tool_status"
        detail = str(error_message)[:OBSERVATION_DETAIL_MAX_CHARS] if error_message else ""
        append_observation(
            root,
            Observation(
                kind=kind,
                client_id=client.client_id,
                session_id=session_id or "",
                tool_name=tool_name or "",
                error_type=error_type or "",
                status=status or "",
                detail=detail,
                ts=time.monotonic(),
            ),
        )
    # Observer: never deny/block from post_tool_call.
    return None


# ---------------------------------------------------------------------------
# Session lifecycle observations
# ---------------------------------------------------------------------------


@_fail_open
def _on_session_start(session_id="", **kwargs):
    home = _resolve_home()
    root = state_root_for(home)
    client = _update_client(root, home, persist=True)
    _tick(root, home)
    _emit(home, root, client, kind="session_start", session_id=session_id)
    return None


@_fail_open
def _on_session_end(session_id="", **kwargs):
    home = _resolve_home()
    root = state_root_for(home)
    client = _update_client(root, home, persist=True)
    _tick(root, home)
    _emit(home, root, client, kind="session_end", session_id=session_id)
    return None


@_fail_open
def _on_session_reset(session_id="", **kwargs):
    home = _resolve_home()
    root = state_root_for(home)
    client = _update_client(root, home, persist=True)
    _tick(root, home)
    _emit(home, root, client, kind="session_reset", session_id=session_id)
    return None
