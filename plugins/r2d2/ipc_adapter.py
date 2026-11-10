"""R2-D2 owning-client IPC adapter — Hermes-native seams (plugin side).

Thin wrapper over :class:`operator_guards.r2d2.ipc_adapter.OwningClientServer`
that wires the HERMES-native seams (imported LAZILY so this module imports
without Hermes, keeping the plugin contract intact under the standalone venv):

* ``reconnector``  — ``tools.mcp_tool_loop.reconnect_mcp_server`` (the
  process-local native transport rebuild; ONLY valid inside the owning client).
* ``server_registry`` — ``tools.mcp_tool._core._servers`` keys (the servers
  THIS client actually owns).
* ``probe_caller`` — a CONFIGURED harmless actual tool call through the
  original owner. There is NO safe default: absent configuration, the harmless
  probe is missing and the adapter yields ``unknown``/escalation (never a
  fabricated success).

The owning-client server is started EXPLICITLY (``start_ipc_server``), not on
every session start: a stopped session cannot service its own socket, and the
server's lifetime belongs to the owning client's plugin lifecycle. The start is
idempotent (a live server is reused).

``configure_ipc_adapter`` records the operator-supplied seams (notably the
harmless ``probe_caller``); ``start_ipc_server`` applies them. A caller-supplied
path is never trusted: the socket path derives from the RESOLVED runtime dir +
UID + profile/client identity.
"""

from __future__ import annotations

import logging
import threading

from operator_guards.r2d2.ipc_adapter import (
    RECONNECT_COOLDOWN_SECONDS,
    OwningClientServer,
)

logger = logging.getLogger("r2d2")

_lock = threading.Lock()
_server: OwningClientServer | None = None
_seams: dict = {}


def configure_ipc_adapter(**seams) -> None:
    """Record operator-supplied seams (e.g. a harmless ``probe_caller``).

    ``probe_caller(server_name) -> {"ok": bool, "tool": str, "result": str}``
    performs the harmless ACTUAL tool call through the original owner. Without
    it the adapter yields ``unknown``/escalation — never a fabricated success.
    """
    with _lock:
        _seams.update(seams)


def _native_reconnector(server_name: str) -> bool:
    """Native transport rebuild, valid ONLY in the owning client's process."""
    try:
        from tools.mcp_tool_loop import reconnect_mcp_server

        return bool(reconnect_mcp_server(server_name))
    except Exception as exc:  # noqa: BLE001 - hermes seams degrade to False
        logger.warning("r2d2: native reconnect unavailable: %s", exc)
        return False


def _native_server_registry() -> frozenset:
    """The servers THIS client owns (process-local ``_servers`` registry)."""
    try:
        # ``tools.mcp_tool`` exposes ``_servers``/``_lock`` only through the
        # ``tools.mcp_tool_common._core`` origin proxy (the module has no
        # ``_core`` attribute of its own), so read the live registry through it.
        from tools.mcp_tool_common import _core

        with _core._lock:
            keys = list(_core._servers.keys())
    except Exception:  # noqa: BLE001
        return frozenset()
    names = set()
    for key in keys:
        # Under a profile multiplexer a connection key is ``(scope, name)``;
        # the IPC contract addresses servers by bare name.
        names.add(key[1] if isinstance(key, tuple) and len(key) == 2 else key)
    return frozenset(names)


def _default_policy_check(home: str):
    """Fail-closed ED-209 policy check for the IPC mutation entry.

    Returns ``policy_check(tool_name, payload) -> str | None``: ``None`` lets
    the mutation proceed; a non-empty string is the deny reason (the server
    rejects with ``STATUS_REJECTED``). FAIL-CLOSED: an absent/unreadable rules
    document REJECTS the mutation — there is no route around ED-209, even when
    the shared policy cannot be loaded. A deny/block is recorded in the shared
    ledger (visible, never silent).
    """
    import os as _os

    from operator_guards.ed209.engine import ACTION_ALLOW
    from operator_guards.ed209.ledger import HitLedger
    from operator_guards.r2d2.executor import Policy

    rules_path = _os.path.join(home, "ed209", "rules.json") if home else ""
    hits_db = _os.path.join(home, "ed209", "hits.db") if home else ""

    def check(tool_name, payload):
        if not rules_path or not _os.path.exists(rules_path):
            return f"no ED-209 rules document at {rules_path!r} (fail-closed)"
        try:
            policy = Policy(
                rules_path=rules_path,
                ledger=HitLedger(hits_db) if hits_db else None,
                session_id="r2d2-ipc",
                profile_home=home or _os.path.expanduser("~"),
            )
            decision = policy.check(tool_name, payload)
        except Exception as exc:  # noqa: BLE001 — fail closed on a broken policy
            return f"ED-209 policy unavailable ({type(exc).__name__})"
        policy.record(decision, tool_name=tool_name, client_id="r2d2-ipc")
        if decision.action == ACTION_ALLOW:
            return None
        return decision.counted_fact or f"ED-209 {decision.action}"

    return check


def start_ipc_server(home=None, state_root=None, **overrides) -> str | None:
    """Start (or reuse) the owning-client IPC server; return its socket path.

    Idempotent: a live server is returned. Fails closed (returns ``None``) if
    the runtime dir / identity cannot be resolved. The shared ED-209 policy is
    ALWAYS re-checked at the mutation entry (``policy_check`` defaults to a
    fail-closed re-evaluation of ``<home>/ed209/rules.json``; an operator seam
    may override it but never to ``None``).
    """
    global _server
    with _lock:
        if _server is not None:
            thread = _server._thread  # noqa: SLF001
            if thread is not None and thread.is_alive():
                return _server.socket_path
        seams = dict(_seams)
        seams.update(overrides)
        seams.setdefault("reconnector", _native_reconnector)
        seams.setdefault("server_registry", _native_server_registry)
        # home/state_root resolution mirrors the observer plugin's state root.
        if home is None:
            import os

            home = os.environ.get("HERMES_HOME", "").strip()
        if state_root is None:
            from operator_guards.r2d2.observer import state_root_for

            state_root = state_root_for(home) if home else None
        if not state_root:
            logger.warning("r2d2: cannot start IPC server without a state root")
            return None
        # Finding 2: wire the real ED-209 policy check at the mutation entry
        # (fail-closed). The shared 'no route around an ED-209 deny' invariant
        # is enforced here, not only by tests.
        seams.setdefault("policy_check", _default_policy_check(home or ""))
        server = OwningClientServer(
            home=home, state_root=state_root,
            profile_id=seams.pop("profile_id", None),
            client_id=seams.pop("client_id", None),
            socket_path=seams.pop("socket_path", None),
            **seams,
        )
        try:
            path = server.start()
        except Exception as exc:  # noqa: BLE001 - fail closed, never crash the client
            logger.warning("r2d2: IPC server failed to start: %s", exc)
            return None
        _server = server
        return path


def stop_ipc_server() -> None:
    global _server
    with _lock:
        server = _server
        _server = None
    if server is not None:
        server.stop()


__all__ = [
    "RECONNECT_COOLDOWN_SECONDS",
    "OwningClientServer",
    "configure_ipc_adapter",
    "start_ipc_server",
    "stop_ipc_server",
]
