"""Owning-client IPC server (plan §4, Task 13).

Runs INSIDE the owning Hermes client process. The daemon connects over a Unix
socket; this server re-validates EVERYTHING immediately before mutation and
performs the native reconnect + harmless actual tool call. It is the client's
half of both-side fencing:

1. **Peer UID** — the OS-reported ``SO_PEERCRED`` uid must equal this process's
   uid (cross-user access prevention; NOT a boundary against a same-UID process).
2. **Identity bind** — ``profile_id``/``client_id`` must match THIS client.
3. **Operation allowlist** — only ``mcp_reconnect`` (else ``unsupported``).
4. **Known server** — the target server must be registered in THIS client.
5. **Durable fencing** — the incident's CURRENT epoch must equal the envelope's
   (a stale queued epoch is rejected IMMEDIATELY before launch), the lease must
   be unexpired, a claimant must exist (dead owner -> ``unknown``), and the phase
   must not be terminal.
6. **Dedupe/replay** — a settled receipt with the same id+hash returns the
   recorded outcome; a CHANGED hash under the same id is REJECTED.
7. **In-flight block** — a STARTED receipt for the incident blocks a new
   mutating epoch (no duplicate after a lost acknowledgment).
8. **Cooldown + shared ED-209 policy** — checked before launch.
9. **Adapter availability** — a missing harmless probe or reconnector yields
   ``unknown``/escalation, never a fabricated success.
10. **Launch barrier** — the receipt transitions ``queued -> started`` only after
    every check passes, then the native reconnect runs and a HARMLESS ACTUAL
    TOOL CALL is proven through the original owner before ``settled``.

The ``reconnector``/``probe_caller``/``server_registry``/``policy_check`` seams
are injectable so this module imports WITHOUT Hermes (standalone test venv); the
plugin wires the native Hermes seams (see ``plugins/r2d2/ipc_adapter.py``).
"""

from __future__ import annotations

import json
import os
import socket
import struct
import threading
import time
from typing import Any, Callable, Mapping

from operator_guards.common.identity import client_id_for, ipc_socket_path, profile_id_for
from operator_guards.common.ipc import (
    IPC_MAX_FRAME_BYTES,
    STATUS_OK,
    STATUS_REJECTED,
    STATUS_UNKNOWN,
    STATUS_UNSUPPORTED,
    DeadlineExceeded,
    IpcError,
    ReplayRejected,
    Reply,
    canonical_op_hash,
    decode_frame,
    encode_frame,
    peer_uid,
    validate_envelope,
)
from operator_guards.common.proof import Verdict
from operator_guards.r2d2.client import ReceiptStore, record_typed_proof
from operator_guards.r2d2.handlers import OP_MCP_RECONNECT
from operator_guards.r2d2.schema import (
    OBSERVED_VALUE_MAX_CHARS,
    PHASE_ESCALATED,
    PHASE_RESOLVED,
    RECEIPT_SETTLED,
)
from operator_guards.r2d2.store import IncidentStore

# Circuit-breaker cooldown: a server reconnected within this window is not
# re-launched (native transport already has its own 30-600s backoff; this
# prevents the daemon from piling a second reconnect on top of it).
RECONNECT_COOLDOWN_SECONDS = 60.0

# Per-connection I/O bounds (Task 13): a peer that opens a connection and then
# dribbles a PARTIAL frame must be cut off and its slot freed, never starve
# other clients. ``recv_timeout`` bounds each recv(); ``frame_deadline`` bounds
# the total time to read one full frame (a slow-loris sending a byte per
# timeout still cannot hold a slot forever).
CONN_RECV_TIMEOUT_SECONDS = 5.0
CONN_FRAME_READ_DEADLINE_SECONDS = 15.0
# Bounded concurrency: connections are served on a bounded pool of threads;
# a connection arriving at the cap is rejected (closed) rather than queued.
MAX_IN_FLIGHT_CONNECTIONS = 16

_FRAME_HEADER = struct.Struct(">I")


class OwningClientServer:
    """The owning client's half of the IPC contract (see module docstring)."""

    def __init__(
        self,
        *,
        home: str | None = None,
        state_root: str,
        socket_path: str | None = None,
        profile_id: str | None = None,
        client_id: str | None = None,
        reconnector: Callable[[str], bool] | None = None,
        probe_caller: Callable[[str], Mapping | None] | None = None,
        server_registry: Callable[[], frozenset] | None = None,
        policy_check: Callable[[str, str], Any] | None = None,
        clock: Callable[[], float] | None = None,
        cooldown_seconds: float = RECONNECT_COOLDOWN_SECONDS,
        uid_fn: Callable[[], int] | None = None,
        recv_timeout: float = CONN_RECV_TIMEOUT_SECONDS,
        frame_deadline: float = CONN_FRAME_READ_DEADLINE_SECONDS,
        max_connections: int = MAX_IN_FLIGHT_CONNECTIONS,
    ):
        self.home = home
        self.state_root = state_root
        self.profile_id = profile_id if profile_id is not None else profile_id_for(home or "")
        self.client_id = client_id if client_id is not None else client_id_for(home or "")
        self.socket_path = socket_path or ipc_socket_path(self.profile_id, self.client_id)
        self._reconnector = reconnector
        self._probe_caller = probe_caller
        self._server_registry = server_registry
        self._policy_check = policy_check
        self._clock = clock if clock is not None else time.monotonic
        self.cooldown_seconds = cooldown_seconds
        self._uid = uid_fn if uid_fn is not None else os.getuid
        self._store = IncidentStore(state_root)
        self._receipts = ReceiptStore(state_root)
        self._last_reconnect: dict[str, float] = {}
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        # Per-connection I/O bounds + bounded concurrency (Task 13).
        self.recv_timeout = recv_timeout
        self.frame_deadline = frame_deadline
        self._conn_slots = threading.BoundedSemaphore(max_connections)
        self._active_conns: set[socket.socket] = set()
        self._active_lock = threading.Lock()

    # -- request handling (pure-ish core; unit-testable without a socket) ----

    def handle(self, record: Mapping[str, Any], peer_uid_value: int) -> dict:
        """Process one request record; return the reply dict."""
        rid = record.get("request_id", "") if isinstance(record, Mapping) else ""

        def reply(status, op_result=None, capability_proof=None):
            return Reply(
                request_id=rid, status=status,
                op_result=op_result, capability_proof=capability_proof,
            ).to_dict()

        # 1. peer UID
        if peer_uid_value != self._uid():
            return reply(STATUS_REJECTED)

        # 2. envelope validation
        try:
            env = validate_envelope(record)
        except IpcError:
            return reply(STATUS_REJECTED)

        # 3. identity bind
        if env.profile_id != self.profile_id or env.client_id != self.client_id:
            return reply(STATUS_REJECTED)

        # 4. operation allowlist
        if env.operation != OP_MCP_RECONNECT:
            return reply(STATUS_UNSUPPORTED)

        # 5. params: exactly the enumerated ``server`` key
        if set(env.params.keys()) != {"server"}:
            return reply(STATUS_REJECTED)
        server = env.params.get("server", "")
        if not isinstance(server, str) or not server.strip():
            return reply(STATUS_REJECTED)

        # 6. the server must be EXPLICITLY KNOWN in this client
        registry = self._server_registry() if self._server_registry is not None else frozenset()
        if server not in registry:
            return reply(STATUS_UNKNOWN)

        # 7. durable fencing (immediately before mutation, not at connect time)
        inc = self._incident(env.incident_id)
        if inc is None:
            return reply(STATUS_UNKNOWN)
        # the envelope's target identity must match the DURABLE incident's
        # recorded identity (a caller cannot substitute a different
        # profile/session/client), in addition to matching THIS client.
        if (
            env.profile_id != inc.profile_id
            or env.client_id != inc.client_id
            or env.session_id != inc.session_id
        ):
            return reply(STATUS_REJECTED)
        if env.epoch != inc.epoch:
            return reply(STATUS_UNKNOWN)  # stale queued epoch -> escalate
        if inc.phase in (PHASE_RESOLVED, PHASE_ESCALATED):
            return reply(STATUS_UNKNOWN)
        if not inc.claimant:
            return reply(STATUS_UNKNOWN)  # dead owner
        if inc.lease_expiry <= self._clock():
            return reply(STATUS_UNKNOWN)  # expired lease

        # 8. dedupe/replay (client receipt before launch)
        op_hash = canonical_op_hash(env)
        try:
            receipt = self._receipts.record_queued(env.request_id, env.epoch, op_hash, env.incident_id)
        except ReplayRejected:
            return reply(STATUS_REJECTED)
        if receipt.get("state") == RECEIPT_SETTLED:
            return reply(
                receipt.get("status") or STATUS_UNKNOWN,
                receipt.get("op_result"),
                receipt.get("capability_proof"),
            )

        # 9. in-flight block: a STARTED receipt for this incident blocks a new
        #    mutating epoch (no duplicate after a lost acknowledgment).
        inflight = self._receipts.find_inflight(env.incident_id)
        if inflight is not None and inflight.get("request_id") != env.request_id:
            return reply(STATUS_UNKNOWN)

        # 10. circuit-breaker cooldown
        with self._lock:
            last = self._last_reconnect.get(server)
        if last is not None and self._clock() - last < self.cooldown_seconds:
            return reply(STATUS_UNKNOWN)

        # 11. shared ED-209 policy recheck
        if self._policy_check is not None:
            decision = self._policy_check(
                OP_MCP_RECONNECT, json.dumps(dict(env.params), sort_keys=True)
            )
            if decision:
                return reply(STATUS_REJECTED)

        # 12. adapter availability (missing harmless probe -> unknown/escalate)
        if self._reconnector is None or self._probe_caller is None:
            return reply(STATUS_UNKNOWN)

        # 13. launch barrier: queued -> started
        self._receipts.mark_started(env.request_id, env.epoch, op_hash)

        # 14. native reconnect + harmless ACTUAL tool call (original owner)
        try:
            if not self._reconnector(server):
                self._receipts.mark_settled(env.request_id, STATUS_UNKNOWN, None, None)
                return reply(STATUS_UNKNOWN)
            with self._lock:
                self._last_reconnect[server] = self._clock()
            probe = self._probe_caller(server)
        except Exception:  # noqa: BLE001 - a raising adapter is contained
            self._receipts.mark_settled(env.request_id, STATUS_UNKNOWN, None, None)
            return reply(STATUS_UNKNOWN)

        ok = bool(probe and probe.get("ok"))
        verdict = Verdict.PASS if ok else Verdict.FAIL
        capability_proof = {
            "verdict": verdict.value,
            "server": server,
            "probe_tool": str((probe or {}).get("tool", "")),
            "probe_result": str((probe or {}).get("result", ""))[:OBSERVED_VALUE_MAX_CHARS],
        }
        op_result = {
            "op_id": f"mcp-{env.request_id[:8]}",
            "kind": "mcp_status",
            "verdict": verdict.value,
            "expected": server,
            "observed": [capability_proof["probe_result"]],
            "evidence": f"harmless probe via {capability_proof['probe_tool']}",
            "epoch": env.epoch,
            "client_id": env.client_id,
        }
        status = STATUS_OK if ok else STATUS_UNKNOWN
        self._receipts.mark_settled(env.request_id, status, op_result, capability_proof)
        if ok:
            record_typed_proof(self._store, env.incident_id, op_result)
        return reply(status, op_result, capability_proof)

    def _incident(self, incident_id: str):
        try:
            self._store.refresh()
        except Exception:  # noqa: BLE001
            pass
        return self._store.get_incident(incident_id)

    # -- socket lifecycle ---------------------------------------------------

    def start(self) -> str:
        """Bind + listen on the user-only socket; serve on a daemon thread."""
        d = os.path.dirname(self.socket_path) or "."
        os.makedirs(d, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self.socket_path)
        os.chmod(self.socket_path, 0o600)
        sock.listen(8)
        sock.settimeout(0.5)
        self._sock = sock
        self._stopping.clear()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self.socket_path

    def stop(self) -> None:
        self._stopping.set()
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        # Wake any blocked per-connection recv threads so they exit promptly
        # (shutdown interrupts a blocked recv() more reliably than close()).
        with self._active_lock:
            conns = list(self._active_conns)
        for conn in conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass

    def _serve(self) -> None:
        while not self._stopping.is_set():
            try:
                conn, _ = self._sock.accept()  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                break
            # Bounded concurrency: a slot is held from accept until the
            # connection is fully handled; a connection arriving at the cap is
            # rejected (closed) rather than queued unboundedly. Each connection
            # is served on its own thread so one stalled peer cannot starve the
            # next client.
            if not self._conn_slots.acquire(blocking=False):
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            threading.Thread(target=self._run_conn, args=(conn,), daemon=True).start()

    def _run_conn(self, conn: socket.socket) -> None:
        try:
            with self._active_lock:
                self._active_conns.add(conn)
            try:
                # Per-connection bounded read: a stalled peer cannot hold its
                # thread (or slot) forever, and cannot block other clients.
                conn.settimeout(self.recv_timeout)
                deadline = time.monotonic() + self.frame_deadline
                self._handle_conn(conn, deadline)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
                with self._active_lock:
                    self._active_conns.discard(conn)
        finally:
            self._conn_slots.release()

    def _handle_conn(self, conn: socket.socket, deadline: float) -> None:
        try:
            uid_value = peer_uid(conn.fileno())
        except OSError:
            uid_value = -1
        try:
            record = self._recv_record(conn, deadline)
        except (IpcError, OSError, ValueError):
            return
        try:
            reply = self.handle(record, uid_value)
        except Exception:  # noqa: BLE001 - a server must never crash on one request
            reply = Reply(request_id=record.get("request_id", ""), status=STATUS_UNKNOWN).to_dict()
        try:
            conn.sendall(encode_frame(reply))
        except OSError:
            pass

    def _recv_record(self, conn: socket.socket, deadline: float) -> dict:
        header = self._recv_exact(conn, _FRAME_HEADER.size, deadline)
        (length,) = _FRAME_HEADER.unpack(header)
        if length > IPC_MAX_FRAME_BYTES:
            raise IpcError("frame declares over-cap length")
        body = self._recv_exact(conn, length, deadline)
        return decode_frame(_FRAME_HEADER.pack(length) + body)

    def _recv_exact(self, conn: socket.socket, n: int, deadline: float) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DeadlineExceeded("frame read deadline exceeded")
            conn.settimeout(min(self.recv_timeout, remaining))
            try:
                chunk = conn.recv(n - len(buf))
            except socket.timeout as exc:
                raise DeadlineExceeded("per-connection recv deadline exceeded") from exc
            if not chunk:
                raise IpcError("connection closed before full frame received")
            buf.extend(chunk)
        return bytes(buf)


__all__ = [
    "RECONNECT_COOLDOWN_SECONDS",
    "CONN_RECV_TIMEOUT_SECONDS",
    "CONN_FRAME_READ_DEADLINE_SECONDS",
    "MAX_IN_FLIGHT_CONNECTIONS",
    "OwningClientServer",
]
