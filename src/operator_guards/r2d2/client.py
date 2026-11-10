"""Owning-client adapter (daemon side) + durable request receipts (plan §4,
Task 13).

The daemon (R2-D2) does NOT touch the owning client's process-local MCP
registry. It sends a bounded request over the IPC socket; the OWNING CLIENT
performs the native reconnect and the harmless actual tool call. This module is
the daemon side of that contract:

* **Intent before send** — :meth:`OwningClientAdapter.request_mcp_reconnect`
  durably records the operation INTENT (a ``queued`` receipt bound to
  ``request_id + epoch + canonical operation hash``) BEFORE the request leaves
  the daemon.
* **Dedupe / replay** — the request id is DETERMINISTIC
  (``deterministic_request_id`` = sha256 of incident+epoch+op-hash), so an
  IDENTICAL retry resolves to the same id and returns the RECORDED outcome
  without re-sending; a CHANGED operation hash under the same id is REJECTED
  (:class:`ReplayRejected`).
* **Receipt states** — ``queued -> started -> settled`` (the ``started``
  transition is performed by the OWNING CLIENT at its launch barrier).
* **Timeout / lost ack -> reconciliation** — a deadline expiry settles the
  receipt as ``unknown``; the caller reconciles, never blindly re-executes.
* **Typed proof** — on an ``ok`` reply, the typed ``OpResult`` is appended to
  the incident's durable ``mutation_plan``.

``ReceiptStore`` is shared by BOTH sides (daemon intent + owning-client
receipt) via the common state root, so dedupe is cross-process. Receipt files
are procedural, same-UID defence-in-depth — NOT tamper-proof.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import time
import uuid
from dataclasses import replace
from typing import Any, Callable, Mapping

from operator_guards.common.ipc import (
    IPC_MAX_FRAME_BYTES,
    IPC_MAX_REQUEST_ID_CHARS,
    STATUS_OK,
    STATUS_UNKNOWN,
    DeadlineExceeded,
    Envelope,
    IpcError,
    PayloadTooLarge,
    ReplayRejected,
    Reply,
    canonical_op_hash,
    encode_frame,
    validate_reply,
)
from operator_guards.r2d2.handlers import OP_MCP_RECONNECT
from operator_guards.r2d2.schema import (
    RECEIPT_QUEUED,
    RECEIPT_SETTLED,
    RECEIPT_STARTED,
    RECEIPT_STATES,
)
from operator_guards.r2d2.store import IncidentStore

DEFAULT_IPC_DEADLINE = 15.0

_FILENAME_SAFE = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)


class ReceiptError(Exception):
    """Base error for the durable receipt store."""


def _safe(value: str) -> str:
    safe = "".join(c if c in _FILENAME_SAFE else "_" for c in value)
    if safe != value or safe in (".", "..") or len(safe) > IPC_MAX_REQUEST_ID_CHARS:
        safe = "s_" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
    return safe


def deterministic_request_id(incident_id: str, epoch: int, op_hash: str) -> str:
    """A STABLE request id for one (incident, epoch, operation).

    Identical retries reproduce the same id (so dedupe returns the recorded
    outcome); a changed operation changes the id (so replay of a DIFFERENT
    payload can never collide with the original under an identical id).
    """
    digest = hashlib.sha256(f"{incident_id}|{epoch}|{op_hash}".encode("utf-8")).hexdigest()
    return "req-" + digest[:24]


# ---------------------------------------------------------------------------
# Durable receipt store (shared by daemon and owning client)
# ---------------------------------------------------------------------------


class ReceiptStore:
    """Durable per-request receipts: ``queued -> started -> settled``.

    ``record_queued`` is idempotent for the SAME hash (a retry) and REJECTS a
    DIFFERENT hash under the same request id (a replayed/changed payload).
    Writes are atomic (temp + fsync + replace); creation uses O_CREAT|O_EXCL so
    a cross-process race yields exactly one winner.
    """

    def __init__(self, root: str):
        self.dir = os.path.join(root, "receipts")

    def _path(self, request_id: str) -> str:
        return os.path.join(self.dir, _safe(request_id) + ".json")

    def lookup(self, request_id: str) -> dict | None:
        try:
            with open(self._path(request_id), encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def list(self) -> list[dict]:
        out: list[dict] = []
        try:
            names = os.listdir(self.dir)
        except OSError:
            return out
        for name in names:
            if not name.endswith(".json"):
                continue
            rec = self.lookup(name[: -len(".json")])
            if rec is not None:
                out.append(rec)
        return out

    def find_inflight(self, incident_id: str) -> dict | None:
        """The STARTED (in-flight, not settled) receipt for an incident, if any."""
        for rec in self.list():
            if rec.get("incident_id") == incident_id and rec.get("state") == RECEIPT_STARTED:
                return rec
        return None

    def record_queued(self, request_id: str, epoch: int, op_hash: str, incident_id: str) -> dict:
        """Persist INTENT (``queued``) before send; dedupe/replay protection.

        An existing receipt with the SAME hash is returned (idempotent retry).
        A DIFFERENT hash under the same id raises :class:`ReplayRejected`.
        """
        existing = self.lookup(request_id)
        if existing is not None:
            if existing.get("op_hash") != op_hash or existing.get("epoch") != epoch:
                raise ReplayRejected(
                    f"request {request_id!r} was reused with a DIFFERENT operation "
                    f"(changed hash/epoch)"
                )
            return existing
        record = {
            "request_id": request_id,
            "incident_id": incident_id,
            "epoch": epoch,
            "op_hash": op_hash,
            "state": RECEIPT_QUEUED,
            "status": "",
            "op_result": None,
            "capability_proof": None,
            "queued_at": time.time(),
            "started_at": 0.0,
            "settled_at": 0.0,
        }
        self._create(record)
        return record

    def mark_started(self, request_id: str, epoch: int, op_hash: str) -> dict:
        """``queued -> started`` (the launch barrier, performed by the OWNING CLIENT)."""
        existing = self.lookup(request_id)
        if existing is None or existing.get("state") != RECEIPT_QUEUED:
            raise ReceiptError(f"no queued request {request_id!r} to start")
        if existing.get("epoch") != epoch or existing.get("op_hash") != op_hash:
            raise ReceiptError(f"request {request_id!r} epoch/hash mismatch at start")
        updated = dict(existing, state=RECEIPT_STARTED, started_at=time.time())
        self._replace(updated)
        return updated

    def mark_settled(
        self, request_id: str, status: str, op_result: Any, capability_proof: Any
    ) -> dict:
        """``queued|started -> settled``, recording the outcome."""
        existing = self.lookup(request_id)
        if existing is None:
            raise ReceiptError(f"no request {request_id!r} to settle")
        if existing.get("state") == RECEIPT_SETTLED:
            return existing
        updated = dict(
            existing,
            state=RECEIPT_SETTLED,
            status=status,
            op_result=op_result,
            capability_proof=capability_proof,
            settled_at=time.time(),
        )
        self._replace(updated)
        return updated

    # -- atomic file I/O ----------------------------------------------------

    def _create(self, record: dict) -> None:
        os.makedirs(self.dir, exist_ok=True)
        data = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
        path = self._path(record["request_id"])
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            # Race: another process created it; re-read and let the caller decide.
            existing = self.lookup(record["request_id"])
            if existing is not None:
                return
            raise ReceiptError(f"receipt {record['request_id']!r} already exists")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            try:
                os.unlink(path)
            except OSError:
                pass
            raise

    def _replace(self, record: dict) -> None:
        os.makedirs(self.dir, exist_ok=True)
        data = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
        path = self._path(record["request_id"])
        tmp = f"{path}.{uuid.uuid4().hex}.tmp"
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Typed proof persistence (shared by daemon and owning client)
# ---------------------------------------------------------------------------


def record_typed_proof(store: IncidentStore, incident_id: str, op_result: Mapping) -> None:
    """Append a typed ``OpResult`` to the incident's durable ``mutation_plan``.

    Idempotent by ``op_id``; validated through the closed ``OpResult`` schema.
    Best-effort (never raises into the request path).
    """
    if not isinstance(op_result, Mapping) or not op_result.get("op_id"):
        return
    from operator_guards.r2d2.schema import IncidentError, load_op_result

    try:
        op = load_op_result(op_result)
    except (IncidentError, KeyError, TypeError, ValueError):
        return

    def _t(inc):
        if any(m.op_id == op.op_id for m in inc.mutation_plan):
            return inc
        return replace(inc, mutation_plan=inc.mutation_plan + (op,))

    try:
        store.update_incident(incident_id, _t)
    except Exception:  # noqa: BLE001 - proof persistence is best-effort
        pass


# ---------------------------------------------------------------------------
# The daemon-side adapter
# ---------------------------------------------------------------------------


class OwningClientAdapter:
    """Daemon side of the owning-client IPC contract.

    ``transport`` is injectable for tests (default = real Unix-socket client).
    It is called with ``(socket_path, frame_bytes, deadline)`` and returns the
    reply frame bytes.
    """

    def __init__(
        self,
        state_root: str,
        *,
        store: IncidentStore | None = None,
        receipts: ReceiptStore | None = None,
        socket_path: str | None = None,
        deadline: float = DEFAULT_IPC_DEADLINE,
        clock: Callable[[], float] | None = None,
        transport: Callable[[str, bytes, float], bytes] | None = None,
    ):
        self.state_root = state_root
        self.store = store if store is not None else IncidentStore(state_root)
        self.receipts = receipts if receipts is not None else ReceiptStore(state_root)
        self.socket_path = socket_path
        self.deadline = deadline
        self.clock = clock if clock is not None else time.monotonic
        self._transport = transport if transport is not None else self._socket_transport
        self.last_request_id = ""
        self.last_reply: Reply | None = None

    # -- request ------------------------------------------------------------

    def request_mcp_reconnect(self, incident_id: str, server: str) -> Reply:
        """Send ``mcp_reconnect`` for a KNOWN server to the owning client."""
        if not isinstance(server, str) or not server.strip():
            return Reply(request_id="", status=STATUS_UNKNOWN)
        inc = self._incident(incident_id)
        if inc is None:
            return Reply(request_id="", status=STATUS_UNKNOWN)

        env = Envelope(
            version=1,
            request_id="",
            incident_id=incident_id,
            epoch=inc.epoch,
            profile_id=inc.profile_id,
            client_id=inc.client_id,
            session_id=inc.session_id,
            operation=OP_MCP_RECONNECT,
            params={"server": server},
        )
        op_hash = canonical_op_hash(env)
        request_id = deterministic_request_id(incident_id, inc.epoch, op_hash)
        self.last_request_id = request_id

        # INTENT before send: dedupe/replay protection at the daemon side.
        receipt = self.receipts.record_queued(request_id, inc.epoch, op_hash, incident_id)
        if receipt.get("state") == RECEIPT_SETTLED:
            # Identical retry: return the recorded outcome, never re-execute.
            reply = Reply(
                request_id=request_id,
                status=receipt.get("status") or STATUS_UNKNOWN,
                op_result=receipt.get("op_result"),
                capability_proof=receipt.get("capability_proof"),
            )
            self.last_reply = reply
            return reply

        env = replace(env, request_id=request_id)
        try:
            reply = self._send(env)
        except (DeadlineExceeded, IpcError, OSError):
            # Lost acknowledgment / dead owner: RECONCILE, never auto-retry.
            reply = Reply(request_id=request_id, status=STATUS_UNKNOWN)
            self.receipts.mark_settled(request_id, STATUS_UNKNOWN, None, None)
            self.last_reply = reply
            return reply

        self.receipts.mark_settled(request_id, reply.status, reply.op_result, reply.capability_proof)
        if reply.status == STATUS_OK:
            record_typed_proof(self.store, incident_id, reply.op_result)
        self.last_reply = reply
        return reply

    def _incident(self, incident_id: str):
        try:
            self.store.refresh()
        except Exception:  # noqa: BLE001
            pass
        return self.store.get_incident(incident_id)

    # -- transport ----------------------------------------------------------

    def _send(self, env: Envelope) -> Reply:
        if self.socket_path is None:
            raise IpcError("no socket path configured")
        frame = encode_frame(env.to_dict())
        reply_body = self._transport(self.socket_path, frame, self.deadline)
        try:
            record = json.loads(reply_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise IpcError(f"invalid reply payload: {exc}") from exc
        return validate_reply(record)

    def _socket_transport(self, socket_path: str, frame: bytes, deadline: float) -> bytes:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(max(float(deadline), 0.1))
        try:
            sock.connect(socket_path)
            sock.sendall(frame)
            header = self._recv_exact(sock, 4)
            (length,) = struct.unpack(">I", header)
            if length > IPC_MAX_FRAME_BYTES:
                raise PayloadTooLarge(f"reply declares {length} bytes > cap")
            return self._recv_exact(sock, length)
        except socket.timeout as exc:
            raise DeadlineExceeded(f"IPC send/recv timed out after {deadline}s") from exc
        finally:
            sock.close()

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise IpcError("connection closed before full frame received")
            buf.extend(chunk)
        return bytes(buf)


__all__ = [
    "DEFAULT_IPC_DEADLINE",
    "ReceiptError",
    "ReceiptStore",
    "deterministic_request_id",
    "record_typed_proof",
    "OwningClientAdapter",
]
