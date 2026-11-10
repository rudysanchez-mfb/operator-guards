"""Owning-client IPC envelope/reply protocol, framing, and peer-credential check
(plan §4, Task 13).

The protocol is CLOSED and BOUNDED:

* **Envelope** — ``{version, request_id, incident_id, epoch, profile_id,
  client_id, session_id, operation, params}``. Unknown top-level fields are
  REJECTED; ids are non-empty strings; ``epoch`` is a non-negative int; ``params``
  is a bounded mapping of bounded strings. ``operation`` is the only field the
  client restricts beyond schema (``mcp_reconnect`` — the single initial client
  operation; everything else is ``unsupported`` at the owning client).
* **Reply** — ``{request_id, status, op_result, capability_proof}`` with
  ``status`` in ``ok | rejected | unknown | unsupported``. ``op_result`` is an
  ``OpResult``-shaped mapping (typed proof); ``capability_proof`` is a bounded
  mapping carrying the harmless-probe verdict.
* **Canonical operation hash** — ``canonical_op_hash`` binds the *operation*
  content (operation + params + incident/epoch/client/session/profile identity,
  NOT the request id) so a changed payload with the same request id is a
  different operation and is rejected.
* **Framing** — a 4-byte big-endian length prefix + JSON, capped at
  ``IPC_MAX_FRAME_BYTES``. The cap is enforced at decode time so a hostile peer
  cannot declare an unbounded frame.
* **Peer UID** — read from ``SO_PEERCRED`` (the OS-reported peer uid of a
  connected socket), never from any caller-supplied value. Same-UID checking
  prevents CROSS-USER access; it is NOT a security boundary against a same-UID
  process (procedural defence-in-depth only).
"""

from __future__ import annotations

import hashlib
import json
import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Mapping

IPC_VERSION = 1

# Bounded frame and params caps (reject over-cap, never silently truncate).
IPC_MAX_FRAME_BYTES = 64 * 1024
IPC_MAX_PARAMS_KEYS = 16
IPC_MAX_PARAM_VALUE_CHARS = 2000

# Bounded request id: a request id doubles as a receipt filename component, so
# it must stay short and filesystem-safe (never ENAMETOOLONG, never traversal).
IPC_MAX_REQUEST_ID_CHARS = 200
IPC_REQUEST_ID_ALPHABET = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)

# Reply statuses (closed union).
STATUS_OK = "ok"
STATUS_REJECTED = "rejected"
STATUS_UNKNOWN = "unknown"
STATUS_UNSUPPORTED = "unsupported"
REPLY_STATUSES = frozenset({STATUS_OK, STATUS_REJECTED, STATUS_UNKNOWN, STATUS_UNSUPPORTED})

# Forbidden param keys (mirrors handlers.FORBIDDEN_PARAM_KEYS; kept local so the
# transport module has no dependency on the handler layer).
IPC_FORBIDDEN_PARAM_KEYS = frozenset(
    {
        "command", "cmd", "exec", "executable", "argv", "shell", "script",
        "path", "exe", "bash", "zsh",
        "kill", "authority", "authorize", "authorized",
        "unlock", "off", "disable", "enable", "policy_off",
        "hook", "approval", "approve", "config_key", "config", "key",
        "pkill", "process",
    }
)

ENVELOPE_FIELDS = frozenset(
    {
        "version", "request_id", "incident_id", "epoch",
        "profile_id", "client_id", "session_id", "operation", "params",
    }
)
REPLY_FIELDS = frozenset({"request_id", "status", "op_result", "capability_proof"})


class IpcError(Exception):
    """Base error for the IPC protocol layer."""


class RequestRejected(IpcError):
    """A request is invalid or untrusted (bad peer, bad identity, bad params)."""


class ReplayRejected(IpcError):
    """A request id was reused with a DIFFERENT canonical operation hash."""


class PayloadTooLarge(IpcError):
    """A frame exceeds ``IPC_MAX_FRAME_BYTES`` (or declares an over-cap length)."""


class DeadlineExceeded(IpcError):
    """A send/recv exceeded its bounded deadline."""


# ---------------------------------------------------------------------------
# Envelope / reply
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Envelope:
    version: int
    request_id: str
    incident_id: str
    epoch: int
    profile_id: str
    client_id: str
    session_id: str
    operation: str
    params: Mapping = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "request_id": self.request_id,
            "incident_id": self.incident_id,
            "epoch": self.epoch,
            "profile_id": self.profile_id,
            "client_id": self.client_id,
            "session_id": self.session_id,
            "operation": self.operation,
            "params": dict(self.params),
        }


@dataclass(frozen=True)
class Reply:
    request_id: str
    status: str
    op_result: Any = None
    capability_proof: Any = None

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "status": self.status,
            "op_result": self.op_result,
            "capability_proof": self.capability_proof,
        }


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise IpcError(message)


def validate_envelope(record: Mapping[str, Any]) -> Envelope:
    """Validate a request record; return a typed :class:`Envelope`.

    The schema is CLOSED (unknown fields rejected) and BOUNDED (params capped).
    ``operation`` must be a non-empty string here; the owning client restricts
    it to ``mcp_reconnect`` (returning ``unsupported`` otherwise).
    """
    if not isinstance(record, Mapping):
        raise IpcError("envelope must be a mapping")
    unknown = sorted((k for k in record if k not in ENVELOPE_FIELDS), key=repr)
    if unknown:
        raise IpcError(f"envelope has unknown field(s) {unknown!r}")

    _require(record.get("version") == IPC_VERSION, "unsupported envelope version")
    for field in ("request_id", "incident_id", "profile_id", "client_id", "session_id", "operation"):
        value = record.get(field)
        _require(isinstance(value, str) and bool(value.strip()), f"envelope {field!r} must be a non-empty string")
    # The request id doubles as a receipt filename component: bound its length
    # and character set so a hostile id cannot produce ENAMETOOLONG or a
    # traversal/unsafe path (the receipt layer hashes defensively as a fallback).
    request_id = record["request_id"]
    _require(len(request_id) <= IPC_MAX_REQUEST_ID_CHARS,
             f"envelope 'request_id' exceeds the {IPC_MAX_REQUEST_ID_CHARS}-char cap")
    _require(all(c in IPC_REQUEST_ID_ALPHABET for c in request_id),
             "envelope 'request_id' contains disallowed characters")
    epoch = record.get("epoch")
    _require(isinstance(epoch, int) and not isinstance(epoch, bool) and epoch >= 0,
             "envelope 'epoch' must be a non-negative int")

    params = record.get("params", {})
    _require(isinstance(params, Mapping), "envelope 'params' must be a mapping")
    _require(len(params) <= IPC_MAX_PARAMS_KEYS,
             f"envelope params exceed the {IPC_MAX_PARAMS_KEYS}-key cap")
    for key, value in params.items():
        _require(isinstance(key, str) and bool(key.strip()), "param keys must be non-empty strings")
        _require(key not in IPC_FORBIDDEN_PARAM_KEYS,
                 f"forbidden param key {key!r} (no command/path/kill/config/hook/authority)")
        _require(isinstance(value, str), f"param {key!r} must be a string")
        _require(len(value) <= IPC_MAX_PARAM_VALUE_CHARS,
                 f"param {key!r} exceeds the {IPC_MAX_PARAM_VALUE_CHARS}-char bound")

    return Envelope(
        version=IPC_VERSION,
        request_id=record["request_id"],
        incident_id=record["incident_id"],
        epoch=epoch,
        profile_id=record["profile_id"],
        client_id=record["client_id"],
        session_id=record["session_id"],
        operation=record["operation"],
        params=dict(params),
    )


def canonical_op_hash(env: Envelope) -> str:
    """A stable hash of the OPERATION content (identity + params, not the id).

    Binds the operation to its target identity, epoch, and allowlisted params so
    a changed payload with the same request id is a DIFFERENT operation.
    """
    canonical = {
        "operation": env.operation,
        "params": dict(sorted(env.params.items())),
        "incident_id": env.incident_id,
        "epoch": env.epoch,
        "profile_id": env.profile_id,
        "client_id": env.client_id,
        "session_id": env.session_id,
    }
    payload = json.dumps(canonical, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def validate_reply(record: Mapping[str, Any]) -> Reply:
    """Validate a reply record; return a typed :class:`Reply`."""
    if not isinstance(record, Mapping):
        raise IpcError("reply must be a mapping")
    unknown = sorted((k for k in record if k not in REPLY_FIELDS), key=repr)
    if unknown:
        raise IpcError(f"reply has unknown field(s) {unknown!r}")
    request_id = record.get("request_id")
    _require(isinstance(request_id, str) and bool(request_id.strip()), "reply 'request_id' must be a non-empty string")
    status = record.get("status")
    _require(status in REPLY_STATUSES, f"reply status {status!r} must be one of {sorted(REPLY_STATUSES)}")
    return Reply(
        request_id=request_id,
        status=status,
        op_result=record.get("op_result"),
        capability_proof=record.get("capability_proof"),
    )


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------

_HEADER = struct.Struct(">I")


def encode_frame(obj: Any) -> bytes:
    """Encode ``obj`` as a length-prefixed JSON frame (4-byte BE length + JSON)."""
    body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(body) > IPC_MAX_FRAME_BYTES:
        raise PayloadTooLarge(f"frame body {len(body)} bytes exceeds {IPC_MAX_FRAME_BYTES}")
    return _HEADER.pack(len(body)) + body


def decode_frame(data: bytes) -> Any:
    """Decode a length-prefixed JSON frame; reject an over-cap declared length."""
    if len(data) < _HEADER.size:
        raise IpcError("truncated frame header")
    (length,) = _HEADER.unpack(data[: _HEADER.size])
    if length > IPC_MAX_FRAME_BYTES:
        raise PayloadTooLarge(f"frame declares {length} bytes > {IPC_MAX_FRAME_BYTES} cap")
    body = data[_HEADER.size: _HEADER.size + length]
    if len(body) != length:
        raise IpcError("truncated frame body")
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise IpcError(f"invalid JSON frame: {exc}") from exc


# ---------------------------------------------------------------------------
# Peer credentials (SO_PEERCRED)
# ---------------------------------------------------------------------------

_SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)
_CRED_SIZE = struct.calcsize("3i")  # struct ucred {pid_t, uid_t, gid_t}


def peer_uid(fd: int) -> int:
    """Return the OS-reported peer UID of a connected socket fd (SO_PEERCRED).

    Raises :class:`OSError` when the credential is unavailable. The value is
    read from the kernel, never from a caller-supplied field. This is used for
    same-UID checking (cross-user access prevention), NOT as a security boundary
    against a same-UID process.
    """
    sock = socket.socket(fileno=fd)
    try:
        data = sock.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, _CRED_SIZE)
    finally:
        # detach, do NOT close the shared underlying fd
        sock.detach()
    if not data or len(data) < _CRED_SIZE:
        raise OSError("SO_PEERCRED unavailable on this socket")
    _pid, uid_value, _gid = struct.unpack("3i", data[: _CRED_SIZE])
    return uid_value


__all__ = [
    "IPC_VERSION",
    "IPC_MAX_FRAME_BYTES",
    "IPC_MAX_PARAMS_KEYS",
    "IPC_MAX_PARAM_VALUE_CHARS",
    "IPC_MAX_REQUEST_ID_CHARS",
    "STATUS_OK",
    "STATUS_REJECTED",
    "STATUS_UNKNOWN",
    "STATUS_UNSUPPORTED",
    "REPLY_STATUSES",
    "IPC_FORBIDDEN_PARAM_KEYS",
    "IpcError",
    "RequestRejected",
    "ReplayRejected",
    "PayloadTooLarge",
    "DeadlineExceeded",
    "Envelope",
    "Reply",
    "validate_envelope",
    "validate_reply",
    "canonical_op_hash",
    "encode_frame",
    "decode_frame",
    "peer_uid",
]
