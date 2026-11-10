"""Operator grants + notification policy (plan §4, Task 14).

**Grants** are the ONLY kill authority in R2-D2. A grant names the exact
other-session/client/process-START identity, the incident/action scope, the
issuer, the issued/expiry times, and a single-use nonce. Consumption is DURABLE
and ONE-WAY: the grant is marked consumed *before* the one authorized attempt,
and a failed resume does NOT refund kill authority (there is no unconsume/refund
path). Consumption ENFORCES the presented identity (session/client/pid/start-
time) and scope against the grant — a grant is not usable for a different
target. Expiry is exact and INCLUSIVE of the boundary: a grant is expired at
``now >= issued_at + ttl`` (the boundary instant itself is expired, not only
anything past it).

Grant creation can never come from an incident payload or a model tool
operation:

* :meth:`GrantStore.issue` accepts only explicit, keyword-only identity fields.
  It has NO ``nonce``/``record``/``payload`` parameter, so an incident record
  (with its ``authorization``/``nonce`` fields) can never be passed in, and the
  nonce is GENERATED here by the issuer's own store — a grant can never accept
  its own authority from incident JSON.
* ``grant issue``/``list``/``revoke`` are OPERATOR CLI verbs only; they are
  NOT in the executor's operation allowlist, and daemon/model execution of them
  is refused and LEDGERED (see ``r2d2/cli.py``).

**Notification policy**: opt-in belongs to the OPERATOR. Absence of an explicit
channel opt-in means LOCAL-ONLY status (no outbound delivery). An explicitly
enabled channel supports at most ONE accepted delivery per incident, with
durable dedupe, a visible suppression reason, and an exact-delivery-receipt
readback path. SMS/Telegram are NEVER enabled merely because a daemon starts.

**Threat-model honesty**: same-UID code can edit these files directly; the
grant store and CLI are procedural defence-in-depth, NOT an OS security
boundary. CLI role labels and operator markers do not prevent arbitrary
same-UID processes from bypassing them.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import Callable, Mapping

# ---------------------------------------------------------------------------
# Grant scopes (the closed §4 action scope)
# ---------------------------------------------------------------------------

GRANT_SCOPE_SESSION_STOP_RESUME = "session_stop_resume"
GRANT_SCOPES = frozenset({GRANT_SCOPE_SESSION_STOP_RESUME})

# ---------------------------------------------------------------------------
# Notification channels
# ---------------------------------------------------------------------------

CHANNEL_LOCAL = "local"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class GrantError(Exception):
    """Base error for the grant store."""


class GrantNotFoundError(GrantError):
    """A grant id does not exist."""


class GrantScopeError(GrantError):
    """A scope is outside the closed action scope."""


class GrantExpiredError(GrantError):
    """The grant's TTL has elapsed."""


class GrantAlreadyConsumedError(GrantError):
    """The single-use grant was already consumed (no refund)."""


class GrantRevokedError(GrantError):
    """The grant was revoked by the operator."""


class GrantNonceMismatchError(GrantError):
    """The presented nonce does not match the issuer-generated nonce."""


class GrantIdentityMismatchError(GrantError):
    """The presented identity (session/client/pid/start-time) does not match the grant."""


class GrantScopeMismatchError(GrantError):
    """The presented scope does not match the grant's scope."""


# ---------------------------------------------------------------------------
# Grant record
# ---------------------------------------------------------------------------

_FILENAME_SAFE = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)
_MAX_NAME = 120

_GRANT_FIELDS = frozenset(
    {
        "grant_id",
        "incident_id",
        "scope",
        "session_id",
        "client_id",
        "pid",
        "start_time",
        "issuer",
        "nonce",
        "issued_at",
        "expires_at",
        "consumed",
        "consumed_at",
        "revoked",
        "revoked_at",
    }
)


@dataclass(frozen=True)
class Grant:
    """A scoped single-use TTL kill grant (plan §4).

    Identity fields (``session_id``, ``client_id``, ``pid``, ``start_time``)
    name the EXACT other-session/process principal; ``scope`` is the incident/
    action scope; ``nonce`` is issuer-generated; ``issued_at``/``expires_at``
    bound the TTL; ``consumed``/``revoked`` mark one-way lifecycle transitions.
    """

    grant_id: str
    incident_id: str
    scope: str
    session_id: str
    client_id: str
    pid: int
    start_time: float
    issuer: str
    nonce: str
    issued_at: float
    expires_at: float
    consumed: bool = False
    consumed_at: float = 0.0
    revoked: bool = False
    revoked_at: float = 0.0

    def to_dict(self) -> dict:
        return {
            "grant_id": self.grant_id,
            "incident_id": self.incident_id,
            "scope": self.scope,
            "session_id": self.session_id,
            "client_id": self.client_id,
            "pid": self.pid,
            "start_time": self.start_time,
            "issuer": self.issuer,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "consumed": self.consumed,
            "consumed_at": self.consumed_at,
            "revoked": self.revoked,
            "revoked_at": self.revoked_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping) -> "Grant":
        if not isinstance(data, Mapping):
            raise GrantError("grant record must be a mapping")
        unknown = sorted((k for k in data if k not in _GRANT_FIELDS), key=repr)
        if unknown:
            raise GrantError(f"grant record has unknown field(s) {unknown!r}")
        for field in (
            "grant_id", "incident_id", "scope", "session_id", "client_id",
            "issuer", "nonce",
        ):
            if not isinstance(data.get(field), str) or not data.get(field).strip():
                raise GrantError(f"grant field {field!r} must be a non-empty string")
        if data.get("scope") not in GRANT_SCOPES:
            raise GrantError(f"grant scope {data.get('scope')!r} is not a known scope")
        pid = data.get("pid")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            raise GrantError("grant field 'pid' must be a positive int")
        for field in ("start_time", "issued_at", "expires_at", "consumed_at", "revoked_at"):
            value = data.get(field, 0.0)
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise GrantError(f"grant field {field!r} must be a number")
        return cls(
            grant_id=data["grant_id"],
            incident_id=data["incident_id"],
            scope=data["scope"],
            session_id=data["session_id"],
            client_id=data["client_id"],
            pid=int(pid),
            start_time=float(data["start_time"]),
            issuer=data["issuer"],
            nonce=data["nonce"],
            issued_at=float(data["issued_at"]),
            expires_at=float(data["expires_at"]),
            consumed=bool(data.get("consumed", False)),
            consumed_at=float(data.get("consumed_at", 0.0)),
            revoked=bool(data.get("revoked", False)),
            revoked_at=float(data.get("revoked_at", 0.0)),
        )


def _safe_name(value: str) -> str:
    safe = "".join(c if c in _FILENAME_SAFE else "_" for c in value)
    if safe != value or safe in (".", ".."):
        safe = "s_" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
    if len(safe) > _MAX_NAME:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        safe = f"{safe[:_MAX_NAME - 9]}_{digest[:8]}"
    return safe


# ---------------------------------------------------------------------------
# Grant store (durable, single-use)
# ---------------------------------------------------------------------------

_LOCK_POLL_SECONDS = 0.01
_LOCK_WAIT_SECONDS = 5.0
_LOCK_STALE_SECONDS = 30.0


class GrantStore:
    """Durable single-use grant store (atomic writes + O_EXCL consume fence).

    Grants are one JSON file each under ``grants_dir``. ``consume`` performs a
    locked read-modify-write and marks the grant consumed BEFORE returning it,
    so single-use holds across processes; there is deliberately NO refund path.
    """

    def __init__(self, grants_dir: str, clock: Callable[[], float] | None = None):
        self.grants_dir = grants_dir
        self.clock = clock if clock is not None else time.time

    # -- paths --------------------------------------------------------------

    def _grant_path(self, grant_id: str) -> str:
        return os.path.join(self.grants_dir, _safe_name(grant_id) + ".json")

    def _lock_path(self, grant_id: str) -> str:
        return os.path.join(self.grants_dir, _safe_name(grant_id) + ".lock")

    # -- reads --------------------------------------------------------------

    def _read(self, grant_id: str) -> Grant | None:
        try:
            with open(self._grant_path(grant_id), encoding="utf-8") as f:
                return Grant.from_dict(json.load(f))
        except (OSError, ValueError, GrantError, TypeError):
            return None

    def get(self, grant_id: str) -> Grant | None:
        return self._read(grant_id)

    def list_for_incident(self, incident_id: str) -> list[Grant]:
        out: list[Grant] = []
        try:
            names = os.listdir(self.grants_dir)
        except OSError:
            return out
        for name in names:
            if not name.endswith(".json"):
                continue
            try:
                grant = Grant.from_dict(
                    json.load(open(os.path.join(self.grants_dir, name), encoding="utf-8"))
                )
            except (OSError, ValueError, GrantError, TypeError):
                continue
            if grant.incident_id == incident_id:
                out.append(grant)
        return sorted(out, key=lambda g: g.issued_at)

    # -- mutations ----------------------------------------------------------

    def issue(
        self,
        *,
        incident_id: str,
        scope: str,
        session_id: str,
        client_id: str,
        pid: int,
        start_time: float,
        issuer: str,
        ttl_seconds: int,
    ) -> Grant:
        """Issue a new scoped single-use grant. The issuer's store GENERATES the
        grant id and the nonce; neither can be supplied (or read from an
        incident record) by the caller."""
        if scope not in GRANT_SCOPES:
            raise GrantScopeError(
                f"grant scope {scope!r} is not known; must be one of {sorted(GRANT_SCOPES)}"
            )
        for field, value in (
            ("incident_id", incident_id),
            ("session_id", session_id),
            ("client_id", client_id),
            ("issuer", issuer),
        ):
            if not isinstance(value, str) or not value.strip():
                raise GrantError(f"grant {field!r} must be a non-empty string")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            raise GrantError("grant 'pid' must be a positive int")
        if not isinstance(start_time, (int, float)) or isinstance(start_time, bool) or start_time <= 0:
            raise GrantError("grant 'start_time' must be a positive number (verified process start)")
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            raise GrantError("grant 'ttl_seconds' must be a positive int")

        now = self.clock()
        grant = Grant(
            grant_id=uuid.uuid4().hex,
            incident_id=incident_id,
            scope=scope,
            session_id=session_id,
            client_id=client_id,
            pid=int(pid),
            start_time=float(start_time),
            issuer=issuer,
            nonce=uuid.uuid4().hex,  # issuer-generated
            issued_at=now,
            expires_at=now + ttl_seconds,
        )
        self._write(grant)
        return grant

    def consume(
        self,
        grant_id: str,
        nonce: str,
        *,
        session_id: str,
        client_id: str,
        pid: int,
        start_time: float,
        scope: str,
    ) -> Grant:
        """Durably consume the grant BEFORE one authorized attempt.

        Single-use, TTL-bounded, nonce-bound, identity-bound, scope-bound, and
        one-way. The PRESENTED identity (session/client/pid/start-time) and
        scope must match the grant exactly — a grant cannot be used for a
        different target. Returns the (now consumed) grant; raises
        :class:`GrantError` subclasses otherwise. There is NO refund: a failed
        resume does not un-consume.

        Expiry is exact and INCLUSIVE of the boundary: a grant is expired at
        ``now >= expires_at`` (equivalently ``now >= issued_at + ttl``), so the
        boundary instant itself is expired, not only anything past it.
        """
        now = self.clock()
        with self._lock(grant_id):
            grant = self._read(grant_id)
            if grant is None:
                raise GrantNotFoundError(f"no grant {grant_id!r}")
            if grant.revoked:
                raise GrantRevokedError(f"grant {grant_id!r} was revoked")
            if grant.consumed:
                raise GrantAlreadyConsumedError(
                    f"grant {grant_id!r} is single-use and already consumed"
                )
            if now >= grant.expires_at:
                raise GrantExpiredError(
                    f"grant {grant_id!r} expired at {grant.expires_at!r} (now {now!r})"
                )
            if not secrets.compare_digest(nonce or "", grant.nonce or ""):
                raise GrantNonceMismatchError(f"grant {grant_id!r} nonce mismatch")
            if scope != grant.scope:
                raise GrantScopeMismatchError(
                    f"grant {grant_id!r} is scoped to {grant.scope!r}, not {scope!r}"
                )
            if (
                session_id != grant.session_id
                or client_id != grant.client_id
                or pid != grant.pid
                or start_time != grant.start_time
            ):
                raise GrantIdentityMismatchError(
                    f"grant {grant_id!r} is bound to session {grant.session_id!r}/"
                    f"client {grant.client_id!r}/pid {grant.pid}/"
                    f"start {grant.start_time!r}; presented "
                    f"{session_id!r}/{client_id!r}/{pid!r}/{start_time!r}"
                )
            updated = replace(grant, consumed=True, consumed_at=now)
            self._write(updated)
            return updated

    def revoke(self, grant_id: str, *, operator: str) -> Grant:
        if not isinstance(operator, str) or not operator.strip():
            raise GrantError("grant revoke requires a non-empty operator marker")
        with self._lock(grant_id):
            grant = self._read(grant_id)
            if grant is None:
                raise GrantNotFoundError(f"no grant {grant_id!r}")
            if grant.revoked:
                return grant
            updated = replace(grant, revoked=True, revoked_at=self.clock())
            self._write(updated)
            return updated

    # -- persistence --------------------------------------------------------

    def _write(self, grant: Grant) -> None:
        data = (json.dumps(grant.to_dict(), sort_keys=True) + "\n").encode("utf-8")
        self._atomic_write(self._grant_path(grant.grant_id), data)

    def _atomic_write(self, path: str, data: bytes) -> None:
        dirpath = os.path.dirname(path) or "."
        os.makedirs(dirpath, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=dirpath)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            self._fsync_dir(dirpath)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @staticmethod
    def _fsync_dir(dirpath: str) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            dfd = os.open(dirpath, flags)
        except OSError:
            return
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    # -- locking ------------------------------------------------------------

    @contextmanager
    def _lock(self, grant_id: str):
        os.makedirs(self.grants_dir, exist_ok=True)
        lock_path = self._lock_path(grant_id)
        deadline = time.monotonic() + _LOCK_WAIT_SECONDS
        fd = None
        while fd is None:
            try:
                fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            except FileExistsError:
                try:
                    stale = time.time() - os.path.getmtime(lock_path) > _LOCK_STALE_SECONDS
                except OSError:
                    stale = True
                if stale:
                    try:
                        os.unlink(lock_path)
                    except OSError:
                        pass
                    continue
                if time.monotonic() >= deadline:
                    raise GrantError(f"grant lock unavailable: {lock_path}")
                time.sleep(_LOCK_POLL_SECONDS)
        try:
            yield
        finally:
            os.close(fd)
            try:
                os.unlink(lock_path)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Notification policy (operator opt-in, local-only default)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NotificationDecision:
    """The policy resolution for one (incident, channel) delivery.

    ``status`` is ``local_only`` (no outbound; the channel is not opted in) or
    ``opted_in`` (the channel is explicitly enabled / is the local sink).
    ``suppression_reason`` is set whenever a delivery is NOT accepted, so a
    suppressed delivery is visible, never silent.
    """

    incident_id: str
    channel: str
    status: str
    suppression_reason: str = ""


class NotificationPolicy:
    """Operator-owned notification opt-in.

    Default (no opt-in) => LOCAL-ONLY: outbound channels resolve ``local_only``
    and no outbound delivery is accepted. An explicitly opted-in channel allows
    at most ONE accepted delivery per incident+channel (durable dedupe via
    ``O_CREAT|O_EXCL``), and :meth:`read_receipt` provides an exact
    delivery-receipt readback. A daemon starting does NOT enable any channel.
    """

    def __init__(
        self,
        opt_in_channels: frozenset = frozenset(),
        receipts_dir: str | None = None,
    ):
        self.opt_in_channels = frozenset(opt_in_channels)
        self.receipts_dir = receipts_dir

    def is_enabled(self, channel: str) -> bool:
        return channel == CHANNEL_LOCAL or channel in self.opt_in_channels

    def resolve(self, incident_id: str, channel: str) -> NotificationDecision:
        if self.is_enabled(channel):
            return NotificationDecision(incident_id, channel, status="opted_in")
        return NotificationDecision(
            incident_id,
            channel,
            status="local_only",
            suppression_reason=(
                f"channel {channel!r} requires explicit operator opt-in; "
                f"local-only (no outbound)"
            ),
        )

    def _receipt_path(self, incident_id: str, channel: str) -> str:
        return os.path.join(
            self.receipts_dir or "", _safe_name(incident_id) + "." + _safe_name(channel) + ".receipt"
        )

    def accept_delivery(self, incident_id: str, channel: str, receipt: str) -> bool:
        """Accept ONE delivery per incident+channel (durable dedupe).

        Returns True only for the first accepted delivery; a second attempt is
        suppressed (returns False) and never overwrites the first receipt.
        A non-enabled (not opted-in) channel is never accepted.
        """
        if not self.is_enabled(channel):
            return False
        if self.receipts_dir is None:
            return False
        os.makedirs(self.receipts_dir, exist_ok=True)
        path = self._receipt_path(incident_id, channel)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            return False  # suppressed: already delivered
        with os.fdopen(fd, "w") as f:
            f.write(receipt)
            f.flush()
            os.fsync(f.fileno())
        return True

    def read_receipt(self, incident_id: str, channel: str) -> str:
        """Exact readback of the accepted delivery receipt (empty if none)."""
        if self.receipts_dir is None:
            return ""
        try:
            with open(self._receipt_path(incident_id, channel), encoding="utf-8") as f:
                return f.read()
        except OSError:
            return ""


__all__ = [
    "GRANT_SCOPE_SESSION_STOP_RESUME",
    "GRANT_SCOPES",
    "CHANNEL_LOCAL",
    "GrantError",
    "GrantNotFoundError",
    "GrantScopeError",
    "GrantExpiredError",
    "GrantAlreadyConsumedError",
    "GrantRevokedError",
    "GrantNonceMismatchError",
    "GrantIdentityMismatchError",
    "GrantScopeMismatchError",
    "Grant",
    "GrantStore",
    "NotificationDecision",
    "NotificationPolicy",
]
