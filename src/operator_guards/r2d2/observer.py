"""Scoped observation + agent escalation (plan §6, Task 12).

R2-D2's observer consumes BOUNDED capability records — post-tool error/status,
client/session start/end/reset, and heartbeat — and classifies them into the
documented predicate set below. It SCANS ONLY registered live clients
(``<root>/clients/``) and current incidents (the durable
:class:`~operator_guards.r2d2.store.IncidentStore`) — NEVER session
transcripts or the MCP cache (the naive 1 Hz sweep over thousands of log dirs
is unbuildable, and this observer does not attempt it).

Supported LINUX predicates (``takeover_without_send`` is the ONE Mac-only
predicate and is deliberately NOT implemented here):

=============================  ==================================================  ==========================
predicate                     detection (Linux-only)                               classification
=============================  ==================================================  ==========================
``client_process_alive``      ``/proc/<pid>/stat`` start-time match               (c) stale/dead client
``heartbeat_fresh``           ``<root>/heartbeat`` mtime/ts within 60 s           supervisor liveness
``client_recent``             client record ``last_seen`` within threshold        quiet-but-alive (not broken)
``reconnect_in_progress``     client ``status == "reconnecting"`` within window   (a) do NOT summon the daemon
``transport_drop``            ``error_type`` in ``TRANSIENT_ERROR_TYPES`` + reg.  (b) recoverable in-session
``capability_registered``     capability in client's ``capabilities`` set         (d) lost registered capability
``permission_block``          ``error_type`` in ``PERMISSION_ERROR_TYPES``        (e) diagnosis/escalation only
``policy_denial``             ``post_tool_status`` denied/blocked                 (f) bounded escalation
``takeover_without_send``     UNSUPPORTED (no real takeover/send observer yet)    unsupported
=============================  ==================================================  ==========================

Every AUTO-created incident carries a CONCRETE observation (a symptom that
names what was observed) and a deterministic DEDUPE key; the durable store's
id/key idempotency plus in-memory rate limiters (recovery backoff, denial
window) bound noise so repeated denied retries do NOT flood the store.

Supervisor absence or a heartbeat stale > 60 s yields an IMMEDIATE local alert
(an ``LocalAlert`` effect written to the alert sink) — never a six-minute wait
for a daemon that is not there. The alert is IDEMPOTENT: repeated polls for the
same condition within ``ALERT_COOLDOWN_SECONDS`` emit one alert; a fresh
heartbeat clears the state and a NEW distinct condition alerts again.

The observation log (``<root>/observations.jsonl``) is BOUNDED: it is rotated
once it exceeds ``OBSERVATIONS_MAX_BYTES`` (prior segment renamed to
``observations.1.jsonl``) and is read by TAILING, never slurped whole.

Reconnect state (``ClientRecord.status == \"reconnecting\"`` and
``reconnect_started``) is EXTERNALLY POPULATED: the plugin's hooks observe
transient tool errors but have no real \"the client is reconnecting\" signal, so
the plugin never fabricates it — a future transport/session manager that
actually tracks reconnect state must set these fields on the client record. An
elapsed-window reconnecting client is classified ``stale_client`` (stuck
reconnect), never ``CLASS_NONE``.

A stale-client incident is re-raisable: once the prior incident reaches a
terminal phase (resolved/escalated), a genuine recurrence raises a NEW incident
under a recurrence-suffixed dedupe key (``stale-client:<id>:rN``).
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from operator_guards.r2d2.claims import proc_start_time
from operator_guards.r2d2.schema import (
    PHASE_ESCALATED,
    PHASE_OPEN,
    PHASE_RESOLVED,
    SEVERITY_BLOCKED,
    SEVERITY_MECHANICAL,
    SYMPTOM_MAX_CHARS,
)
from operator_guards.r2d2.store import DEFAULT_STATE_ROOT, IncidentStore

# ---------------------------------------------------------------------------
# Bounded thresholds
# ---------------------------------------------------------------------------

# Supervisor absence/stale threshold: heartbeat older than this -> immediate
# local alert (the Mac handoff's 60 s pre-flight, applied here on Linux).
SUPERVISOR_STALE_SECONDS = 60.0

# A registered client whose own last_seen exceeds this is stale/dead.
CLIENT_STALE_SECONDS = 600.0

# Native reconnect window: a client in "reconnecting" within this window is an
# in-progress native reconnect (do NOT summon the daemon).
RECONNECT_WINDOW_SECONDS = 30.0

# Session-local recovery backoff: at most ONE recovery request per
# (client, session) per window (respects native backoff).
RECOVERY_BACKOFF_SECONDS = 60.0

# Repeated policy-denial bounding: escalate only after this many denials in a
# window; the incident is then deduped by key.
DENIAL_WINDOW_SECONDS = 300.0
MAX_DENIALS_BEFORE_ESCALATE = 3

# Bounded record fields.
OBSERVATION_DETAIL_MAX_CHARS = 500
CLIENT_CAPABILITIES_MAX = 50

# Minimum interval between heartbeat writes (plugin "periodic" heartbeat).
HEARTBEAT_MIN_INTERVAL_SECONDS = 15.0

# Bounded observation-log cap: append_observation rotates the log once it
# exceeds this many bytes (the prior segment is renamed to observations.1.jsonl),
# so total on-disk size stays at ~2x the cap.
OBSERVATIONS_MAX_BYTES = 2 * 1024 * 1024

# Supervisor alert cooldown: repeated alerts for the SAME condition within this
# window collapse to ONE (mirrors RECOVERY_BACKOFF_SECONDS — no pager storm).
ALERT_COOLDOWN_SECONDS = RECOVERY_BACKOFF_SECONDS

# Bounded in-memory limiters: expired entries are swept (keyed to their window)
# and the dicts are LRU-capped at this many entries.
LIMITER_MAX_ENTRIES = 10_000

# ---------------------------------------------------------------------------
# Predicate token sets (Linux-supported, closed; no Mac Teams/Claude names)
# ---------------------------------------------------------------------------

TRANSIENT_ERROR_TYPES = frozenset(
    {
        "connection_reset",
        "connection_refused",
        "connection_aborted",
        "connection_closed",
        "transport_closed",
        "transport_drop",
        "mcp_disconnected",
        "timeout",
        "eof",
        "broken_pipe",
        "network_unreachable",
        "host_unreachable",
    }
)

PERMISSION_ERROR_TYPES = frozenset(
    {"permission_denied", "access_denied", "forbidden", "not_authorized", "eacces"}
)

CAPABILITY_LOSS_ERROR_TYPES = frozenset(
    {"capability_missing", "tool_not_registered", "mcp_deregistered", "unknown_tool"}
)

# Predicates this observer does NOT support (never fabricated). ``takeover_without_send``
# needs a real takeover/send observer (the Mac desktop pane-move signal); until one
# exists it is reported UNSUPPORTED.
UNSUPPORTED_PREDICATES = frozenset({"takeover_without_send"})

# ---------------------------------------------------------------------------
# Classification kinds
# ---------------------------------------------------------------------------

CLASS_RECONNECT_IN_PROGRESS = "reconnect_in_progress"
CLASS_TRANSPORT_DROP = "transport_drop"
CLASS_STALE_CLIENT = "stale_client"
CLASS_LOST_CAPABILITY = "lost_capability"
CLASS_PERMISSION_BLOCK = "permission_block"
CLASS_POLICY_DENIAL = "policy_denial"
CLASS_UNSUPPORTED = "unsupported"
CLASS_NONE = "none"

OBSERVATION_KINDS = frozenset(
    {
        "post_tool_error",
        "post_tool_status",
        "client_start",
        "client_end",
        "session_start",
        "session_end",
        "session_reset",
        "heartbeat",
    }
)

CLIENT_STATUS_REGISTERED = "registered"
CLIENT_STATUS_RECONNECTING = "reconnecting"
CLIENT_STATUS_ENDED = "ended"
CLIENT_STATUSES = frozenset(
    {CLIENT_STATUS_REGISTERED, CLIENT_STATUS_RECONNECTING, CLIENT_STATUS_ENDED}
)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Observation:
    """One bounded capability observation (closed kinds, capped detail)."""

    kind: str
    client_id: str = ""
    session_id: str = ""
    tool_name: str = ""
    error_type: str = ""
    status: str = ""
    capability: str = ""
    detail: str = ""
    rule_id: str = ""
    predicate: str = ""
    ts: float = 0.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "detail", (self.detail or "")[:OBSERVATION_DETAIL_MAX_CHARS])
        if self.kind not in OBSERVATION_KINDS:
            raise ValueError(
                f"observation kind {self.kind!r} is not a known kind; "
                f"must be one of {sorted(OBSERVATION_KINDS)}"
            )

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "client_id": self.client_id,
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "error_type": self.error_type,
            "status": self.status,
            "capability": self.capability,
            "detail": self.detail,
            "rule_id": self.rule_id,
            "predicate": self.predicate,
            "ts": self.ts,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Observation":
        return cls(
            kind=str(d.get("kind", "")),
            client_id=str(d.get("client_id", "")),
            session_id=str(d.get("session_id", "")),
            tool_name=str(d.get("tool_name", "")),
            error_type=str(d.get("error_type", "")),
            status=str(d.get("status", "")),
            capability=str(d.get("capability", "")),
            detail=str(d.get("detail", "")),
            rule_id=str(d.get("rule_id", "")),
            predicate=str(d.get("predicate", "")),
            ts=float(d.get("ts", 0.0) or 0.0),
        )


@dataclass(frozen=True)
class ClientRecord:
    """A bounded registered-live-client record (scoped scan target)."""

    client_id: str
    status: str = CLIENT_STATUS_REGISTERED
    capabilities: frozenset = frozenset()
    pid: int = 0
    pid_start_time: float = 0.0
    last_seen: float = 0.0
    reconnect_started: float = 0.0

    def __post_init__(self) -> None:
        if self.status not in CLIENT_STATUSES:
            raise ValueError(
                f"client status {self.status!r} is not a known status; "
                f"must be one of {sorted(CLIENT_STATUSES)}"
            )

    def to_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "status": self.status,
            "capabilities": sorted(self.capabilities),
            "pid": self.pid,
            "pid_start_time": self.pid_start_time,
            "last_seen": self.last_seen,
            "reconnect_started": self.reconnect_started,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ClientRecord":
        caps = d.get("capabilities") or []
        if isinstance(caps, str):
            caps = [caps]
        return cls(
            client_id=str(d.get("client_id", "")),
            status=str(d.get("status", CLIENT_STATUS_REGISTERED)),
            capabilities=frozenset(sorted(str(c) for c in caps)[:CLIENT_CAPABILITIES_MAX]),
            pid=int(d.get("pid", 0) or 0),
            pid_start_time=float(d.get("pid_start_time", 0.0) or 0.0),
            last_seen=float(d.get("last_seen", 0.0) or 0.0),
            reconnect_started=float(d.get("reconnect_started", 0.0) or 0.0),
        )


# ---------------------------------------------------------------------------
# Classification (pure — no I/O)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Classification:
    kind: str
    reason: str = ""
    unsupported: bool = False


def classify(
    observation: Observation, client: ClientRecord | None, now: float
) -> Classification:
    """Pure: classify one bounded observation against a (possibly absent) client.

    ``client`` is the registered-live-client state (or ``None`` when the client
    is not registered). ``now`` is the current time. Returns a
    :class:`Classification` naming one of the documented predicates.
    """
    if observation.predicate in UNSUPPORTED_PREDICATES:
        return Classification(
            CLASS_UNSUPPORTED,
            unsupported=True,
            reason=(
                f"predicate {observation.predicate!r} is UNSUPPORTED: no real "
                f"takeover/send observer exists yet"
            ),
        )

    kind = observation.kind
    if kind == "post_tool_error":
        et = (observation.error_type or "").lower()
        cap = observation.capability
        if et in CAPABILITY_LOSS_ERROR_TYPES:
            if client is not None and cap and cap in client.capabilities:
                return Classification(
                    CLASS_LOST_CAPABILITY,
                    reason=f"registered capability {cap!r} lost ({et})",
                )
            return Classification(CLASS_NONE, reason=f"unregistered capability signal {et!r}")
        if et in PERMISSION_ERROR_TYPES:
            return Classification(
                CLASS_PERMISSION_BLOCK,
                reason=f"explicit permission block ({et})",
            )
        if et in TRANSIENT_ERROR_TYPES:
            if client is not None and client.status == CLIENT_STATUS_RECONNECTING:
                if now - client.reconnect_started < RECONNECT_WINDOW_SECONDS:
                    return Classification(
                        CLASS_RECONNECT_IN_PROGRESS,
                        reason="native reconnect in progress (do not summon)",
                    )
                # Reconnect window elapsed: the client is STUCK reconnecting.
                # Escalate as stale/dead rather than CLASS_NONE (which would
                # leave it unclassifiable and never escalated).
                return Classification(
                    CLASS_STALE_CLIENT,
                    reason=(
                        f"stuck reconnecting past the "
                        f"{RECONNECT_WINDOW_SECONDS:.0f}s window"
                    ),
                )
            if client is not None and client.status == CLIENT_STATUS_REGISTERED:
                return Classification(
                    CLASS_TRANSPORT_DROP,
                    reason=f"ordinary transport drop ({et}), recoverable in-session",
                )
        return Classification(CLASS_NONE, reason=f"unclassified error {et!r}")

    if kind == "post_tool_status":
        if observation.status in ("denied", "blocked"):
            return Classification(
                CLASS_POLICY_DENIAL,
                reason=f"policy {observation.status} on {observation.tool_name!r}",
            )
        return Classification(CLASS_NONE)

    # client/session lifecycle and heartbeat records are informative; they do
    # not themselves trigger escalation (staleness is assessed in the scan).
    return Classification(CLASS_NONE)


# ---------------------------------------------------------------------------
# Effects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Effect:
    """Base effect emitted by the observer."""


@dataclass(frozen=True)
class NoEffect(Effect):
    kind: str = "none"


@dataclass(frozen=True)
class LocalAlert(Effect):
    message: str
    kind: str = "local_alert"


@dataclass(frozen=True)
class RaiseIncident(Effect):
    incident_id: str
    dedupe_key: str
    severity: str
    symptom: str
    kind: str = "raise_incident"


@dataclass(frozen=True)
class RecoveryRequest(Effect):
    client_id: str
    session_id: str
    detail: str
    kind: str = "recovery_request"


@dataclass(frozen=True)
class UnsupportedEffect(Effect):
    predicate: str
    reason: str
    kind: str = "unsupported"


# ---------------------------------------------------------------------------
# File record helpers (shared by the observer and the r2d2 Hermes plugin)
# ---------------------------------------------------------------------------

_FILENAME_SAFE = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)
# Cap basenames so a pathological client_id cannot overflow NAME_MAX
# (mirrors store._MAX_NAME).
_MAX_NAME = 120


def state_root_for(home: str) -> str:
    """The r2d2 state dir for a Hermes profile home (``<home>/r2d2``)."""
    return os.path.join(home, "r2d2")


def _safe_component(value: str) -> str:
    safe = "".join(c if c in _FILENAME_SAFE else "_" for c in value)
    if safe != value or not safe or safe in (".", ".."):
        safe = "s_" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
    if len(safe) > _MAX_NAME:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        safe = f"{safe[:_MAX_NAME - 9]}_{digest[:8]}"
    return safe


def _atomic_write(path: str, data: bytes) -> None:
    dirpath = os.path.dirname(path) or "."
    os.makedirs(dirpath, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=dirpath)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _fsync_dir(dirpath: str) -> None:
    """Directory fsync (strict, mirrors store.py) for append-log durability."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    dfd = os.open(dirpath, flags)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def append_observation(root: str, observation: Observation) -> None:
    """Append one bounded observation line to ``<root>/observations.jsonl``.

    BOUNDED: once the log exceeds :data:`OBSERVATIONS_MAX_BYTES` it is rotated
    (the current segment is renamed to ``observations.1.jsonl`` and a fresh one
    is started), so total on-disk size stays at ~2x the cap. The append is a
    single O_APPEND write + fsync (atomic per record, no whole-file rewrite),
    and the parent dir is fsynced on first creation / rotation — consistent
    with store.py's durability.
    """
    if not os.path.isdir(root):
        os.makedirs(root, exist_ok=True)
    line = json.dumps(observation.to_dict(), ensure_ascii=False, sort_keys=True) + "\n"
    data = line.encode("utf-8")
    path = os.path.join(root, "observations.jsonl")
    existed = os.path.exists(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        if os.fstat(fd).st_size + len(data) > OBSERVATIONS_MAX_BYTES:
            os.close(fd)
            fd = -1
            os.replace(path, os.path.join(root, "observations.1.jsonl"))
            existed = False  # a fresh file is created below -> fsync the dir
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        if fd >= 0:
            os.close(fd)
    if not existed:
        _fsync_dir(root)


def _tail_records(path: str, limit: int) -> list[bytes]:
    """Return up to ``limit`` trailing lines (bytes) by seeking from the end.

    Never slurps the whole file: it reads backwards in bounded chunks until it
    has at least ``limit`` complete lines (or reaches the start).
    """
    if limit <= 0:
        return []
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size == 0:
                return []
            chunk = 8192
            buf = bytearray()
            pos = size
            while pos > 0:
                read_size = min(chunk, pos)
                pos -= read_size
                f.seek(pos)
                buf[:0] = f.read(read_size)
                if buf.count(b"\n") >= limit + 1:
                    break
            raw_lines = bytes(buf).split(b"\n")
            if pos == 0:
                if raw_lines and raw_lines[-1] == b"":
                    raw_lines.pop()
            else:
                # buf starts mid-line: drop the partial leading fragment
                raw_lines = raw_lines[1:]
                if raw_lines and raw_lines[-1] == b"":
                    raw_lines.pop()
            return raw_lines[-limit:]
    except OSError:
        return []


def iter_observations(root: str, limit: int = 1000) -> list[Observation]:
    """Read at most ``limit`` observation records (bounded, newest-last).

    TAILS the log (seeks to the last ``limit`` records) instead of reading the
    whole file, so it is O(limit), not O(file size).
    """
    path = os.path.join(root, "observations.jsonl")
    out: list[Observation] = []
    for line in _tail_records(path, limit):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(Observation.from_dict(json.loads(line)))
        except (ValueError, TypeError):
            continue
    return out


def write_client_record(root: str, client: ClientRecord) -> None:
    """Atomically write a bounded client record to ``<root>/clients/<id>.json``."""
    dirpath = os.path.join(root, "clients")
    os.makedirs(dirpath, exist_ok=True)
    data = (json.dumps(client.to_dict(), ensure_ascii=False, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    _atomic_write(os.path.join(dirpath, _safe_component(client.client_id) + ".json"), data)


def load_client_record(root: str, client_id: str) -> ClientRecord | None:
    """Read one client record, or ``None`` if absent/unparseable."""
    path = os.path.join(root, "clients", _safe_component(client_id) + ".json")
    try:
        with open(path, encoding="utf-8") as f:
            return ClientRecord.from_dict(json.load(f))
    except (OSError, ValueError, TypeError):
        return None


def list_client_records(root: str) -> dict[str, ClientRecord]:
    """Scan ONLY the ``clients/`` dir (never transcripts or the MCP cache)."""
    clients_dir = os.path.join(root, "clients")
    out: dict[str, ClientRecord] = {}
    try:
        names = os.listdir(clients_dir)
    except OSError:
        return out
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(clients_dir, name), encoding="utf-8") as f:
                client = ClientRecord.from_dict(json.load(f))
        except (OSError, ValueError, TypeError):
            continue
        out[client.client_id] = client
    return out


def read_heartbeat_file(root: str) -> float | None:
    """Return the heartbeat timestamp, or ``None`` if absent/unreadable."""
    path = os.path.join(root, "heartbeat")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        ts = data.get("ts") if isinstance(data, dict) else None
        return float(ts) if ts is not None else None
    except (OSError, ValueError, TypeError):
        return None


def write_heartbeat_file(root: str, ts: float | None = None, host: str | None = None) -> None:
    """Atomically write ``<root>/heartbeat`` (supervisor liveness).

    The timestamp is MONOTONIC by default (``time.monotonic``), so staleness is
    measured against a clock that cannot jump (matching the lock clock). Pass an
    explicit ``ts`` to inject one.
    """
    os.makedirs(root, exist_ok=True)
    payload: dict[str, Any] = {"ts": float(ts if ts is not None else time.monotonic())}
    if host is None:
        host = socket.gethostname()
    payload["host"] = host
    data = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write(os.path.join(root, "heartbeat"), data)


def _incident_id(dedupe_key: str) -> str:
    return "auto-" + hashlib.sha256(dedupe_key.encode("utf-8")).hexdigest()[:24]


# ---------------------------------------------------------------------------
# The observer
# ---------------------------------------------------------------------------


class Observer:
    """Scoped observation consumer: classify + bounded escalation + liveness."""

    def __init__(
        self,
        root: str = DEFAULT_STATE_ROOT,
        *,
        store: IncidentStore | None = None,
        clock: Callable[[], float] | None = None,
        proc_start: Callable[[int], float | None] | None = None,
        alert_writer: Callable[[str], None] | None = None,
    ):
        self.root = root
        self.store = store if store is not None else IncidentStore(root)
        self.clock = clock if clock is not None else time.monotonic
        self._proc_start_time = proc_start if proc_start is not None else proc_start_time
        self._alert_writer = alert_writer
        # In-memory rate limiters (bounded noise, on top of store id/key dedupe).
        self._recovery_last: dict[tuple[str, str], float] = {}
        self._denials: dict[str, dict] = {}
        # Supervisor alert cooldown: (condition, last_alert_ts), one alert per
        # distinct condition per ALERT_COOLDOWN_SECONDS window.
        self._supervisor_alert_state: tuple[str, float] | None = None

    # -- scoped reads -------------------------------------------------------

    def load_client(self, client_id: str) -> ClientRecord | None:
        return load_client_record(self.root, client_id)

    def list_clients(self) -> dict[str, ClientRecord]:
        return list_client_records(self.root)

    def read_heartbeat(self) -> float | None:
        return read_heartbeat_file(self.root)

    def write_heartbeat(self, ts: float | None = None) -> None:
        write_heartbeat_file(self.root, ts=ts)

    def write_client_record(self, client: ClientRecord) -> None:
        write_client_record(self.root, client)

    # -- liveness checks ----------------------------------------------------

    def check_supervisor(self) -> LocalAlert | None:
        """IMMEDIATE local alert when the heartbeat is absent or stale > 60 s.

        IDEMPOTENT: repeated polls for the SAME condition within
        ``ALERT_COOLDOWN_SECONDS`` emit ONE alert (no pager storm). A fresh
        heartbeat clears the cooldown state, and a NEW distinct condition
        (absent -> stale) can alert again even within the window.
        """
        now = self.clock()
        ts = self.read_heartbeat()
        if ts is None:
            condition = "absent"
            message = (
                "r2d2 supervisor heartbeat ABSENT — local alert (no daemon to wait for)"
            )
        elif now - ts > SUPERVISOR_STALE_SECONDS:
            condition = "stale"
            message = (
                f"r2d2 supervisor heartbeat STALE "
                f"({now - ts:.0f}s > {SUPERVISOR_STALE_SECONDS:.0f}s) — local alert"
            )
        else:
            self._supervisor_alert_state = None  # fresh: clear cooldown
            return None
        last = self._supervisor_alert_state
        if last is not None and last[0] == condition and now - last[1] < ALERT_COOLDOWN_SECONDS:
            return None  # within cooldown for the SAME condition: already alerted
        self._supervisor_alert_state = (condition, now)
        if self._alert_writer is not None:
            try:
                self._alert_writer(message)
            except Exception:  # noqa: BLE001 - alert delivery must not raise
                pass
        return LocalAlert(message=message)

    def _client_dead(self, client: ClientRecord) -> bool:
        """Whether the client's process is provably dead (Linux /proc)."""
        if client.pid <= 0 or client.pid_start_time <= 0:
            return False
        st = self._proc_start_time(client.pid)
        return st is None or st != client.pid_start_time

    def check_clients(self) -> list[Effect]:
        """Scan ONLY registered live clients; escalate stale/dead clients.

        A quiet session (no recent tool activity) whose client is still fresh
        and whose process is alive is NOT broken — only a provably-dead process
        (Linux ``/proc``) or a client past ``CLIENT_STALE_SECONDS`` escalates.
        """
        now = self.clock()
        effects: list[Effect] = []
        for client in self.list_clients().values():
            if client.status == CLIENT_STATUS_ENDED:
                continue
            dead = self._client_dead(client)
            stale = bool(client.last_seen) and (now - client.last_seen) > CLIENT_STALE_SECONDS
            if dead or stale:
                detail = "process dead (/proc)" if dead else "client heartbeat stale"
                obs = Observation(kind="heartbeat", client_id=client.client_id, detail=detail)
                effects.append(self._raise_kind(CLASS_STALE_CLIENT, obs))
        return effects

    # -- observation consumption -------------------------------------------

    def consume(self, observation: Observation) -> list[Effect]:
        """Classify one observation and apply bounded escalation.

        Self-sufficient: it consults liveness directly, so a provably dead
        registered client escalates here regardless of whether ``check_clients``
        has run (no hidden call-order coupling). Returns the effects applied
        (raise/recovery/alert/unsupported), and applies ``RaiseIncident`` to the
        durable store (idempotent by id/key).
        """
        now = self.clock()
        client = self.load_client(observation.client_id) if observation.client_id else None
        cls = classify(observation, client, now)

        if cls.kind == CLASS_RECONNECT_IN_PROGRESS:
            return []  # native reconnect in progress: do NOT summon the daemon
        if cls.kind == CLASS_STALE_CLIENT:
            # stuck reconnect (or any stale classification) escalates directly
            obs = Observation(
                kind="heartbeat",
                client_id=observation.client_id,
                session_id=observation.session_id,
                detail=cls.reason or "stale/dead client",
            )
            return [self._raise_kind(CLASS_STALE_CLIENT, obs)]
        if cls.kind == CLASS_TRANSPORT_DROP:
            if client is not None and self._client_dead(client):
                # provably dead client escalates regardless of call order
                obs = Observation(kind="heartbeat", client_id=client.client_id, detail="process dead (/proc)")
                return [self._raise_kind(CLASS_STALE_CLIENT, obs)]
            eff = self._recovery(observation)
            return [eff] if eff is not None else []
        if cls.kind == CLASS_LOST_CAPABILITY:
            return [self._raise_kind(CLASS_LOST_CAPABILITY, observation)]
        if cls.kind == CLASS_PERMISSION_BLOCK:
            return [self._raise_kind(CLASS_PERMISSION_BLOCK, observation)]
        if cls.kind == CLASS_POLICY_DENIAL:
            eff = self._policy_denial(observation)
            return [eff] if eff is not None else []
        if cls.kind == CLASS_UNSUPPORTED:
            return [UnsupportedEffect(predicate=observation.predicate, reason=cls.reason)]
        return []

    # -- bounded escalation helpers ----------------------------------------

    def _recovery(self, observation: Observation) -> RecoveryRequest | None:
        now = self.clock()
        key = (observation.client_id, observation.session_id)
        last = self._recovery_last.get(key)
        if last is not None and now - last < RECOVERY_BACKOFF_SECONDS:
            return None  # native backoff: one bounded session-local recovery request
        self._recovery_last[key] = now
        self._bound_limiters(now)
        return RecoveryRequest(
            client_id=observation.client_id,
            session_id=observation.session_id,
            detail=observation.detail or observation.error_type,
        )

    def _policy_denial(self, observation: Observation) -> RaiseIncident | None:
        now = self.clock()
        key = f"{observation.session_id or ''}:{observation.rule_id or observation.tool_name or ''}"
        state = self._denials.get(key)
        if state is None or now - state["window_start"] > DENIAL_WINDOW_SECONDS:
            state = {"window_start": now, "count": 0, "raised": False}
            self._denials[key] = state
            self._bound_limiters(now)
        state["count"] += 1
        if state["raised"]:
            return None
        if state["count"] < MAX_DENIALS_BEFORE_ESCALATE:
            return None
        state["raised"] = True
        return self._raise_kind(CLASS_POLICY_DENIAL, observation)

    def _raise_kind(self, kind: str, observation: Observation) -> RaiseIncident:
        record = self._build_incident(kind, observation)
        incident = self.store.raise_incident(record)
        return RaiseIncident(
            incident_id=incident.id,
            dedupe_key=incident.dedupe_key,
            severity=incident.severity,
            symptom=incident.symptom,
        )

    # -- bounded in-memory limiters (expiry + LRU cap) ----------------------

    def _bound_limiters(self, now: float) -> None:
        """Sweep expired limiter entries and LRU-cap the dicts.

        Keys older than their window (``RECOVERY_BACKOFF_SECONDS`` for recovery,
        ``DENIAL_WINDOW_SECONDS`` for denials) are dropped, and each dict is
        capped at ``LIMITER_MAX_ENTRIES`` so a flood of distinct keys cannot
        grow memory without bound.
        """
        for key in [
            k for k, ts in self._recovery_last.items() if now - ts >= RECOVERY_BACKOFF_SECONDS
        ]:
            del self._recovery_last[key]
        for key in [
            k
            for k, st in self._denials.items()
            if now - st["window_start"] > DENIAL_WINDOW_SECONDS
        ]:
            del self._denials[key]
        while len(self._recovery_last) > LIMITER_MAX_ENTRIES:
            self._recovery_last.pop(next(iter(self._recovery_last)))
        while len(self._denials) > LIMITER_MAX_ENTRIES:
            self._denials.pop(next(iter(self._denials)))

    def _stale_client_dedupe(self, client_id: str) -> str:
        """Dedupe key for a stale client, with a recurrence token (issue #6).

        The base key ``stale-client:<id>`` is one-shot while an incident for it
        is OPEN. Once the prior incident reaches a TERMINAL phase (resolved or
        escalated), a genuine recurrence raises a NEW incident under a
        recurrence-suffixed key (``stale-client:<id>:r2``, ``:r3``, ...) rather
        than being silently swallowed by the store's key dedupe.
        """
        base = f"stale-client:{client_id}"
        terminal = 0
        for inc in self.store.list_incidents():
            key = inc.dedupe_key or ""
            if key == base or key.startswith(base + ":"):
                if inc.phase in (PHASE_RESOLVED, PHASE_ESCALATED):
                    terminal += 1
        return base if terminal == 0 else f"{base}:r{terminal + 1}"

    def _build_incident(self, kind: str, observation: Observation) -> dict:
        """Build a bounded auto-incident record with a CONCRETE observation and
        a deterministic DEDUPE key (the store then dedupes by id and key)."""
        client_id = observation.client_id or ""
        session_id = observation.session_id or ""
        if kind == CLASS_LOST_CAPABILITY:
            cap = observation.capability or observation.tool_name or "unknown"
            dedupe = f"lost-capability:{client_id}:{cap}"
            severity = SEVERITY_BLOCKED
            symptom = (
                f"registered capability {cap!r} lost for client {client_id!r}: "
                f"{observation.detail or observation.error_type}"
            )
        elif kind == CLASS_STALE_CLIENT:
            dedupe = self._stale_client_dedupe(client_id)
            severity = SEVERITY_MECHANICAL
            symptom = (
                f"client {client_id!r} is stale/dead: "
                f"{observation.detail or 'no recent client heartbeat'}"
            )
        elif kind == CLASS_PERMISSION_BLOCK:
            dedupe = f"permission-block:{client_id}:{observation.tool_name}"
            severity = SEVERITY_BLOCKED
            symptom = (
                f"permission block on {observation.tool_name!r} for client "
                f"{client_id!r}: {observation.detail or observation.error_type}"
            )
        elif kind == CLASS_POLICY_DENIAL:
            dedupe = f"policy-denial:{session_id}:{observation.rule_id or observation.tool_name}"
            severity = SEVERITY_MECHANICAL
            symptom = (
                f"repeated policy denial in session {session_id!r}: "
                f"{observation.status} on {observation.tool_name!r}"
            )
        else:  # pragma: no cover - internal callers only pass the four kinds above
            raise ValueError(f"cannot auto-raise for classification {kind!r}")

        record: dict[str, Any] = {
            "id": _incident_id(dedupe),
            "severity": severity,
            "symptom": symptom[:SYMPTOM_MAX_CHARS],
            "phase": PHASE_OPEN,
            "dedupe_key": dedupe,
            "observed": [
                o
                for o in (
                    observation.detail,
                    observation.error_type,
                    observation.capability,
                    observation.tool_name,
                )
                if o
            ],
        }
        if client_id:
            record["client_id"] = client_id
        if session_id:
            record["session_id"] = session_id
        return record


__all__ = [
    "SUPERVISOR_STALE_SECONDS",
    "CLIENT_STALE_SECONDS",
    "RECONNECT_WINDOW_SECONDS",
    "RECOVERY_BACKOFF_SECONDS",
    "DENIAL_WINDOW_SECONDS",
    "MAX_DENIALS_BEFORE_ESCALATE",
    "OBSERVATION_DETAIL_MAX_CHARS",
    "CLIENT_CAPABILITIES_MAX",
    "HEARTBEAT_MIN_INTERVAL_SECONDS",
    "OBSERVATIONS_MAX_BYTES",
    "ALERT_COOLDOWN_SECONDS",
    "LIMITER_MAX_ENTRIES",
    "TRANSIENT_ERROR_TYPES",
    "PERMISSION_ERROR_TYPES",
    "CAPABILITY_LOSS_ERROR_TYPES",
    "UNSUPPORTED_PREDICATES",
    "CLASS_RECONNECT_IN_PROGRESS",
    "CLASS_TRANSPORT_DROP",
    "CLASS_STALE_CLIENT",
    "CLASS_LOST_CAPABILITY",
    "CLASS_PERMISSION_BLOCK",
    "CLASS_POLICY_DENIAL",
    "CLASS_UNSUPPORTED",
    "CLASS_NONE",
    "OBSERVATION_KINDS",
    "CLIENT_STATUS_REGISTERED",
    "CLIENT_STATUS_RECONNECTING",
    "CLIENT_STATUS_ENDED",
    "Observation",
    "ClientRecord",
    "Classification",
    "classify",
    "Effect",
    "NoEffect",
    "LocalAlert",
    "RaiseIncident",
    "RecoveryRequest",
    "UnsupportedEffect",
    "Observer",
    "state_root_for",
    "append_observation",
    "iter_observations",
    "write_client_record",
    "load_client_record",
    "list_client_records",
    "read_heartbeat_file",
    "write_heartbeat_file",
]
