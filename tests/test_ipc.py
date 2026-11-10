"""Owning-client IPC + native MCP adapter (plan §4/§6, Task 13).

Locks the IPC contract with REAL temp filesystems, REAL Unix sockets, and REAL
SO_PEERCRED where the OS primitive is exercised:

* the envelope/reply schema is closed, bounded, and versioned;
* the frame codec enforces a payload cap and a deadline;
* peer UID is read from SO_PEERCRED (never a caller-supplied path);
* intent is persisted BEFORE send and a client receipt (queued/started/settled)
  binds request_id + epoch + canonical operation hash BEFORE launch;
* identical retries return the recorded outcome; a CHANGED operation hash with
  the same id is REJECTED;
* both daemon AND owning client re-validate the current claim/epoch/lease,
  target identity, allowlisted params and shared ED-209 policy immediately
  before mutation;
* timeout/lost-ack enters RECONCILIATION (never automatic duplicate execution);
* a stale queued epoch is rejected at the launch barrier; a STARTED receipt
  blocks a new mutating epoch;
* the executor's ``mcp_reconnect`` dispatches over IPC when an adapter is
  wired, and stays UNSUPPORTED when it is not.

Run the real-dispatch layer with ``G/scripts/run_plugin_tests.sh``.
"""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import socket
import struct
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from operator_guards.common.proof import Verdict

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "plugins" / "r2d2"
FIXTURE_SERVER = Path(__file__).resolve().parent / "_fixtures" / "mcp_fixture_server.py"

HERMES_AVAILABLE = False
try:
    import hermes_cli.plugins  # noqa: F401

    HERMES_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only under G/.venv
    pass

requires_hermes = pytest.mark.skipif(
    not HERMES_AVAILABLE,
    reason="Hermes source not importable; run via G/scripts/run_plugin_tests.sh",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _raise_and_claim(store, incident_id="inc-1", *, epoch=None, lease_expiry=None):
    """Raise an incident and acquire a durable claim (epoch 1, live lease)."""
    store.raise_incident(
        {
            "id": incident_id,
            "severity": "mechanical",
            "symptom": "mcp server unreachable",
            "phase": "open",
            "dedupe_key": f"d-{incident_id}",
            "profile_id": "default",
            "client_id": "host:default",
            "session_id": "sess-1",
        }
    )
    from operator_guards.r2d2.claims import ClaimManager

    mgr = ClaimManager(store, lease_seconds=3600.0, clock=lambda: 0.0)
    fence = mgr.acquire(incident_id, "daemon", owned_proc=False)
    if epoch is not None:
        store.update_incident(
            incident_id,
            lambda i: replace(
                i,
                epoch=epoch,
                lease_expiry=(lease_expiry if lease_expiry is not None else i.lease_expiry),
            ),
        )
    return store, fence


def _envelope(server="demo-server", **overrides):
    env = {
        "version": 1,
        "request_id": "req-abc",
        "incident_id": "inc-1",
        "epoch": 1,
        "profile_id": "default",
        "client_id": "host:default",
        "session_id": "sess-1",
        "operation": "mcp_reconnect",
        "params": {"server": server},
    }
    env.update(overrides)
    return env


def _receipts(tmp_path):
    from operator_guards.r2d2.client import ReceiptStore

    return ReceiptStore(str(tmp_path / "r2d2"))


def _load_r2d2_plugin_ipc():
    """Load ``plugins/r2d2/ipc_adapter.py`` directly by file path.

    ``plugins`` cannot be imported as a package here: the Hermes checkout ships
    its OWN ``plugins`` package (loaded first on ``PYTHONPATH``), which shadows
    this repo's ``plugins/`` directory. Loading the file by path still yields the
    REAL plugin seams (``_native_reconnector`` / ``_native_server_registry``).
    """
    spec = importlib.util.spec_from_file_location(
        "r2d2_plugin_ipc", PLUGIN_DIR / "ipc_adapter.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _pid_alive(pid: int) -> bool:
    """True while a Linux PID is a live (non-zombie) process."""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
            state = fh.read().split(")")[1].split()[0]
        return state != "Z"
    except (OSError, IndexError):
        return False


def _wait_pid_dead(pid: int, timeout: float = 10.0) -> bool:
    """Poll until ``pid`` is gone or a zombie (a reaped child counts as dead)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.05)
    return False


def _wait_fresh_session(srv, old_session, timeout: float = 30.0) -> bool:
    """Poll until ``srv`` exposes a READY session that is NOT ``old_session``."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        sess = srv.session
        ready = getattr(srv, "_ready", None)
        is_ready = bool(ready.is_set()) if ready is not None else True
        if sess is not None and is_ready and sess is not old_session:
            return True
        time.sleep(0.1)
    return False


# ---------------------------------------------------------------------------
# identity + ipc schema / frame / peer-cred unit tests
# ---------------------------------------------------------------------------


def test_runtime_dir_and_socket_path_resolve_uid():
    from operator_guards.common import identity

    assert identity.uid() == os.getuid()
    rt = identity.runtime_dir()
    assert rt and os.path.isdir(rt)
    path = identity.ipc_socket_path("default", "host:default")
    assert path.startswith(identity.ipc_socket_dir())
    assert "hermes-guards" in path


def test_profile_and_client_id_resolution():
    from operator_guards.common import identity

    assert identity.profile_id_for("/home/rsanchez/.hermes") == ".hermes"
    assert identity.profile_id_for("/tmp/whatever") == "whatever"
    assert identity.client_id_for("/home/rsanchez/.hermes", host="h") == "h:.hermes"


def test_envelope_validation_rejects_unknown_field():
    from operator_guards.common.ipc import IpcError, validate_envelope

    with pytest.raises(IpcError):
        validate_envelope({**_envelope(), "extra": 1})


def test_envelope_validation_requires_nonempty_ids():
    from operator_guards.common.ipc import IpcError, validate_envelope

    with pytest.raises(IpcError):
        validate_envelope(_envelope(request_id=""))
    with pytest.raises(IpcError):
        validate_envelope(_envelope(epoch=-1))
    with pytest.raises(IpcError):
        validate_envelope(_envelope(operation=""))  # empty operation string


def test_envelope_params_cap_enforced():
    from operator_guards.common.ipc import IpcError, validate_envelope

    params = {f"k{i}": "v" for i in range(100)}
    with pytest.raises(IpcError):
        validate_envelope(_envelope(params=params))


def test_canonical_op_hash_differs_on_changed_params():
    from operator_guards.common.ipc import Envelope, canonical_op_hash, validate_envelope

    a = canonical_op_hash(validate_envelope(_envelope(server="a")))
    b = canonical_op_hash(validate_envelope(_envelope(server="b")))
    c = canonical_op_hash(validate_envelope(_envelope(server="a")))
    assert a != b
    assert a == c


def test_frame_roundtrip_and_oversize_rejected():
    from operator_guards.common.ipc import PayloadTooLarge, decode_frame, encode_frame

    payload = {"a": 1, "b": [1, 2, 3]}
    assert decode_frame(encode_frame(payload)) == payload
    with pytest.raises(PayloadTooLarge):
        decode_frame(b"\x00\x01\x00\x01" + b"x")  # declares 65537 > frame cap


def test_peer_uid_returns_own_uid_on_real_socketpair():
    from operator_guards.common.ipc import peer_uid

    a, b = socket.socketpair()
    try:
        assert peer_uid(a.fileno()) == os.getuid()
        assert peer_uid(b.fileno()) == os.getuid()
    finally:
        a.close()
        b.close()


# ---------------------------------------------------------------------------
# ReceiptStore: durable intent/receipt, dedupe, replay protection
# ---------------------------------------------------------------------------


def test_receipt_record_queued_idempotent_same_hash(tmp_path):
    store = _receipts(tmp_path)
    r1 = store.record_queued("req-1", 1, "hash-a", "inc-1")
    r2 = store.record_queued("req-1", 1, "hash-a", "inc-1")
    assert r1["state"] == "queued"
    assert r2["state"] == "queued"  # idempotent, no exception


def test_receipt_changed_hash_same_id_rejected(tmp_path):
    from operator_guards.common.ipc import ReplayRejected

    store = _receipts(tmp_path)
    store.record_queued("req-1", 1, "hash-a", "inc-1")
    with pytest.raises(ReplayRejected):
        store.record_queued("req-1", 1, "hash-B", "inc-1")


def test_receipt_states_queued_started_settled(tmp_path):
    store = _receipts(tmp_path)
    store.record_queued("req-1", 1, "h", "inc-1")
    assert store.lookup("req-1")["state"] == "queued"
    store.mark_started("req-1", 1, "h")
    assert store.lookup("req-1")["state"] == "started"
    store.mark_settled("req-1", "ok", {"verdict": "PASS"}, {"verdict": "PASS"})
    got = store.lookup("req-1")
    assert got["state"] == "settled"
    assert got["status"] == "ok"
    assert got["op_result"]["verdict"] == "PASS"


def test_receipt_mark_started_requires_matching_epoch(tmp_path):
    from operator_guards.r2d2.client import ReceiptError

    store = _receipts(tmp_path)
    store.record_queued("req-1", 1, "h", "inc-1")
    with pytest.raises(ReceiptError):
        store.mark_started("req-1", 2, "h")  # epoch mismatch


# ---------------------------------------------------------------------------
# OwningClientAdapter (daemon side): intent-before-send, timeout->reconcile,
# dedupe/replay
# ---------------------------------------------------------------------------


class _Transport:
    """Injected transport recording calls; returns canned reply frames."""

    def __init__(self, replies=None, raise_exc=None, on_send=None):
        self.calls = 0
        self.sent = []
        self.replies = list(replies or [])
        self.raise_exc = raise_exc
        self.on_send = on_send

    def __call__(self, socket_path, frame, deadline):
        from operator_guards.common.ipc import decode_frame

        self.calls += 1
        payload = decode_frame(frame)  # frame is length-prefixed, like a real socket
        self.sent.append(payload)
        if self.on_send is not None:
            self.on_send(payload)
        if self.raise_exc:
            raise self.raise_exc
        reply = self.replies.pop(0) if self.replies else {
            "request_id": "req-x", "status": "ok", "op_result": None, "capability_proof": None
        }
        return json.dumps(reply).encode("utf-8")


def _adapter(tmp_path, transport):
    from operator_guards.r2d2.client import OwningClientAdapter
    from operator_guards.r2d2.store import IncidentStore

    root = str(tmp_path / "r2d2")
    store = IncidentStore(root)
    _raise_and_claim(store, incident_id="inc-1")
    adapter = OwningClientAdapter(
        root, store=store, socket_path=str(tmp_path / "s.sock"),
        transport=transport, clock=lambda: 0.0,
    )
    return adapter, store


def test_adapter_persists_intent_before_send(tmp_path):
    from operator_guards.r2d2.client import ReceiptStore

    seen = {}
    rs = ReceiptStore(str(tmp_path / "r2d2"))

    def on_send(payload):
        # at the moment the transport fires, the intent receipt MUST already
        # be durable (queued or beyond).
        seen["receipt"] = rs.lookup(payload["request_id"])

    transport = _Transport(on_send=on_send)
    adapter, store = _adapter(tmp_path, transport)
    adapter.request_mcp_reconnect("inc-1", "demo-server")
    assert transport.calls == 1
    assert seen["receipt"] is not None  # intent was persisted BEFORE the send


def test_adapter_timeout_reconciles_no_duplicate(tmp_path):
    from operator_guards.common.ipc import DeadlineExceeded
    from operator_guards.r2d2.client import ReceiptStore

    transport = _Transport(raise_exc=DeadlineExceeded("timeout"))
    adapter, store = _adapter(tmp_path, transport)
    reply = adapter.request_mcp_reconnect("inc-1", "demo-server")
    assert reply.status == "unknown"
    # the intent receipt is settled (reconciliation), not left in-flight
    rid = transport.sent[0]["request_id"]
    assert ReceiptStore(str(tmp_path / "r2d2")).lookup(rid)["state"] == "settled"


def test_adapter_replay_same_id_returns_recorded_outcome(tmp_path):
    transport = _Transport(replies=[
        {"request_id": "req-abc", "status": "ok",
         "op_result": {"op_id": "m1", "kind": "mcp_status", "verdict": "PASS"},
         "capability_proof": {"verdict": "PASS", "server": "demo-server"}},
    ])
    adapter, store = _adapter(tmp_path, transport)
    first = adapter.request_mcp_reconnect("inc-1", "demo-server")
    second = adapter.request_mcp_reconnect("inc-1", "demo-server")  # identical retry
    assert first.status == "ok"
    assert second.status == "ok"
    # the transport was hit ONCE: the retry returned the recorded outcome
    assert transport.calls == 1


def test_adapter_changed_hash_rejected(tmp_path):
    from operator_guards.common.ipc import ReplayRejected
    from operator_guards.r2d2.client import ReceiptStore

    transport = _Transport()
    adapter, store = _adapter(tmp_path, transport)
    adapter.request_mcp_reconnect("inc-1", "demo-server")
    rid = transport.sent[0]["request_id"]
    epoch = store.get_incident("inc-1").epoch
    rs = ReceiptStore(str(tmp_path / "r2d2"))
    with pytest.raises(ReplayRejected):
        rs.record_queued(rid, epoch, "DIFFERENT-HASH", "inc-1")


# ---------------------------------------------------------------------------
# OwningClientServer (owning-client side): both-side fencing, identity, dedupe,
# harmless-probe recovery proof, rejections
# ---------------------------------------------------------------------------


def _server(tmp_path, incident_id="inc-1", **overrides):
    from operator_guards.r2d2.ipc_adapter import OwningClientServer
    from operator_guards.r2d2.store import IncidentStore

    root = str(tmp_path / "r2d2")
    store = IncidentStore(root)
    _raise_and_claim(store, incident_id=incident_id)
    kwargs = dict(
        home=str(tmp_path / "hermes-home"),
        profile_id="default",
        client_id="host:default",
        state_root=root,
        socket_path=str(tmp_path / "s.sock"),
        reconnector=lambda server: True,
        probe_caller=lambda server: {"ok": True, "tool": "echo", "result": "probe-ok"},
        server_registry=lambda: frozenset({"demo-server"}),
        policy_check=lambda tool, payload: None,  # allow
        clock=lambda: 0.0,
    )
    kwargs.update(overrides)
    return OwningClientServer(**kwargs), store


def _handle(server, env):
    return server.handle(env, os.getuid())


def test_server_rejects_wrong_peer_uid(tmp_path):
    server, _ = _server(tmp_path)
    reply = server.handle(_envelope(), os.getuid() + 1)
    assert reply["status"] == "rejected"


def test_server_rejects_wrong_identity(tmp_path):
    server, _ = _server(tmp_path)
    reply = _handle(server, _envelope(profile_id="other"))
    assert reply["status"] == "rejected"
    reply = _handle(server, _envelope(client_id="other:host"))
    assert reply["status"] == "rejected"


def test_server_rejects_mismatched_session_identity(tmp_path):
    # the envelope's session_id must match the DURABLE incident's session_id
    server, _ = _server(tmp_path)
    reply = _handle(server, _envelope(session_id="other-session"))
    assert reply["status"] == "rejected"


def test_server_rejects_unknown_operation(tmp_path):
    server, _ = _server(tmp_path)
    reply = _handle(server, _envelope(operation="config_set", params={}))
    assert reply["status"] == "unsupported"


def test_server_rejects_unknown_server(tmp_path):
    server, _ = _server(tmp_path)
    reply = _handle(server, _envelope(server="not-registered"))
    assert reply["status"] == "unknown"


def test_server_rejects_on_ed209_policy_deny(tmp_path):
    server, _ = _server(tmp_path, policy_check=lambda tool, payload: "deny")
    reply = _handle(server, _envelope())
    assert reply["status"] == "rejected"


# ---------------------------------------------------------------------------
# Finding 2: the PLUGIN's start_ipc_server wires a REAL, fail-closed ED-209
# policy check at the IPC mutation entry (not only tests set it).
# ---------------------------------------------------------------------------

def test_plugin_start_ipc_server_wires_ed209_policy_check(tmp_path):
    plugin = _load_r2d2_plugin_ipc()
    home = tmp_path / "home"
    (home / "ed209").mkdir(parents=True)
    (home / "ed209" / "rules.json").write_text(json.dumps({
        "version": 1,
        "rules": [{
            "id": "deny-mcp", "surface": "tool", "class": "restrict",
            "action": "deny", "pattern": "demo-server",
            "reason": "no reconnect without review", "origin": "test",
        }],
    }))
    path = plugin.start_ipc_server(
        home=str(home), state_root=str(tmp_path / "r2d2"),
        reconnector=lambda s: True,
        probe_caller=lambda s: {"ok": True, "tool": "echo", "result": "x"},
        server_registry=lambda: frozenset({"demo-server"}),
        profile_id="default", client_id="host:default",
        socket_path=str(tmp_path / "s.sock"),
    )
    try:
        assert path is not None
        assert plugin._server._policy_check is not None
        # A matching deny rule vetoes the mutation entry (non-None = reject).
        assert plugin._server._policy_check(
            "mcp_reconnect", json.dumps({"server": "demo-server"})
        )
    finally:
        plugin.stop_ipc_server()


def test_plugin_ipc_policy_check_fail_closed_without_rules(tmp_path):
    plugin = _load_r2d2_plugin_ipc()
    home = tmp_path / "home"  # no ed209/rules.json at all
    check = plugin._default_policy_check(str(home))
    # Fail-closed: no rules document -> the mutation entry is REJECTED (never a
    # route around ED-209).
    assert check("mcp_reconnect", json.dumps({"server": "x"}))


def test_plugin_ipc_policy_check_allows_when_no_matching_deny(tmp_path):
    plugin = _load_r2d2_plugin_ipc()
    home = tmp_path / "home"
    (home / "ed209").mkdir(parents=True)
    (home / "ed209" / "rules.json").write_text(json.dumps({"version": 1, "rules": []}))
    check = plugin._default_policy_check(str(home))
    assert check("mcp_reconnect", json.dumps({"server": "x"})) is None


def test_client_rejects_expired_queued_request(tmp_path):
    # A stale queued epoch is rejected IMMEDIATELY before launch: the durable
    # incident has moved to epoch 2 but the request carries epoch 1.
    calls = []
    server, store = _server(
        tmp_path,
        reconnector=lambda s: calls.append("reconnect") or True,
        probe_caller=lambda s: calls.append("probe") or {"ok": True, "tool": "echo", "result": "x"},
    )
    store.update_incident("inc-1", lambda i: replace(i, epoch=2))
    reply = _handle(server, _envelope(epoch=1))
    assert reply["status"] == "unknown"  # stale epoch -> escalate, not launched
    assert calls == []  # neither reconnect nor probe ran


def test_server_rejects_dead_owner(tmp_path):
    server, store = _server(tmp_path)
    store.update_incident(
        "inc-1", lambda i: replace(i, claimant="", lease_expiry=0.0)
    )
    reply = _handle(server, _envelope())
    assert reply["status"] == "unknown"


def test_server_rejects_missing_harmless_probe(tmp_path):
    server, _ = _server(tmp_path, probe_caller=None)
    reply = _handle(server, _envelope())
    assert reply["status"] == "unknown"


def test_server_rejects_cooldown(tmp_path):
    clock = {"t": 0.0}
    calls = []
    server, _ = _server(
        tmp_path,
        clock=lambda: clock["t"],
        reconnector=lambda s: calls.append(s) or True,
    )
    first = _handle(server, _envelope())
    assert first["status"] == "ok"
    second = _handle(server, _envelope(request_id="req-2"))
    assert second["status"] == "unknown"
    assert len(calls) == 1  # only the first reconnect ran


def test_server_rejects_replayed_request(tmp_path):
    # A settled request replayed with a DIFFERENT hash (same id) is rejected.
    server, _ = _server(
        tmp_path, server_registry=lambda: frozenset({"demo-server", "other-server"})
    )
    first = _handle(server, _envelope())
    assert first["status"] == "ok"
    # same request_id but a changed (still-known) operation -> changed hash -> reject
    reply = _handle(server, _envelope(server="other-server"))
    assert reply["status"] == "rejected"


def test_started_request_blocks_new_mutating_epoch(tmp_path):
    # A STARTED receipt blocks a new mutating epoch: no duplicate launch after
    # a lost acknowledgment.
    from operator_guards.common.ipc import canonical_op_hash, validate_envelope
    from operator_guards.r2d2.client import ReceiptStore

    calls = []
    root = str(tmp_path / "r2d2")
    server, store = _server(
        tmp_path,
        reconnector=lambda s: calls.append(s) or True,
        probe_caller=lambda s: calls.append("probe") or {"ok": True, "tool": "echo", "result": "x"},
    )
    rs = ReceiptStore(root)
    rs.record_queued("req-1", 1, canonical_op_hash(validate_envelope(_envelope())), "inc-1")
    rs.mark_started("req-1", 1, canonical_op_hash(validate_envelope(_envelope())))
    reply = _handle(server, _envelope(request_id="req-2"))
    assert reply["status"] in ("unknown", "rejected")
    assert calls == []  # the harmless probe did NOT run twice


def test_server_success_roundtrip_with_harmless_probe(tmp_path):
    calls = []
    server, store = _server(
        tmp_path,
        reconnector=lambda s: calls.append(("reconnect", s)) or True,
        probe_caller=lambda s: calls.append(("probe", s)) or {"ok": True, "tool": "echo", "result": "probe-ok"},
    )
    reply = _handle(server, _envelope())
    assert reply["status"] == "ok"
    assert reply["request_id"] == "req-abc"
    assert reply["capability_proof"]["verdict"] == "PASS"
    assert reply["capability_proof"]["server"] == "demo-server"
    assert ("reconnect", "demo-server") in calls
    assert ("probe", "demo-server") in calls
    assert reply["op_result"]["kind"] == "mcp_status"
    assert reply["op_result"]["verdict"] == "PASS"


def test_server_full_socket_roundtrip(tmp_path):
    # REAL unix socket: adapter (daemon) -> server (owning client) -> reply.
    from operator_guards.r2d2.client import OwningClientAdapter

    root = str(tmp_path / "r2d2")
    server, store = _server(tmp_path)
    path = server.start()
    try:
        adapter = OwningClientAdapter(
            root, store=store, socket_path=path, clock=lambda: 0.0, deadline=5.0,
        )
        reply = adapter.request_mcp_reconnect("inc-1", "demo-server")
        assert reply.status == "ok"
        assert reply.capability_proof["verdict"] == "PASS"
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Executor wiring: mcp_reconnect dispatches via the adapter, else UNSUPPORTED
# ---------------------------------------------------------------------------


def _exec_setup(tmp_path, adapter=None, policy=None):
    from operator_guards.r2d2.claims import ClaimManager
    from operator_guards.r2d2.executor import Executor
    from operator_guards.r2d2.handlers import HandlerContext
    from operator_guards.r2d2.store import IncidentStore

    root = str(tmp_path / "r2d2")
    store = IncidentStore(root)
    store.raise_incident(
        {
            "id": "inc-1", "severity": "mechanical", "symptom": "mcp down",
            "phase": "open", "dedupe_key": "d-1",
            "profile_id": "default", "client_id": "host:default", "session_id": "sess-1",
        }
    )
    claims = ClaimManager(store, clock=lambda: 0.0)
    ctx = HandlerContext(mcp_reconnect_adapter=adapter)
    executor = Executor(store, claims, policy=policy, context=ctx, clock=lambda: 0.0)
    fence = claims.acquire("inc-1", "daemon")
    return store, claims, executor, fence


def test_mcp_reconnect_dispatches_via_adapter(tmp_path):
    from operator_guards.r2d2.client import OwningClientAdapter
    from operator_guards.r2d2.executor import Plan, Policy, Step
    from operator_guards.r2d2.handlers import OP_MCP_RECONNECT

    # a real adapter with an injected transport: the executor/handler routes
    # mcp_reconnect through it (not UNSUPPORTED) and the incident gains typed proof.
    transport = _Transport(replies=[
        {"request_id": "req-abc", "status": "ok",
         "op_result": {"op_id": "mcp-req-abc", "kind": "mcp_status", "verdict": "PASS",
                       "expected": "demo-server", "observed": ["probe-ok"],
                       "evidence": "harmless probe", "epoch": 1, "client_id": "host:default"},
         "capability_proof": {"verdict": "PASS", "server": "demo-server",
                              "probe_tool": "echo", "probe_result": "probe-ok"}},
    ])
    adapter = OwningClientAdapter(
        str(tmp_path / "r2d2"),
        store=None, socket_path=str(tmp_path / "s.sock"),
        transport=transport, clock=lambda: 0.0,
    )
    rules_path = str(tmp_path / "rules.json")
    with open(rules_path, "w") as f:
        json.dump({"version": 1, "rules": []}, f)
    policy = Policy(rules_path=rules_path, ledger=None)

    store, claims, executor, fence = _exec_setup(tmp_path, adapter=adapter, policy=policy)

    report = executor.execute(fence, Plan(mutations=(
        Step(op_id="m1", operation=OP_MCP_RECONNECT, params={"server": "demo-server"},
             verify_kind="contains", expected="PASS"),
    )))
    assert transport.calls == 1
    assert report.resolved is True
    assert report.verdict is Verdict.PASS
    assert report.unsupported == ()


def test_mcp_reconnect_still_unsupported_without_adapter(tmp_path):
    from operator_guards.r2d2.executor import Plan, Step
    from operator_guards.r2d2.handlers import OP_MCP_RECONNECT

    store, claims, executor, fence = _exec_setup(tmp_path)  # no adapter
    report = executor.execute(fence, Plan(mutations=(
        Step(op_id="m1", operation=OP_MCP_RECONNECT, params={"server": "demo-server"},
             verify_kind=None, expected=None),
    )))
    assert report.resolved is False
    assert report.unsupported == ("mcp_reconnect",)


# ---------------------------------------------------------------------------
# session_stop_resume stays UNSUPPORTED (separately-verified external launcher
# is out of scope for this task)
# ---------------------------------------------------------------------------

def test_session_stop_resume_still_unsupported(tmp_path):
    from operator_guards.r2d2.executor import Plan, Step
    from operator_guards.r2d2.handlers import OP_SESSION_STOP_RESUME

    store, claims, executor, fence = _exec_setup(tmp_path)
    report = executor.execute(fence, Plan(mutations=(
        Step(op_id="m1", operation=OP_SESSION_STOP_RESUME, params={},
             verify_kind=None, expected=None),
    )))
    assert report.resolved is False
    assert report.unsupported == ("session_stop_resume",)


# ---------------------------------------------------------------------------
# Real-dispatch integration (skip unless the Hermes checkout is importable)
# ---------------------------------------------------------------------------


@requires_hermes
def test_real_socket_roundtrip_harmless_tool_call_through_owner(tmp_path, monkeypatch):
    """Real unix socket + real dispatch: a harmless ACTUAL tool call succeeds
    through the ORIGINAL owner (the in-process server), and the incident has
    TYPED proof."""
    import model_tools
    from operator_guards.r2d2.client import OwningClientAdapter
    from operator_guards.r2d2.ipc_adapter import OwningClientServer
    from operator_guards.r2d2.store import IncidentStore

    root = str(tmp_path / "r2d2")
    store = IncidentStore(root)
    _raise_and_claim(store, incident_id="inc-1")

    probe_results = []

    def probe_caller(server):
        try:
            out = model_tools.handle_function_call(
                "echo", {"message": f"harmless-probe-{server}"}
            )
            probe_results.append(out)
            return {"ok": True, "tool": "echo", "result": str(out)[:200]}
        except Exception as exc:  # noqa: BLE001
            probe_results.append(exc)
            return {"ok": False, "tool": "echo", "result": str(exc)[:200]}

    server = OwningClientServer(
        home=str(tmp_path / "hermes-home"),
        state_root=root,
        socket_path=str(tmp_path / "s.sock"),
        profile_id="default",
        client_id="host:default",
        reconnector=lambda s: True,
        probe_caller=probe_caller,
        server_registry=lambda: frozenset({"demo-server"}),
        policy_check=lambda tool, payload: None,
        clock=lambda: 0.0,
    )
    path = server.start()
    try:
        adapter = OwningClientAdapter(
            root, store=store, socket_path=path, clock=lambda: 0.0, deadline=10.0,
        )
        reply = adapter.request_mcp_reconnect("inc-1", "demo-server")
        assert reply.status == "ok"
        assert reply.capability_proof["verdict"] == "PASS"
        assert probe_results
    finally:
        server.stop()


def test_plugin_ipc_adapter_module_import_safe():
    """The ipc_adapter module imports without Hermes (G/.venv contract)."""
    spec = importlib.util.spec_from_file_location(
        "r2d2_ipc_adapter_under_test", PLUGIN_DIR / "ipc_adapter.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, "OwningClientServer")


@requires_hermes
def test_real_fixture_mcp_dies_owner_lives_native_reconnect_typed_proof(tmp_path):
    """The spec's full integration scenario, end to end, nothing stubbed.

    1. A REAL fixture MCP server (``tests/_fixtures/mcp_fixture_server.py``, a
       genuine stdio MCP server on the installed ``mcp`` SDK) is registered
       through Hermes's OWN MCP client (``register_mcp_servers``), and a
       harmless ACTUAL MCP tool call (``mcp__<name>__echo``) succeeds.
    2. The fixture's stdio child is SIGKILLed; the owning Hermes process stays
       RESPONSIVE (its MCP loop is alive and its tool registry still dispatches).
    3. The REAL native seams are wired (loaded from ``plugins/r2d2/ipc_adapter.py``
       by path — NOT stubbed): ``_native_reconnector`` (→
       ``tools.mcp_tool_loop.reconnect_mcp_server``) and ``_native_server_registry``
       (→ the process-local ``_servers`` keys).
    4. R2-D2 (the daemon-side adapter) requests ``mcp_reconnect`` over a REAL
       Unix socket; the OWNING client performs the native reconnect AND a
       harmless ACTUAL MCP tool call through the RECOVERED server (not echo).
    5. Recovery is proven with an ACTUAL MCP tool call through the recovered
       server in the original owner context.
    6. The incident's DURABLE ``mutation_plan`` carries the TYPED ``mcp_status``
       proof (kind == "mcp_status", verdict == PASS), re-read from a FRESH store.
    """
    import model_tools
    from tools import mcp_tool, mcp_tool_loop
    from tools.mcp_tool_discovery import register_mcp_servers
    from tools.mcp_tool_lifecycle import shutdown_mcp_servers
    from tools.mcp_tool_scope import _resolve_server_key
    from tools.registry import registry

    from operator_guards.r2d2.client import OwningClientAdapter
    from operator_guards.r2d2.ipc_adapter import OwningClientServer
    from operator_guards.r2d2.store import IncidentStore

    SERVER_NAME = "r2d2fixture"
    TOOL = f"mcp__{SERVER_NAME}__echo"

    # 1. Register the REAL fixture stdio MCP server via Hermes's own client.
    pid_file = str(tmp_path / "fixture.pid")
    registered = register_mcp_servers(
        {
            SERVER_NAME: {
                "command": sys.executable,
                "args": [str(FIXTURE_SERVER)],
                "env": {"FIXTURE_PID_FILE": pid_file},
                "connect_timeout": 30,
                "timeout": 30,
            }
        }
    )
    assert TOOL in registered
    with mcp_tool._lock:
        srv = mcp_tool._servers.get(_resolve_server_key(SERVER_NAME))
    assert srv is not None and srv.session is not None
    old_session = srv.session
    old_pid = int(Path(pid_file).read_text())

    try:
        # 2a. USABLE: a harmless ACTUAL MCP tool call succeeds.
        out1 = registry.dispatch(TOOL, {"message": "before-death"})
        assert "ECHO:before-death" in str(out1)

        # 2b. DIES: kill the fixture's stdio child (SIGKILL) and prove it dead.
        os.kill(old_pid, signal.SIGKILL)
        assert _wait_pid_dead(old_pid)

        # 2c. OWNER STAYS RESPONSIVE: the MCP loop is alive and the owner's
        # tool dispatch (registry -> handler) still executes while the MCP
        # server is dead.
        assert mcp_tool_loop._running_loop() is not None
        sentinel_calls = []

        def _sentinel_handler(args, **kw):
            sentinel_calls.append(args)
            return json.dumps({"sentinel": True})

        registry.register(
            name="r2d2_responsive_sentinel",
            toolset="r2d2-test",
            schema={
                "name": "r2d2_responsive_sentinel",
                "description": "owner-responsiveness probe",
                "parameters": {"type": "object", "properties": {}},
            },
            handler=_sentinel_handler,
        )
        try:
            resp = model_tools.handle_function_call(
                "r2d2_responsive_sentinel",
                {"marker": "alive"},
                session_id="sess",
                turn_id="t1",
                tool_call_id="c1",
            )
        except Exception:  # noqa: BLE001 - middleware may be absent in the test harness
            resp = registry.dispatch("r2d2_responsive_sentinel", {"marker": "alive"})
        assert sentinel_calls and "sentinel" in str(resp)

        # 3. REAL native seams, loaded from the plugin by path (NOT stubbed).
        plugin = _load_r2d2_plugin_ipc()
        native_reconnector = plugin._native_reconnector
        native_server_registry = plugin._native_server_registry
        # The native registry sees THIS client's own live server.
        assert SERVER_NAME in native_server_registry()

        # 4. REAL IPC: daemon-side adapter -> owning-client server over a Unix socket.
        root = str(tmp_path / "r2d2")
        store = IncidentStore(root)
        _raise_and_claim(store, incident_id="inc-1")

        def probe_caller(server_name):
            # A harmless ACTUAL tool call THROUGH THE RECOVERED MCP SERVER (an
            # MCP tool, NOT the built-in echo): wait for a FRESH ready session
            # (the reconnect was just signalled) then call it on the MCP loop.
            with mcp_tool._lock:
                s = mcp_tool._servers.get(_resolve_server_key(SERVER_NAME))
            if s is None:
                return {"ok": False, "tool": TOOL, "result": "server not registered"}
            current = s.session
            if not _wait_fresh_session(s, current):
                return {"ok": False, "tool": TOOL, "result": "no fresh ready session"}

            async def _call():
                async with s._rpc_lock:
                    result = await s.session.call_tool(
                        "echo", arguments={"message": "reconnect-probe"}
                    )
                from tools.mcp_tool_handlers import _render_call_tool_result

                return _render_call_tool_result(result, SERVER_NAME)

            try:
                out = mcp_tool_loop._run_on_mcp_loop(_call, timeout=30.0)
            except Exception as exc:  # noqa: BLE001
                return {"ok": False, "tool": TOOL, "result": f"{type(exc).__name__}: {exc}"}
            return {"ok": True, "tool": TOOL, "result": str(out)[:200]}

        server = OwningClientServer(
            home=str(tmp_path / "hermes-home"),
            state_root=root,
            socket_path=str(tmp_path / "s.sock"),
            profile_id="default",
            client_id="host:default",
            reconnector=native_reconnector,  # REAL native reconnector
            server_registry=native_server_registry,  # REAL native registry
            probe_caller=probe_caller,  # REAL MCP tool call through the recovered server
            policy_check=lambda tool, payload: None,
            clock=lambda: 0.0,
        )
        path = server.start()
        try:
            adapter = OwningClientAdapter(
                root, store=store, socket_path=path, clock=lambda: 0.0, deadline=60.0,
            )
            reply = adapter.request_mcp_reconnect("inc-1", SERVER_NAME)
        finally:
            server.stop()

        assert reply.status == "ok"
        assert reply.capability_proof["verdict"] == "PASS"
        assert reply.op_result["kind"] == "mcp_status"
        assert reply.op_result["verdict"] == "PASS"

        # 5. Recovery: an ACTUAL MCP tool call succeeds through the recovered
        # server in the original owner context.
        out2 = registry.dispatch(TOOL, {"message": "after-recovery"})
        assert "ECHO:after-recovery" in str(out2)

        # The recovered server is a NEW child process (the old one is dead).
        new_pid = int(Path(pid_file).read_text())
        assert new_pid != old_pid

        # 6. DURABLE typed proof: re-read from a FRESH store instance.
        fresh_store = IncidentStore(root)
        inc = fresh_store.get_incident("inc-1")
        assert inc is not None
        mcp_ops = [op for op in inc.mutation_plan if op.kind == "mcp_status"]
        assert mcp_ops, "no typed mcp_status proof in the durable mutation_plan"
        assert mcp_ops[-1].verdict is Verdict.PASS
        assert mcp_ops[-1].client_id == "host:default"
    finally:
        # Tear down the fixture MCP connection and stop the MCP loop so no
        # daemon thread or child process leaks into later tests.
        shutdown_mcp_servers(timeout=15.0)


# ---------------------------------------------------------------------------
# Task 13 code-quality fixes: per-connection read deadline + bounded request_id
# ---------------------------------------------------------------------------


def test_envelope_rejects_overlong_request_id():
    # An uncapped request_id doubles as a receipt filename component: it must be
    # bounded so a hostile long id cannot produce errno 36 (ENAMETOOLONG).
    from operator_guards.common.ipc import IpcError, validate_envelope

    with pytest.raises(IpcError):
        validate_envelope(_envelope(request_id="r" * 10_000))


def test_envelope_rejects_unsafe_request_id_chars():
    from operator_guards.common.ipc import IpcError, validate_envelope

    with pytest.raises(IpcError):
        validate_envelope(_envelope(request_id="../etc/passwd"))


def test_receipt_store_bounds_pathological_request_id_filename(tmp_path):
    # A very long (filesystem-safe) request_id must never yield errno 36
    # (ENAMETOOLONG): the receipt filename derives from a hash, not the raw id.
    from operator_guards.r2d2.client import ReceiptStore

    store = _receipts(tmp_path)
    hostile = "a" * 10_000
    store.record_queued(hostile, 1, "hash-a", "inc-1")  # must NOT raise OSError
    rec = store.lookup(hostile)
    assert rec is not None
    assert rec["request_id"] == hostile  # the record keeps the raw id ...
    # ... but the on-disk filename is bounded (hashed), and list() reads it back.
    recs = store.list()
    assert len(recs) == 1
    assert recs[0]["request_id"] == hostile


def test_stalled_partial_frame_peer_does_not_block_second_client(tmp_path):
    # A peer that opens a connection and sends only a PARTIAL frame must be cut
    # off by the per-connection read deadline, and must NOT starve a second
    # client that sends a complete request.
    from operator_guards.r2d2.client import OwningClientAdapter

    root = str(tmp_path / "r2d2")
    server, store = _server(tmp_path, recv_timeout=0.2, frame_deadline=0.5)
    path = server.start()
    stalled = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        stalled.connect(path)
        # A PARTIAL frame: the 4-byte header declares 100 bytes but only 3 sent.
        stalled.sendall(struct.pack(">I", 100) + b"xyz")
        time.sleep(0.1)  # let the server accept + block on the partial frame

        # A SECOND client still completes a full request end-to-end.
        adapter = OwningClientAdapter(
            root, store=store, socket_path=path, clock=lambda: 0.0, deadline=3.0,
        )
        reply = adapter.request_mcp_reconnect("inc-1", "demo-server")
        assert reply.status == "ok"

        # The stalled connection is closed once its read deadline elapses.
        stalled.settimeout(3.0)
        assert stalled.recv(1) == b""  # EOF: the server closed the stalled peer
    finally:
        server.stop()
        stalled.close()


def test_server_rejects_connection_beyond_inflight_cap(tmp_path):
    # Concurrency is bounded: connections beyond the in-flight cap are rejected
    # (closed immediately) rather than queued unboundedly.
    server, _ = _server(tmp_path, recv_timeout=5.0, frame_deadline=5.0, max_connections=2)
    path = server.start()
    conns = []
    try:
        for _ in range(2):
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.connect(path)
            c.sendall(struct.pack(">I", 100) + b"x")  # partial frame holds a slot
            conns.append(c)
        time.sleep(0.2)  # both accepted and blocked on their partial frames
        third = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        third.connect(path)
        third.settimeout(2.0)
        assert third.recv(1) == b""  # rejected at the cap: closed immediately
        third.close()
    finally:
        server.stop()
        for c in conns:
            try:
                c.close()
            except OSError:
                pass

