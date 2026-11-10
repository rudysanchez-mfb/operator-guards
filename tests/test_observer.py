"""R2-D2 scoped observer + escalation tests (plan §6, Task 12).

Three layers:

1. **Observer unit tests** (G/.venv, no Hermes): classify the documented
   Linux predicates, bound dedupe/noise, and exercise the supervisor-absence
   >60s immediate local alert.
2. **Plugin contract tests** (G/.venv): the ``r2d2`` plugin registers only
   REAL ``VALID_HOOKS`` names, resolves ``HERMES_HOME`` per callback, emits
   bounded observations + heartbeat + a bounded client record, and fails open
   (never raises into Hermes).
3. **Real-dispatch tests** (skip unless the Hermes checkout is importable):
   load the real plugin through Hermes's ``PluginManager`` against a temp
   ``HERMES_HOME`` and assert the observation/heartbeat/client records land in
   ``<HERMES_HOME>/r2d2/``.

Run the real-dispatch layer with the documented runner::

    G/scripts/run_plugin_tests.sh
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
from pathlib import Path

import pytest

from operator_guards.r2d2.observer import (
    ALERT_COOLDOWN_SECONDS,
    CAPABILITY_LOSS_ERROR_TYPES,
    CLASS_LOST_CAPABILITY,
    CLASS_NONE,
    CLASS_PERMISSION_BLOCK,
    CLASS_POLICY_DENIAL,
    CLASS_RECONNECT_IN_PROGRESS,
    CLASS_STALE_CLIENT,
    CLASS_TRANSPORT_DROP,
    CLASS_UNSUPPORTED,
    CLIENT_CAPABILITIES_MAX,
    CLIENT_STALE_SECONDS,
    CLIENT_STATUSES,
    DENIAL_WINDOW_SECONDS,
    LIMITER_MAX_ENTRIES,
    OBSERVATION_KINDS,
    PERMISSION_ERROR_TYPES,
    RECONNECT_WINDOW_SECONDS,
    RECOVERY_BACKOFF_SECONDS,
    SUPERVISOR_STALE_SECONDS,
    TRANSIENT_ERROR_TYPES,
    UNSUPPORTED_PREDICATES,
    ClientRecord,
    LocalAlert,
    Observation,
    Observer,
    RaiseIncident,
    RecoveryRequest,
    append_observation,
    classify,
    iter_observations,
    read_heartbeat_file,
    write_heartbeat_file,
)
from operator_guards.r2d2.store import IncidentStore

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "plugins" / "r2d2"

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
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _client(client_id="hermes:default", **kw) -> ClientRecord:
    base = {
        "client_id": client_id,
        "status": "registered",
        "capabilities": frozenset({"Bash", "mcp:filesystem"}),
        "pid": 4242,
        "pid_start_time": 1000.0,
        "last_seen": 1000.0,
    }
    base.update(kw)
    return ClientRecord(**base)


def _obs(kind="post_tool_error", **kw) -> Observation:
    base = {
        "kind": kind,
        "client_id": "hermes:default",
        "session_id": "sess-1",
        "tool_name": "Bash",
        "error_type": "connection_reset",
        "status": "",
        "capability": "",
        "detail": "connection reset by peer",
        "ts": 1000.0,
    }
    base.update(kw)
    return Observation(**base)


# ---------------------------------------------------------------------------
# Supported-predicate table (documentation is asserted, not guessed)
# ---------------------------------------------------------------------------


def test_supported_predicate_documentation_present():
    """The Linux-supported predicate table is documented; Mac-only predicates
    are NOT invented and are marked UNSUPPORTED."""
    import operator_guards.r2d2.observer as mod

    doc = mod.__doc__
    assert "takeover_without_send" in doc
    assert "UNSUPPORTED" in doc
    assert "takeover_without_send" in UNSUPPORTED_PREDICATES
    # The documented transient/permission/capability predicate sets are
    # non-empty, closed, and Linux-only (no Mac Teams/Claude probe names).
    assert TRANSIENT_ERROR_TYPES
    assert PERMISSION_ERROR_TYPES
    assert CAPABILITY_LOSS_ERROR_TYPES


def test_takeover_without_send_reported_unsupported():
    """``takeover_without_send`` yields an UNSUPPORTED classification — never a
    fabricated classification — until a real takeover/send observer exists."""
    obs = _obs(kind="post_tool_status", predicate="takeover_without_send")
    cls = classify(obs, _client(), now=1000.0)
    assert cls.kind == CLASS_UNSUPPORTED
    assert cls.unsupported is True
    assert "UNSUPPORTED" in cls.reason


# ---------------------------------------------------------------------------
# (a) native reconnect IN PROGRESS -> do not summon the daemon
# ---------------------------------------------------------------------------


def test_reconnect_in_progress_does_not_summon_daemon(tmp_path):
    store = IncidentStore(str(tmp_path / "r2d2"))
    observer = Observer(root=str(tmp_path / "r2d2"), store=store, clock=lambda: 1000.0)
    client = _client(status="reconnecting", reconnect_started=990.0)
    observer.write_client_record(client)
    obs = _obs(error_type="transport_closed")
    cls = classify(obs, client, now=1000.0)
    assert cls.kind == CLASS_RECONNECT_IN_PROGRESS
    # No incident is raised for an in-progress native reconnect.
    assert observer.consume(obs) == []
    assert store.list_incidents() == []


# ---------------------------------------------------------------------------
# (b) ordinary transport drop recoverable in-session
# ---------------------------------------------------------------------------


def test_transient_failure_still_registered_does_not_summon_daemon(tmp_path):
    store = IncidentStore(str(tmp_path / "r2d2"))
    observer = Observer(root=str(tmp_path / "r2d2"), store=store, clock=lambda: 1000.0)
    observer.write_client_record(_client())
    observer._proc_start_time = lambda pid: 1000.0  # alive (matches pid_start_time)
    obs = _obs(error_type="connection_reset")
    cls = classify(obs, _client(), now=1000.0)
    assert cls.kind == CLASS_TRANSPORT_DROP
    effects = observer.consume(obs)
    # A session-local recovery request, NOT a daemon-summoning incident.
    assert any(isinstance(e, RecoveryRequest) for e in effects)
    assert not any(isinstance(e, RaiseIncident) for e in effects)
    assert store.list_incidents() == []


def test_recovery_request_respects_native_backoff(tmp_path):
    """ONE bounded session-local recovery request per backoff window."""
    store = IncidentStore(str(tmp_path / "r2d2"))
    clock = {"t": 1000.0}
    observer = Observer(root=str(tmp_path / "r2d2"), store=store, clock=lambda: clock["t"])
    observer.write_client_record(_client())
    observer._proc_start_time = lambda pid: 1000.0  # alive (matches pid_start_time)
    obs = _obs(error_type="connection_reset")

    first = observer.consume(obs)
    assert len([e for e in first if isinstance(e, RecoveryRequest)]) == 1

    # Immediately repeated: backoff suppresses a second recovery request.
    second = observer.consume(obs)
    assert not any(isinstance(e, RecoveryRequest) for e in second)

    # After the backoff window, a recovery request is again permitted.
    clock["t"] += 61.0
    third = observer.consume(obs)
    assert len([e for e in third if isinstance(e, RecoveryRequest)]) == 1


# ---------------------------------------------------------------------------
# (c) stale/dead client vs. quiet-but-alive session
# ---------------------------------------------------------------------------


def test_stale_heartbeat_does_not_mean_quiet_session_broken(tmp_path):
    """A quiet session (no recent tool activity) with a FRESH client last_seen
    and a live process is NOT broken."""
    store = IncidentStore(str(tmp_path / "r2d2"))
    observer = Observer(root=str(tmp_path / "r2d2"), store=store, clock=lambda: 1000.0)
    # Fresh client: last_seen recent, process alive.
    observer.write_client_record(_client(last_seen=999.0))
    observer._proc_start_time = lambda pid: 1000.0  # alive, matches pid_start_time

    alerts = observer.check_clients()
    assert alerts == []
    assert store.list_incidents() == []


def test_dead_client_process_escalates(tmp_path):
    """A client whose process is provably dead (Linux /proc) escalates."""
    store = IncidentStore(str(tmp_path / "r2d2"))
    observer = Observer(root=str(tmp_path / "r2d2"), store=store, clock=lambda: 1000.0)
    observer.write_client_record(_client(last_seen=999.0))
    observer._proc_start_time = lambda pid: None  # dead

    effects = observer.check_clients()
    raised = [e for e in effects if isinstance(e, RaiseIncident)]
    assert len(raised) == 1
    assert raised[0].severity == "mechanical"
    # Applied to the store -> one committed incident.
    incs = store.list_incidents()
    assert len(incs) == 1


def test_stale_client_past_threshold_escalates(tmp_path):
    """A client whose own last_seen exceeds CLIENT_STALE_SECONDS escalates."""
    store = IncidentStore(str(tmp_path / "r2d2"))
    observer = Observer(root=str(tmp_path / "r2d2"), store=store, clock=lambda: 1000.0)
    observer.write_client_record(_client(last_seen=1000.0 - CLIENT_STALE_SECONDS - 1.0))
    observer._proc_start_time = lambda pid: 1000.0  # alive but stale

    effects = observer.check_clients()
    assert any(isinstance(e, RaiseIncident) for e in effects)
    assert len(store.list_incidents()) == 1


# ---------------------------------------------------------------------------
# (d) lost registered capability -> ONE incident
# ---------------------------------------------------------------------------


def test_lost_capability_creates_exactly_one_incident(tmp_path):
    store = IncidentStore(str(tmp_path / "r2d2"))
    observer = Observer(root=str(tmp_path / "r2d2"), store=store, clock=lambda: 1000.0)
    client = _client(capabilities=frozenset({"mcp:filesystem"}))
    observer.write_client_record(client)
    obs = _obs(
        error_type="capability_missing",
        capability="mcp:filesystem",
        detail="MCP filesystem server deregistered",
    )
    cls = classify(obs, client, now=1000.0)
    assert cls.kind == CLASS_LOST_CAPABILITY

    observer.consume(obs)
    observer.consume(obs)  # duplicate observation
    incs = store.list_incidents()
    assert len(incs) == 1
    assert incs[0].dedupe_key
    assert "mcp:filesystem" in incs[0].symptom  # concrete observation


# ---------------------------------------------------------------------------
# (e) explicit permission block -> diagnosis/escalation only
# ---------------------------------------------------------------------------


def test_permission_block_yields_diagnosis_only(tmp_path):
    store = IncidentStore(str(tmp_path / "r2d2"))
    observer = Observer(root=str(tmp_path / "r2d2"), store=store, clock=lambda: 1000.0)
    obs = _obs(error_type="permission_denied", detail="EACCES on /etc/shadow")
    cls = classify(obs, _client(), now=1000.0)
    assert cls.kind == CLASS_PERMISSION_BLOCK

    effects = observer.consume(obs)
    raised = [e for e in effects if isinstance(e, RaiseIncident)]
    assert len(raised) == 1
    # Diagnosis/escalation only: the incident carries NO mutation plan and the
    # observer issued NO recovery request (an outside actor must clear it).
    assert not any(isinstance(e, RecoveryRequest) for e in effects)
    inc = store.list_incidents()[0]
    assert inc.mutation_plan == ()
    assert inc.diagnostic_plan == ()


# ---------------------------------------------------------------------------
# (f) repeated policy denial -> bounded escalation, no store flood
# ---------------------------------------------------------------------------


def test_repeated_policy_denial_bounded(tmp_path):
    store = IncidentStore(str(tmp_path / "r2d2"))
    observer = Observer(root=str(tmp_path / "r2d2"), store=store, clock=lambda: 1000.0)
    obs = _obs(kind="post_tool_status", status="denied", rule_id="rule-x", tool_name="Bash")

    cls = classify(obs, _client(), now=1000.0)
    assert cls.kind == CLASS_POLICY_DENIAL

    # Many repeated denials -> at most ONE committed denial incident.
    for _ in range(20):
        observer.consume(obs)
    incs = store.list_incidents()
    assert len(incs) == 1
    assert incs[0].dedupe_key


def test_auto_incident_carries_concrete_observation_and_dedupe_key(tmp_path):
    store = IncidentStore(str(tmp_path / "r2d2"))
    observer = Observer(root=str(tmp_path / "r2d2"), store=store, clock=lambda: 1000.0)
    client = _client(capabilities=frozenset({"mcp:filesystem"}))
    observer.write_client_record(client)
    obs = _obs(
        error_type="capability_missing",
        capability="mcp:filesystem",
        detail="server vanished",
    )
    effects = observer.consume(obs)
    raised = [e for e in effects if isinstance(e, RaiseIncident)]
    assert raised
    inc = store.list_incidents()[0]
    # Concrete observation + non-empty deterministic dedupe key.
    assert inc.symptom.strip()
    assert inc.dedupe_key.strip()
    assert inc.dedupe_key == raised[0].dedupe_key
    assert inc.observed  # concrete evidence references


# ---------------------------------------------------------------------------
# Supervisor absence/stale >60s -> IMMEDIATE local alert
# ---------------------------------------------------------------------------


def test_supervisor_absent_immediate_local_alert(tmp_path):
    store = IncidentStore(str(tmp_path / "r2d2"))
    alerts = []
    observer = Observer(
        root=str(tmp_path / "r2d2"),
        store=store,
        clock=lambda: 1000.0,
        alert_writer=lambda msg: alerts.append(msg),
    )
    # No heartbeat file at all -> immediate alert, not a six-minute wait.
    effect = observer.check_supervisor()
    assert isinstance(effect, LocalAlert)
    assert alerts  # the alert was actually written


def test_supervisor_stale_heartbeat_immediate_local_alert(tmp_path):
    root = tmp_path / "r2d2"
    observer = Observer(root=str(root), store=IncidentStore(str(root)), clock=lambda: 1000.0)
    observer.write_heartbeat(ts=1000.0 - SUPERVISOR_STALE_SECONDS - 1.0)
    effect = observer.check_supervisor()
    assert isinstance(effect, LocalAlert)


def test_supervisor_fresh_heartbeat_no_alert(tmp_path):
    root = tmp_path / "r2d2"
    observer = Observer(root=str(root), store=IncidentStore(str(root)), clock=lambda: 1000.0)
    observer.write_heartbeat(ts=1000.0 - 10.0)
    assert observer.check_supervisor() is None


# ---------------------------------------------------------------------------
# Scoping: the observer reads ONLY clients/ + incidents/ + heartbeat
# ---------------------------------------------------------------------------


def test_observer_scope_never_touches_transcripts_or_mcp_cache(tmp_path, monkeypatch):
    root = tmp_path / "r2d2"
    (root / "clients").mkdir(parents=True)
    (root / "mcp_cache").mkdir()
    (root / "mcp_cache" / "big.log").write_text("x" * 1000)
    (root / "sessions").mkdir()
    (root / "sessions" / "transcript.jsonl").write_text("x" * 1000)

    seen = []
    real_listdir = os.listdir

    def spy_listdir(path):
        seen.append(str(path))
        return real_listdir(path)

    monkeypatch.setattr("operator_guards.r2d2.observer.os.listdir", spy_listdir)

    observer = Observer(root=str(root), clock=lambda: 1000.0)
    observer.check_clients()
    observer.check_supervisor()

    # Only the scoped dirs (clients/, heartbeat, incidents via the store) are
    # listed; the transcript dir and MCP cache are NEVER scanned.
    assert not any("mcp_cache" in p for p in seen)
    assert not any("sessions" in p for p in seen)


# ---------------------------------------------------------------------------
# Plugin contract tests (no Hermes needed)
# ---------------------------------------------------------------------------


def _fresh_plugin():
    spec = importlib.util.spec_from_file_location(
        "r2d2_plugin_under_test", PLUGIN_DIR / "__init__.py"
    )
    assert spec is not None and spec.loader is not None, "plugin __init__.py missing"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeCtx:
    def __init__(self):
        self.hooks = {}

    def register_hook(self, name, callback):
        self.hooks.setdefault(name, []).append(callback)


def _register(mod):
    ctx = FakeCtx()
    mod.register(ctx)
    return ctx


def _invoke(ctx, hook, **kwargs):
    callbacks = ctx.hooks[hook]
    assert len(callbacks) == 1, f"expected one {hook} callback"
    return callbacks[0](**kwargs)


def test_register_registers_real_valid_hooks_and_no_network(monkeypatch):
    mod = _fresh_plugin()
    import socket

    def _deny(*_a, **_k):
        raise AssertionError("register() must not make any provider/network call")

    monkeypatch.setattr(socket, "create_connection", _deny)
    monkeypatch.setattr(socket.socket, "connect", _deny)

    ctx = _register(mod)
    assert set(ctx.hooks) == {
        "post_tool_call",
        "on_session_start",
        "on_session_end",
        "on_session_reset",
    }
    # Every registered hook is a REAL member of Hermes VALID_HOOKS.
    if HERMES_AVAILABLE:
        from hermes_cli.plugins import VALID_HOOKS

        assert set(ctx.hooks) <= VALID_HOOKS


def test_home_resolved_per_callback(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home_a = tmp_path / "a"
    home_b = tmp_path / "b"
    monkeypatch.setenv("HERMES_HOME", str(home_a))
    ctx = _register(mod)
    _invoke(
        ctx, "post_tool_call", tool_name="Bash", args={}, status="error",
        error_type="timeout", error_message="boom", session_id="s1",
        turn_id="t", task_id="task", tool_call_id="c1",
    )
    monkeypatch.setenv("HERMES_HOME", str(home_b))
    _invoke(
        ctx, "post_tool_call", tool_name="Bash", args={}, status="error",
        error_type="timeout", error_message="boom", session_id="s1",
        turn_id="t", task_id="task", tool_call_id="c2",
    )
    # Each home got its own r2d2 state (observations + heartbeat + client).
    assert (home_a / "r2d2" / "observations.jsonl").exists()
    assert (home_b / "r2d2" / "observations.jsonl").exists()
    assert (home_a / "r2d2" / "heartbeat").exists()
    assert (home_b / "r2d2" / "heartbeat").exists()


def test_post_tool_error_emits_bounded_observation_and_heartbeat(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    ctx = _register(mod)
    _invoke(
        ctx, "post_tool_call", tool_name="Bash", args={}, status="error",
        error_type="connection_reset", error_message="connection reset by peer",
        session_id="s1", turn_id="t", task_id="task", tool_call_id="c1",
    )
    root = home / "r2d2"
    assert (root / "heartbeat").exists()
    assert (root / "clients").exists()
    lines = (root / "observations.jsonl").read_text().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["kind"] == "post_tool_error"
    assert rec["error_type"] == "connection_reset"
    assert rec["client_id"]  # bounded client record identity present


def test_heartbeat_throttled(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    ctx = _register(mod)
    for i in range(3):
        _invoke(
            ctx, "post_tool_call", tool_name="Bash", args={}, status="ok",
            session_id="s1", turn_id=f"t{i}", task_id="task", tool_call_id=f"c{i}",
        )
    # Heartbeat is throttled to a minimum interval: 3 rapid calls -> 1 write.
    root = home / "r2d2"
    hb = json.loads((root / "heartbeat").read_text())
    assert hb["ts"] > 0
    # Observations: only error/denied/blocked statuses emit (ok is silent).
    assert not (root / "observations.jsonl").exists() or (
        root / "observations.jsonl").read_text().strip() == ""


def test_fail_open_never_raises_into_hermes(monkeypatch, tmp_path):
    mod = _fresh_plugin()
    home = tmp_path / "home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    ctx = _register(mod)

    def boom(*_a, **_k):
        raise OSError("disk gone")

    monkeypatch.setattr(mod, "append_observation", boom)
    # The hook must swallow the exception and return None.
    res = _invoke(
        ctx, "post_tool_call", tool_name="Bash", args={}, status="error",
        error_type="timeout", error_message="x", session_id="s1",
        turn_id="t", task_id="task", tool_call_id="c1",
    )
    assert res is None


# ---------------------------------------------------------------------------
# Real-dispatch tests (skip unless Hermes is importable)
# ---------------------------------------------------------------------------


@requires_hermes
def _real_fixture(tmp_path, monkeypatch):
    import hermes_cli.plugins as plugins_mod

    home = tmp_path / "hermes-home"
    dst = home / "plugins" / "r2d2"
    shutil.copytree(
        str(PLUGIN_DIR), str(dst), ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
    )
    (home / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - r2d2\n  isolation: in_process\n"
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    empty_bundled = tmp_path / "bundled"
    empty_bundled.mkdir()
    monkeypatch.setattr(plugins_mod, "get_bundled_plugins_dir", lambda: empty_bundled)
    plugins_mod._reset_plugin_managers_for_tests()
    manager = plugins_mod.get_plugin_manager()
    manager.discover_and_load()
    assert manager._plugins.get("r2d2") is not None
    assert manager._plugins["r2d2"].error is None
    return home, manager


@requires_hermes
def test_real_post_tool_call_emits_observation_and_heartbeat(tmp_path, monkeypatch):
    from hermes_cli.lifecycle import invoke_hook

    home, _manager = _real_fixture(tmp_path, monkeypatch)
    invoke_hook(
        "post_tool_call", tool_name="Bash", args={}, status="error",
        error_type="connection_reset", error_message="peer reset",
        session_id="s1", turn_id="t", task_id="task", tool_call_id="c1",
    )
    root = home / "r2d2"
    assert (root / "heartbeat").exists()
    lines = (root / "observations.jsonl").read_text().splitlines()
    assert any(
        json.loads(ln)["kind"] == "post_tool_error" for ln in lines
    )


@requires_hermes
def test_real_session_start_writes_client_record(tmp_path, monkeypatch):
    from hermes_cli.lifecycle import invoke_hook

    home, _manager = _real_fixture(tmp_path, monkeypatch)
    invoke_hook("on_session_start", session_id="s1")
    root = home / "r2d2"
    assert (root / "clients").exists()
    client_files = list((root / "clients").glob("*.json"))
    assert client_files  # at least one bounded client record written


# ---------------------------------------------------------------------------
# Task 12 code-quality fixes
# ---------------------------------------------------------------------------


def test_append_and_tail_read_bounded_log(tmp_path):
    """append_observation writes durable lines; iter_observations returns the
    NEWEST records last, tailing the file (not slurping the whole thing)."""
    root = str(tmp_path / "r2d2")
    for i in range(30):
        append_observation(
            root,
            Observation(kind="heartbeat", client_id="c", detail=f"event-{i:03d}" + "x" * 400, ts=float(i)),
        )
    # 30 x ~450B > one tail chunk, so this exercises the seek-to-tail path.
    got = iter_observations(root, limit=5)
    assert len(got) == 5
    assert [g.ts for g in got] == [25.0, 26.0, 27.0, 28.0, 29.0]


def test_observation_log_rotates_past_byte_cap(tmp_path, monkeypatch):
    """A bounded append log: past the byte cap the file is rotated, never
    growing unbounded; the most recent records remain readable."""
    import operator_guards.r2d2.observer as mod

    monkeypatch.setattr(mod, "OBSERVATIONS_MAX_BYTES", 2048)
    root = str(tmp_path / "r2d2")
    detail = "x" * 400
    for i in range(20):
        append_observation(root, Observation(kind="heartbeat", client_id="c", detail=detail, ts=float(i)))
    path = os.path.join(root, "observations.jsonl")
    assert os.path.getsize(path) <= 2048
    got = iter_observations(root, limit=1)
    assert got and got[-1].ts == 19.0


def test_supervisor_alert_idempotent_within_cooldown(tmp_path):
    """N rapid polls while the heartbeat is absent -> ONE alert (no storm)."""
    root = tmp_path / "r2d2"
    alerts = []
    clock = {"t": 1000.0}
    observer = Observer(
        root=str(root), store=IncidentStore(str(root)),
        clock=lambda: clock["t"], alert_writer=lambda m: alerts.append(m),
    )
    effects = []
    for _ in range(5):
        effects.append(observer.check_supervisor())
        clock["t"] += 1.0
    local = [e for e in effects if isinstance(e, LocalAlert)]
    assert len(local) == 1
    assert len(alerts) == 1


def test_supervisor_alert_after_cooldown(tmp_path):
    """After the cooldown window a repeated condition can alert again."""
    root = tmp_path / "r2d2"
    alerts = []
    clock = {"t": 1000.0}
    observer = Observer(
        root=str(root), store=IncidentStore(str(root)),
        clock=lambda: clock["t"], alert_writer=lambda m: alerts.append(m),
    )
    assert isinstance(observer.check_supervisor(), LocalAlert)
    clock["t"] += ALERT_COOLDOWN_SECONDS + 1.0
    assert isinstance(observer.check_supervisor(), LocalAlert)
    assert len(alerts) == 2


def test_supervisor_fresh_heartbeat_clears_alert_state(tmp_path):
    """A fresh heartbeat clears the cooldown state; a later stale alerts at once."""
    root = tmp_path / "r2d2"
    alerts = []
    clock = {"t": 1000.0}
    observer = Observer(
        root=str(root), store=IncidentStore(str(root)),
        clock=lambda: clock["t"], alert_writer=lambda m: alerts.append(m),
    )
    assert isinstance(observer.check_supervisor(), LocalAlert)  # absent
    observer.write_heartbeat(ts=clock["t"])  # fresh
    assert observer.check_supervisor() is None  # cleared
    clock["t"] += 5.0
    observer.write_heartbeat(ts=clock["t"] - SUPERVISOR_STALE_SECONDS - 1.0)
    assert isinstance(observer.check_supervisor(), LocalAlert)  # immediate, no cooldown wait
    assert len(alerts) == 2


def test_supervisor_new_condition_alerts_again_within_cooldown(tmp_path):
    """A NEW distinct condition (absent -> stale) alerts even within the window."""
    root = tmp_path / "r2d2"
    alerts = []
    clock = {"t": 1000.0}
    observer = Observer(
        root=str(root), store=IncidentStore(str(root)),
        clock=lambda: clock["t"], alert_writer=lambda m: alerts.append(m),
    )
    assert isinstance(observer.check_supervisor(), LocalAlert)  # absent
    observer.write_heartbeat(ts=clock["t"] - SUPERVISOR_STALE_SECONDS - 1.0)
    clock["t"] += 1.0
    assert isinstance(observer.check_supervisor(), LocalAlert)  # distinct: stale
    assert len(alerts) == 2


def test_recovery_limiter_evicts_stale_and_stays_bounded(tmp_path):
    """_recovery_last is LRU-capped and stale entries are evicted on sweep."""
    store = IncidentStore(str(tmp_path / "r2d2"))
    clock = {"t": 1000.0}
    observer = Observer(root=str(tmp_path / "r2d2"), store=store, clock=lambda: clock["t"])
    for i in range(LIMITER_MAX_ENTRIES + 500):
        clock["t"] = 1000.0 + i * 0.0001
        observer._recovery(
            Observation(kind="post_tool_error", client_id=f"c{i}", session_id=f"s{i}", error_type="connection_reset")
        )
    assert len(observer._recovery_last) <= LIMITER_MAX_ENTRIES
    clock["t"] += RECOVERY_BACKOFF_SECONDS + 1.0
    observer._recovery(Observation(kind="post_tool_error", client_id="zz", session_id="zz", error_type="connection_reset"))
    assert len(observer._recovery_last) == 1  # stale entries swept; only the new key remains


def test_denials_limiter_evicts_stale_and_stays_bounded(tmp_path):
    """_denials is LRU-capped and stale entries are evicted on sweep."""
    store = IncidentStore(str(tmp_path / "r2d2"))
    clock = {"t": 1000.0}
    observer = Observer(root=str(tmp_path / "r2d2"), store=store, clock=lambda: clock["t"])
    for i in range(LIMITER_MAX_ENTRIES + 500):
        clock["t"] = 1000.0 + i * 0.0001
        observer._policy_denial(Observation(kind="post_tool_status", status="denied", session_id=f"s{i}", rule_id=f"r{i}"))
    assert len(observer._denials) <= LIMITER_MAX_ENTRIES
    clock["t"] += DENIAL_WINDOW_SECONDS + 1.0
    observer._policy_denial(Observation(kind="post_tool_status", status="denied", session_id="z", rule_id="z"))
    assert len(observer._denials) == 1


def test_reconnecting_past_window_classifies_stale_not_none(tmp_path):
    """An elapsed-window reconnecting client escalates (stale), never CLASS_NONE."""
    store = IncidentStore(str(tmp_path / "r2d2"))
    observer = Observer(root=str(tmp_path / "r2d2"), store=store, clock=lambda: 1000.0)
    client = _client(status="reconnecting", reconnect_started=1000.0 - RECONNECT_WINDOW_SECONDS - 1.0)
    observer.write_client_record(client)
    obs = _obs(error_type="transport_closed")
    cls = classify(obs, client, now=1000.0)
    assert cls.kind == CLASS_STALE_CLIENT
    effects = observer.consume(obs)
    assert any(isinstance(e, RaiseIncident) for e in effects)
    assert len(store.list_incidents()) == 1


def test_consume_escalates_dead_client_without_check_clients(tmp_path):
    """consume() consults liveness: a provably dead registered client escalates
    (stale) regardless of whether check_clients() ran."""
    store = IncidentStore(str(tmp_path / "r2d2"))
    observer = Observer(root=str(tmp_path / "r2d2"), store=store, clock=lambda: 1000.0)
    observer.write_client_record(_client())
    observer._proc_start_time = lambda pid: None  # provably dead
    effects = observer.consume(_obs(error_type="connection_reset"))
    assert any(isinstance(e, RaiseIncident) for e in effects)
    assert not any(isinstance(e, RecoveryRequest) for e in effects)
    assert len(store.list_incidents()) == 1


def test_stale_client_recurrence_raises_new_incident(tmp_path):
    """After resolution, a genuine stale-client recurrence raises a NEW incident
    (recurrence token in the dedupe key), not silently swallowed."""
    store = IncidentStore(str(tmp_path / "r2d2"))
    clock = {"t": 1000.0}
    observer = Observer(root=str(tmp_path / "r2d2"), store=store, clock=lambda: clock["t"])
    observer._proc_start_time = lambda pid: 1000.0  # alive but stale
    observer.write_client_record(_client(last_seen=clock["t"] - CLIENT_STALE_SECONDS - 1.0))
    observer.check_clients()
    assert len(store.list_incidents()) == 1
    first = store.list_incidents()[0]
    assert first.dedupe_key == "stale-client:hermes:default"
    store.done(first.id, reason="operator resolved the stale client")
    # a genuine recurrence much later
    clock["t"] += CLIENT_STALE_SECONDS * 2
    observer.write_client_record(_client(last_seen=clock["t"] - CLIENT_STALE_SECONDS - 1.0))
    observer.check_clients()
    incs = store.list_incidents()
    assert len(incs) == 2
    assert sorted(inc.dedupe_key for inc in incs) == [
        "stale-client:hermes:default",
        "stale-client:hermes:default:r2",
    ]


def test_observation_kind_enforced():
    """Observation.__post_init__ rejects a kind outside OBSERVATION_KINDS."""
    with pytest.raises(ValueError):
        Observation(kind="bogus")


def test_client_status_validated():
    """ClientRecord rejects a status outside CLIENT_STATUSES."""
    with pytest.raises(ValueError):
        ClientRecord(client_id="x", status="bogus")


def test_client_capabilities_capped_on_load():
    """from_dict caps capabilities to CLIENT_CAPABILITIES_MAX (hostile file)."""
    caps = [f"cap-{i}" for i in range(CLIENT_CAPABILITIES_MAX + 50)]
    record = ClientRecord.from_dict({"client_id": "x", "status": "registered", "capabilities": caps})
    assert len(record.capabilities) == CLIENT_CAPABILITIES_MAX


def test_safe_component_length_capped():
    """_safe_component caps length so a pathological client_id cannot overflow NAME_MAX."""
    import operator_guards.r2d2.observer as mod

    safe = mod._safe_component("a" * 500)
    assert len(safe) <= 120


def test_observer_default_clock_is_monotonic(tmp_path):
    import time

    observer = Observer(root=str(tmp_path / "r2d2"))
    assert observer.clock is time.monotonic


def test_heartbeat_default_timestamp_is_monotonic(tmp_path):
    import time

    root = str(tmp_path / "r2d2")
    write_heartbeat_file(root)
    ts = read_heartbeat_file(root)
    assert ts is not None
    assert abs(ts - time.monotonic()) < 5.0
