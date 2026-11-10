"""Durable R2-D2 incident store tests (plan §4/§6, leaf 9b).

Locks the write-ahead event log + snapshot durability contract with REAL
temp-filesystem operations (no mock-only coverage):

* lossless ``Incident <-> dict`` and ``OpResult <-> dict`` round-trips,
  including via JSON (what the event log actually persists);
* ``raise`` reports an id only after event AND state durability are confirmed;
* raise is idempotent by id and dedupe_key — a failed raise followed by a
  retry never yields two committed incidents;
* torn tails (partial JSON OR valid-JSON-without-newline) are sealed: the
  committed prefix is recovered once, prior bytes preserved, and subsequent
  records land in a NEW numbered segment; interior corruption stops recovery
  and escalates;
* failure injection at event-append / fsync / replace / dir-fsync / fdopen:
  nonzero result, no success id, no torn log tail, and a retry commits exactly
  one incident;
* ``done`` rejects a blank proof and bare prose, keeps manual closure
  distinct from verified (PASS) resolution.
"""

import json
import os
import stat
import subprocess
import sys
import threading

import pytest

from operator_guards.common.proof import Verdict
from operator_guards.r2d2.schema import (
    PHASE_ESCALATED,
    PHASE_RESOLVED,
    incident_from_dict,
    incident_to_dict,
    load_incident,
    load_op_result,
    op_result_from_dict,
    op_result_to_dict,
)
from operator_guards.r2d2.store import (
    IncidentStore,
    StoreCorruptionError,
    StoreError,
)


def _op(**overrides):
    op = {
        "op_id": "op-1",
        "kind": "exit_code",
        "verdict": "PASS",
        "expected": 0,
        "observed": [],
        "evidence": "ev-1",
        "started_at": 0.0,
        "ended_at": 0.0,
        "epoch": 0,
        "client_id": "client-1",
        "exit_status": 0,
    }
    op.update(overrides)
    return op


def _full_record():
    return {
        "id": "inc-full",
        "severity": "stuck_critical",
        "symptom": "mcp server down",
        "phase": "repairing",
        "dedupe_key": "dedupe-full",
        "schema_version": 1,
        "created_at": 1_700_000_000.25,
        "updated_at": 1_700_000_001.5,
        "host_id": "host-1",
        "profile_id": "prof-1",
        "client_id": "client-1",
        "session_id": "sess-1",
        "observed": ["obs-1", "obs-2"],
        "authorization": ["auth-1"],
        "diagnostic_plan": [_op(op_id="diag-1", kind="exit_code", expected=0)],
        "mutation_plan": [_op(op_id="mut-1", kind="contains", expected="ok", observed=["ok"])],
        "epoch": 3,
        "claimant": "worker-1",
        "lease": 900,
        "attempts": 2,
        "max_attempts": 3,
        "proof": "FAIL",
        "notification": "n/a",
    }


# ---------------------------------------------------------------------------
# Serialization round-trips (leaf 9b: lossless dataclass <-> dict)
# ---------------------------------------------------------------------------

def test_incident_to_from_dict_roundtrip_full():
    inc = load_incident(_full_record())
    assert incident_from_dict(incident_to_dict(inc)) == inc


def test_incident_to_from_dict_roundtrip_via_json():
    inc = load_incident(_full_record())
    data = json.loads(json.dumps(incident_to_dict(inc)))
    assert incident_from_dict(data) == inc


def test_minimal_incident_roundtrip(valid_incident):
    inc = load_incident(valid_incident)
    assert incident_from_dict(incident_to_dict(inc)) == inc


def test_resolved_incident_roundtrip():
    record = {
        "id": "inc-resolved",
        "severity": "blocked",
        "symptom": "s",
        "phase": "resolved",
        "dedupe_key": "d",
        "proof": "PASS",
        "mutation_plan": [_op()],
    }
    inc = load_incident(record)
    assert inc.proof is Verdict.PASS
    assert incident_from_dict(incident_to_dict(inc)) == inc


def test_op_result_to_from_dict_roundtrip():
    op = load_op_result(_op())
    assert op_result_from_dict(op_result_to_dict(op)) == op


def test_incident_to_dict_is_json_serializable():
    inc = load_incident(_full_record())
    json.dumps(incident_to_dict(inc))  # must not raise


# ---------------------------------------------------------------------------
# raise: durable commit + idempotency
# ---------------------------------------------------------------------------

def test_raise_reports_id_only_after_durable_commit(r2d2_cli, tmp_path):
    root = tmp_path / "r2d2"
    proc = r2d2_cli(
        "raise", "--id", "inc-a", "--severity", "mechanical", "--symptom", "s",
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "inc-a"
    # a FRESH reader sees the incident committed durably (event + snapshot)
    store = IncidentStore(str(root))
    assert store.get_incident("inc-a") is not None
    creates = [e for e in store.list_events() if e["type"] == "incident.created"]
    assert any(e["incident_id"] == "inc-a" for e in creates)


def test_raise_is_idempotent_by_id(r2d2_cli, tmp_path):
    root = tmp_path / "r2d2"
    args = ("raise", "--id", "inc-a", "--severity", "mechanical", "--symptom", "s")
    first = r2d2_cli(*args)
    second = r2d2_cli(*args)
    assert first.returncode == 0 and second.returncode == 0
    assert first.stdout.strip() == second.stdout.strip() == "inc-a"
    store = IncidentStore(str(root))
    assert store.list_incident_ids() == ["inc-a"]
    creates = [e for e in store.list_events() if e["type"] == "incident.created"]
    assert len(creates) == 1


def test_raise_dedupes_by_dedupe_key(tmp_path):
    store = IncidentStore(str(tmp_path / "root"))
    a = store.raise_incident({"id": "inc-a", "severity": "mechanical", "symptom": "s", "phase": "open", "dedupe_key": "k"})
    b = store.raise_incident({"id": "inc-b", "severity": "mechanical", "symptom": "s", "phase": "open", "dedupe_key": "k"})
    assert a.id == b.id == "inc-a"
    assert store.list_incident_ids() == ["inc-a"]


def test_raise_rejects_invalid_incident(r2d2_cli):
    proc = r2d2_cli(
        "raise", "--id", "inc-bad", "--severity", "nope", "--symptom", "s",
    )
    assert proc.returncode != 0
    assert "inc-bad" not in proc.stdout
    assert "error" in proc.stderr.lower()


def test_raise_fails_cleanly_when_root_unwritable(tmp_path, monkeypatch):
    # A real OSError during state-root creation surfaces as a clean nonzero
    # result with no success id (the CLI error path, no traceback).
    from operator_guards.r2d2.store import IncidentStore as _IS

    store = _IS(str(tmp_path / "root"))
    monkeypatch.setattr(os, "makedirs", lambda *a, **k: (_ for _ in ()).throw(OSError("read-only")))
    with pytest.raises(StoreError):
        store.raise_incident({"id": "inc-x", "severity": "mechanical", "symptom": "s", "phase": "open", "dedupe_key": "d"})


# ---------------------------------------------------------------------------
# Torn tail / segment sealing / recovery
# ---------------------------------------------------------------------------

def _event_line(seq, event_id, incident_id, inc_dict, ts=1.0, type_="incident.created"):
    return json.dumps(
        {
            "seq": seq,
            "event_id": event_id,
            "type": type_,
            "incident_id": incident_id,
            "ts": ts,
            "data": {"incident": inc_dict},
        }
    )


def _old_incident_dict():
    return incident_to_dict(
        load_incident({"id": "old", "severity": "mechanical", "symptom": "x", "phase": "open", "dedupe_key": "old"})
    )


def _segment_names(root):
    names = []
    if os.path.exists(os.path.join(root, "events.jsonl")):
        names.append("events.jsonl")
    for n in sorted(os.listdir(root)):
        if n.startswith("events.") and n.endswith(".jsonl"):
            names.append(n)
    return names


def test_torn_tail_sealed_before_new_segment(r2d2_cli, tmp_path):
    root = tmp_path / "r2d2"
    root.mkdir(parents=True)
    committed_line = _event_line(1, "ev-1", "old", _old_incident_dict()) + "\n"
    torn = b'{"seq": 2, "event_id": "ev-2", "type": "incident.created", "incident'
    (root / "events.jsonl").write_bytes(committed_line.encode() + torn)

    proc = r2d2_cli(
        "raise", "--id", "inc-new", "--severity", "mechanical", "--symptom", "s",
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "inc-new"

    # the torn segment is preserved byte-for-byte (never rewritten)
    raw = (root / "events.jsonl").read_bytes()
    assert raw.endswith(torn)
    assert raw.startswith(committed_line.encode())

    # subsequent committed record went to a NEW numbered segment
    assert (root / "events.1.jsonl").exists()
    assert "inc-new" in (root / "events.1.jsonl").read_text()

    # a fresh reader recovered the committed prefix (old) AND the new incident
    store = IncidentStore(str(root))
    assert store.get_incident("old") is not None
    assert store.get_incident("inc-new") is not None
    # ... and did NOT create yet another segment (recover once)
    assert not (root / "events.2.jsonl").exists()


def test_valid_json_without_newline_is_uncommitted(r2d2_cli, tmp_path):
    root = tmp_path / "r2d2"
    root.mkdir(parents=True)
    committed_line = _event_line(1, "ev-1", "old", _old_incident_dict()) + "\n"
    ghost_dict = {**_old_incident_dict(), "id": "ghost", "dedupe_key": "ghost"}
    valid_no_newline = _event_line(2, "ev-2", "ghost", ghost_dict)
    (root / "events.jsonl").write_bytes(committed_line.encode() + valid_no_newline.encode())

    proc = r2d2_cli(
        "raise", "--id", "inc-new", "--severity", "mechanical", "--symptom", "s",
    )
    assert proc.returncode == 0, proc.stderr

    store = IncidentStore(str(root))
    assert store.get_incident("old") is not None       # committed prefix recovered
    assert store.get_incident("ghost") is None          # valid-but-unterminated suffix is UNCOMMITTED
    assert store.get_incident("inc-new") is not None
    assert (root / "events.1.jsonl").exists()           # sealed into a new segment


def test_interior_corruption_stops_recovery_and_escalates(r2d2_cli, tmp_path):
    root = tmp_path / "r2d2"
    root.mkdir(parents=True)
    committed_line = _event_line(1, "ev-1", "old", _old_incident_dict()) + "\n"
    corrupt = b"{ this is not valid json }\n"
    after = _event_line(3, "ev-3", "later", _old_incident_dict()) + "\n"
    (root / "events.jsonl").write_bytes(committed_line.encode() + corrupt + after.encode())

    proc = r2d2_cli(
        "raise", "--id", "inc-new", "--severity", "mechanical", "--symptom", "s",
    )
    assert proc.returncode != 0
    assert "error" in proc.stderr.lower()
    # no new segment was created (recovery stopped before any append)
    assert not (root / "events.1.jsonl").exists()

    store = IncidentStore(str(root))
    with pytest.raises(StoreCorruptionError):
        store.list_incidents()


def test_segment_rollover_then_restart_recovers_once(r2d2_cli, tmp_path):
    root = tmp_path / "r2d2"
    first = r2d2_cli("raise", "--id", "inc-1", "--severity", "mechanical", "--symptom", "s")
    assert first.returncode == 0, first.stderr
    # tear the tail of segment 0
    with open(root / "events.jsonl", "ab") as f:
        f.write(b'{"seq": 999, "event_id": "torn", "type": "incident.cr')
    second = r2d2_cli("raise", "--id", "inc-2", "--severity", "mechanical", "--symptom", "s")
    assert second.returncode == 0, second.stderr
    assert (root / "events.1.jsonl").exists()

    # another restart: recovers once, no further rollover
    store = IncidentStore(str(root))
    assert store.get_incident("inc-1") is not None
    assert store.get_incident("inc-2") is not None
    assert sorted(store.list_incident_ids()) == ["inc-1", "inc-2"]
    assert len([e for e in store.list_events() if e["type"] == "incident.created"]) == 2
    assert not (root / "events.2.jsonl").exists()


def test_recovery_preserves_committed_prefix_bytes(r2d2_cli, tmp_path):
    root = tmp_path / "r2d2"
    root.mkdir(parents=True)
    committed_line = _event_line(1, "ev-1", "old", _old_incident_dict()) + "\n"
    (root / "events.jsonl").write_bytes(committed_line.encode() + b"torn-tail-no-newline")
    proc = r2d2_cli("raise", "--id", "inc-new", "--severity", "mechanical", "--symptom", "s")
    assert proc.returncode == 0, proc.stderr
    # the committed prefix is byte-identical and the torn bytes are untouched
    raw = (root / "events.jsonl").read_bytes()
    assert raw == committed_line.encode() + b"torn-tail-no-newline"


# ---------------------------------------------------------------------------
# Failure injection (real fs ops, single injected syscall failure)
# ---------------------------------------------------------------------------

def _fail_event_fsync(monkeypatch):
    monkeypatch.setattr(
        os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("injected event fsync failure"))
    )


def _fail_snapshot_fsync(monkeypatch):
    real = os.fsync
    state = {"n": 0}

    def fsync(fd):
        # Fail the SNAPSHOT TEMP-FILE fsync — the barrier that makes the state
        # file durable BEFORE os.replace. Only REGULAR files are counted (the
        # 1st regular-file fsync is the event segment, the 2nd is the snapshot
        # temp file); directory fsyncs (event dir, snapshot dir) are the
        # durability of the *rename*, not the pre-replace state barrier.
        if stat.S_ISREG(os.fstat(fd).st_mode):
            state["n"] += 1
            if state["n"] == 2:
                raise OSError("injected snapshot temp-file fsync failure")
        return real(fd)

    monkeypatch.setattr(os, "fsync", fsync)


def _fail_replace(monkeypatch):
    monkeypatch.setattr(
        os, "replace", lambda a, b: (_ for _ in ()).throw(OSError("injected replace failure"))
    )


def _fail_dir_fsync(monkeypatch):
    monkeypatch.setattr(
        IncidentStore,
        "_fsync_dir",
        lambda self, d: (_ for _ in ()).throw(OSError("injected dir fsync failure")),
    )


def _fail_fdopen(monkeypatch):
    monkeypatch.setattr(
        os, "fdopen", lambda fd, *a, **k: (_ for _ in ()).throw(OSError("injected fdopen failure"))
    )


INJECTIONS = [
    ("event_fsync", _fail_event_fsync),
    ("snapshot_fsync", _fail_snapshot_fsync),
    ("replace", _fail_replace),
    ("dir_fsync", _fail_dir_fsync),
    ("fdopen", _fail_fdopen),
]


@pytest.mark.parametrize("name,inject", INJECTIONS, ids=[n for n, _ in INJECTIONS])
def test_raise_failure_injection_no_partial_commit(tmp_path, monkeypatch, name, inject):
    root = str(tmp_path / "root")
    record = {"id": "inc-x", "severity": "mechanical", "symptom": "s", "phase": "open", "dedupe_key": "d-x"}

    store = IncidentStore(root)
    inject(monkeypatch)
    with pytest.raises(StoreError):
        store.raise_incident(record)
    monkeypatch.undo()

    # a fresh reader (new process) retrying must commit exactly ONE incident
    out = IncidentStore(root).raise_incident(record)
    assert out.id == "inc-x"

    fresh = IncidentStore(root)
    assert fresh.list_incident_ids() == ["inc-x"]
    creates = [
        e for e in fresh.list_events()
        if e["type"] == "incident.created" and e["incident_id"] == "inc-x"
    ]
    assert len(creates) == 1

    # no torn log tail (every segment ends with a newline or is empty)
    for seg in _segment_names(root):
        raw = open(os.path.join(root, seg), "rb").read()
        assert raw == b"" or raw.endswith(b"\n"), f"torn tail in {seg}"

    # no leftover atomic-write temp files
    assert not [p for p in os.listdir(os.path.join(root, "incidents")) if p.startswith(".tmp-")]


def test_failed_raise_then_retry_does_not_produce_two_committed_incidents(tmp_path, monkeypatch):
    # The plan's explicit contract: a failed raise followed by a retry must not
    # produce two committed incidents, even when the event landed but the
    # snapshot write was interrupted (replace failure).
    root = str(tmp_path / "root")
    record = {"id": "inc-y", "severity": "mechanical", "symptom": "s", "phase": "open", "dedupe_key": "d-y"}

    monkeypatch.setattr(
        os, "replace", lambda a, b: (_ for _ in ()).throw(OSError("injected replace failure"))
    )
    with pytest.raises(StoreError):
        IncidentStore(root).raise_incident(record)
    monkeypatch.undo()

    out = IncidentStore(root).raise_incident(record)
    assert out.id == "inc-y"
    store = IncidentStore(root)
    assert store.list_incident_ids() == ["inc-y"]
    assert len([e for e in store.list_events() if e["incident_id"] == "inc-y"]) == 1


def test_snapshot_temp_fsync_is_barrier_before_replace(tmp_path, monkeypatch):
    # Pins WHICH fsync is the durability barrier: the snapshot TEMP-file fsync
    # must gate os.replace, and the event file fsync must precede it
    # (event-durable-then-state-durable ordering).
    root = str(tmp_path / "root")
    store = IncidentStore(root)
    real_fsync = os.fsync
    real_replace = os.replace
    ops = []

    def _kind(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            return "dir", None
        try:
            return "file", os.path.basename(os.readlink(f"/proc/self/fd/{fd}"))
        except OSError:
            return "file", None

    def fsync(fd):
        kind, base = _kind(fd)
        ops.append(("fsync", kind, base))
        return real_fsync(fd)

    def replace(a, b):
        ops.append(("replace", os.path.basename(a), os.path.basename(b)))
        return real_replace(a, b)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)

    store.raise_incident(
        {"id": "inc-b", "severity": "mechanical", "symptom": "s", "phase": "open", "dedupe_key": "d-b"}
    )

    event_fsync = [i for i, o in enumerate(ops) if o[0] == "fsync" and o[1] == "file" and o[2] == "events.jsonl"]
    tmp_fsync = [i for i, o in enumerate(ops) if o[0] == "fsync" and o[1] == "file" and o[2] and o[2].startswith(".tmp-")]
    replace_at = [i for i, o in enumerate(ops) if o[0] == "replace"]

    assert event_fsync, f"event segment fsync not observed: {ops}"
    assert tmp_fsync, f"snapshot temp-file fsync not observed: {ops}"
    assert replace_at, f"os.replace not observed: {ops}"
    # event-durable-then-state-durable ordering
    assert event_fsync[-1] < tmp_fsync[0], f"event fsync must precede snapshot temp fsync: {ops}"
    # the snapshot temp-file fsync is the barrier that gates the rename
    assert tmp_fsync[-1] < replace_at[0], f"snapshot temp fsync must precede os.replace: {ops}"


# ---------------------------------------------------------------------------
# Concurrency: sequence allocation must be strictly monotonic under the lock
# ---------------------------------------------------------------------------

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_concurrent_raises_allocate_strictly_monotonic_seqs(tmp_path):
    # N threads, each with its OWN store instance pre-recovered against an
    # empty log (so every in-memory next-seq is stale at 1). With the OLD code
    # the sequence was assigned outside the event-log lock, so this emitted
    # duplicate seqs ([1, 1, ...]); the fix must serialize allocation and
    # yield strictly monotonic, unique seqs.
    root = str(tmp_path / "root")
    n = 8
    stores = [IncidentStore(root) for _ in range(n)]
    for s in stores:
        s.list_incidents()  # force recovery; each instance caches an empty log

    barrier = threading.Barrier(n)
    errors = []

    def worker(i):
        try:
            barrier.wait()
            stores[i].raise_incident({
                "id": f"inc-{i}",
                "severity": "mechanical",
                "symptom": "s",
                "phase": "open",
                "dedupe_key": f"d-{i}",
            })
        except BaseException as exc:  # noqa: BLE001 - surface any failure
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors

    fresh = IncidentStore(root)
    assert sorted(fresh.list_incident_ids()) == [f"inc-{i}" for i in range(n)]
    seqs = [e["seq"] for e in fresh.list_events()]
    assert seqs == list(range(1, n + 1)), f"seqs not strictly monotonic/unique: {seqs}"
    for seg in _segment_names(root):
        raw = open(os.path.join(root, seg), "rb").read()
        assert raw == b"" or raw.endswith(b"\n"), f"torn tail in {seg}"


def test_concurrent_subprocess_raises_monotonic_seqs(tmp_path):
    # Real OS processes racing on the same root: the file lock must serialize
    # sequence allocation across processes (not just threads).
    root = tmp_path / "root"
    n = 6
    procs = [
        subprocess.Popen(
            [sys.executable, "-m", "operator_guards.r2d2.cli", "--root", str(root),
             "raise", "--id", f"inc-{i}", "--severity", "mechanical", "--symptom", "s"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=_REPO_ROOT,
        )
        for i in range(n)
    ]
    for p in procs:
        out, err = p.communicate()
        assert p.returncode == 0, f"raise failed: {err}"

    fresh = IncidentStore(str(root))
    assert sorted(fresh.list_incident_ids()) == [f"inc-{i}" for i in range(n)]
    seqs = [e["seq"] for e in fresh.list_events()]
    assert seqs == list(range(1, n + 1)), f"subprocess seqs not monotonic: {seqs}"
    for seg in _segment_names(str(root)):
        raw = open(os.path.join(str(root), seg), "rb").read()
        assert raw == b"" or raw.endswith(b"\n"), f"torn tail in {seg}"


# ---------------------------------------------------------------------------
# done: proof validation + manual closure distinct from verified resolution
# ---------------------------------------------------------------------------

def test_blank_done_proof_rejected(r2d2_cli, committed_incident):
    result = r2d2_cli("done", "--id", committed_incident, "--proof", "")
    assert result.returncode != 0
    assert "proof" in result.stderr.lower()


def test_done_rejects_bare_prose_proof(r2d2_cli, committed_incident):
    result = r2d2_cli("done", "--id", committed_incident, "--proof", "fixed")
    assert result.returncode != 0
    assert "proof" in result.stderr.lower() or "verdict" in result.stderr.lower()


@pytest.mark.parametrize("proof", ["FAIL", "UNKNOWN"])
def test_done_rejects_non_pass_proof(r2d2_cli, committed_incident, proof):
    result = r2d2_cli("done", "--id", committed_incident, "--proof", proof)
    assert result.returncode != 0


def test_done_requires_proof_or_reason(r2d2_cli, committed_incident):
    result = r2d2_cli("done", "--id", committed_incident)
    assert result.returncode != 0


def test_done_manual_reason_escalates(r2d2_cli, committed_incident, tmp_path):
    result = r2d2_cli(
        "done", "--id", committed_incident, "--reason", "operator took over manually",
    )
    assert result.returncode == 0, result.stderr
    assert committed_incident in result.stdout
    store = IncidentStore(str(tmp_path / "r2d2"))
    inc = store.get_incident(committed_incident)
    assert inc.phase == PHASE_ESCALATED
    assert "operator took over manually" in inc.notification
    # manual closure is DISTINCT from verified resolution
    assert inc.phase != PHASE_RESOLVED
    assert inc.proof is not Verdict.PASS


def test_done_verified_resolution_requires_pass_and_plan(tmp_path):
    store = IncidentStore(str(tmp_path / "root"))
    # A fresh open incident has no mutation plan -> verified PASS cannot resolve.
    inc = store.raise_incident({"id": "inc-v", "severity": "mechanical", "symptom": "s", "phase": "open", "dedupe_key": "d"})
    with pytest.raises(StoreError):
        store.done(inc.id, proof="PASS")

    # An incident committed WITH a resolvable (all-PASS) mutation plan resolves.
    store2 = IncidentStore(str(tmp_path / "root2"))
    resolvable = store2.raise_incident({
        "id": "inc-r", "severity": "mechanical", "symptom": "s", "phase": "repairing",
        "dedupe_key": "dr", "mutation_plan": [_op(op_id="mut-1")],
    })
    result = store2.done(resolvable.id, proof="PASS")
    assert result.phase == PHASE_RESOLVED
    assert result.proof is Verdict.PASS
    # durable: a fresh reader sees the resolved incident
    assert IncidentStore(str(tmp_path / "root2")).get_incident("inc-r").phase == PHASE_RESOLVED


def test_done_on_missing_incident_errors(r2d2_cli):
    result = r2d2_cli("done", "--id", "does-not-exist", "--reason", "x")
    assert result.returncode != 0
    assert "error" in result.stderr.lower()
