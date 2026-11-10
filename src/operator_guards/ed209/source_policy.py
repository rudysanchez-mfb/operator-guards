"""Source-backed policy provenance: a rule activates only when it cites a genuine user message verbatim.

Ported from the live ED-209 policy module. This is an OPTIONAL provenance layer,
separate from the Hermes plugin's runtime rule loader: the plugin enforces the
operator-authored ``rules.json`` document, while this module records a proposal
and requires an exact user message (``activate policy <digest>``) before the
proposal is installed into its own active manifest.

The store must be protected externally. Hashes detect drift, not a hostile
writer who can replace both data and code. The legacy baseline has no invented
provenance. A matching quote proves that text exists in the message; it does not
prove that an inferred executable rule follows from the text. Exact digest
acceptance addresses that separate interpretation problem.

Transcript adapters: Claude JSONL user messages (``uuid``/``id`` or ``line:N``)
and Codex ``event_msg`` / ``user_message`` JSONL events. Assistant messages,
tool-result blocks, sidechains, meta, synthetic, and compact-summary messages
are rejected. Set ``OPERATOR_GUARDS_SOURCE_ROOTS`` (os.pathsep separated) to
change the transcript search roots; the default remains the Claude and Codex
locations.
"""
from __future__ import annotations

import contextlib
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from ..common.paths import default_home, env_path


def default_store(environ: dict | None = None) -> Path:
    """The default proposal/active store (override: OPERATOR_GUARDS_POLICY_STORE)."""
    return Path(env_path("OPERATOR_GUARDS_POLICY_STORE", str(Path(default_home(environ)) / "ed209" / "policy"), environ))


STORE = default_store()


class PolicyError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _read(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise PolicyError(f"Cannot read policy artifact {path}: {exc}") from exc


def _atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".policy-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            output.write(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def _lock(store):
    store = Path(store)
    store.mkdir(parents=True, exist_ok=True)
    with (store / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def _user_text(entry):
    if not isinstance(entry, dict):
        return None
    if any(entry.get(key) for key in ("isMeta", "isSidechain", "isCompactSummary", "isSummary", "isSynthetic")):
        return None
    if entry.get("type") == "event_msg":
        payload = entry.get("payload", {})
        if payload.get("type") == "user_message" and isinstance(payload.get("message"), str):
            return payload["message"]
        return None
    if entry.get("type") != "user":
        return None
    message = entry.get("message", {})
    if not isinstance(message, dict) or message.get("role", "user") != "user":
        return None
    content = message.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list) or any(not isinstance(b, dict) or b.get("type") != "text" for b in content):
        return None
    return "\n".join(b.get("text", "") for b in content)


def source(source_path, message_id, quote=None):
    path = Path(source_path).expanduser().resolve(strict=True)
    matches = []
    with path.open() as stream:
        for number, line in enumerate(stream, 1):
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if not isinstance(entry, dict):
                continue
            identifiers = {f"line:{number}"}
            identifiers.update(str(entry[key]) for key in ("uuid", "id") if key in entry)
            if str(message_id) in identifiers:
                matches.append(entry)
    if len(matches) != 1:
        raise PolicyError("Source must identify exactly one transcript message")
    entry = matches[0]
    text = _user_text(entry)
    if not text or not text.strip():
        raise PolicyError("Source is not a genuine user text message")
    if quote is not None and (not quote.strip() or quote not in text):
        raise PolicyError("Exact nonempty quotation is absent from user message")
    return {"path": str(path), "message_id": str(message_id), "message_sha256": digest(entry),
            "quote": quote if quote is not None else text}, text


def _default_source_roots():
    configured = (os.environ.get("OPERATOR_GUARDS_SOURCE_ROOTS") or "").strip()
    if configured:
        return [Path(part) for part in configured.split(os.pathsep) if part]
    home = Path.home()
    return [home / ".claude/projects", home / ".codex/sessions"]


def find_source(quote, *, roots=None, max_age_hours=48):
    """Newest genuine user message containing the exact quote, across Claude and Codex transcripts."""
    import time
    if not quote or not quote.strip():
        raise PolicyError("Exact nonempty quotation required")
    roots = roots or _default_source_roots()
    cutoff = time.time() - max_age_hours * 3600
    files = sorted((f for r in roots if Path(r).is_dir() for f in Path(r).rglob("*.jsonl")
                    if f.stat().st_mtime >= cutoff and "subagents" not in f.parts),
                   key=lambda f: f.stat().st_mtime, reverse=True)
    for path in files:
        found = None
        with path.open(errors="replace") as stream:
            for number, line in enumerate(stream, 1):
                if quote not in line and json.dumps(quote)[1:-1] not in line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                text = _user_text(entry)
                if text and quote in text:
                    ident = str(entry["uuid"]) if entry.get("uuid") else f"line:{number}"
                    found = ident
        if found:
            return str(path), found
    raise PolicyError("No genuine user message in recent transcripts contains that exact quote")


def _validate_source(receipt):
    actual, _ = source(receipt["path"], receipt["message_id"], receipt["quote"])
    if actual != receipt:
        raise PolicyError("Source user message changed after it was recorded")


def _validate_rule(rule):
    if not isinstance(rule, dict) or not isinstance(rule.get("id"), str) or not rule["id"].strip():
        raise PolicyError("Rule needs a nonempty id")
    if rule.get("surface") not in ("tool", "reply"):
        raise PolicyError("Rule surface must be tool or reply")
    if rule.get("action") not in ("deny", "check", "escalate", "inject", "memory-first", "block", "log"):
        raise PolicyError("Unknown rule action")
    if not isinstance(rule.get("reason"), str) or not rule["reason"].strip():
        raise PolicyError("Rule needs a reason")
    try:
        re.compile(rule["pattern"])
        for key in ("exempt", "cwd_pattern"):
            if rule.get(key):
                re.compile(rule[key])
    except (KeyError, TypeError, re.error) as exc:
        raise PolicyError(f"Invalid rule pattern: {exc}") from exc


def propose(rule, source_path, message_id, quote, *, store=None, activate=True):
    store = Path(store) if store is not None else STORE
    _validate_rule(rule)
    receipt, _ = source(source_path, message_id, quote)
    body = {"schema": 1, "kind": "policy-proposal", "rule": copy.deepcopy(rule), "source": receipt}
    proposal_id = digest(body)
    document = {"id": proposal_id, "body": body}
    with _lock(store):
        target = store / "proposals" / f"{proposal_id}.json"
        if target.exists() and _read(target) != document:
            raise PolicyError("Existing proposal differs from its digest")
        _atomic(target, document)
        if activate:
            _install(store, proposal_id, rule["id"], {"kind": "verified-quote", **receipt})
    return proposal_id


def _install(store, proposal_id, rule_id, approval):
    state_path = store / "active.json"
    state = _read(state_path) if state_path.exists() else {"schema": 1, "active": [], "history": []}
    kept = []
    for old in state["active"]:
        if old["rule_id"] == rule_id:
            if old["proposal_id"] == proposal_id:
                return
            state["history"].append({**old, "status": "superseded", "superseded_by": proposal_id})
        else:
            kept.append(old)
    state["active"] = kept + [{"rule_id": rule_id, "proposal_id": proposal_id, "approval": approval, "status": "active"}]
    _atomic(state_path, state)


def _proposal(store, proposal_id):
    if not re.fullmatch(r"[0-9a-f]{64}", proposal_id):
        raise PolicyError("Invalid proposal digest")
    item = _read(store / "proposals" / f"{proposal_id}.json")
    if item.get("id") != proposal_id or digest(item.get("body")) != proposal_id:
        raise PolicyError("Proposal content does not match digest")
    body = item["body"]
    if body.get("schema") != 1 or body.get("kind") != "policy-proposal":
        raise PolicyError("Unsupported policy proposal")
    _validate_rule(body["rule"])
    _validate_source(body["source"])
    return item


def activate(proposal_id, source_path, message_id, *, store=None):
    store = Path(store) if store is not None else STORE
    receipt, text = source(source_path, message_id)
    if text.strip() != f"activate policy {proposal_id}":
        raise PolicyError("User message must be exactly: activate policy <proposal digest>")
    with _lock(store):
        proposal = _proposal(store, proposal_id)
        _install(store, proposal_id, proposal["body"]["rule"]["id"], receipt)
    return proposal_id


def load_baseline(*, store=None):
    store = Path(store) if store is not None else STORE
    try:
        raw = (store / "baseline.json").read_bytes()
        expected = (store / "baseline.sha256").read_text().strip()
    except OSError as exc:
        raise PolicyError(f"Trusted legacy baseline unavailable: {exc}") from exc
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or hashlib.sha256(raw).hexdigest() != expected:
        raise PolicyError("Trusted legacy baseline integrity check failed")
    try:
        config = json.loads(raw)
    except ValueError as exc:
        raise PolicyError("Legacy baseline is not valid JSON") from exc
    if not isinstance(config, dict) or not isinstance(config.get("rules"), list):
        raise PolicyError("Legacy baseline needs a rules list")
    config["_policy_status"] = "legacy-baseline; provenance not verified"
    config["_policy_errors"] = []
    return config


def load_rules(*, store=None):
    store = Path(store) if store is not None else STORE
    config = load_baseline(store=store)
    path = store / "active.json"
    if not path.exists():
        return config
    try:
        state = _read(path)
        if state.get("schema") != 1 or not isinstance(state.get("active"), list):
            raise PolicyError("Invalid active policy manifest")
        rules = copy.deepcopy(config["rules"])
        seen = set()
        for record in state["active"]:
            proposal = _proposal(store, record["proposal_id"])
            rule = proposal["body"]["rule"]
            if record.get("status") != "active" or record["rule_id"] != rule["id"] or rule["id"] in seen:
                raise PolicyError("Active manifest has invalid status or duplicate/mismatched rule id")
            seen.add(rule["id"])
            approval = dict(record["approval"])
            if approval.pop("kind", None) == "verified-quote":
                if approval != proposal["body"]["source"]:
                    raise PolicyError("Verified-quote approval does not match the proposal's own source")
            else:
                _validate_source(approval)
                if approval["quote"].strip() != f"activate policy {record['proposal_id']}":
                    raise PolicyError("Approval does not authorize this exact policy digest")
            rule = {**rule, "policy_status": "verified-active", "policy_proposal_id": record["proposal_id"]}
            rules = [existing for existing in rules if existing["id"] != rule["id"]] + [rule]
        config["rules"] = rules
    except (PolicyError, OSError, KeyError, TypeError, ValueError) as exc:
        config["_policy_errors"].append(f"Active policy rejected; retaining legacy baseline: {exc}")
    return config
