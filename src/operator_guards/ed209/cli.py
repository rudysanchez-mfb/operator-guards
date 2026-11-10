"""Sanctioned ED-209 operator CLI (Task 5).

Verbs: ``list``, ``add``, ``correct``, ``disable``, ``enable``, ``test-tool``,
``test-reply``, ``hits``, ``replay``. This is the *sanctioned* path for changing
the rules
document — the only write path, mirroring the upstream ``~/.local/bin/ed209``
(ED-209-HANDOFF.md §6). There is intentionally NO ``policy-off`` / ``limits`` /
``off`` verb: changing budgets or blanket-disabling the guard is a hand-edit by
Rudy, not a CLI action.

Security posture (stated honestly):

* **Dry-run verbs never mutate.** ``test-reply`` / ``test-tool`` / ``replay``
  call only the pure :func:`~operator_guards.ed209.engine.evaluate` with an
  empty ``available`` interface set (no memory/gh/reviewer), so they never
  consume a reviewer or block budget, never open the ledger, never run a live
  ``gh`` check, and never write state. There is no ``--live`` flag in the dry
  path: live checks/reviewer belong to the plugin adapter (Task 7/8), not this
  CLI. ``hits`` reads the *real* ledger (live outcomes), never dry-run traffic
  (dry runs never write a row).
* **Operator-gated protective actions.** ``disable`` / ``enable`` require an
  explicit ``--operator <marker>`` and refuse to run when the invocation
  presents as automatic agent recovery (``--recovery`` / ``--automatic`` flags,
  or an operator marker in a known agent/recovery denylist). Each such action
  is recorded (who/when) in the document's ``_operator_actions`` list. A rule
  is flipped, never deleted — disabled entries are preserved.
* **Same-UID is not a security boundary.** An ``--operator`` string is a
  *procedural* record, not an identity proof: any same-UID process (the agent
  included) can lie about it or bypass this CLI and edit the file directly.
  This CLI implements the behavior and records the action; it does NOT claim a
  role-label is isolation. The *real* interception of an agent trying to
  disable a guard is the shared ED-209 evaluation of the terminal op, which
  belongs to the plugin (Task 7/8) — noted here, not implemented here.
* **Atomic, validated writes only.** ``add`` / ``disable`` / ``enable`` write
  via temp file + fsync + ``os.replace`` + parent-dir fsync. Duplicate ids and
  invalid regex are rejected (``RulesError``) before any write. ``add`` only
  appends a new rule — it never weakens an enabled ``deny``, never changes
  ``limits``, and never exposes ``overridable``.
* **``correct`` is the deterministic correction path.** ``correct`` takes the
  correction verbatim via ``--text`` and embeds it (with ``--operator`` author
  attribution and ``--date``) as the rule ``origin`` — never paraphrased, never
  merged, never intent-inferred. It performs the exact same sanctioned
  ``add``-only append (deny-weakening guard, no ``overridable``), so same
  inputs (including ``--date``) produce the same rule.

Default rules path is ``<OPERATOR_GUARDS_HOME>/ed209/rules.json`` at runtime;
when that file is absent the CLI seeds from the bundled ``documented-initial``
rulepack (read-only first-run seed) so ``test-reply`` works pre-deployment. An
explicit ``--rules`` path is never seeded from the bundle: a missing explicit
path is created empty on ``add`` (only the added rule is written) and is a
clean error on read-only verbs. Tests pass explicit ``--rules`` / ``--db``
under ``tmp_path``.

LIMITATION: rule patterns are operator-authored and trusted — catastrophic
backtracking patterns are a known engine limitation, and the match subject is
already bounded, so no regex-timeout machinery is applied.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .engine import (
    EvaluationContext,
    evaluate,
)
from ..common.paths import default_home, env_path
from .ledger import DEFAULT_HITS_DB, HitLedger
from .rules import (
    SUPPORTED_ACTIONS,
    SUPPORTED_SURFACES,
    RulesError,
    compile_rules,
    load_rules,
)

# Default runtime rules path (tests MUST pass an explicit --rules).
# Configurable: OPERATOR_GUARDS_ED209_RULES, else <home>/ed209/rules.json.
DEFAULT_RULES_PATH = env_path(
    "OPERATOR_GUARDS_ED209_RULES",
    str(Path(default_home()) / "ed209" / "rules.json"),
)

# Bundled seed rulepack (read-only) — resolved relative to the source tree.
# An installed wheel does not ship ``rulepacks/``; set OPERATOR_GUARDS_RULEPACK
# to a copied rulepack when running outside a source checkout.
_REPO_ROOT = Path(__file__).resolve().parents[3]
BUNDLED_RULEPACK = Path(
    env_path(
        "OPERATOR_GUARDS_RULEPACK",
        str(_REPO_ROOT / "rulepacks" / "documented-initial.json"),
    )
)

# Operator markers that "present as automatic agent recovery" and are refused.
AGENT_RECOVERY_MARKERS = frozenset(
    {"automatic", "auto", "recovery", "agent", "self", "r2d2", "daemon"}
)

_SUCCESSOR_RE = re.compile(r"^(?P<base>.+)-v\d+$")


class OperatorActionRefused(Exception):
    """Raised when a protective action is invoked as automatic agent recovery."""


# ---------------------------------------------------------------------------
# Rules-document load / persistence (atomic, validated)
# ---------------------------------------------------------------------------

def _rules_target(rules_arg: str | None) -> str:
    return rules_arg if rules_arg else DEFAULT_RULES_PATH


def _skeleton_doc() -> dict:
    """Minimal valid document (handoff §3 shape) when no source exists."""
    return {
        "version": 1,
        "_about": "operator-guards ED-209 rules document (sanctioned CLI)",
        "reviewer": {"chain": ["copilot", "cursor"], "model": "gpt-5.4", "timeout_s": 50},
        "limits": {"max_blocks_per_session": 12, "max_reviewer_calls_per_session": 12},
        "rules": [],
    }


def _read_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RulesError(f"cannot read rules document {path!r}: {exc}") from exc
    if not isinstance(data, dict):
        raise RulesError(f"rules document must be a JSON object, got {type(data).__name__}")
    return data


def _resolve_doc(rules_arg: str | None, *, allow_create: bool = False) -> dict:
    """Load the rules document.

    * Default runtime path (``rules_arg is None``) that does not yet exist is
      seeded from the bundled rulepack (read-only first-run behavior).
    * An explicit ``--rules`` path that does not exist is NEVER seeded from the
      bundle: write verbs get a fresh empty skeleton (``allow_create=True``),
      read-only verbs raise :class:`RulesError` (no implicit bundle seed).
    """
    target = _rules_target(rules_arg)
    if os.path.exists(target):
        return _read_json(target)
    if rules_arg is None:
        if os.path.exists(BUNDLED_RULEPACK):
            return _read_json(str(BUNDLED_RULEPACK))
        return _skeleton_doc()
    if allow_create:
        return _skeleton_doc()
    raise RulesError(f"rules file does not exist: {target}")


def _fsync_dir(dirpath: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        dfd = os.open(dirpath, flags)
    except OSError:
        return  # filesystem does not support directory fsync; best effort
    try:
        try:
            os.fsync(dfd)
        except OSError:
            pass  # best effort: os.replace already landed the file; degrade, don't fail
    finally:
        os.close(dfd)


def _atomic_write_json(path: str, doc: dict) -> None:
    """Durable, atomic write: temp file + fsync + os.replace + dir fsync."""
    data = (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    dirpath = os.path.dirname(path) or "."
    os.makedirs(dirpath, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=dirpath)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        _fsync_dir(dirpath)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# add: origin capture, deny-weakening guard
# ---------------------------------------------------------------------------

def _base_id(rule_id: str) -> str | None:
    m = _SUCCESSOR_RE.match(rule_id)
    return m.group("base") if m else None


def _capture_origin(rule_id: str, user_origin: str, existing_rules: list) -> str:
    """A successor id (``-v2``/``-v3``) captures the origin it supersedes."""
    base = _base_id(rule_id)
    if base is None:
        return user_origin
    for r in existing_rules:
        if r.get("id") == base:
            base_origin = (r.get("origin") or "").strip()
            if base_origin and base_origin not in user_origin:
                return f"{user_origin}; supersedes {base}: {base_origin}"
    return user_origin


def _guard_no_deny_weaken(rule_id: str, action: str, existing_rules: list) -> None:
    """Refuse to supersede an enabled deny rule with a non-deny action."""
    base = _base_id(rule_id)
    if base is None:
        return
    for r in existing_rules:
        if r.get("id") != base:
            continue
        enabled = r.get("enabled", True) is not False
        if enabled and r.get("action") == "deny" and action != "deny":
            raise RulesError(
                f"refusing to supersede enabled deny rule {base!r} with action "
                f"{action!r}: a deny may not be weakened"
            )


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def _cmd_list(args) -> int:
    doc = _resolve_doc(args.rules)
    rules = load_rules(doc)  # validate: a malformed document errors cleanly
    if not rules:
        print("(no rules)")
        return 0
    for r in rules:
        print(f"{r.id}\t{r.surface}\t{r.action}\t{r.enabled}\t{r.rule_class}\t{r.origin}")
    return 0


def _append_new_rule(args, doc: dict, path: str, origin: str) -> None:
    """The single sanctioned append path shared by ``add`` and ``correct``.

    Appends exactly ONE new rule: rejects duplicate ids, captures successor
    origin, refuses to weaken an enabled deny, never sets ``overridable``, and
    validates the whole document before an atomic write. ``origin`` is supplied
    by the caller (already verbatim for ``correct``); it is NOT paraphrased
    here.
    """
    rules = doc.setdefault("rules", [])
    if not isinstance(rules, list):
        raise RulesError("rules document 'rules' must be a list")

    existing_ids = [r.get("id") for r in rules]
    if args.id in existing_ids:
        raise RulesError(f"duplicate rule id: {args.id!r}")

    origin = _capture_origin(args.id, origin, rules)
    _guard_no_deny_weaken(args.id, args.action, rules)

    if args.pattern == "":
        print(
            "warning: empty pattern matches every input; verify this is intended",
            file=sys.stderr,
        )

    rule = {
        "id": args.id,
        "surface": args.surface,
        "class": args.rule_class,
        "action": args.action,
        "pattern": args.pattern,
        "reason": args.reason,
        "origin": origin,
        "enabled": True,  # added rules are enabled; overridable is NOT exposed
    }
    for field, value in (
        ("tools", args.tools),
        ("exempt", args.exempt),
        ("memory", args.memory),
        ("check", args.check),
        ("requires", args.requires),
        ("cwd", args.cwd),
    ):
        if value is not None:
            rule[field] = value

    rules.append(rule)
    load_rules(doc)  # validate (duplicate id / invalid regex / field types)
    _atomic_write_json(path, doc)


def _cmd_add(args) -> int:
    path = _rules_target(args.rules)
    doc = _resolve_doc(args.rules, allow_create=True)
    _append_new_rule(args, doc, path, args.origin)
    print(f"added: {args.id}")
    return 0


def _cmd_correct(args) -> int:
    """Deterministic correction: verbatim origin + the sanctioned add-only write.

    The correction text is embedded VERBATIM (with operator author + date) as
    the rule ``origin``; the rule itself is built by the exact same append path
    as ``add``, so it can only ADD — never weaken/supersede an existing deny,
    never change limits, never mark a rule ``overridable``. Same inputs
    (including ``--date``) yield the same rule.
    """
    _require_operator(args)
    path = _rules_target(args.rules)
    doc = _resolve_doc(args.rules, allow_create=True)
    day = args.date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    origin = f"{args.operator}: {args.text} [{day}]"
    _append_new_rule(args, doc, path, origin)
    print(f"corrected: {args.id}")
    return 0


def _require_operator(args) -> None:
    if getattr(args, "recovery", False) or getattr(args, "automatic", False):
        raise OperatorActionRefused(
            "automatic agent recovery is not permitted: disabling/enabling a "
            "guard requires an explicit human operator action"
        )
    marker = (args.operator or "").strip().lower()
    if not marker:
        raise OperatorActionRefused(
            "operator marker must not be empty or whitespace-only"
        )
    if marker in AGENT_RECOVERY_MARKERS:
        raise OperatorActionRefused(
            f"operator marker {args.operator!r} presents as automatic agent "
            "recovery; refusing to disable/enable a guard"
        )


def _flip_enabled(args, enabled: bool) -> int:
    _require_operator(args)
    path = _rules_target(args.rules)
    doc = _resolve_doc(args.rules, allow_create=True)
    rules = doc.setdefault("rules", [])
    for r in rules:
        if r.get("id") != args.rule_id:
            continue
        r["enabled"] = enabled  # flip only; the entry is preserved, never deleted
        doc.setdefault("_operator_actions", []).append(
            {
                "verb": "disable" if not enabled else "enable",
                "rule_id": args.rule_id,
                "operator": args.operator,
                "at": datetime.now(timezone.utc).isoformat(),
            }
        )
        _atomic_write_json(path, doc)
        print(f"{'enabled' if enabled else 'disabled'}: {args.rule_id}")
        return 0
    raise RulesError(f"no rule with id {args.rule_id!r}")


def _cmd_disable(args) -> int:
    return _flip_enabled(args, False)


def _cmd_enable(args) -> int:
    return _flip_enabled(args, True)


def _dry_run(args, *, surface, tool_name=None, capabilities=frozenset(), payload=None, candidate_text=None) -> int:
    """Pure evaluation. No ledger, no budget, no live checks, no state write."""
    doc = _resolve_doc(args.rules)
    rules = load_rules(doc)
    compiled = compile_rules(rules)
    ctx = EvaluationContext(
        profile_home=os.path.expanduser("~"),
        client_id="cli",
        session_id="dry-run",
        turn_id="dry-run",
        surface=surface,
        tool_name=tool_name,
        capabilities=frozenset(capabilities),
        payload=payload,
        candidate_text=candidate_text,
        # Empty interface set: matched escalate/check/inject become
        # `unavailable` (fail-open), never a live reviewer/gh call.
        available=frozenset(),
    )
    decision = evaluate(compiled, ctx)
    label = "reply" if surface == "reply" else "tool"
    if decision.matched_rule_ids:
        by_id = {r.id: r for r in rules}
        print(f"dry-run ({label}): {len(decision.matched_rule_ids)} rule(s) matched")
        for rid in decision.matched_rule_ids:
            rule = by_id.get(rid)
            print(f"  - {rid}  action={rule.action if rule else '?'}")
        if decision.counted_fact:
            print(f"counted_fact: {decision.counted_fact}")
    else:
        print(f"dry-run ({label}): no match")
    print(f"decision: {decision.action}")
    return 0


def _cmd_test_reply(args) -> int:
    return _dry_run(args, surface="reply", candidate_text=args.text)


def _cmd_test_tool(args) -> int:
    real, caps = _resolve_tool_for_cli(args.tool)
    return _dry_run(args, surface="tool", tool_name=real, capabilities=caps, payload=args.payload)


def _resolve_tool_for_cli(tool_name: str):
    from .capabilities import resolve_tool

    return resolve_tool(tool_name)


def _cmd_hits(args) -> int:
    """Read the REAL ledger (live outcomes). Dry-run traffic never lands here."""
    db = args.db if args.db else DEFAULT_HITS_DB
    if not os.path.exists(db):
        print("(no hits)")
        return 0
    ledger = HitLedger(db)
    if getattr(args, "rule", None):
        hist = ledger.outcomes_for_rule(args.rule)
        if not hist:
            print(f"(no hits for rule {args.rule!r})")
            return 0
        for outcome, n in sorted(hist.items()):
            print(f"{args.rule}\t{outcome}\t{n}")
        return 0
    # Reuse the ledger's bounded, schema-creating read path (same package).
    rows = ledger._query(  # noqa: SLF001 — in-package read path
        "SELECT rule_id, outcome, COUNT(*) AS n FROM hits "
        "GROUP BY rule_id, outcome ORDER BY rule_id, outcome",
        (),
    )
    if not rows:
        print("(no hits)")
        return 0
    for r in rows:
        print(f"{r['rule_id']}\t{r['outcome']}\t{r['n']}")
    return 0


def _cmd_replay(args) -> int:
    """Deterministic, non-mutating re-evaluation of recorded hits vs current rules."""
    db = args.db if args.db else DEFAULT_HITS_DB
    if not os.path.exists(db):
        print("(no hits to replay)")
        return 0
    ledger = HitLedger(db)
    doc = _resolve_doc(args.rules)
    by_id = {r.id: r for r in load_rules(doc)}
    rows = ledger._query("SELECT DISTINCT rule_id FROM hits ORDER BY rule_id", ())  # noqa: SLF001
    if not rows:
        print("(no hits to replay)")
        return 0
    for row in rows:
        rid = row["rule_id"]
        hist = ledger.outcomes_for_rule(rid)
        rule = by_id.get(rid)
        if rule is None:
            present, enabled, action = "false", "-", "-"
        else:
            present, enabled, action = "true", str(rule.enabled).lower(), rule.action
        hist_s = ",".join(f"{o}={n}" for o, n in sorted(hist.items()))
        print(f"{rid}\tpresent={present}\tenabled={enabled}\taction={action}\t{hist_s}")
    return 0


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ed209",
        description="Sanctioned ED-209 operator CLI (rule source of truth).",
    )
    p.add_argument("--rules", help="rules JSON path (default: runtime rules.json)")
    p.add_argument("--db", help="hits.db ledger path (hits/replay)")
    sub = p.add_subparsers(dest="verb", required=True)

    p_list = sub.add_parser("list", help="list rules (incl. disabled) with origin")
    p_list.set_defaults(func=_cmd_list)

    p_add = sub.add_parser("add", help="persist a NEW rule (atomic, validated)")
    p_add.add_argument("--id", required=True)
    p_add.add_argument("--surface", required=True, choices=SUPPORTED_SURFACES)
    p_add.add_argument("--class", dest="rule_class", required=True)
    p_add.add_argument("--action", required=True, choices=SUPPORTED_ACTIONS)
    p_add.add_argument("--pattern", required=True)
    p_add.add_argument("--reason", required=True)
    p_add.add_argument("--origin", required=True)
    p_add.add_argument("--tools", nargs="+")
    p_add.add_argument("--exempt", nargs="+")
    p_add.add_argument("--memory", nargs="+")
    p_add.add_argument("--check")
    p_add.add_argument("--requires", nargs="+")
    p_add.add_argument("--cwd")
    p_add.set_defaults(func=_cmd_add)

    p_correct = sub.add_parser(
        "correct",
        help="deterministic correction: verbatim origin + sanctioned add (operator-only)",
    )
    p_correct.add_argument("--text", required=True, help="correction text, preserved VERBATIM")
    p_correct.add_argument("--id", required=True)
    p_correct.add_argument("--surface", required=True, choices=SUPPORTED_SURFACES)
    p_correct.add_argument("--class", dest="rule_class", required=True)
    p_correct.add_argument("--action", required=True, choices=SUPPORTED_ACTIONS)
    p_correct.add_argument("--pattern", required=True)
    p_correct.add_argument("--reason", required=True)
    p_correct.add_argument(
        "--operator", required=True,
        help="explicit operator marker (who is acting); recorded as provenance",
    )
    p_correct.add_argument(
        "--date",
        help="provenance date (YYYY-MM-DD); defaults to today (UTC). Pin it for deterministic replay.",
    )
    p_correct.add_argument(
        "--recovery", action="store_true",
        help="REFUSED: presents the action as automatic agent recovery",
    )
    p_correct.add_argument(
        "--automatic", action="store_true",
        help="REFUSED: presents the action as automatic agent recovery",
    )
    p_correct.add_argument("--tools", nargs="+")
    p_correct.add_argument("--exempt", nargs="+")
    p_correct.add_argument("--memory", nargs="+")
    p_correct.add_argument("--check")
    p_correct.add_argument("--requires", nargs="+")
    p_correct.add_argument("--cwd")
    p_correct.set_defaults(func=_cmd_correct)

    for name, verb in (("disable", False), ("enable", True)):
        sp = sub.add_parser(
            name, help=f"{name} a rule (operator action; entry preserved)"
        )
        sp.add_argument("rule_id")
        sp.add_argument(
            "--operator", required=True,
            help="explicit operator marker (who is acting); recorded as provenance",
        )
        sp.add_argument(
            "--recovery", action="store_true",
            help="REFUSED: presents the action as automatic agent recovery",
        )
        sp.add_argument(
            "--automatic", action="store_true",
            help="REFUSED: presents the action as automatic agent recovery",
        )
        sp.set_defaults(func=_cmd_disable if verb is False else _cmd_enable)

    p_reply = sub.add_parser("test-reply", help="dry-run a reply phrase (no mutation)")
    p_reply.add_argument("text")
    p_reply.set_defaults(func=_cmd_test_reply)

    p_tool = sub.add_parser("test-tool", help="dry-run a tool payload (no mutation)")
    p_tool.add_argument("tool")
    p_tool.add_argument("payload")
    p_tool.set_defaults(func=_cmd_test_tool)

    p_hits = sub.add_parser("hits", help="query the real ledger, grouped by rule/outcome")
    p_hits.add_argument("--rule", help="restrict to one rule id")
    p_hits.set_defaults(func=_cmd_hits)

    p_replay = sub.add_parser("replay", help="deterministic dry-run re-read of recorded hits")
    p_replay.set_defaults(func=_cmd_replay)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except RulesError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OperatorActionRefused as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
