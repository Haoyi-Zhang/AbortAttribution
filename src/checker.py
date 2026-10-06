"""Reference implementation of an IDEAL-RECEIPT evidence checker.

This is a finite model, not a cryptographic eVRF, signature, or NIZK library.
The context and receipt registry are trusted inputs representing authenticated
public records. Candidate certificates are untrusted. No network calls occur.
"""
from __future__ import annotations
import hashlib
import json
from typing import Any


def commitment(context: str, actor: int, tag: Any, nonce: str) -> str:
    """A domain-separated fixture commitment; no hiding claim is made."""
    wire = json.dumps(["exponent-tag-opening", context, actor, tag, nonce],
                      ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(wire.encode("ascii")).hexdigest()


def integer(value: Any) -> bool:
    return type(value) is int


def _small_prime(value: int) -> bool:
    """Exact bounded trial division, not production parameter validation."""
    if not 2 <= value <= 65535:
        return False
    divisor = 2
    while divisor * divisor <= value:
        if value % divisor == 0:
            return False
        divisor += 1
    return True


_CONTEXT_FIELDS = {
    "id", "roster", "group", "threshold", "coefficient_tags", "service",
    "accept_by", "deadline", "compute_bound", "delivery_bound", "read_bound",
}


def valid_environment(env: Any) -> bool:
    """Fail-closed parser boundary for the trusted ideal-board encoding."""
    if type(env) is not dict or set(env) != {"context", "receipts", "closures"}:
        return False
    ctx, receipts, closures = env.get("context"), env.get("receipts"), env.get("closures")
    if type(ctx) is not dict or set(ctx) != _CONTEXT_FIELDS:
        return False
    if type(ctx.get("id")) is not str or not ctx["id"]:
        return False
    roster = ctx.get("roster")
    if (type(roster) is not list or not roster
            or any(type(x) is not int or x <= 0 for x in roster)
            or len(set(roster)) != len(roster)):
        return False
    group = ctx.get("group")
    if (type(group) is not dict or set(group) != {"p", "q", "g"}
            or any(type(group.get(k)) is not int for k in ("p", "q", "g"))
            or not _small_prime(group["p"]) or not _small_prime(group["q"])
            or not (2 < group["p"] and 1 < group["q"] < group["p"]
                    and 1 < group["g"] < group["p"]
                    and (group["p"] - 1) % group["q"] == 0
                    and pow(group["g"], group["q"], group["p"]) == 1)):
        return False
    if (type(ctx.get("threshold")) is not int
            or not (1 <= ctx["threshold"] <= len(roster))):
        return False
    tags = ctx.get("coefficient_tags")
    if (type(tags) is not list or len(tags) != ctx["threshold"]
            or any(type(x) is not int or not (1 <= x < group["p"])
                   or pow(x, group["q"], group["p"]) != 1 for x in tags)):
        return False
    timings = [ctx.get("accept_by"), ctx.get("deadline"), ctx.get("read_bound"),
               ctx.get("compute_bound"), ctx.get("delivery_bound")]
    if any(type(x) is not int for x in timings):
        return False
    accept_by, deadline, read_bound, compute_bound, delivery_bound = timings
    if (accept_by < 0 or deadline < accept_by
            or min(read_bound, compute_bound, delivery_bound) < 0
            or deadline - read_bound - compute_bound - delivery_bound < 0):
        return False
    if type(ctx.get("service")) is not str or ctx["service"] not in {"bounded_delivery", "censorable"}:
        return False
    if (type(receipts) is not dict
            or any(type(k) is not str or type(v) is not dict
                   or type(v.get("actor")) is not int for k, v in receipts.items())):
        return False
    if (type(closures) is not dict
            or any(type(k) is not str or type(v) is not dict for k, v in closures.items())):
        return False
    return True


def expected_tag(ctx: dict[str, Any], actor: int) -> int:
    p, q = ctx["group"]["p"], ctx["group"]["q"]
    product = 1
    for power, coefficient in enumerate(ctx["coefficient_tags"]):
        product = product * pow(coefficient, pow(actor, power, q), p) % p
    return product


def record(env: dict[str, Any], token: Any) -> dict[str, Any] | None:
    if not isinstance(token, str):
        return None
    return env["receipts"].get(token)


def active(env: dict[str, Any], r: dict[str, Any] | None,
           actor: int | None = None, kind: str | None = None) -> bool:
    if r is None or r.get("context") != env["context"]["id"]:
        return False
    if actor is not None and (not integer(r.get("actor")) or r.get("actor") != actor):
        return False
    if kind is not None and r.get("kind") != kind:
        return False
    return True


def accepted(env: dict[str, Any], actor: int) -> str | None:
    """The class requires exactly one well-formed accepted opening duty."""
    ctx = env["context"]
    candidates = []
    for token, r in env["receipts"].items():
        b = r.get("body")
        if not active(env, r, actor, "accept") or not isinstance(b, dict):
            continue
        if set(b) != {"commitment", "deadline", "round"}:
            continue
        if (type(b["commitment"]) is str and len(b["commitment"]) == 64
                and all(c in "0123456789abcdef" for c in b["commitment"])
                and integer(b["deadline"]) and b["deadline"] == ctx["deadline"]
                and b["round"] == "open"
                and integer(r["time"]) and 0 <= r["time"] <= ctx["accept_by"]):
            candidates.append(token)
    return candidates[0] if len(candidates) == 1 else None


def opening_status(env: dict[str, Any], actor: int, accept: str,
                   token: str) -> str:
    r, a = record(env, token), record(env, accept)
    if (not active(env, r, actor, "open") or a is None
            or not integer(r["time"]) or r["time"] < a["time"]
            or r["time"] > env["context"]["deadline"]):
        return "out_of_class"
    b = r["body"]
    if (not isinstance(b, dict) or set(b) != {"tag", "nonce"}
            or not integer(b.get("tag")) or type(b.get("nonce")) is not str):
        return "malformed"
    tag = b["tag"]
    p, q = env["context"]["group"]["p"], env["context"]["group"]["q"]
    if not 1 <= tag < p or pow(tag, q, p) != 1:
        return "malformed"
    c = commitment(env["context"]["id"], actor, tag, b["nonce"])
    if c != a["body"]["commitment"]:
        return "commitment_mismatch"
    if tag != expected_tag(env["context"], actor):
        return "tag_mismatch"
    return "valid"


def ready_record(env: dict[str, Any]) -> str | None:
    ctx = env["context"]
    last_ready = ctx["deadline"] - ctx["read_bound"] - ctx["compute_bound"] - ctx["delivery_bound"]
    options = []
    for token, r in env["receipts"].items():
        if (active(env, r, 0, "ready") and r["body"] == {"round": "open"}
                and integer(r["time"]) and 0 <= r["time"] <= last_ready):
            options.append(token)
    return min(options) if options else None


def closed_contents(env: dict[str, Any], token: Any) -> list[str] | None:
    ctx = env["context"]
    snap = env["closures"].get(token) if isinstance(token, str) else None
    if (not isinstance(snap, dict) or set(snap) != {"context", "cutoff", "records"}
            or snap["context"] != ctx["id"] or not integer(snap["cutoff"])
            or snap["cutoff"] != ctx["deadline"]):
        return None
    expected = sorted(k for k, r in env["receipts"].items()
                      if r["context"] == ctx["id"] and r["time"] <= ctx["deadline"])
    # Completeness is an ideal board axiom. This equality checks our encoding of it.
    if snap["records"] != expected:
        return None
    return expected


def verify(env: dict[str, Any], certificate: Any) -> bool:
    """Fail closed for an untrusted certificate and damaged setup encoding."""
    if not valid_environment(env):
        return False
    try:
        if not isinstance(certificate, dict):
            return False
        c, ctx = certificate, env["context"]
        if (c.get("context") != ctx["id"] or not integer(c.get("actor"))
                or c["actor"] not in ctx["roster"]):
            return False
        actor = c["actor"]
        accept = accepted(env, actor)
        if accept is None or c.get("accept") != accept:
            return False
        if c.get("kind") == "bad_opening":
            if set(c) != {"kind", "context", "actor", "accept", "opening"}:
                return False
            return opening_status(env, actor, accept, c["opening"]) in {
                "malformed", "commitment_mismatch", "tag_mismatch"}
        if c.get("kind") == "nonopening":
            if set(c) != {"kind", "context", "actor", "accept", "closure", "ready"}:
                return False
            # Reliability cannot be asserted by the certificate itself.
            if ctx["service"] != "bounded_delivery":
                return False
            ready = ready_record(env)
            if ready is None or c["ready"] != ready:
                return False
            contents = closed_contents(env, c["closure"])
            if contents is None or accept not in contents or ready not in contents:
                return False
            # A malformed opening is handled by the positive-evidence rule instead.
            return not any(active(env, record(env, t), actor, "open") for t in contents)
        return False
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def extract(env: dict[str, Any]) -> list[dict[str, Any]]:
    """Canonical public extraction. It has no access to scalar witnesses."""
    if not valid_environment(env):
        return []
    try:
        ctx = env["context"]
        result = []
        for actor in ctx["roster"]:
            a = accepted(env, actor)
            if a is None:
                continue
            base = {"context": ctx["id"], "actor": actor, "accept": a}
            bad = []
            for token in sorted(env["receipts"]):
                c = dict(base, kind="bad_opening", opening=token)
                if verify(env, c):
                    bad.append(c)
            if bad:
                result.append(bad[0])
                continue
            for token in sorted(env["closures"]):
                c = dict(base, kind="nonopening", closure=token, ready=ready_record(env))
                if verify(env, c):
                    result.append(c)
                    break
        return result
    except (KeyError, TypeError, ValueError, OverflowError):
        return []
