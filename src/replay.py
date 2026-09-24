"""Separately written replay predicate; imports no producer/checker helpers.

This is an implementation cross-check, not an independent human review or a
proof assistant. The authenticated-record oracle is the same declared model.
"""
from __future__ import annotations
import hashlib
import json
from typing import Any


_CONTEXT_KEYS = {
    "id", "roster", "group", "threshold", "coefficient_tags", "service",
    "accept_by", "deadline", "compute_bound", "delivery_bound", "read_bound",
}


def _well_formed_setup(env: Any) -> bool:
    if type(env) is not dict or set(env) != {"context", "receipts", "closures"}:
        return False
    ctx, receipts, closures = env.get("context"), env.get("receipts"), env.get("closures")
    if type(ctx) is not dict or set(ctx) != _CONTEXT_KEYS:
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
            or not (2 < group["p"] and 1 < group["q"] < group["p"]
                    and 1 < group["g"] < group["p"]
                    and (group["p"] - 1) % group["q"] == 0
                    and pow(group["g"], group["q"], group["p"]) == 1)):
        return False
    if type(ctx.get("threshold")) is not int or not (1 <= ctx["threshold"] <= len(roster)):
        return False
    tags = ctx.get("coefficient_tags")
    if (type(tags) is not list or len(tags) != ctx["threshold"]
            or any(type(x) is not int or not (1 <= x < group["p"])
                   or pow(x, group["q"], group["p"]) != 1 for x in tags)):
        return False
    times = [ctx.get("accept_by"), ctx.get("deadline"), ctx.get("read_bound"),
             ctx.get("compute_bound"), ctx.get("delivery_bound")]
    if any(type(x) is not int for x in times):
        return False
    accept_by, deadline, read_bound, compute_bound, delivery_bound = times
    if (accept_by < 0 or deadline < accept_by
            or min(read_bound, compute_bound, delivery_bound) < 0
            or deadline - read_bound - compute_bound - delivery_bound < 0):
        return False
    if type(ctx.get("service")) is not str or ctx["service"] not in {"bounded_delivery", "censorable"}:
        return False
    return bool(type(receipts) is dict
                and all(type(k) is str and type(v) is dict for k, v in receipts.items())
                and type(closures) is dict
                and all(type(k) is str and type(v) is dict for k, v in closures.items()))


def replay(env: dict[str, Any], cert: Any) -> bool:
    if not _well_formed_setup(env):
        return False
    try:
        ctx = env["context"]
        if type(cert) is not dict or cert.get("context") != ctx["id"]:
            return False
        who = cert.get("actor")
        if type(who) is not int or who not in ctx["roster"]:
            return False
        recs = env["receipts"]
        accepts = []
        for name in recs:
            r = recs[name]
            if r["context"] != ctx["id"] or r["actor"] != who or r["kind"] != "accept":
                continue
            b = r["body"]
            if (type(b) is dict and set(b.keys()) == {"commitment", "deadline", "round"}
                    and type(b["commitment"]) is str and len(b["commitment"]) == 64
                    and set(b["commitment"]).issubset(set("0123456789abcdef"))
                    and type(b["deadline"]) is int and b["deadline"] == ctx["deadline"]
                    and b["round"] == "open" and type(r["time"]) is int
                    and r["time"] >= 0 and r["time"] <= ctx["accept_by"]):
                accepts.append(name)
        if len(accepts) != 1 or cert.get("accept") != accepts[0]:
            return False
        a = recs[accepts[0]]
        if cert.get("kind") == "bad_opening":
            if set(cert.keys()) != {"kind", "context", "actor", "accept", "opening"}:
                return False
            if type(cert["opening"]) is not str or cert["opening"] not in recs:
                return False
            r = recs[cert["opening"]]
            if (r["actor"] != who or r["context"] != ctx["id"] or r["kind"] != "open"
                    or type(r["time"]) is not int or r["time"] < a["time"]
                    or r["time"] > ctx["deadline"]):
                return False
            b = r["body"]
            if type(b) is not dict or set(b) != {"tag", "nonce"}:
                return True
            if type(b["tag"]) is not int or type(b["nonce"]) is not str:
                return True
            p, q = ctx["group"]["p"], ctx["group"]["q"]
            if b["tag"] < 1 or b["tag"] >= p or pow(b["tag"], q, p) != 1:
                return True
            message = ["exponent-tag-opening", ctx["id"], who, b["tag"], b["nonce"]]
            encoded = json.dumps(message, ensure_ascii=True, sort_keys=True,
                                 separators=(",", ":")).encode("ascii")
            if hashlib.sha256(encoded).hexdigest() != a["body"]["commitment"]:
                return True
            want = 1
            xpower = 1
            for v in ctx["coefficient_tags"]:
                want = want * pow(v, xpower, p) % p
                xpower = xpower * who % q
            return b["tag"] != want
        if cert.get("kind") != "nonopening" or set(cert) != {
                "kind", "context", "actor", "accept", "closure", "ready"}:
            return False
        if ctx["service"] != "bounded_delivery":
            return False
        limit = ctx["deadline"] - ctx["delivery_bound"] - ctx["compute_bound"] - ctx["read_bound"]
        enabled = sorted(name for name, r in recs.items()
                         if r["context"] == ctx["id"] and r["actor"] == 0
                         and r["kind"] == "ready" and r["body"] == {"round": "open"}
                         and type(r["time"]) is int and 0 <= r["time"] <= limit)
        if not enabled or cert["ready"] != enabled[0]:
            return False
        if type(cert["closure"]) is not str or cert["closure"] not in env["closures"]:
            return False
        close = env["closures"][cert["closure"]]
        if (set(close) != {"context", "cutoff", "records"}
                or close["context"] != ctx["id"] or type(close["cutoff"]) is not int
                or close["cutoff"] != ctx["deadline"]):
            return False
        visible = []
        for name, r in recs.items():
            if r["context"] == ctx["id"] and r["time"] <= ctx["deadline"]:
                visible.append(name)
        if close["records"] != sorted(visible):
            return False
        if accepts[0] not in visible or enabled[0] not in visible:
            return False
        for name in visible:
            r = recs[name]
            if r["actor"] == who and r["kind"] == "open":
                return False
        return True
    except (KeyError, TypeError, ValueError, OverflowError):
        return False
