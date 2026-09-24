"""Independent replay checker for compiler certificates.

This implementation intentionally does not import compiler_checker or
compiler_cases.  It re-expresses the public rules with different control flow.
"""
from __future__ import annotations
from hashlib import sha256
import json
from typing import Any


def _wire(value: Any) -> bytes:
    if value is None or type(value) in {bool, int}:
        pass
    elif type(value) is str:
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            raise ValueError("surrogate code point")
    elif type(value) is list:
        for item in value:
            _wire(item)
    elif type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("non-string object key")
            _wire(key); _wire(item)
    else:
        raise TypeError("unsupported JSON value")
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _hash(obj: Any) -> str | None:
    try:
        return sha256(_wire(obj)).hexdigest()
    except (TypeError, ValueError, UnicodeError):
        return None


_REQUIRED_CONTEXT = {
    "id", "roster", "round", "sender", "recipient", "group",
    "accept_by", "deadline", "read_bound", "compute_bound",
    "delivery_bound", "service",
}


def _setup_is_well_formed(env: Any) -> bool:
    # Independently restated parser boundary; no producer/checker helper import.
    if type(env) is not dict or set(env) != {"context", "records", "closures"}:
        return False
    ctx, records, closures = env.get("context"), env.get("records"), env.get("closures")
    if type(ctx) is not dict or set(ctx) != _REQUIRED_CONTEXT:
        return False
    if type(ctx.get("id")) is not str or not ctx["id"] or _hash(ctx["id"]) is None:
        return False
    roster = ctx.get("roster")
    if (type(roster) is not list or not (1 <= len(roster) <= 10)
            or any(type(x) is not int or x <= 0 for x in roster)
            or len(set(roster)) != len(roster)):
        return False
    if (type(ctx.get("round")) is not int or not (1 <= ctx["round"] <= 8)
            or type(ctx.get("sender")) is not int or ctx["sender"] not in roster
            or type(ctx.get("recipient")) is not int or ctx["recipient"] not in roster):
        return False
    group = ctx.get("group")
    if (type(group) is not dict or set(group) != {"p", "q", "g"}
            or any(type(group.get(k)) is not int for k in ("p", "q", "g"))
            or not (2 < group["p"] and 1 < group["q"] < group["p"]
                    and 1 < group["g"] < group["p"]
                    and (group["p"] - 1) % group["q"] == 0
                    and pow(group["g"], group["q"], group["p"]) == 1)):
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
    return bool(type(records) is dict
                and all(type(k) is str and type(v) is dict for k, v in records.items())
                and type(closures) is dict
                and all(type(k) is str and type(v) is dict for k, v in closures.items()))


def replay(env: dict[str, Any], cert: dict[str, Any]) -> bool:
    if not _setup_is_well_formed(env):
        return False
    if type(cert) is not dict:
        return False
    ctx = env.get("context")
    records = env.get("records")
    if type(ctx) is not dict or type(records) is not dict:
        return False
    actor = cert.get("actor")
    if type(actor) is not int or actor not in ctx.get("roster", []) or cert.get("context") != ctx.get("id"):
        return False

    def rec(name: Any) -> dict[str, Any] | None:
        x = records.get(name) if type(name) is str else None
        return x if type(x) is dict and x.get("context") == ctx["id"] else None

    def envelope(name: Any) -> tuple[bool, bool]:
        r = rec(name)
        if not r or r.get("kind") != "envelope" or r.get("actor") != actor or r.get("signature_valid") is not True:
            return False, False
        if type(r.get("time")) is not int or not (0 <= r["time"] <= ctx["deadline"]):
            return False, False
        b = r.get("body")
        if type(b) is not dict or set(b) != {"statement", "entry_proof_valid", "entry_proof_statement"}:
            return True, False
        s = b.get("statement")
        shape = (type(s) is dict and set(s) == {"sender", "recipient", "round", "tag", "ciphertext"}
                 and s.get("sender") == actor and s.get("recipient") == ctx["recipient"]
                 and s.get("round") == ctx["round"] and type(s.get("tag")) is int
                 and type(s.get("ciphertext")) is str and b.get("entry_proof_statement") == _hash(s))
        return True, bool(shape and b.get("entry_proof_valid") is True)

    kind = cert.get("kind")
    if kind == "bad_entry" and set(cert) == {"kind", "context", "actor", "envelope"}:
        attributable, accepted = envelope(cert["envelope"])
        return attributable and not accepted
    if kind == "bad_message" and set(cert) == {"kind", "context", "actor", "envelope", "complaint"}:
        _, accepted = envelope(cert["envelope"])
        if not accepted:
            return False
        c = rec(cert["complaint"])
        if not c or c.get("kind") != "complaint" or c.get("actor") != ctx["recipient"] or c.get("signature_valid") is not True:
            return False
        cited = rec(cert["envelope"])
        if (type(c.get("time")) is not int or not (0 <= c["time"] <= ctx["deadline"])
                or not cited or type(cited.get("time")) is not int or c["time"] < cited["time"]):
            return False
        b = c.get("body")
        return bool(type(b) is dict
                    and set(b) == {"envelope", "accused", "claim", "complaint_proof_valid", "complaint_statement"}
                    and b.get("envelope") == cert["envelope"] and b.get("accused") == actor
                    and b.get("claim") == "base_relation_false" and b.get("complaint_proof_valid") is True
                    and b.get("complaint_statement") == _hash([ctx["id"], cert["envelope"], actor,
                                                               ctx["recipient"], ctx["round"]]))
    if kind == "nonopening" and set(cert) == {"kind", "context", "actor", "accept", "ready", "closure"}:
        if ctx.get("service") != "bounded_delivery":
            return False
        a, r = rec(cert["accept"]), rec(cert["ready"])
        def accepted(name: str) -> bool:
            item = rec(name)
            return bool(item and item.get("kind") == "accept" and item.get("actor") == actor
                        and item.get("signature_valid") is True and type(item.get("time")) is int
                        and 0 <= item["time"] <= ctx["accept_by"]
                        and item.get("body") == {"round": ctx["round"], "recipient": ctx["recipient"],
                                                 "deadline": ctx["deadline"]})
        accepted_names = [name for name in records if accepted(name)]
        if len(accepted_names) != 1 or accepted_names[0] != cert["accept"] or not a:
            return False
        latest = ctx["deadline"] - ctx["read_bound"] - ctx["compute_bound"] - ctx["delivery_bound"]
        if not (r and r.get("kind") == "ready" and r.get("actor") == 0 and r.get("signature_valid") is True
                and type(r.get("time")) is int and 0 <= r["time"] <= latest
                and r.get("body") == {"round": ctx["round"]}):
            return False
        snap = env.get("closures", {}).get(cert["closure"])
        if not (type(snap) is dict and set(snap) == {"context", "cutoff", "complete", "records"}
                and snap.get("context") == ctx["id"] and snap.get("cutoff") == ctx["deadline"]
                and snap.get("complete") is True and type(snap.get("records")) is list
                and all(type(x) is str for x in snap["records"])):
            return False
        actual = sorted(k for k, value in records.items()
                        if value.get("context") == ctx["id"] and type(value.get("time")) is int
                        and value["time"] <= ctx["deadline"])
        if snap["records"] != actual:
            return False
        return not any(envelope(name)[0] for name in actual)
    return False
