"""Reference checker for the ideal attribution-compiler transcript.

Ideal signature/NIZK verification results are trusted transcript inputs.  This
module checks binding, context, deadlines, closure completeness, and evidence
shape.  It does not implement encryption, signatures, NIZKs, or an eVRF.
"""
from __future__ import annotations
from hashlib import sha256
import json
from typing import Any


def _canonical(value: Any) -> bytes:
    if value is None or type(value) in {bool, int}:
        pass
    elif type(value) is str:
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            raise ValueError("surrogate code point")
    elif type(value) is list:
        for item in value:
            _canonical(item)
    elif type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("non-string object key")
            _canonical(key); _canonical(item)
    else:
        raise TypeError("unsupported JSON value")
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _digest(obj: Any) -> str | None:
    try:
        return sha256(_canonical(obj)).hexdigest()
    except (TypeError, ValueError, UnicodeError):
        return None


def _int(value: Any) -> bool:
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
    "id", "roster", "round", "sender", "recipient", "group",
    "accept_by", "deadline", "read_bound", "compute_bound",
    "delivery_bound", "service",
}


def valid_environment(env: Any) -> bool:
    """Validate the trusted-context encoding before evaluating untrusted evidence.

    The theorem treats the board context as setup input.  The implementation
    nevertheless fails closed when a serialized setup is damaged, rather than
    throwing or accidentally interpreting Python coercions as protocol values.
    Deliberately malformed *record bodies* remain admissible because they are
    exactly what positive-evidence certificates classify.
    """
    if type(env) is not dict or set(env) != {"context", "records", "closures"}:
        return False
    ctx, records, closures = env.get("context"), env.get("records"), env.get("closures")
    if type(ctx) is not dict or set(ctx) != _CONTEXT_FIELDS:
        return False
    if type(ctx.get("id")) is not str or not ctx["id"] or _digest(ctx["id"]) is None:
        return False
    roster = ctx.get("roster")
    if (type(roster) is not list or not (1 <= len(roster) <= 10)
            or any(type(x) is not int or x <= 0 for x in roster)
            or len(set(roster)) != len(roster)):
        return False
    if (not _int(ctx.get("round")) or not (1 <= ctx["round"] <= 8)
            or type(ctx.get("sender")) is not int or ctx["sender"] not in roster
            or type(ctx.get("recipient")) is not int or ctx["recipient"] not in roster):
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
    timing = (ctx.get("accept_by"), ctx.get("deadline"), ctx.get("read_bound"),
              ctx.get("compute_bound"), ctx.get("delivery_bound"))
    if any(type(x) is not int for x in timing):
        return False
    accept_by, deadline, read_bound, compute_bound, delivery_bound = timing
    if (accept_by < 0 or deadline < accept_by
            or min(read_bound, compute_bound, delivery_bound) < 0
            or deadline - read_bound - compute_bound - delivery_bound < 0):
        return False
    if type(ctx.get("service")) is not str or ctx["service"] not in {"bounded_delivery", "censorable"}:
        return False
    if (type(records) is not dict or any(type(k) is not str or type(v) is not dict
                                         for k, v in records.items())):
        return False
    if (type(closures) is not dict or any(type(k) is not str or type(v) is not dict
                                          for k, v in closures.items())):
        return False
    return True


def _record(env: dict[str, Any], token: Any) -> dict[str, Any] | None:
    return env.get("records", {}).get(token) if isinstance(token, str) else None


def _active(env: dict[str, Any], record: dict[str, Any] | None, kind: str, actor: int | None = None) -> bool:
    if not isinstance(record, dict) or record.get("context") != env["context"]["id"]:
        return False
    if record.get("kind") != kind:
        return False
    if actor is not None and (not _int(record.get("actor")) or record.get("actor") != actor):
        return False
    return True


def _valid_accept(env: dict[str, Any], actor: int, token: Any) -> bool:
    ctx = env["context"]
    r = _record(env, token)
    return bool(
        _active(env, r, "accept", actor)
        and r.get("signature_valid") is True
        and _int(r.get("time")) and 0 <= r["time"] <= ctx["accept_by"]
        and type(r.get("body")) is dict
        and all(_int(r["body"].get(field)) for field in ("round", "recipient", "deadline"))
        and r.get("body") == {"round": ctx["round"], "recipient": ctx["recipient"], "deadline": ctx["deadline"]}
    )


def _accepted_duty(env: dict[str, Any], actor: int, token: Any) -> bool:
    """Require one and only one active accepted duty for this actor."""
    valid = [name for name in env.get("records", {}) if _valid_accept(env, actor, name)]
    return len(valid) == 1 and valid[0] == token


def _envelope_shape(env: dict[str, Any], token: Any, actor: int) -> tuple[bool, bool]:
    """Return ``(sender_attributable, content_valid)`` for any received envelope.

    Receipt time is intentionally *not* part of the positive-content predicate.
    A correct envelope observed at ``D+1`` is not a malformed entry merely
    because transport was late.  Timely fulfilment is decided separately by the
    bounded-service non-opening rule and the complete closure at ``D``.
    """
    ctx = env["context"]
    r = _record(env, token)
    if not (_active(env, r, "envelope", actor) and r.get("signature_valid") is True
            and _int(r.get("time")) and r["time"] >= 0):
        return False, False
    body = r.get("body")
    if not isinstance(body, dict) or set(body) != {"statement", "entry_proof_valid", "entry_proof_statement"}:
        return True, False
    st = body.get("statement")
    if not isinstance(st, dict) or set(st) != {"sender", "recipient", "round", "tag", "ciphertext"}:
        return True, False
    if (any(not _int(st.get(field)) for field in ("sender", "recipient", "round"))
            or st.get("sender") != actor or st.get("recipient") != ctx["recipient"] or st.get("round") != ctx["round"]
            or not _int(st.get("tag")) or type(st.get("ciphertext")) is not str
            or body.get("entry_proof_statement") != _digest(st)):
        return True, False
    return True, body.get("entry_proof_valid") is True


def _complaint_valid(env: dict[str, Any], token: Any, actor: int, envelope: str) -> bool:
    ctx = env["context"]
    r = _record(env, token)
    cited = _record(env, envelope)
    if not (_active(env, r, "complaint", ctx["recipient"]) and r.get("signature_valid") is True
            and _int(r.get("time")) and 0 <= r["time"] <= ctx["deadline"]
            and isinstance(cited, dict) and _int(cited.get("time"))
            and cited["time"] <= r["time"]):
        return False
    body = r.get("body")
    expected_statement = _digest([ctx["id"], envelope, actor, ctx["recipient"], ctx["round"]])
    return bool(
        isinstance(body, dict)
        and set(body) == {"envelope", "accused", "claim", "complaint_proof_valid", "complaint_statement"}
        and body.get("envelope") == envelope
        and _int(body.get("accused"))
        and body.get("accused") == actor
        and body.get("claim") == "base_relation_false"
        and body.get("complaint_statement") == expected_statement
        and body.get("complaint_proof_valid") is True
    )


def _ready(env: dict[str, Any], token: Any) -> bool:
    ctx = env["context"]
    r = _record(env, token)
    latest = ctx["deadline"] - ctx["read_bound"] - ctx["compute_bound"] - ctx["delivery_bound"]
    return bool(
        _active(env, r, "ready", 0)
        and r.get("signature_valid") is True
        and type(r.get("body")) is dict and _int(r["body"].get("round"))
        and r.get("body") == {"round": ctx["round"]}
        and _int(r.get("time")) and 0 <= r["time"] <= latest
    )


def _closed(env: dict[str, Any], token: Any) -> set[str] | None:
    ctx = env["context"]
    snap = env.get("closures", {}).get(token) if isinstance(token, str) else None
    if not (isinstance(snap, dict) and set(snap) == {"context", "cutoff", "complete", "records"}
            and snap.get("context") == ctx["id"] and _int(snap.get("cutoff")) and snap.get("cutoff") == ctx["deadline"]
            and snap.get("complete") is True and isinstance(snap.get("records"), list)
            and all(type(x) is str for x in snap["records"])):
        return None
    expected = sorted(k for k, r in env["records"].items()
                      if r.get("context") == ctx["id"] and _int(r.get("time")) and r["time"] <= ctx["deadline"])
    if snap["records"] != expected:
        return None
    return set(expected)


def verify(env: dict[str, Any], cert: dict[str, Any]) -> bool:
    if not valid_environment(env):
        return False
    if not isinstance(cert, dict) or set(cert) not in (
        {"kind", "context", "actor", "envelope"},
        {"kind", "context", "actor", "envelope", "complaint"},
        {"kind", "context", "actor", "accept", "ready", "closure"},
    ):
        return False
    ctx = env.get("context", {})
    actor = cert.get("actor")
    if cert.get("context") != ctx.get("id") or type(actor) is not int or actor not in ctx.get("roster", []):
        return False
    if cert["kind"] == "bad_entry":
        if set(cert) != {"kind", "context", "actor", "envelope"}:
            return False
        attributable, accepted = _envelope_shape(env, cert["envelope"], actor)
        return attributable and not accepted
    if cert["kind"] == "bad_message":
        if set(cert) != {"kind", "context", "actor", "envelope", "complaint"}:
            return False
        _, accepted = _envelope_shape(env, cert["envelope"], actor)
        return accepted and _complaint_valid(env, cert["complaint"], actor, cert["envelope"])
    if cert["kind"] == "nonopening":
        if set(cert) != {"kind", "context", "actor", "accept", "ready", "closure"}:
            return False
        if ctx.get("service") != "bounded_delivery":
            return False
        if not _accepted_duty(env, actor, cert["accept"]) or not _ready(env, cert["ready"]):
            return False
        contents = _closed(env, cert["closure"])
        if contents is None:
            return False
        for token in contents:
            attributable, _ = _envelope_shape(env, token, actor)
            if attributable:
                return False
        return True
    return False


def extract(env: dict[str, Any]) -> list[dict[str, Any]]:
    """Canonical public extraction without reserved record names.

    Every reference is discovered by its validated record semantics.  When
    several readiness or deadline-closure records qualify, the lexicographically
    least valid reference tuple is chosen.  Accepted duties remain unique by the
    certificate-class definition.
    """
    if not valid_environment(env):
        return []
    try:
        ctx = env["context"]
        actor = ctx["sender"]
        out: list[dict[str, Any]] = []
        for token in sorted(env["records"]):
            attributable, content_valid = _envelope_shape(env, token, actor)
            if attributable and not content_valid:
                candidate = {"kind": "bad_entry", "context": ctx["id"], "actor": actor, "envelope": token}
                if verify(env, candidate):
                    out.append(candidate)
            if content_valid:
                for complaint in sorted(env["records"]):
                    candidate = {"kind": "bad_message", "context": ctx["id"], "actor": actor,
                                 "envelope": token, "complaint": complaint}
                    if verify(env, candidate):
                        out.append(candidate)
                        break

        accepts = sorted(name for name in env["records"] if _valid_accept(env, actor, name))
        if len(accepts) == 1:
            ready_refs = sorted(name for name in env["records"] if _ready(env, name))
            closure_refs = sorted(name for name in env["closures"] if _closed(env, name) is not None)
            chosen: dict[str, Any] | None = None
            for ready in ready_refs:
                for closure in closure_refs:
                    candidate = {"kind": "nonopening", "context": ctx["id"], "actor": actor,
                                 "accept": accepts[0], "ready": ready, "closure": closure}
                    if verify(env, candidate):
                        chosen = candidate
                        break
                if chosen is not None:
                    break
            if chosen is not None:
                out.append(chosen)

        def order(cert: dict[str, Any]) -> tuple[Any, ...]:
            return (cert["actor"], cert["kind"], cert.get("envelope", ""),
                    cert.get("complaint", ""), cert.get("accept", ""),
                    cert.get("ready", ""), cert.get("closure", ""))
        return sorted(out, key=order)
    except (KeyError, TypeError, ValueError, OverflowError):
        return []
