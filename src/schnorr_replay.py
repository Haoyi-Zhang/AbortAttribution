"""Independent replay predicate for the concrete Schnorr-response fixtures.

It intentionally does not import schnorr_bridge.  Constants and equations are
repeated so producer/replay agreement is not a shared-function tautology.
"""
from __future__ import annotations
from hashlib import sha256
import json
from math import gcd
from typing import Any

P, Q, G = 467, 233, 4
N = 1009 * 1013
N2 = N * N
GP = N + 1
MASK_MAX = 65535
EMOD = 251
MAX_S = MASK_MAX + (EMOD - 1) * (Q - 1)


def _check_json(value: Any) -> None:
    if value is None or type(value) in {bool, int}:
        return
    if type(value) is str:
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            raise ValueError("surrogate code point")
        return
    if type(value) is list:
        for item in value:
            _check_json(item)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("non-string object key")
            _check_json(key); _check_json(item)
        return
    raise TypeError("unsupported JSON value")


def enc(obj: Any) -> bytes:
    _check_json(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def hint(domain: str, *parts: Any, modulus: int) -> int:
    h = sha256(); h.update(domain.encode("ascii") + b"\0")
    for part in parts:
        raw = enc(part); h.update(len(raw).to_bytes(8, "big")); h.update(raw)
    return int.from_bytes(h.digest(), "big") % modulus


def scalar(domain: str, *parts: Any) -> int:
    return hint(domain, *parts, modulus=Q)


def subgroup(x: Any) -> bool:
    return type(x) is int and 1 <= x < P and pow(x, Q, P) == 1


_SEED_KEYS = {"ceremony", "roster", "round", "message", "variant"}
_CONTEXT_KEYS = {"seed_context", "verification_shares", "nonce_tags", "sender", "auth_public"}


def transcript_context(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "seed_context": context["seed_context"],
        "nonce_tags": context["nonce_tags"],
    }


def context_ok(context: Any) -> bool:
    if type(context) is not dict or set(context) != _CONTEXT_KEYS:
        return False
    try:
        enc(context)
    except (TypeError, ValueError, UnicodeError):
        return False
    seed = context.get("seed_context")
    if type(seed) is not dict or set(seed) != _SEED_KEYS:
        return False
    roster = seed.get("roster")
    shares = context.get("verification_shares")
    nonces = context.get("nonce_tags")
    return bool(
        type(seed.get("ceremony")) is str and seed["ceremony"]
        and type(seed.get("message")) is str and seed["message"]
        and type(seed.get("variant")) is str and seed["variant"]
        and type(roster) is list and 3 <= len(roster) <= 10
        and all(type(member) is int for member in roster)
        and roster == list(range(1, len(roster) + 1))
        and type(seed.get("round")) is int and 1 <= seed["round"] <= 8
        and type(context.get("sender")) is int and context["sender"] in roster
        and subgroup(context.get("auth_public"))
        and type(shares) is list and len(shares) == len(roster)
        and all(subgroup(share) for share in shares)
        and type(nonces) is list and len(nonces) == len(roster)
        and all(subgroup(tag) for tag in nonces)
    )


def auth(body: Any, public: Any, sig: Any) -> bool:
    if not (isinstance(body, dict) and subgroup(public) and isinstance(sig, dict)
            and set(sig) == {"commitment", "response"} and subgroup(sig["commitment"])
            and type(sig["response"]) is int and 0 <= sig["response"] < Q):
        return False
    try:
        e = scalar("nfaa-auth-challenge-v1", public, sig["commitment"], body)
    except (TypeError, ValueError, UnicodeError):
        return False
    return pow(G, sig["response"], P) == (sig["commitment"] * pow(public, e, P)) % P


def lagrange(i: int, signers: list[int]) -> int | None:
    if i not in signers or len(set(signers)) != len(signers): return None
    num, den = 1, 1
    for j in signers:
        if j != i:
            num = num * (-j) % Q; den = den * (i - j) % Q
    try: return num * pow(den, -1, Q) % Q
    except ValueError: return None


def bind_context(body: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    return {
        "transcript_context": transcript_context(context),
        "verification_shares": context["verification_shares"],
        "sender": context["sender"],
        "auth_public": context["auth_public"],
        "recipient_encryption_key": {"scheme": "toy-paillier", "modulus": N},
        "purpose": "encrypted-schnorr-response",
    }


def binding(ctx: dict[str, Any], c: Any, ztag: Any, proof: Any) -> bool:
    if not (subgroup(ztag) and type(c) is int and 1 <= c < N2 and gcd(c, N) == 1
            and isinstance(proof, dict)
            and set(proof) == {"a_group", "a_paillier", "challenge", "response", "response_randomness"}):
        return False
    A, B, e, s, t = (proof[k] for k in ("a_group", "a_paillier", "challenge", "response", "response_randomness"))
    if not (subgroup(A) and type(B) is int and 1 <= B < N2 and type(e) is int and 0 <= e < EMOD
            and type(s) is int and 0 <= s <= MAX_S < N and type(t) is int and 1 <= t < N and gcd(t, N) == 1):
        return False
    try:
        expected = hint("nfaa-binding-challenge-v1", ctx, c, ztag, A, B, modulus=EMOD)
    except (TypeError, ValueError, UnicodeError):
        return False
    if e != expected: return False
    return (pow(G, s, P) == A * pow(ztag, e, P) % P
            and pow(GP, s, N2) * pow(t, N, N2) % N2 == B * pow(c, e, N2) % N2)


def signing_challenge(context: dict[str, Any]) -> int:
    seed = context["seed_context"]
    aggregate_nonce = 1
    for tag in context["nonce_tags"]:
        aggregate_nonce = aggregate_nonce * tag % P
    statement = {
        "ceremony": seed["ceremony"],
        "roster": seed["roster"],
        "round": seed["round"],
        "message": seed["message"],
        "variant": seed["variant"],
        "aggregate_nonce": aggregate_nonce,
    }
    return scalar("nfaa-signing-challenge-v2", statement)


def equation(body: dict[str, Any]) -> bool:
    keys = {"context", "sender", "round", "signers", "evrf_verified", "nonce_tag",
            "verification_share", "challenge", "lagrange", "response_tag", "ciphertext", "binding_proof"}
    if not isinstance(body, dict) or set(body) != keys: return False
    context, s = body.get("context"), body.get("signers")
    if not context_ok(context): return False
    seed = context["seed_context"]
    if not (type(body.get("sender")) is int and body["sender"] == context["sender"]
            and type(body.get("round")) is int and body["round"] == seed["round"]
            and isinstance(s, list) and s == seed["roster"] and all(type(x) is int for x in s)
            and body.get("evrf_verified") is True
            and subgroup(body.get("nonce_tag"))
            and body["nonce_tag"] == context["nonce_tags"][body["sender"] - 1]
            and subgroup(body.get("verification_share"))
            and body["verification_share"] == context["verification_shares"][body["sender"] - 1]
            and subgroup(body.get("response_tag")) and type(body.get("challenge")) is int
            and 0 <= body["challenge"] < Q and type(body.get("lagrange")) is int and 0 <= body["lagrange"] < Q):
        return False
    lam = lagrange(body["sender"], s)
    try:
        expected_challenge = signing_challenge(context)
    except (TypeError, ValueError, UnicodeError):
        return False
    if lam is None or lam != body["lagrange"] or body["challenge"] != expected_challenge:
        return False
    exponent = body["challenge"] * lam % Q
    return body["response_tag"] == body["nonce_tag"] * pow(body["verification_share"], exponent, P) % P


def replay(case: dict[str, Any]) -> str:
    context = case.get("context")
    if (not context_ok(context) or case.get("auth_public") != context["auth_public"]
            or type(case.get("service")) is not str
            or case["service"] not in {"bounded_delivery", "censorable"}):
        return "none"
    present = case.get("envelope_present")
    env = case.get("envelope")
    if type(present) is not bool or present != (env is not None):
        return "none"
    if not present:
        if (case.get("service") == "bounded_delivery" and case.get("accepted_duty") is True
                and case.get("ready_on_time") is True and case.get("complete_closure") is True):
            return "qualified_nonopening"
        return "none"
    if not (isinstance(env, dict) and set(env) == {"body", "signature"} and isinstance(env.get("body"), dict)):
        return "none"
    body = env["body"]
    if not auth(body, case.get("auth_public"), env.get("signature")): return "none"
    if body.get("context") != context: return "none"
    seed = context["seed_context"]
    if (body.get("round") != seed["round"]
            or body.get("sender") != context["sender"]
            or body.get("signers") != seed["roster"]):
        return "bad_binding"
    if not binding(bind_context(body, context), body.get("ciphertext"), body.get("response_tag"), body.get("binding_proof")):
        return "bad_binding"
    if not equation(body): return "bad_response"
    return "none"
