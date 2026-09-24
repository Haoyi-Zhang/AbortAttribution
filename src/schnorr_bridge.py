"""Concrete toy arithmetic for the eVRF-driven Schnorr response bridge.

This is a deterministic conformance model, not production cryptography.  It
implements a prime-order subgroup, Paillier encryption, a deliberately tiny
Fiat--Shamir plaintext/exponent equality transcript, Schnorr authentication,
the partial-response equation, and the qualified-omission boundary.  The tiny
transcript is used only to check honest algebra and to retain an explicit
small-challenge forgery negative control; it is not the proof system assumed by
the paper theorem.  The eVRF proof is an imported verification bit; the nonce
scalar is generated only to construct owned fixtures.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
import json
from math import gcd, lcm
from typing import Any

# Small fixed parameters selected for exact deterministic conformance checks.
GROUP_P = 467
GROUP_Q = 233
GROUP_G = 4
PAILLIER_P = 1009
PAILLIER_Q = 1013
PAILLIER_N = PAILLIER_P * PAILLIER_Q
PAILLIER_N2 = PAILLIER_N * PAILLIER_N
PAILLIER_G = PAILLIER_N + 1
MASK_MAX = 65535
CHALLENGE_MOD = 251
MAX_RESPONSE = MASK_MAX + (CHALLENGE_MOD - 1) * (GROUP_Q - 1)


def _validate_canonical_json(value: Any) -> None:
    """Reject values whose JSON spelling is ambiguous across implementations."""
    if value is None or type(value) in {bool, int}:
        return
    if type(value) is str:
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            raise ValueError("lone Unicode surrogate is not a canonical string")
        return
    if type(value) is list:
        for item in value:
            _validate_canonical_json(item)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("canonical JSON object keys must be strings")
            _validate_canonical_json(key)
            _validate_canonical_json(item)
        return
    raise TypeError(f"unsupported canonical JSON type: {type(value).__name__}")


def canonical(obj: Any) -> bytes:
    _validate_canonical_json(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _hash_int(domain: str, *parts: Any, modulus: int) -> int:
    h = sha256()
    h.update(domain.encode("ascii") + b"\0")
    for part in parts:
        raw = canonical(part)
        h.update(len(raw).to_bytes(8, "big"))
        h.update(raw)
    return int.from_bytes(h.digest(), "big") % modulus


def hash_scalar(domain: str, *parts: Any, nonzero: bool = False) -> int:
    value = _hash_int(domain, *parts, modulus=GROUP_Q)
    return 1 if nonzero and value == 0 else value


def _coprime_from_hash(domain: str, *parts: Any, modulus: int) -> int:
    value = 2 + _hash_int(domain, *parts, modulus=modulus - 2)
    while gcd(value, modulus) != 1:
        value += 1
        if value >= modulus:
            value = 2
    return value


def subgroup_element(value: Any) -> bool:
    return type(value) is int and 1 <= value < GROUP_P and pow(value, GROUP_Q, GROUP_P) == 1


_CONTEXT_FIELDS = {"ceremony", "roster", "round", "message", "variant", "sender", "auth_public", "nonce_tags"}


def valid_context(context: Any) -> bool:
    """Validate the fixed toy ceremony context and its registered sender key."""
    if type(context) is not dict or set(context) != _CONTEXT_FIELDS:
        return False
    try:
        canonical(context)
    except (TypeError, ValueError, UnicodeError):
        return False
    roster = context.get("roster")
    if (type(context.get("ceremony")) is not str or not context["ceremony"]
            or type(context.get("message")) is not str or not context["message"]
            or type(context.get("variant")) is not str or not context["variant"]
            or type(roster) is not list or not (3 <= len(roster) <= 10)
            or roster != list(range(1, len(roster) + 1))
            or type(context.get("sender")) is not int or context["sender"] not in roster
            or type(context.get("round")) is not int or not (1 <= context["round"] <= 8)
            or not subgroup_element(context.get("auth_public"))):
        return False
    nonce_tags = context.get("nonce_tags")
    if (type(nonce_tags) is not list or len(nonce_tags) != len(roster)
            or not all(subgroup_element(tag) for tag in nonce_tags)):
        return False
    return True


def paillier_encrypt(message: int, randomness: int) -> int:
    if not (0 <= message < PAILLIER_N and 1 <= randomness < PAILLIER_N and gcd(randomness, PAILLIER_N) == 1):
        raise ValueError("invalid Paillier plaintext or randomizer")
    return (pow(PAILLIER_G, message, PAILLIER_N2) * pow(randomness, PAILLIER_N, PAILLIER_N2)) % PAILLIER_N2


def paillier_decrypt(ciphertext: int) -> int:
    lam = lcm(PAILLIER_P - 1, PAILLIER_Q - 1)
    u = pow(ciphertext, lam, PAILLIER_N2)
    ell = (u - 1) // PAILLIER_N
    base = pow(PAILLIER_G, lam, PAILLIER_N2)
    mu = pow((base - 1) // PAILLIER_N, -1, PAILLIER_N)
    return (ell * mu) % PAILLIER_N


def _binding_challenge(context: dict[str, Any], ciphertext: int, tag: int, a_group: int, a_paillier: int) -> int:
    return _hash_int(
        "nfaa-binding-challenge-v1",
        context,
        ciphertext,
        tag,
        a_group,
        a_paillier,
        modulus=CHALLENGE_MOD,
    )


def binding_prove(context: dict[str, Any], ciphertext: int, tag: int, message: int, randomness: int) -> dict[str, int]:
    if type(message) is not int or not (0 <= message < GROUP_Q):
        raise ValueError("binding witness is not the canonical scalar representative")
    if tag != pow(GROUP_G, message, GROUP_P) or paillier_encrypt(message, randomness) != ciphertext:
        raise ValueError("witness does not open both public values")
    mask = _hash_int("nfaa-binding-mask-v1", context, ciphertext, tag, modulus=MASK_MAX + 1)
    blind = _coprime_from_hash("nfaa-binding-blind-v1", context, ciphertext, tag, modulus=PAILLIER_N)
    a_group = pow(GROUP_G, mask, GROUP_P)
    a_paillier = (pow(PAILLIER_G, mask, PAILLIER_N2) * pow(blind, PAILLIER_N, PAILLIER_N2)) % PAILLIER_N2
    challenge = _binding_challenge(context, ciphertext, tag, a_group, a_paillier)
    response = mask + challenge * message
    response_randomness = (blind * pow(randomness, challenge, PAILLIER_N)) % PAILLIER_N
    return {
        "a_group": a_group,
        "a_paillier": a_paillier,
        "challenge": challenge,
        "response": response,
        "response_randomness": response_randomness,
    }


def binding_verify(context: dict[str, Any], ciphertext: Any, tag: Any, proof: Any) -> bool:
    if not (subgroup_element(tag) and type(ciphertext) is int and 1 <= ciphertext < PAILLIER_N2
            and gcd(ciphertext, PAILLIER_N) == 1 and isinstance(proof, dict)
            and set(proof) == {"a_group", "a_paillier", "challenge", "response", "response_randomness"}):
        return False
    a_group = proof["a_group"]
    a_paillier = proof["a_paillier"]
    challenge = proof["challenge"]
    response = proof["response"]
    response_randomness = proof["response_randomness"]
    if not (subgroup_element(a_group) and type(a_paillier) is int and 1 <= a_paillier < PAILLIER_N2
            and type(challenge) is int and 0 <= challenge < CHALLENGE_MOD
            and type(response) is int and 0 <= response <= MAX_RESPONSE < PAILLIER_N
            and type(response_randomness) is int and 1 <= response_randomness < PAILLIER_N
            and gcd(response_randomness, PAILLIER_N) == 1):
        return False
    try:
        expected = _binding_challenge(context, ciphertext, tag, a_group, a_paillier)
    except (TypeError, ValueError, UnicodeError):
        return False
    if challenge != expected:
        return False
    left_group = pow(GROUP_G, response, GROUP_P)
    right_group = (a_group * pow(tag, challenge, GROUP_P)) % GROUP_P
    left_paillier = (pow(PAILLIER_G, response, PAILLIER_N2)
                     * pow(response_randomness, PAILLIER_N, PAILLIER_N2)) % PAILLIER_N2
    right_paillier = (a_paillier * pow(ciphertext, challenge, PAILLIER_N2)) % PAILLIER_N2
    return left_group == right_group and left_paillier == right_paillier


def private_binding_relation(ciphertext: Any, tag: Any) -> bool:
    """Toy secret-key oracle for the canonical bounded relation.

    The production statement is existential and is verified by a proof system.
    This helper may decrypt only because the finite test owns the toy Paillier
    factors.  It therefore never participates in the public verdict.
    """
    if not (type(ciphertext) is int and 1 <= ciphertext < PAILLIER_N2
            and gcd(ciphertext, PAILLIER_N) == 1 and subgroup_element(tag)):
        return False
    message = paillier_decrypt(ciphertext)
    return 0 <= message < GROUP_Q and pow(GROUP_G, message, GROUP_P) == tag


def forge_tiny_challenge_binding(
    context: dict[str, Any], ciphertext: int, tag: int, *, max_outer: int = 1000
) -> tuple[dict[str, int], int, int]:
    """Find a Fiat--Shamir fixed point for the deliberately tiny challenge.

    For chosen ``e, s, t``, both verification equations determine ``A`` and
    ``B``.  Searching for ``H(statement, A, B) == e`` succeeds quickly when the
    challenge has only 251 values.  This is retained as a falsifying control for
    any accidental claim that the executable transcript is a sound NIZK.

    Returns ``(proof, challenge_evaluations, outer_index)``.  It is intended
    only for the owned toy parameters and must not be used as an attack tool.
    """
    if not (type(ciphertext) is int and 1 <= ciphertext < PAILLIER_N2
            and gcd(ciphertext, PAILLIER_N) == 1 and subgroup_element(tag)):
        raise ValueError("invalid public statement")
    evaluations = 0
    for outer in range(max_outer):
        response = (outer * 7919 + 12345) % (MAX_RESPONSE + 1)
        response_randomness = 2 + (outer * 65537 + 19) % (PAILLIER_N - 2)
        while gcd(response_randomness, PAILLIER_N) != 1:
            response_randomness += 1
            if response_randomness >= PAILLIER_N:
                response_randomness = 2
        for challenge in range(CHALLENGE_MOD):
            a_group = (
                pow(GROUP_G, response, GROUP_P)
                * pow(pow(tag, challenge, GROUP_P), -1, GROUP_P)
            ) % GROUP_P
            a_paillier = (
                pow(PAILLIER_G, response, PAILLIER_N2)
                * pow(response_randomness, PAILLIER_N, PAILLIER_N2)
                * pow(pow(ciphertext, challenge, PAILLIER_N2), -1, PAILLIER_N2)
            ) % PAILLIER_N2
            evaluations += 1
            if _binding_challenge(context, ciphertext, tag, a_group, a_paillier) != challenge:
                continue
            proof = {
                "a_group": a_group,
                "a_paillier": a_paillier,
                "challenge": challenge,
                "response": response,
                "response_randomness": response_randomness,
            }
            if binding_verify(context, ciphertext, tag, proof):
                return proof, evaluations, outer
    raise AssertionError("tiny-challenge fixed point not found within declared bound")


def tiny_challenge_negative_control() -> dict[str, Any]:
    """Construct the retained false-statement acceptance control."""
    context = {
        "context": {
            "ceremony": "neg",
            "roster": [1, 2, 3],
            "round": 1,
            "message": "m",
            "variant": "base",
        },
        "sender": 1,
        "round": 1,
        "purpose": "encrypted-schnorr-response",
    }
    ciphertext_message = 17
    tag_message = 18
    randomness = 17
    while gcd(randomness, PAILLIER_N) != 1:
        randomness += 1
    ciphertext = paillier_encrypt(ciphertext_message, randomness)
    tag = pow(GROUP_G, tag_message, GROUP_P)
    if private_binding_relation(ciphertext, tag):
        raise AssertionError("negative-control statement unexpectedly true")
    proof, evaluations, outer = forge_tiny_challenge_binding(context, ciphertext, tag)
    return {
        "model": "deliberately insecure 251-value Fiat-Shamir challenge; conformance negative control",
        "context": context,
        "ciphertext": ciphertext,
        "tag": tag,
        "ciphertext_message": ciphertext_message,
        "tag_message": tag_message,
        "relation_holds": False,
        "proof": proof,
        "producer_accepts": binding_verify(context, ciphertext, tag, proof),
        "challenge_space": CHALLENGE_MOD,
        "challenge_evaluations": evaluations,
        "outer_index": outer,
        "expected_interpretation": "false statement accepted by toy transcript; production theorem must import a sound proof system",
    }


def schnorr_sign(body: dict[str, Any], secret: int) -> dict[str, int]:
    public = pow(GROUP_G, secret, GROUP_P)
    nonce = hash_scalar("nfaa-auth-nonce-v1", secret, body, nonzero=True)
    commitment = pow(GROUP_G, nonce, GROUP_P)
    challenge = hash_scalar("nfaa-auth-challenge-v1", public, commitment, body)
    response = (nonce + challenge * secret) % GROUP_Q
    return {"commitment": commitment, "response": response}


def schnorr_verify(body: Any, public: Any, signature: Any) -> bool:
    if not (isinstance(body, dict) and subgroup_element(public) and isinstance(signature, dict)
            and set(signature) == {"commitment", "response"}
            and subgroup_element(signature["commitment"])
            and type(signature["response"]) is int and 0 <= signature["response"] < GROUP_Q):
        return False
    try:
        challenge = hash_scalar("nfaa-auth-challenge-v1", public, signature["commitment"], body)
    except (TypeError, ValueError, UnicodeError):
        return False
    left = pow(GROUP_G, signature["response"], GROUP_P)
    right = (signature["commitment"] * pow(public, challenge, GROUP_P)) % GROUP_P
    return left == right


def lagrange_at_zero(index: int, signers: list[int]) -> int:
    if index not in signers or len(set(signers)) != len(signers):
        raise ValueError("invalid signer set")
    num, den = 1, 1
    for other in signers:
        if other == index:
            continue
        num = (num * (-other)) % GROUP_Q
        den = (den * (index - other)) % GROUP_Q
    return (num * pow(den, -1, GROUP_Q)) % GROUP_Q


def _signing_challenge(context: dict[str, Any]) -> int:
    """Recompute the common Schnorr challenge from the fixed public nonce vector."""
    aggregate_nonce = 1
    for tag in context["nonce_tags"]:
        aggregate_nonce = (aggregate_nonce * tag) % GROUP_P
    statement = {
        "ceremony": context["ceremony"],
        "roster": context["roster"],
        "round": context["round"],
        "message": context["message"],
        "variant": context["variant"],
        "aggregate_nonce": aggregate_nonce,
    }
    return hash_scalar("nfaa-signing-challenge-v2", statement)


def response_equation(body: dict[str, Any]) -> bool:
    required = {"context", "sender", "round", "signers", "evrf_verified", "nonce_tag",
                "verification_share", "challenge", "lagrange", "response_tag", "ciphertext", "binding_proof"}
    if not isinstance(body, dict) or set(body) != required:
        return False
    context = body.get("context")
    if not valid_context(context):
        return False
    if not (type(body["sender"]) is int and body["sender"] == context["sender"]
            and type(body["round"]) is int and body["round"] == context["round"]
            and isinstance(body["signers"], list) and body["signers"] == context["roster"]
            and all(type(x) is int for x in body["signers"])
            and body["evrf_verified"] is True
            and subgroup_element(body["nonce_tag"])
            and body["nonce_tag"] == context["nonce_tags"][body["sender"] - 1]
            and subgroup_element(body["verification_share"])
            and subgroup_element(body["response_tag"])
            and type(body["challenge"]) is int and 0 <= body["challenge"] < GROUP_Q
            and type(body["lagrange"]) is int and 0 <= body["lagrange"] < GROUP_Q):
        return False
    try:
        expected_lambda = lagrange_at_zero(body["sender"], body["signers"])
        expected_challenge = _signing_challenge(context)
    except (TypeError, ValueError, UnicodeError, ZeroDivisionError):
        return False
    if body["lagrange"] != expected_lambda or body["challenge"] != expected_challenge:
        return False
    exponent = (body["challenge"] * body["lagrange"]) % GROUP_Q
    expected_tag = (body["nonce_tag"] * pow(body["verification_share"], exponent, GROUP_P)) % GROUP_P
    return body["response_tag"] == expected_tag


def envelope_status(context: dict[str, Any], envelope: Any, auth_public: Any) -> str:
    """Return accepted, bad_binding, bad_response, off_context, or unauthenticated."""
    if not valid_context(context) or auth_public != context["auth_public"]:
        return "off_context"
    if not (isinstance(envelope, dict) and set(envelope) == {"body", "signature"}
            and isinstance(envelope["body"], dict)):
        return "unauthenticated"
    body = envelope["body"]
    if not schnorr_verify(body, auth_public, envelope["signature"]):
        return "unauthenticated"
    if body.get("context") != context:
        return "off_context"
    if (body.get("round") != context["round"]
            or body.get("sender") != context["sender"]
            or body.get("signers") != context["roster"]):
        return "bad_binding"
    binding_context = {
        "context": context,
        "sender": body.get("sender"),
        "round": body.get("round"),
        "purpose": "encrypted-schnorr-response",
    }
    if not binding_verify(binding_context, body.get("ciphertext"), body.get("response_tag"), body.get("binding_proof")):
        return "bad_binding"
    if not response_equation(body):
        return "bad_response"
    return "accepted"


def verdict(context: dict[str, Any], envelope: Any, auth_public: Any, *, service: str, accepted_duty: bool,
            ready_on_time: bool, complete_closure: bool, envelope_present: bool) -> str:
    if (not valid_context(context) or auth_public != context["auth_public"]
            or type(service) is not str or service not in {"bounded_delivery", "censorable"}):
        return "none"
    if type(envelope_present) is not bool or envelope_present != (envelope is not None):
        return "none"
    if envelope_present:
        status = envelope_status(context, envelope, auth_public)
        return {
            "accepted": "none",
            "bad_binding": "bad_binding",
            "bad_response": "bad_response",
            "off_context": "none",
            "unauthenticated": "none",
        }[status]
    if (service == "bounded_delivery" and accepted_duty is True
            and ready_on_time is True and complete_closure is True):
        return "qualified_nonopening"
    return "none"


def _nonce_seed_context(roster_size: int, round_number: int, variant: str) -> dict[str, Any]:
    return {
        "ceremony": "evrf-schnorr-response-v1",
        "roster": list(range(1, roster_size + 1)),
        "round": round_number,
        "message": f"message-{round_number}",
        "variant": variant,
    }


def fixture_nonce_scalar(context: dict[str, Any], sender: int) -> int:
    """Deterministic private nonce used only to construct owned toy fixtures."""
    seed_context = {key: context[key] for key in ("ceremony", "roster", "round", "message", "variant")}
    return hash_scalar("nfaa-imported-evrf-nonce-v2", seed_context, sender, nonzero=True)


def _context(roster_size: int, sender: int, round_number: int, variant: str = "base") -> dict[str, Any]:
    auth_secret = hash_scalar("nfaa-auth-secret-v1", roster_size, sender, nonzero=True)
    seed_context = _nonce_seed_context(roster_size, round_number, variant)
    nonce_tags = [
        pow(GROUP_G, hash_scalar("nfaa-imported-evrf-nonce-v2", seed_context, actor, nonzero=True), GROUP_P)
        for actor in seed_context["roster"]
    ]
    return {
        **seed_context,
        "sender": sender,
        "auth_public": pow(GROUP_G, auth_secret, GROUP_P),
        "nonce_tags": nonce_tags,
    }


def make_case(roster_size: int, sender: int, round_number: int, family: str) -> dict[str, Any]:
    if not (3 <= roster_size <= 10 and 1 <= sender <= roster_size and 1 <= round_number <= 8):
        raise ValueError("fixture dimensions out of range")
    context = _context(roster_size, sender, round_number)
    signers = context["roster"]
    share = hash_scalar("nfaa-share-v1", roster_size, sender, nonzero=True)
    auth_secret = hash_scalar("nfaa-auth-secret-v1", roster_size, sender, nonzero=True)
    auth_public = context["auth_public"]
    verification_share = pow(GROUP_G, share, GROUP_P)
    nonce = fixture_nonce_scalar(context, sender)
    nonce_tag = context["nonce_tags"][sender - 1]
    challenge = _signing_challenge(context)
    lagrange = lagrange_at_zero(sender, signers)
    response = (nonce + challenge * lagrange * share) % GROUP_Q
    response_tag = pow(GROUP_G, response, GROUP_P)
    randomness = _coprime_from_hash("nfaa-paillier-randomizer-v1", context, sender, modulus=PAILLIER_N)
    ciphertext = paillier_encrypt(response, randomness)
    binding_context = {"context": context, "sender": sender, "round": round_number,
                       "purpose": "encrypted-schnorr-response"}
    proof = binding_prove(binding_context, ciphertext, response_tag, response, randomness)
    body = {
        "context": context,
        "sender": sender,
        "round": round_number,
        "signers": signers,
        "evrf_verified": True,
        "nonce_tag": nonce_tag,
        "verification_share": verification_share,
        "challenge": challenge,
        "lagrange": lagrange,
        "response_tag": response_tag,
        "ciphertext": ciphertext,
        "binding_proof": proof,
    }
    envelope_present = family not in {"missing_bounded", "missing_censorable"}
    service = "bounded_delivery" if family == "missing_bounded" else "censorable"
    expected = "none"
    if family == "bad_response":
        wrong = (response + 1) % GROUP_Q
        body["response_tag"] = pow(GROUP_G, wrong, GROUP_P)
        wrong_randomness = _coprime_from_hash("nfaa-wrong-randomizer-v1", context, sender, modulus=PAILLIER_N)
        body["ciphertext"] = paillier_encrypt(wrong, wrong_randomness)
        body["binding_proof"] = binding_prove(binding_context, body["ciphertext"], body["response_tag"], wrong, wrong_randomness)
        expected = "bad_response"
    elif family == "bad_challenge":
        # Make every algebraic field self-consistent for an attacker-selected
        # challenge.  A correct judge still rejects because c is fixed by H.
        wrong_challenge = (challenge + 1) % GROUP_Q
        wrong = (nonce + wrong_challenge * lagrange * share) % GROUP_Q
        body["challenge"] = wrong_challenge
        body["response_tag"] = pow(GROUP_G, wrong, GROUP_P)
        wrong_randomness = _coprime_from_hash("nfaa-wrong-challenge-randomizer-v1", context, sender, modulus=PAILLIER_N)
        body["ciphertext"] = paillier_encrypt(wrong, wrong_randomness)
        body["binding_proof"] = binding_prove(binding_context, body["ciphertext"], body["response_tag"], wrong, wrong_randomness)
        expected = "bad_response"
    elif family == "bad_binding":
        body["ciphertext"] = (body["ciphertext"] * PAILLIER_G) % PAILLIER_N2
        expected = "bad_binding"
    elif family == "bad_binding_context":
        # Choose a foreign statement whose Fiat-Shamir challenge is distinct;
        # the tiny challenge space makes accidental collisions observable.
        for offset in range(1, CHALLENGE_MOD + 2):
            foreign_binding_context = {**binding_context, "round": round_number + offset}
            candidate = binding_prove(foreign_binding_context, ciphertext, response_tag, response, randomness)
            if not binding_verify(binding_context, ciphertext, response_tag, candidate):
                body["binding_proof"] = candidate
                break
        else:
            raise AssertionError("failed to construct a context-bound negative fixture")
        expected = "bad_binding"
    elif family == "bad_evrf_proof":
        body["evrf_verified"] = False
        expected = "bad_response"
    elif family == "bad_signature":
        expected = "none"
    elif family == "replay_context":
        expected = "none"
    elif family == "missing_bounded":
        expected = "qualified_nonopening"
    elif family in {"honest", "missing_censorable"}:
        expected = "none"
    else:
        raise ValueError("unknown family")
    signature = schnorr_sign(body, auth_secret)
    if family == "bad_signature":
        signature = {**signature, "response": (signature["response"] + 1) % GROUP_Q}
    envelope = {"body": body, "signature": signature}
    judge_context = context
    if family == "replay_context":
        judge_context = _context(roster_size, sender, round_number, variant="foreign")
    return {
        "case": f"n{roster_size}-s{sender}-r{round_number}-{family}",
        "family": family,
        "context": judge_context,
        "auth_public": auth_public,
        "envelope": envelope if envelope_present else None,
        "service": service,
        "accepted_duty": True,
        "ready_on_time": True,
        "complete_closure": True,
        "envelope_present": envelope_present,
        "expected": expected,
    }


def generate_cases() -> list[dict[str, Any]]:
    families = ["honest", "bad_response", "bad_challenge", "bad_binding", "bad_binding_context",
                "bad_evrf_proof", "bad_signature", "replay_context", "missing_bounded",
                "missing_censorable"]
    return [make_case(n, sender, round_number, family)
            for n in range(3, 11)
            for round_number in range(1, 9)
            for sender in range(1, n + 1)
            for family in families]
