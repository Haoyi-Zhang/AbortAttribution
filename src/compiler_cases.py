"""Deterministic fixtures for the delivery-aware attribution compiler.

The fixtures model ideal verification outcomes for signatures and NIZKs.  They
are not cryptographic implementations.  Private scalars are used only while
constructing fixtures; public checkers consume transcript records and ideal
verification bits.
"""
from __future__ import annotations
from hashlib import sha256
import json
from typing import Any

P, Q, G = 23, 11, 2
FAULTS = (
    "honest_valid",
    "honest_delayed",
    "malformed_entry",
    "invalid_message",
    "forged_complaint",
    "missing_bounded",
    "missing_censorable",
    "tag_only_unbound",
)


def _digest(obj: Any) -> str:
    wire = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(wire.encode("ascii")).hexdigest()


def expected_scalar(sender: int, recipient: int, round_no: int) -> int:
    """A benign, public fixture relation; not an eVRF relation."""
    return (7 + 3 * sender + 5 * recipient + 2 * round_no) % Q


def scalar_tag(value: int) -> int:
    return pow(G, value % Q, P)


def fixture(n: int, sender: int, round_no: int, fault: str) -> dict[str, Any]:
    if fault not in FAULTS:
        raise ValueError(f"unknown fixture fault {fault}")
    if n < 3 or n > 10 or sender not in range(1, n + 1) or round_no not in range(1, 9):
        raise ValueError("fixture dimensions outside the bounded campaign")
    recipient = sender % n + 1
    sid = f"compiler-n{n}-r{round_no}-s{sender}-{fault}"
    service = "censorable" if fault in {"missing_censorable", "tag_only_unbound"} else "bounded_delivery"
    context = {
        "id": sid,
        "roster": list(range(1, n + 1)),
        "round": round_no,
        "sender": sender,
        "recipient": recipient,
        "group": {"p": P, "q": Q, "g": G},
        "accept_by": 2,
        "deadline": 12,
        "read_bound": 2,
        "compute_bound": 2,
        "delivery_bound": 2,
        "service": service,
    }
    records: dict[str, Any] = {}
    records["accept"] = {
        "context": sid,
        "kind": "accept",
        "actor": sender,
        "time": 1,
        "signature_valid": True,
        "body": {"round": round_no, "recipient": recipient, "deadline": 12},
    }
    records["ready"] = {
        "context": sid,
        "kind": "ready",
        "actor": 0,
        "time": 6,
        "signature_valid": True,
        "body": {"round": round_no},
    }

    expected = expected_scalar(sender, recipient, round_no)
    delivered = (expected + 1) % Q if fault == "invalid_message" else expected
    envelope_present = fault not in {"missing_bounded", "missing_censorable", "tag_only_unbound"}
    if envelope_present:
        statement = {
            "sender": sender,
            "recipient": recipient,
            "round": round_no,
            "tag": scalar_tag(delivered),
            "ciphertext": _digest(["ideal-ciphertext", sid, sender, recipient, round_no, delivered]),
        }
        records["envelope"] = {
            "context": sid,
            "kind": "envelope",
            "actor": sender,
            "time": 12 if fault == "honest_delayed" else 4,
            "signature_valid": True,
            "body": {
                "statement": statement,
                "entry_proof_valid": fault != "malformed_entry",
                "entry_proof_statement": _digest(statement),
            },
        }
    elif fault == "tag_only_unbound":
        records["tag"] = {
            "context": sid,
            "kind": "tag",
            "actor": sender,
            "time": 4,
            "signature_valid": True,
            "body": {"round": round_no, "tag": scalar_tag(expected)},
        }

    if fault in {"invalid_message", "forged_complaint"}:
        records["complaint"] = {
            "context": sid,
            "kind": "complaint",
            "actor": recipient,
            "time": 9,
            "signature_valid": True,
            "body": {
                "envelope": "envelope",
                "accused": sender,
                "claim": "base_relation_false",
                "complaint_proof_valid": fault == "invalid_message",
                "complaint_statement": _digest([sid, "envelope", sender, recipient, round_no]),
            },
        }

    closures = {
        "early": {
            "context": sid,
            "cutoff": 11,
            "complete": True,
            "records": sorted(k for k, r in records.items() if r["time"] <= 11),
        },
        "final": {
            "context": sid,
            "cutoff": 12,
            "complete": True,
            "records": sorted(k for k, r in records.items() if r["time"] <= 12),
        },
    }
    if fault == "malformed_entry":
        expected_certs = [[sender, "bad_entry"]]
    elif fault == "invalid_message":
        expected_certs = [[sender, "bad_message"]]
    elif fault == "missing_bounded":
        expected_certs = [[sender, "nonopening"]]
    else:
        expected_certs = []
    public = {"context": context, "records": records, "closures": closures}
    return {
        "case": sid,
        "family": fault,
        "public": public,
        "expected": expected_certs,
        "private_annotation": {
            "expected_scalar": expected,
            "delivered_scalar": delivered if envelope_present else None,
            "semantic_relation_holds": delivered == expected if envelope_present else None,
        },
    }


def generate() -> list[dict[str, Any]]:
    return [
        fixture(n, sender, round_no, fault)
        for n in range(3, 11)
        for round_no in range(1, 9)
        for sender in range(1, n + 1)
        for fault in FAULTS
    ]
