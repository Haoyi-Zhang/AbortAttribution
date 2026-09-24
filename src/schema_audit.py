"""Deterministic cross-implementation vectors for the canonical JSON boundary."""
from __future__ import annotations
from hashlib import sha256
from typing import Any, Callable

from schnorr_bridge import canonical
from schnorr_replay import enc


VALID_VECTORS: tuple[tuple[str, Any, bytes], ...] = (
    ("null", None, b"null"),
    ("booleans", [True, False], b"[true,false]"),
    ("integers", [0, -1, 233], b"[0,-1,233]"),
    ("key-order", {"z": 0, "a": 1}, b'{"a":1,"z":0}'),
    ("nested", {"x": [1, {"b": False, "a": None}]}, b'{"x":[1,{"a":null,"b":false}]}'),
    ("escaped", {"s": "line\nquote\"slash\\"}, b'{"s":"line\\nquote\\\"slash\\\\"}'),
    ("unicode", {"s": "lambda-\u03bb"}, b'{"s":"lambda-\\u03bb"}'),
    ("empty", {"a": [], "b": {}}, b'{"a":[],"b":{}}'),
)


def invalid_factories() -> tuple[tuple[str, Callable[[], Any]], ...]:
    # Factories prevent a lone surrogate from entering a source-level JSON result.
    return (
        ("float", lambda: 1.5),
        ("nan", lambda: float("nan")),
        ("non-string-key", lambda: {1: "x"}),
        ("tuple", lambda: (1, 2)),
        ("bytes", lambda: b"x"),
        ("surrogate-value", lambda: "\ud800"),
        ("surrogate-key", lambda: {"\ud800": 1}),
    )


def _rejected(fn: Callable[[Any], bytes], value: Any) -> bool:
    try:
        fn(value)
    except (TypeError, ValueError, UnicodeError):
        return True
    return False


def run_schema_audit() -> dict[str, Any]:
    valid = []
    failures: list[str] = []
    obligations = 0
    for name, value, expected in VALID_VECTORS:
        producer = canonical(value)
        replay = enc(value)
        obligations += 2
        ok_producer = producer == expected
        ok_replay = replay == expected
        if not ok_producer:
            failures.append(name + ": producer bytes")
        if not ok_replay:
            failures.append(name + ": replay bytes")
        valid.append({
            "name": name,
            "expected_ascii": expected.decode("ascii"),
            "producer_matches": ok_producer,
            "replay_matches": ok_replay,
        })

    invalid = []
    for name, factory in invalid_factories():
        value = factory()
        producer_rejects = _rejected(canonical, value)
        replay_rejects = _rejected(enc, value)
        obligations += 2
        if not producer_rejects:
            failures.append(name + ": producer accepted")
        if not replay_rejects:
            failures.append(name + ": replay accepted")
        invalid.append({
            "name": name,
            "producer_rejects": producer_rejects,
            "replay_rejects": replay_rejects,
        })

    known_wire = b'{"a":1,"z":0}'
    known_digest = "b55af27c4bd5f02ebeca8f901b84d2940b22e7bea7230e4d06f275d903bfdd72"
    observed_digest = sha256(known_wire).hexdigest()
    obligations += 1
    if observed_digest != known_digest:
        failures.append("known digest")

    return {
        "model": "strict canonical JSON bytes for signed and hashed toy transcript fields",
        "valid_vectors": valid,
        "invalid_vectors": invalid,
        "known_digest": {"wire_ascii": known_wire.decode("ascii"), "sha256": observed_digest,
                         "matches_frozen_value": observed_digest == known_digest},
        "counted_elementary_obligations": obligations,
        "failures": failures,
    }
