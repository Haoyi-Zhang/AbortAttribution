"""Finite conformance checks for the privacy theorem's length interface.

This module does not implement encryption, simulate a cryptographic primitive,
change any attribution predicate, or establish computational indistinguishability.
It checks two interfaces used by the paper proof: legal same-length dummy
encodings, and a non-vacuous leakage-field partition that does not silently copy
the transcript being simulated.  These are conformance checks, not a proof that
a concrete protocol satisfies the corresponding simulation assumptions.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from fractions import Fraction
from typing import Any

MAX_BYTES = 8192


def fixed_width(modulus: int) -> int:
    """Bytes for all representatives in [0, modulus); no decimal/bit-length leak."""
    if type(modulus) is not int or modulus < 2:
        raise ValueError("modulus must be an integer greater than one")
    return ((modulus - 1).bit_length() + 7) // 8


def encode_scalar(value: int, modulus: int) -> bytes:
    width = fixed_width(modulus)
    if type(value) is not int or not 0 <= value < modulus:
        raise ValueError("scalar is not a canonical in-range integer")
    return value.to_bytes(width, "big")


def decode_scalar(encoded: bytes, modulus: int) -> int:
    width = fixed_width(modulus)
    if type(encoded) is not bytes or len(encoded) != width:
        raise ValueError("scalar encoding is not the public fixed width")
    value = int.from_bytes(encoded, "big")
    if value >= modulus:
        raise ValueError("decoded scalar is out of range")
    return value


def _response_domain(modulus: int, order: int) -> None:
    fixed_width(modulus)
    if type(order) is not int or not 1 < order < modulus:
        raise ValueError("response order must be an integer between one and modulus")


def encode_response_scalar(value: int, modulus: int, order: int) -> bytes:
    """Encode the bridge's narrower [0, q) domain at the public N-based width."""
    _response_domain(modulus, order)
    if type(value) is not int or not 0 <= value < order:
        raise ValueError("response scalar is outside [0, q)")
    return encode_scalar(value, modulus)


def decode_response_scalar(encoded: bytes, modulus: int, order: int) -> int:
    _response_domain(modulus, order)
    value = decode_scalar(encoded, modulus)
    if value >= order:
        raise ValueError("decoded response scalar is outside [0, q)")
    return value


def checked_dummy(
    length: int,
    sample: Callable[[int], bytes],
    member: Callable[[bytes], bool],
    *,
    max_bytes: int = MAX_BYTES,
) -> bytes:
    """Select from public length alone; verify length AND encoded-domain membership.

    The polynomial-time bound and completeness of the supplied sampler are
    protocol assumptions, not certified by this runtime check. Exceptions signal
    failure of the supplied contract, not a public blame verdict.
    """
    if type(max_bytes) is not int or max_bytes < 0:
        raise ValueError("max_bytes must be a nonnegative integer")
    if type(length) is not int or not 0 <= length <= max_bytes:
        raise ValueError("missing, non-integer, negative, or excessive length")
    dummy = sample(length)
    if type(dummy) is not bytes or len(dummy) != length:
        raise ValueError("dummy has the wrong encoding type or length")
    if member(dummy) is not True:
        raise ValueError("dummy is not in the declared encoded-message domain")
    return dummy


def simulate_profile(
    profile: Sequence[tuple[str, int]],
    sample: Callable[[int], bytes],
    member: Callable[[bytes], bool],
) -> list[tuple[str, bytes]]:
    """Preserve public order and per-occurrence lengths; never inspect plaintexts."""
    seen: set[str] = set()
    result: list[tuple[str, bytes]] = []
    for item in profile:
        if type(item) is not tuple or len(item) != 2:
            raise ValueError("each profile item must be an occurrence/length pair")
        occurrence, length = item
        if type(occurrence) is not str or not occurrence or occurrence in seen:
            raise ValueError("each occurrence must have a unique nonempty name")
        seen.add(occurrence)
        result.append((occurrence, checked_dummy(length, sample, member)))
    return result


_RAW_TRANSCRIPT_NAMES = frozenset({
    "all_public_values",
    "base_public_values",
    "base_transcript",
    "base_transcript_bytes",
    "real_transcript",
    "transcript",
    "transcript_bytes",
    "whole_transcript",
})


def _field_names(value: Sequence[str], label: str) -> tuple[str, ...]:
    if type(value) not in (tuple, list):
        raise ValueError(f"{label} must be a list or tuple of field names")
    result: list[str] = []
    for field in value:
        if type(field) is not str or not field or field.strip() != field:
            raise ValueError(f"{label} contains a malformed field name")
        if field in result:
            raise ValueError(f"{label} contains a duplicate field name")
        result.append(field)
    return tuple(result)


def checked_leakage_partition(
    *,
    base_fields: Sequence[str],
    attribution_fields: Sequence[str],
    transcript_fields: Sequence[str],
    declared_ideal_outputs: Sequence[str],
    declared_adversary_outputs: Sequence[str] = (),
    declared_precompilation_inputs: Sequence[str] = (),
) -> dict[str, tuple[str, ...]]:
    """Validate a published leakage-field manifest without reading transcript values.

    Semantic ideal outputs and inputs fixed before compiler randomness may also
    appear in the transcript if declared. Merely calling a reactive public record
    an "adversary output" does not make it lawful fixed leakage. Such responses
    must be regenerated on the current prefix by the causal renderer.
    `declared_adversary_outputs` is retained only to fail closed on the former
    interface; nonempty values always raise. The new precompilation annotation
    is not a proof of independence: the theorem's semantic sampler/dataflow
    condition must also hold. This function checks field structure only.
    """
    base = _field_names(base_fields, "base_fields")
    attribution = _field_names(attribution_fields, "attribution_fields")
    transcript = _field_names(transcript_fields, "transcript_fields")
    declared = _field_names(declared_ideal_outputs, "declared_ideal_outputs")
    adversary = _field_names(declared_adversary_outputs, "declared_adversary_outputs")
    precompiled = _field_names(declared_precompilation_inputs, "declared_precompilation_inputs")
    if adversary:
        raise ValueError("reactive adversary outputs cannot be fixed leakage; regenerate them causally")

    leaked = set(base) | set(attribution)
    forbidden = leaked & _RAW_TRANSCRIPT_NAMES
    if forbidden:
        raise ValueError("raw or ambiguous transcript fields cannot be declared leakage")
    if set(base) & set(attribution):
        raise ValueError("base and attribution leakage field names must be disjoint")
    if not set(declared) <= set(base):
        raise ValueError("every declared ideal output must occur in base leakage")
    if not set(precompiled) <= set(base):
        raise ValueError("every precompilation input must occur in base leakage")
    if set(declared) & set(precompiled):
        raise ValueError("ideal outputs and precompilation inputs must be disjoint")
    if (set(declared) | set(precompiled)) & _RAW_TRANSCRIPT_NAMES:
        raise ValueError("a raw transcript container cannot be a declared output")
    if set(attribution) & set(transcript):
        raise ValueError("attribution metadata cannot copy transcript fields")
    undeclared_overlap = (set(base) & set(transcript)) - set(declared) - set(precompiled)
    if undeclared_overlap:
        raise ValueError("base/transcript overlap must be an explicitly declared output")
    return {
        "base_fields": base,
        "attribution_fields": attribution,
        "transcript_fields": transcript,
        "declared_ideal_outputs": declared,
        "declared_adversary_outputs": adversary,
        "declared_precompilation_inputs": precompiled,
    }


def _tv(left: dict[Any, Fraction], right: dict[Any, Fraction]) -> Fraction:
    return sum((abs(left.get(k, Fraction()) - right.get(k, Fraction()))
                for k in left.keys() | right.keys()), Fraction()) / 2


def _framed(payload: bytes) -> bytes:
    # The two-byte payload count is inside encryption; zero padding to 8-byte blocks.
    result = len(payload).to_bytes(2, "big") + payload
    return result + b"\0" * ((-len(result)) % 8)


def _framed_member(encoded: bytes) -> bool:
    if len(encoded) < 8 or len(encoded) % 8:
        return False
    size = int.from_bytes(encoded[:2], "big")
    if size > len(encoded) - 2:
        return False
    return _framed(encoded[2:2+size]) == encoded


def _framed_dummy(length: int) -> bytes:
    if length < 8 or length % 8:
        raise ValueError("unattainable padded length")
    return _framed(bytes(max(0, length - 9)))


def run_length_audit() -> dict[str, Any]:
    """Frozen finite vectors; count one recorded assertion per obligation."""
    rows: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    def check(name: str, expected: Any, observed: Any, **detail: Any) -> None:
        row = {"name": name, "expected": expected, "observed": observed, **detail}
        rows.append(row)
        if expected != observed:
            failures.append(row)

    def refuses(name: str, action: Callable[[], Any]) -> None:
        try:
            action()
        except (TypeError, ValueError):
            check(name, True, True)
        except Exception as exc:
            check(name, "contract refusal", type(exc).__name__)
        else:
            check(name, True, False)

    any_bytes = lambda value: type(value) is bytes
    zeros = lambda size: bytes(size)
    for length in (0, 1, 2, 31, 32, 255, 256):
        value = checked_dummy(length, zeros, any_bytes)
        check(f"byte-domain-{length}", [length, True], [len(value), value == bytes(length)])
    for name, length in (("bool", True), ("negative", -1), ("float", 1.0),
                         ("none", None), ("list", []), ("object", {}),
                         ("over-budget", MAX_BYTES + 1)):
        refuses(f"invalid-length-{name}", lambda x=length: checked_dummy(x, zeros, any_bytes))
    refuses("wrong-dummy-length", lambda: checked_dummy(2, lambda _: b"0", any_bytes))
    refuses("noncanonical-bytearray", lambda: checked_dummy(1, lambda _: bytearray(1), any_bytes))
    prefix_domain = lambda value: bool(value) and value[0] == 255
    refuses("zero-not-in-structured-domain", lambda: checked_dummy(2, zeros, prefix_domain))
    structured = checked_dummy(2, lambda n: b"\xff" + bytes(n-1), prefix_domain)
    check("structured-domain-dummy", "ff00", structured.hex())

    first = simulate_profile([("a", 1), ("b", 3)], zeros, any_bytes)
    second = simulate_profile([("a", 2), ("b", 2)], zeros, any_bytes)
    check("per-occurrence-profile-not-total", [[1, 3], [2, 2]],
          [[len(value) for _, value in first], [len(value) for _, value in second]])
    check("same-total-still-different-profile", True,
          sum(len(v) for _, v in first) == sum(len(v) for _, v in second) and first != second)
    check("absence-versus-empty-message", [0, 1],
          [len(simulate_profile([], zeros, any_bytes)),
           len(simulate_profile([("a", 0)], zeros, any_bytes))])
    check("order-retained", ["z", "a"],
          [a for a, _ in simulate_profile([("z", 1), ("a", 2)], zeros, any_bytes)])
    refuses("duplicate-occurrence", lambda: simulate_profile([("a", 1), ("a", 2)], zeros, any_bytes))

    for size, expected in ((0, 8), (1, 8), (6, 8), (7, 16), (8, 16), (15, 24)):
        encoded = _framed(b"x" * size)
        dummy = checked_dummy(len(encoded), _framed_dummy, _framed_member)
        check(f"framing-padding-{size}", [expected, expected, True],
              [len(encoded), len(dummy), _framed_member(dummy)])
    check("utf8-bytes-not-characters", [1, 2], [len("é"), len("é".encode("utf-8"))])
    refuses("padded-zero-string-not-canonical", lambda: checked_dummy(16, zeros, _framed_member))

    # Observation-only counterexample: exact length header; no insecure toy PKE invented.
    world0, world1 = {1: Fraction(1)}, {2: Fraction(1)}
    mixture = {1: Fraction(1, 2), 2: Fraction(1, 2)}
    check("different-length-observation-tv", "1", str(_tv(world0, world1)))
    check("shared-simulator-tv-world0", "1/2", str(_tv(world0, mixture)))
    check("shared-simulator-tv-world1", "1/2", str(_tv(world1, mixture)))
    with_lengths = [simulate_profile([("a", x)], zeros, any_bytes) for x in (1, 2)]
    check("length-informed-observation-reconstruction", [1, 2],
          [len(values[0][1]) for values in with_lengths])

    # Same marginal base bit, but incorrect correlation with length.
    actual = {(0, 1): Fraction(1, 2), (1, 2): Fraction(1, 2)}
    marginal_only = {(bit, length): Fraction(1, 4)
                     for bit in (0, 1) for length in (1, 2)}
    check("marginal-simulation-does-not-imply-joint", "1/2", str(_tv(actual, marginal_only)))
    joint = {(length-1, length): Fraction(1, 2) for length in (1, 2)}
    check("length-conditioned-joint-simulation", "0", str(_tv(actual, joint)))

    # Published leakage-schema boundary: semantic ideal outputs may overlap the
    # transcript only by explicit declaration; raw bytes and catch-all phrases may not.
    manifest = checked_leakage_partition(
        base_fields=("exponent_tag", "corrupt_input", "corrupt_recipient_plaintext",
                     "precommitted_corrupt_input"),
        attribution_fields=("occurrence_order", "sender", "recipient", "receipt_time",
                            "absence_pattern", "certificate_class", "complaint_accepted"),
        transcript_fields=("exponent_tag", "precommitted_corrupt_input", "base_proof_bytes",
                           "ciphertext_bytes", "proof_bytes", "signature_bytes", "digest_bytes"),
        declared_ideal_outputs=("exponent_tag",),
        declared_precompilation_inputs=("precommitted_corrupt_input",),
    )
    check("explicit-ideal-output-overlap", ["exponent_tag"],
          list(manifest["declared_ideal_outputs"]))
    check("explicit-precompilation-input-overlap", ["precommitted_corrupt_input"],
          list(manifest["declared_precompilation_inputs"]))
    check("metadata-excludes-transcript-fields", True,
          not (set(manifest["attribution_fields"]) & set(manifest["transcript_fields"])))
    check("base-overlap-is-declared", ["exponent_tag", "precommitted_corrupt_input"],
          sorted(set(manifest["base_fields"]) & set(manifest["transcript_fields"])))
    refuses("reactive-record-cannot-be-fixed-leakage", lambda: checked_leakage_partition(
        base_fields=("corrupt_public_record",), attribution_fields=(),
        transcript_fields=("corrupt_public_record",), declared_ideal_outputs=(),
        declared_adversary_outputs=("corrupt_public_record",)))
    refuses("ambiguous-all-public-values", lambda: checked_leakage_partition(
        base_fields=("all_public_values",), attribution_fields=(),
        transcript_fields=("ciphertext_bytes",), declared_ideal_outputs=()))
    refuses("raw-base-transcript-copy", lambda: checked_leakage_partition(
        base_fields=("base_transcript",), attribution_fields=(),
        transcript_fields=("base_transcript",), declared_ideal_outputs=("base_transcript",)))
    refuses("raw-attribution-transcript-copy", lambda: checked_leakage_partition(
        base_fields=(), attribution_fields=("proof_bytes",),
        transcript_fields=("proof_bytes",), declared_ideal_outputs=()))
    refuses("undeclared-semantic-overlap", lambda: checked_leakage_partition(
        base_fields=("exponent_tag",), attribution_fields=(),
        transcript_fields=("exponent_tag",), declared_ideal_outputs=()))
    refuses("declared-output-not-base-leakage", lambda: checked_leakage_partition(
        base_fields=(), attribution_fields=(), transcript_fields=("exponent_tag",),
        declared_ideal_outputs=("exponent_tag",)))
    refuses("declared-adversary-output-not-base-leakage", lambda: checked_leakage_partition(
        base_fields=(), attribution_fields=(), transcript_fields=("corrupt_public_record",),
        declared_ideal_outputs=(), declared_adversary_outputs=("corrupt_public_record",)))
    refuses("ideal-adversary-declaration-collision", lambda: checked_leakage_partition(
        base_fields=("shared_output",), attribution_fields=(), transcript_fields=("shared_output",),
        declared_ideal_outputs=("shared_output",), declared_adversary_outputs=("shared_output",)))
    refuses("duplicate-leakage-field", lambda: checked_leakage_partition(
        base_fields=("exponent_tag", "exponent_tag"), attribution_fields=(),
        transcript_fields=("exponent_tag",), declared_ideal_outputs=("exponent_tag",)))
    refuses("nonstring-leakage-field", lambda: checked_leakage_partition(
        base_fields=(True,), attribution_fields=(), transcript_fields=(),
        declared_ideal_outputs=()))
    refuses("base-attribution-name-collision", lambda: checked_leakage_partition(
        base_fields=("sender",), attribution_fields=("sender",),
        transcript_fields=(), declared_ideal_outputs=()))

    # Independent fixed expected widths, including power-of-256 boundaries.
    for modulus, expected in ((2, 1), (255, 1), (256, 1), (257, 2),
                              (65536, 2), (65537, 3)):
        check(f"public-width-{modulus}", expected, fixed_width(modulus))
        for scalar in (0, modulus-1):
            enc = encode_scalar(scalar, modulus)
            check(f"fixed-width-roundtrip-{modulus}-{scalar}", [expected, scalar],
                  [len(enc), decode_scalar(enc, modulus)])
    modulus, scalar_order = 1_022_117, 233
    check("Paillier-public-widths", [3, 5], [fixed_width(modulus), fixed_width(modulus**2)])
    dummy = encode_response_scalar(0, modulus, scalar_order)
    check("Paillier-dummy", "000000", dummy.hex())
    for scalar in range(scalar_order):
        encoded = encode_response_scalar(scalar, modulus, scalar_order)
        check(f"Paillier-scalar-{scalar}", [3, scalar, True],
              [len(encoded), decode_response_scalar(encoded, modulus, scalar_order), len(encoded) == len(dummy)])
    for name, value in (("bool", True), ("negative", -1), ("upper-bound", modulus), ("float", 1.0)):
        refuses(f"scalar-refusal-{name}", lambda x=value: encode_scalar(x, modulus))
    refuses("short-scalar", lambda: decode_scalar(b"\0", modulus))
    refuses("long-scalar", lambda: decode_scalar(b"\0" * 4, modulus))
    refuses("out-of-range-scalar", lambda: decode_scalar(modulus.to_bytes(3, "big"), modulus))
    refuses("bool-modulus", lambda: fixed_width(True))

    refuses("response-order-encode-boundary", lambda: encode_response_scalar(233, modulus, 233))
    refuses("response-order-decode-boundary", lambda: decode_response_scalar((233).to_bytes(3, "big"), modulus, 233))
    refuses("response-order-exceeds-modulus", lambda: encode_response_scalar(0, modulus, modulus))
    refuses("response-order-bool", lambda: encode_response_scalar(0, modulus, True))
    refuses("response-order-zero", lambda: encode_response_scalar(0, modulus, 0))
    check("response-zero-dummy-in-narrow-domain", 0, decode_response_scalar(dummy, modulus, scalar_order))

    return {
        "model": "finite length-contract and encoding checks; no encryption security experiment",
        "length_unit": "bytes of the complete encoded encryption input, after framing/padding",
        "proof_obligation": "non-feedback semantic leakage; publicly computable lengths or explicit per-occurrence length leakage; valid efficient dummy; joint base simulation with retained authentication state and initial corrupt state",
        "attribution_predicates_changed": False,
        "scalar_values_checked": scalar_order,
        "paillier_modulus": modulus,
        "paillier_plaintext_width": 3,
        "paillier_ciphertext_width": 5,
        "checks": rows,
        "counted_elementary_obligations": len(rows),
        "failures": failures,
    }
