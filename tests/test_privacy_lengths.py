"""Regressions for the explicit length interface, separate from crypto claims."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from privacy_lengths import (checked_dummy, checked_leakage_partition, decode_scalar,
                             encode_scalar, fixed_width, encode_response_scalar,
                             decode_response_scalar, run_length_audit, simulate_profile)
from schnorr_bridge import GROUP_Q, PAILLIER_N


class PrivacyLengthTests(unittest.TestCase):
    def test_finite_audit(self):
        result = run_length_audit()
        self.assertEqual(result["failures"], [])
        self.assertEqual(result["counted_elementary_obligations"], len(result["checks"]))
        self.assertEqual(len({x["name"] for x in result["checks"]}), len(result["checks"]))

    def test_parameter_mapping(self):
        result = run_length_audit()
        self.assertEqual(result["paillier_modulus"], PAILLIER_N)
        self.assertEqual(result["scalar_values_checked"], GROUP_Q)
        self.assertEqual(fixed_width(PAILLIER_N), 3)

    def test_plaintext_value_does_not_change_fixed_width(self):
        for value in (0, 1, 62, 206, 232, 256, PAILLIER_N-1):
            with self.subTest(value=value):
                encoded = encode_scalar(value, PAILLIER_N)
                self.assertEqual(len(encoded), 3)
                self.assertEqual(decode_scalar(encoded, PAILLIER_N), value)

    def test_response_domain_is_narrower_than_paillier_domain(self):
        for value in (GROUP_Q, GROUP_Q+1, PAILLIER_N-1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                encode_response_scalar(value, PAILLIER_N, GROUP_Q)
            with self.subTest(encoded=value), self.assertRaises(ValueError):
                decode_response_scalar(encode_scalar(value, PAILLIER_N), PAILLIER_N, GROUP_Q)

    def test_response_domain_parameters(self):
        for order in (True, 0, 1, PAILLIER_N, PAILLIER_N+1, 233.0):
            with self.subTest(order=order), self.assertRaises(ValueError):
                encode_response_scalar(0, PAILLIER_N, order)
        zero = encode_response_scalar(0, PAILLIER_N, GROUP_Q)
        self.assertEqual(zero, b"\0\0\0")
        self.assertEqual(decode_response_scalar(zero, PAILLIER_N, GROUP_Q), 0)

    def test_public_dummy_needs_no_secret(self):
        self.assertEqual(checked_dummy(3, bytes, lambda x: x == b"\0\0\0"), b"\0\0\0")

    def test_length_is_not_sufficient_without_domain(self):
        with self.assertRaises(ValueError):
            checked_dummy(2, bytes, lambda x: x.startswith(b"\xff"))
        self.assertEqual(checked_dummy(2, lambda n: b"\xff" + bytes(n-1),
                                       lambda x: x.startswith(b"\xff")), b"\xff\0")

    def test_exact_integer_lengths(self):
        for length in (True, False, None, [], {}, 2.0, -1, 8193):
            with self.subTest(length=length), self.assertRaises(ValueError):
                checked_dummy(length, bytes, lambda _: True)

    def test_wrong_length_and_encoding_type(self):
        for sampler in (lambda _: b"x", lambda _: bytearray(2), lambda _: "xx"):
            with self.assertRaises(ValueError):
                checked_dummy(2, sampler, lambda _: True)

    def test_profile_preserves_occurrence_order(self):
        actual = simulate_profile([("second-named", 3), ("first-named", 1)], bytes, lambda _: True)
        self.assertEqual([(k, len(v)) for k, v in actual], [("second-named", 3), ("first-named", 1)])

    def test_empty_message_is_not_absence(self):
        self.assertEqual(simulate_profile([], bytes, lambda _: True), [])
        self.assertEqual(simulate_profile([("a", 0)], bytes, lambda _: True), [("a", b"")])

    def test_duplicates_and_malformed_profile_reject(self):
        for profile in ([('a', 1), ('a', 2)], [([], 1)], [(True, 1)], [("", 1)], [["a", 1]]):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                simulate_profile(profile, bytes, lambda _: True)

    def test_length_only_negative_control_not_fixed_width_failure(self):
        rows = {row["name"]: row for row in run_length_audit()["checks"]}
        self.assertEqual(rows["different-length-observation-tv"]["observed"], "1")
        self.assertEqual(rows["Paillier-public-widths"]["observed"], [3, 5])

    def test_joint_not_just_marginal_simulation(self):
        rows = {row["name"]: row for row in run_length_audit()["checks"]}
        self.assertEqual(rows["marginal-simulation-does-not-imply-joint"]["observed"], "1/2")
        self.assertEqual(rows["length-conditioned-joint-simulation"]["observed"], "0")

    def test_nonvacuous_leakage_partition(self):
        manifest = checked_leakage_partition(
            base_fields=("exponent_tag", "corrupt_input", "precommitted_corrupt_input"),
            attribution_fields=("sender", "receipt_time", "certificate_class"),
            transcript_fields=("exponent_tag", "precommitted_corrupt_input", "proof_bytes", "signature_bytes"),
            declared_ideal_outputs=("exponent_tag",),
            declared_precompilation_inputs=("precommitted_corrupt_input",),
        )
        self.assertEqual(manifest["declared_ideal_outputs"], ("exponent_tag",))
        self.assertEqual(manifest["declared_precompilation_inputs"], ("precommitted_corrupt_input",))

    def test_raw_or_ambiguous_transcript_leakage_rejects(self):
        cases = [
            dict(base_fields=("all_public_values",), attribution_fields=(),
                 transcript_fields=(), declared_ideal_outputs=()),
            dict(base_fields=("base_transcript",), attribution_fields=(),
                 transcript_fields=("base_transcript",),
                 declared_ideal_outputs=("base_transcript",)),
            dict(base_fields=(), attribution_fields=("proof_bytes",),
                 transcript_fields=("proof_bytes",), declared_ideal_outputs=()),
            dict(base_fields=("exponent_tag",), attribution_fields=(),
                 transcript_fields=("exponent_tag",), declared_ideal_outputs=()),
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                checked_leakage_partition(**case)

    def test_leakage_manifest_types_and_partition_reject(self):
        cases = [
            dict(base_fields=(True,), attribution_fields=(), transcript_fields=(),
                 declared_ideal_outputs=()),
            dict(base_fields=("sender",), attribution_fields=("sender",),
                 transcript_fields=(), declared_ideal_outputs=()),
            dict(base_fields=("tag", "tag"), attribution_fields=(),
                 transcript_fields=("tag",), declared_ideal_outputs=("tag",)),
            dict(base_fields=(), attribution_fields=(), transcript_fields=("tag",),
                 declared_ideal_outputs=("tag",)),
            dict(base_fields=(), attribution_fields=(), transcript_fields=("corrupt_record",),
                 declared_ideal_outputs=(), declared_adversary_outputs=("corrupt_record",)),
            dict(base_fields=("shared",), attribution_fields=(), transcript_fields=("shared",),
                 declared_ideal_outputs=("shared",), declared_adversary_outputs=("shared",)),
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                checked_leakage_partition(**case)


if __name__ == "__main__":
    unittest.main()
