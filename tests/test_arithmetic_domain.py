"""Owned finite arithmetic/setup regressions, not cryptographic attack tests."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import cases
import checker
import replay
import compiler_cases
import compiler_checker
import compiler_replay
import schnorr_bridge
import schnorr_replay


class ArithmeticDomainTests(unittest.TestCase):
    def test_composite_parameters_are_refused_by_ideal_apis(self):
        for group in ({"p": 31, "q": 15, "g": 2}, {"p": 25, "q": 2, "g": 24}):
            with self.subTest(group=group):
                env = cases.fixture(1, "nonopening")
                cert = checker.extract(env)[0]
                env["context"]["group"] = group
                env["context"]["coefficient_tags"] = [1, 1, 1]
                self.assertFalse(checker.valid_environment(env))
                self.assertFalse(checker.verify(env, cert))
                self.assertFalse(replay.replay(env, cert))
                self.assertEqual(checker.extract(env), [])

    def test_composite_parameters_are_refused_by_compiler_apis(self):
        for group in ({"p": 31, "q": 15, "g": 2}, {"p": 25, "q": 2, "g": 24}):
            with self.subTest(group=group):
                env = compiler_cases.fixture(5, 2, 3, "missing_bounded")["public"]
                cert = compiler_checker.extract(env)[0]
                env["context"]["group"] = group
                self.assertFalse(compiler_checker.valid_environment(env))
                self.assertFalse(compiler_checker.verify(env, cert))
                self.assertFalse(compiler_replay.replay(env, cert))
                self.assertEqual(compiler_checker.extract(env), [])

    def test_small_prime_recognizers_against_divisor_oracle(self):
        validators = (checker._small_prime, replay._finite_prime,
                      compiler_checker._small_prime, compiler_replay._finite_prime)
        # Full-divisor oracle deliberately differs from the sqrt-bounded paths.
        for n in range(0, 513):
            expected = n >= 2 and not any(n % d == 0 for d in range(2, n))
            for validator in validators:
                with self.subTest(n=n, validator=validator.__module__):
                    self.assertEqual(validator(n), expected)
        for validator in validators:
            self.assertTrue(validator(65521))
            self.assertFalse(validator(65535))
            self.assertFalse(validator(65537))  # Prime but outside finite API.

    def test_real_prime_group_remains_accepted(self):
        env = cases.fixture(2, "nonopening")
        cert = checker.extract(env)[0]
        self.assertTrue(checker.verify(env, cert))
        self.assertTrue(replay.replay(env, cert))
        env = compiler_cases.fixture(5, 2, 3, "missing_bounded")["public"]
        cert = compiler_checker.extract(env)[0]
        self.assertTrue(compiler_checker.verify(env, cert))
        self.assertTrue(compiler_replay.replay(env, cert))

    def test_receipt_identities_have_exact_integer_types(self):
        for token, value in (("accept-1", True), ("accept-1", 1.0), ("ready", False)):
            with self.subTest(token=token, value=value):
                env = cases.fixture(1, "nonopening")
                cert = checker.extract(env)[0]
                env["receipts"][token]["actor"] = value
                self.assertFalse(checker.verify(env, cert))
                self.assertFalse(replay.replay(env, cert))
                self.assertEqual(checker.extract(env), [])
        env = cases.fixture(1, "bad_shape")
        cert = checker.extract(env)[0]
        env["receipts"]["open-1"]["actor"] = True
        self.assertFalse(checker.verify(env, cert))
        self.assertFalse(replay.replay(env, cert))
        self.assertEqual(checker.extract(env), [])

    def test_identity_authentication_key_is_not_generated_setup(self):
        case = schnorr_bridge.make_case(5, 2, 3, "missing_bounded")
        original = deepcopy(case)
        case["context"]["auth_public"] = case["auth_public"] = 1
        self.assertFalse(schnorr_bridge.valid_context(case["context"]))
        self.assertFalse(schnorr_replay.context_ok(case["context"]))
        keys = ("context", "envelope", "auth_public", "service", "accepted_duty",
                "ready_on_time", "complete_closure", "envelope_present")
        self.assertEqual(schnorr_bridge.verdict(**{k: case[k] for k in keys}), "none")
        self.assertEqual(schnorr_replay.replay(case), "none")
        self.assertEqual(schnorr_bridge.verdict(**{k: original[k] for k in keys}),
                         "qualified_nonopening")
        self.assertEqual(schnorr_replay.replay(original), "qualified_nonopening")


if __name__ == "__main__":
    unittest.main()
