"""Focused setup and correlation regressions; no cryptographic security claim."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from privacy_composition import (AuthState, fixture_setup, sign_record, verify_record,
                                 require_matching_state, render_prefixes, hash_responder,
                                 check_causal_links, check_dependency_manifest,
                                 salt_distributions, run_composition_audit)
from privacy_lengths import checked_leakage_partition


class PrivacyCompositionTests(unittest.TestCase):
    def setUp(self):
        self.public, self.honest, self.corrupt = fixture_setup()

    def test_finite_assertions_have_unique_names(self):
        result = run_composition_audit()
        self.assertEqual(result["failures"], [])
        self.assertEqual(result["counted_elementary_obligations"], len(result["checks"]))
        self.assertEqual(len(result["checks"]), len({r["name"] for r in result["checks"]}))
        self.assertFalse(result["private_state_exported"])

    def test_matching_state_resigns_new_body(self):
        original = sign_record(self.public, self.honest, "honest", {"ciphertext": "00"})
        changed = sign_record(self.public, self.honest, "honest", {"ciphertext": "01"})
        self.assertTrue(verify_record(self.public, original))
        self.assertTrue(verify_record(self.public, changed))
        self.assertNotEqual(original["body"], changed["body"])

    def test_public_setup_alone_is_not_signing_state(self):
        for missing in (None, {}, self.public):
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                require_matching_state(self.public, missing, "honest")

    def test_fresh_key_does_not_match_old_registration(self):
        wrong = AuthState(self.honest.registration, {"honest": 18})
        with self.assertRaises(ValueError):
            sign_record(self.public, wrong, "honest", {"ciphertext": "01"})

    def test_no_registration_call_inside_renderer(self):
        with patch("privacy_composition.fixture_setup", side_effect=AssertionError("unexpected key regeneration")):
            result = render_prefixes(self.public, self.honest, [b"a", b"b"],
                                     hash_responder(self.public, self.corrupt))
        self.assertTrue(check_causal_links(self.public, result))

    def test_mismatched_public_registry_rejects(self):
        altered = deepcopy(self.public)
        altered["auth_registry"]["honest"] = altered["auth_registry"]["corrupt"]
        with self.assertRaises(ValueError):
            require_matching_state(altered, self.honest, "honest")

    def test_corrupt_state_has_no_honest_signing_credential(self):
        with self.assertRaises(ValueError):
            sign_record(self.public, self.corrupt, "honest", {})

    def test_auth_state_exact_types_and_immutability(self):
        for value in (True, False, 17.0, None, [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                AuthState("registration", {"honest": value})
        with self.assertRaises(TypeError):
            self.honest.secrets["honest"] = 18

    def test_reactive_records_are_regenerated(self):
        a = render_prefixes(self.public, self.honest, [b"a", b"b"], hash_responder(self.public, self.corrupt))
        b = render_prefixes(self.public, self.honest, [b"c", b"d"], hash_responder(self.public, self.corrupt))
        self.assertTrue(check_causal_links(self.public, a))
        self.assertTrue(check_causal_links(self.public, b))
        self.assertNotEqual(a[1], b[1])
        self.assertNotEqual(a[3], b[3])

    def test_stale_copy_has_valid_signatures_but_wrong_joint_view(self):
        a = render_prefixes(self.public, self.honest, [b"a"], hash_responder(self.public, self.corrupt))
        b = render_prefixes(self.public, self.honest, [b"b"], hash_responder(self.public, self.corrupt))
        stale = [b[0], a[1]]
        self.assertTrue(all(verify_record(self.public, record) for record in stale))
        self.assertFalse(check_causal_links(self.public, stale))

    def test_signed_boolean_counter_and_wrong_role_reject(self):
        records = render_prefixes(self.public, self.honest, [b"a"], hash_responder(self.public, self.corrupt))
        payload = deepcopy(records[1]["body"]["payload"])
        payload["call"] = True
        malformed = [records[0], sign_record(self.public, self.corrupt, "corrupt", payload)]
        self.assertFalse(check_causal_links(self.public, malformed))
        wrong = [records[0], sign_record(self.public, self.honest, "honest", records[1]["body"]["payload"])]
        self.assertFalse(check_causal_links(self.public, wrong))

    def test_renderer_detaches_registration_from_callback_aliases(self):
        fixed_public = deepcopy(self.public)
        responder = hash_responder(fixed_public, self.corrupt)
        def callback(prefix):
            self.public["registration"] = "mutated-outside-renderer"
            return responder(prefix)
        result = render_prefixes(self.public, self.honest, [b"a", b"b"], callback)
        self.assertTrue(check_causal_links(fixed_public, result))

    def test_responder_gets_immutable_prefix(self):
        seen = []
        ordinary = hash_responder(self.public, self.corrupt)
        def responder(prefix):
            seen.append(type(prefix))
            return ordinary(prefix)
        render_prefixes(self.public, self.honest, [b"a", b"b"], responder)
        self.assertEqual(seen, [bytes, bytes])

    def test_marginal_equality_does_not_preserve_frozen_echo(self):
        result = salt_distributions(4)
        self.assertEqual(result["public_salt_marginal_tv"], "0")
        self.assertEqual(result["stale_joint_tv"], "3/4")
        self.assertEqual(result["regenerated_joint_tv"], "0")
        self.assertEqual((result["real_support"], result["stale_support"]), (4, 16))

    def test_corrupt_records_not_laundered_as_fixed_leakage(self):
        with self.assertRaises(ValueError):
            checked_leakage_partition(base_fields=("corrupt_record",), attribution_fields=(),
                transcript_fields=("corrupt_record",), declared_ideal_outputs=(),
                declared_adversary_outputs=("corrupt_record",))

    def test_precompilation_declaration_is_separate(self):
        result = checked_leakage_partition(base_fields=("selected_input",), attribution_fields=(),
            transcript_fields=("selected_input",), declared_ideal_outputs=(),
            declared_precompilation_inputs=("selected_input",))
        self.assertEqual(result["declared_adversary_outputs"], ())
        self.assertEqual(result["declared_precompilation_inputs"], ("selected_input",))

    def test_public_dependency_allowed_hidden_feedback_refused(self):
        root = {"name": "ciphertext", "role": "source", "parents": [], "origin": "wrapper_bytes"}
        response = {"name": "reply", "role": "public_response", "parents": ["ciphertext"], "origin": None}
        self.assertEqual(check_dependency_manifest([root, response])["reply"], ["wrapper_bytes"])
        for role in ("semantic", "leakage"):
            with self.subTest(role=role), self.assertRaises(ValueError):
                check_dependency_manifest([root, response,
                    {"name": "followup", "role": role, "parents": ["reply"], "origin": None}])

    def test_schema_rejects_cycles_aliasing_and_unknown_origins(self):
        cases = [
            [{"name": "x", "role": "semantic", "parents": ["x"], "origin": None}],
            [{"name": "x", "role": "source", "parents": [], "origin": "wrapper_bytes"},
             {"name": "y", "role": "semantic", "parents": ["x"], "origin": "base_semantics"}],
            [{"name": "x", "role": "source", "parents": [], "origin": "declared_safe"}],
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                check_dependency_manifest(case)

    def test_malformed_public_records_fail_closed(self):
        for value in (None, True, [], {}, {"body": []}, {"body": {}, "signature": []}):
            with self.subTest(value=value):
                self.assertFalse(verify_record(self.public, value))


if __name__ == "__main__":
    unittest.main()
