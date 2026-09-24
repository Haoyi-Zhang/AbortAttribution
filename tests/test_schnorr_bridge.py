"""Regression tests for the concrete eVRF/Schnorr response bridge."""
from __future__ import annotations
import ast
from copy import deepcopy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from schnorr_bridge import (GROUP_G, GROUP_P, GROUP_Q, PAILLIER_N, binding_prove,
                            binding_verify, envelope_status, fixture_nonce_scalar, generate_cases, hash_scalar, make_case,
                            paillier_decrypt, paillier_encrypt, private_binding_relation,
                            response_equation, schnorr_sign, tiny_challenge_negative_control, verdict)
from schnorr_replay import binding as replay_binding, replay


class SchnorrBridgeTests(unittest.TestCase):
    def test_parameters_and_campaign_size(self):
        self.assertEqual(pow(GROUP_G, GROUP_Q, GROUP_P), 1)
        self.assertEqual(len(generate_cases()), 4160)

    def test_honest_response_and_binding(self):
        case = make_case(5, 2, 3, "honest")
        body = case["envelope"]["body"]
        self.assertTrue(response_equation(body))
        plaintext = paillier_decrypt(body["ciphertext"])
        self.assertLess(plaintext, PAILLIER_N)
        self.assertEqual(pow(GROUP_G, plaintext, GROUP_P), body["response_tag"])
        ctx = {"context": case["context"], "sender": 2, "round": 3,
               "purpose": "encrypted-schnorr-response"}
        self.assertTrue(binding_verify(ctx, body["ciphertext"], body["response_tag"], body["binding_proof"]))
        self.assertEqual(envelope_status(case["context"], case["envelope"], case["auth_public"]), "accepted")
        self.assertEqual(verdict(**{k: case[k] for k in ("context", "envelope", "auth_public", "service", "accepted_duty", "ready_on_time", "complete_closure", "envelope_present")}), "none")
        self.assertEqual(replay(case), "none")

    def test_private_oracle_matches_honest_statement(self):
        case = make_case(5, 2, 3, "honest")
        body = case["envelope"]["body"]
        self.assertTrue(private_binding_relation(body["ciphertext"], body["response_tag"]))

    def test_tiny_challenge_false_statement_negative_control(self):
        control = tiny_challenge_negative_control()
        self.assertFalse(control["relation_holds"])
        self.assertEqual(control["ciphertext_message"], 17)
        self.assertEqual(control["tag_message"], 18)
        self.assertEqual(control["challenge_evaluations"], 617)
        self.assertTrue(control["producer_accepts"])
        self.assertTrue(replay_binding(control["context"], control["ciphertext"],
                                       control["tag"], control["proof"]))

    def test_bad_response_has_positive_evidence(self):
        case = make_case(8, 7, 4, "bad_response")
        self.assertEqual(verdict(**{k: case[k] for k in ("context", "envelope", "auth_public", "service", "accepted_duty", "ready_on_time", "complete_closure", "envelope_present")}), "bad_response")
        self.assertEqual(replay(case), "bad_response")

    def test_binding_and_context_failures(self):
        for family in ("bad_binding", "bad_binding_context"):
            case = make_case(6, 4, 2, family)
            self.assertEqual(replay(case), "bad_binding")
        case = make_case(6, 4, 2, "replay_context")
        self.assertEqual(replay(case), "none")

    def test_bad_evrf_proof_is_signed_positive_evidence(self):
        case = make_case(9, 5, 6, "bad_evrf_proof")
        self.assertEqual(replay(case), "bad_response")

    def test_signature_failure_not_attributed(self):
        case = make_case(4, 1, 8, "bad_signature")
        self.assertEqual(replay(case), "none")

    def test_omission_requires_service(self):
        self.assertEqual(replay(make_case(3, 2, 1, "missing_bounded")), "qualified_nonopening")
        self.assertEqual(replay(make_case(3, 2, 1, "missing_censorable")), "none")

    def test_presence_flag_mismatch_never_accuses(self):
        present = make_case(5, 2, 3, "honest")
        present["envelope_present"] = False
        self.assertEqual(verdict(**{k: present[k] for k in ("context", "envelope", "auth_public", "service", "accepted_duty", "ready_on_time", "complete_closure", "envelope_present")}), "none")
        self.assertEqual(replay(present), "none")

        absent = make_case(5, 2, 3, "missing_bounded")
        absent["envelope_present"] = True
        self.assertEqual(verdict(**{k: absent[k] for k in ("context", "envelope", "auth_public", "service", "accepted_duty", "ready_on_time", "complete_closure", "envelope_present")}), "none")
        self.assertEqual(replay(absent), "none")

    def test_signed_context_fields_still_match_judging_context(self):
        base = make_case(6, 4, 2, "honest")
        secret = hash_scalar("nfaa-auth-secret-v1", 6, 4, nonzero=True)
        mutations = [
            ("round", 3),
            ("sender", 3),
            ("signers", [1, 2, 3, 4, 5]),
        ]
        for field, value in mutations:
            with self.subTest(field=field):
                case = deepcopy(base)
                case["envelope"]["body"][field] = value
                case["envelope"]["signature"] = schnorr_sign(case["envelope"]["body"], secret)
                self.assertEqual(envelope_status(case["context"], case["envelope"], case["auth_public"]), "bad_binding")
                self.assertEqual(verdict(**{k: case[k] for k in ("context", "envelope", "auth_public", "service", "accepted_duty", "ready_on_time", "complete_closure", "envelope_present")}), "bad_binding")
                self.assertEqual(replay(case), "bad_binding")

    def test_nonboolean_omission_flags_rejected(self):
        mutations = [("accepted_duty", 1), ("ready_on_time", "yes"), ("complete_closure", 1)]
        for field, value in mutations:
            with self.subTest(field=field):
                case = make_case(5, 2, 3, "missing_bounded")
                case[field] = value
                self.assertEqual(verdict(**{k: case[k] for k in ("context", "envelope", "auth_public", "service", "accepted_duty", "ready_on_time", "complete_closure", "envelope_present")}), "none")
                self.assertEqual(replay(case), "none")

    def test_challenge_is_recomputed_from_fixed_context(self):
        case = make_case(5, 2, 3, "honest")
        body = case["envelope"]["body"]
        body["challenge"] = (body["challenge"] + 1) % GROUP_Q
        share = hash_scalar("nfaa-share-v1", 5, 2, nonzero=True)
        nonce = fixture_nonce_scalar(case["context"], 2)
        response = (nonce + body["challenge"] * body["lagrange"] * share) % GROUP_Q
        body["response_tag"] = pow(GROUP_G, response, GROUP_P)
        randomness = 2
        body["ciphertext"] = paillier_encrypt(response, randomness)
        bind_ctx = {"context": case["context"], "sender": 2, "round": 3,
                    "purpose": "encrypted-schnorr-response"}
        body["binding_proof"] = binding_prove(
            bind_ctx, body["ciphertext"], body["response_tag"], response, randomness
        )
        secret = hash_scalar("nfaa-auth-secret-v1", 5, 2, nonzero=True)
        case["envelope"]["signature"] = schnorr_sign(body, secret)
        # The altered response equation is self-consistent only for the
        # attacker-selected challenge; the fixed context hashes to another one.
        self.assertFalse(response_equation(body))
        self.assertEqual(envelope_status(case["context"], case["envelope"], case["auth_public"]),
                         "bad_response")
        self.assertEqual(replay(case), "bad_response")

    def test_common_challenge_uses_all_public_nonce_tags(self):
        first = make_case(5, 1, 3, "honest")
        second = make_case(5, 4, 3, "honest")
        self.assertEqual(first["envelope"]["body"]["challenge"],
                         second["envelope"]["body"]["challenge"])
        changed = deepcopy(first)
        changed["context"]["nonce_tags"][1] = pow(GROUP_G, 17, GROUP_P)
        body = changed["envelope"]["body"]
        body["context"] = deepcopy(changed["context"])
        response = paillier_decrypt(body["ciphertext"])
        randomness = 2
        body["ciphertext"] = paillier_encrypt(response, randomness)
        bind_ctx = {"context": changed["context"], "sender": 1, "round": 3,
                    "purpose": "encrypted-schnorr-response"}
        body["binding_proof"] = binding_prove(
            bind_ctx, body["ciphertext"], body["response_tag"], response, randomness
        )
        secret = hash_scalar("nfaa-auth-secret-v1", 5, 1, nonzero=True)
        changed["envelope"]["signature"] = schnorr_sign(body, secret)
        self.assertEqual(envelope_status(changed["context"], changed["envelope"], changed["auth_public"]),
                         "bad_response")
        self.assertEqual(replay(changed), "bad_response")

    def test_absence_requires_valid_registered_context(self):
        for field, value in (("roster", None), ("sender", 99), ("auth_public", 1),
                             ("round", True), ("ceremony", "")):
            with self.subTest(field=field):
                case = make_case(5, 2, 3, "missing_bounded")
                case["context"][field] = value
                kwargs = {k: case[k] for k in (
                    "context", "envelope", "auth_public", "service", "accepted_duty",
                    "ready_on_time", "complete_closure", "envelope_present"
                )}
                self.assertEqual(verdict(**kwargs), "none")
                self.assertEqual(replay(case), "none")

    def test_registered_authentication_key_is_context_bound(self):
        case = make_case(5, 2, 3, "missing_bounded")
        case["auth_public"] = pow(GROUP_G, 7, GROUP_P)
        kwargs = {k: case[k] for k in (
            "context", "envelope", "auth_public", "service", "accepted_duty",
            "ready_on_time", "complete_closure", "envelope_present"
        )}
        self.assertEqual(verdict(**kwargs), "none")
        self.assertEqual(replay(case), "none")

    def test_binding_prover_rejects_noncanonical_scalar(self):
        case = make_case(5, 2, 3, "honest")
        body = case["envelope"]["body"]
        with self.assertRaises(ValueError):
            binding_prove({"context": case["context"], "sender": 2, "round": 3,
                           "purpose": "encrypted-schnorr-response"},
                          body["ciphertext"], body["response_tag"], GROUP_Q, 2)

    def test_mutated_proof_rejected(self):
        case = make_case(7, 3, 5, "honest")
        changed = deepcopy(case)
        changed["envelope"]["body"]["binding_proof"]["response"] += 1
        # Signature no longer authenticates the body, so the public result is no attribution.
        self.assertEqual(replay(changed), "none")

    def test_replay_independent(self):
        source = Path(__file__).resolve().parents[1] / "src" / "schnorr_replay.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import): names += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom): names.append(node.module)
        self.assertNotIn("schnorr_bridge", names)


if __name__ == "__main__":
    unittest.main()
