"""Canonical encoding and parser-boundary regressions."""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from compiler_cases import fixture
from compiler_checker import extract, verify
from compiler_replay import replay as replay_compiler
from schema_audit import run_schema_audit
from setup_boundary_audit import run_setup_boundary_audit
from schnorr_bridge import canonical, make_case, verdict
from schnorr_replay import enc, replay as replay_schnorr


class SchemaTests(unittest.TestCase):
    def test_frozen_cross_implementation_vectors(self):
        audit = run_schema_audit()
        self.assertEqual(audit["failures"], [])
        self.assertTrue(audit["known_digest"]["matches_frozen_value"])

    def test_non_json_types_are_rejected(self):
        for value in (1.5, {1: "x"}, (1, 2), b"x", "\ud800", {"\ud800": 1}):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises((TypeError, ValueError, UnicodeError)):
                    canonical(value)
                with self.assertRaises((TypeError, ValueError, UnicodeError)):
                    enc(value)

    def test_noncanonical_signed_compiler_entry_is_malformed(self):
        case = fixture(5, 2, 3, "honest_valid")
        env = deepcopy(case["public"])
        env["records"]["envelope"]["body"]["statement"]["ciphertext"] = "\ud800"
        certs = extract(env)
        self.assertEqual(len(certs), 1)
        self.assertEqual(certs[0]["kind"], "bad_entry")
        self.assertTrue(verify(env, certs[0]))
        self.assertTrue(replay_compiler(env, certs[0]))

    def test_setup_boundary_audit_is_fail_closed(self):
        result = run_setup_boundary_audit()
        self.assertGreaterEqual(result["compiler_mutations"], 1)
        self.assertGreaterEqual(result["ideal_receipt_mutations"], 1)
        self.assertGreaterEqual(result["schnorr_mutations"], 1)
        self.assertEqual(result["exceptions"], 0)
        self.assertEqual(result["unsafe_results"], 0)
        self.assertEqual(result["failures"], [])
        self.assertEqual(result["counted_elementary_obligations"], result["public_api_calls"])

    def test_malformed_schnorr_context_never_crashes_or_accuses(self):
        case = make_case(5, 2, 3, "honest")
        changed = deepcopy(case)
        changed["envelope"]["body"]["context"]["ceremony"] = "\ud800"
        kwargs = {k: changed[k] for k in (
            "context", "envelope", "auth_public", "service", "accepted_duty",
            "ready_on_time", "complete_closure", "envelope_present"
        )}
        self.assertEqual(verdict(**kwargs), "none")
        self.assertEqual(replay_schnorr(changed), "none")


if __name__ == "__main__":
    unittest.main()
