"""Small contract regressions; the exhaustive oracle is run by reproduce.py."""
from __future__ import annotations
import ast
from copy import deepcopy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cases import fixture
from checker import extract, verify
from replay import replay
from linear_oracle import rank


class ContractTests(unittest.TestCase):
    def both(self, env, cert, expected):
        self.assertEqual(verify(env, cert), expected)
        self.assertEqual(replay(env, cert), expected)

    def test_signed_malformed_is_evidence(self):
        env = fixture(2, "bad_noninteger")
        certs = extract(env)
        self.assertEqual(len(certs), 1)
        self.both(env, certs[0], True)

    def test_censorable_nonopening_is_not_evidence(self):
        env = fixture(2, "nonopening", service="censorable")
        self.assertEqual(extract(env), [])
        self.both(env, {"context": "ceremony", "actor": 2, "kind": "nonopening",
                        "accept": "accept-2", "ready": "ready", "closure": "final"}, False)

    def test_late_readiness_is_not_fault(self):
        self.assertEqual(extract(fixture(2, "late_ready")), [])

    def test_receipt_at_deadline_is_included(self):
        self.assertEqual(extract(fixture(2, delay=3)), [])

    def test_premature_closure_rejected(self):
        env = fixture(2, "nonopening")
        cert = extract(env)[0]
        cert["closure"] = "early"
        self.both(env, cert, False)

    def test_truncated_closure_not_a_complete_snapshot(self):
        env = fixture(2, "none")
        altered = deepcopy(env)
        altered["closures"]["final"]["records"].remove("open-2")
        self.both(altered, {"context": "ceremony", "actor": 2, "kind": "nonopening",
                            "accept": "accept-2", "ready": "ready", "closure": "final"}, False)

    def test_scalar_rank_criterion(self):
        q = 11
        rows = [[1, x, x*x % q] for x in (1, 2)]
        self.assertEqual(rank(rows, q, 3), 2)
        self.assertEqual(rank(rows + [[1, 0, 0]], q, 3), 3)
        self.assertEqual(rank(rows + [[1, 3, 9]], q, 3), 3)

    def test_boolean_actor_is_rejected(self):
        env = fixture(1, "nonopening")
        cert = extract(env)[0]
        cert["actor"] = True
        self.both(env, cert, False)

    def test_new_fields_do_not_override_service(self):
        env = fixture(2, "nonopening", service="censorable")
        cert = {"context": "ceremony", "actor": 2, "kind": "nonopening",
                "accept": "accept-2", "ready": "ready", "closure": "final",
                "service": "bounded_delivery"}
        self.both(env, cert, False)

    def test_foreign_record_cannot_create_active_offense(self):
        self.assertEqual(extract(fixture(2, "foreign_context")), [])

    def test_incorrect_subject_reference_rejected(self):
        env = fixture(2, "tag_mismatch")
        cert = extract(env)[0]
        cert["opening"] = "open-1"
        self.both(env, cert, False)

    def test_damaged_ideal_setup_fails_closed(self):
        base = fixture(2, "nonopening")
        cert = extract(base)[0]
        mutations = []
        for path, value in [
            (("context", "roster"), None),
            (("context", "roster"), [1, 1, 2]),
            (("context", "deadline"), "20"),
            (("context", "read_bound"), True),
            (("context", "group"), None),
            (("context", "coefficient_tags"), [True]),
            (("context", "threshold"), 99),
            (("context", "service"), "unknown"),
            (("receipts",), []),
            (("closures",), []),
        ]:
            env = deepcopy(base)
            target = env
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            mutations.append(env)
        env = deepcopy(base); env["receipts"]["broken"] = None; mutations.append(env)
        env = deepcopy(base); env["closures"]["broken"] = None; mutations.append(env)
        env = deepcopy(base); env["unexpected"] = True; mutations.append(env)
        for index, env in enumerate(mutations):
            with self.subTest(index=index):
                self.assertFalse(verify(env, cert))
                self.assertFalse(replay(env, cert))
                self.assertEqual(extract(env), [])

    def test_replay_has_no_producer_dependency(self):
        source = Path(__file__).resolve().parents[1] / "src" / "replay.py"
        tree = ast.parse(source.read_text())
        names = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        self.assertNotIn("checker", names)
        self.assertNotIn("cases", names)


if __name__ == "__main__":
    unittest.main()
