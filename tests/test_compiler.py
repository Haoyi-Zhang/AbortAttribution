"""Contract regressions for the ideal attribution compiler."""
from __future__ import annotations
import ast
from copy import deepcopy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from compiler_cases import fixture, generate
from compiler_checker import extract, verify
from compiler_replay import replay


class CompilerTests(unittest.TestCase):
    def both(self, env, cert, expected):
        self.assertEqual(verify(env, cert), expected)
        self.assertEqual(replay(env, cert), expected)

    def test_campaign_size(self):
        self.assertEqual(len(generate()), 3328)

    def test_bad_entry_positive_evidence(self):
        case = fixture(5, 2, 3, "malformed_entry")
        cert = extract(case["public"])[0]
        self.assertEqual(cert["kind"], "bad_entry")
        self.both(case["public"], cert, True)

    def test_bad_private_message_uses_bound_complaint(self):
        case = fixture(5, 2, 3, "invalid_message")
        cert = extract(case["public"])[0]
        self.assertEqual(cert["kind"], "bad_message")
        self.both(case["public"], cert, True)
        changed = deepcopy(cert)
        changed["complaint"] = "accept"
        self.both(case["public"], changed, False)

    def test_forged_complaint_rejected(self):
        case = fixture(6, 3, 7, "forged_complaint")
        self.assertEqual(extract(case["public"]), [])

    def test_missing_requires_bounded_service(self):
        bounded = fixture(4, 1, 2, "missing_bounded")
        censorable = fixture(4, 1, 2, "missing_censorable")
        self.assertEqual(extract(bounded["public"])[0]["kind"], "nonopening")
        self.assertEqual(extract(censorable["public"]), [])

    def test_tag_alone_is_not_delivery_evidence(self):
        case = fixture(7, 6, 8, "tag_only_unbound")
        self.assertEqual(extract(case["public"]), [])

    def test_truncated_closure_rejected(self):
        case = fixture(3, 2, 1, "missing_bounded")
        env = deepcopy(case["public"])
        env["closures"]["final"]["records"].remove("ready")
        cert = {"kind": "nonopening", "context": env["context"]["id"], "actor": 2,
                "accept": "accept", "ready": "ready", "closure": "final"}
        self.both(env, cert, False)

    def test_ambiguous_duplicate_accept_rejected(self):
        case = fixture(5, 3, 4, "missing_bounded")
        env = deepcopy(case["public"])
        env["records"]["accept-duplicate"] = deepcopy(env["records"]["accept"])
        env["closures"]["final"]["records"] = sorted(env["records"])
        cert = {"kind": "nonopening", "context": env["context"]["id"], "actor": 3,
                "accept": "accept", "ready": "ready", "closure": "final"}
        self.both(env, cert, False)
        self.assertEqual(extract(env), [])

    def test_complaint_cannot_predate_cited_envelope(self):
        case = fixture(5, 2, 3, "invalid_message")
        env = deepcopy(case["public"])
        env["records"]["complaint"]["time"] = 3
        cert = {"kind": "bad_message", "context": env["context"]["id"], "actor": 2,
                "envelope": "envelope", "complaint": "complaint"}
        self.both(env, cert, False)
        self.assertEqual(extract(env), [])

    def test_negative_complaint_time_rejected(self):
        case = fixture(5, 2, 3, "invalid_message")
        env = deepcopy(case["public"])
        env["records"]["complaint"]["time"] = -1
        cert = {"kind": "bad_message", "context": env["context"]["id"], "actor": 2,
                "envelope": "envelope", "complaint": "complaint"}
        self.both(env, cert, False)

    def test_malformed_setup_fails_closed(self):
        case = fixture(5, 2, 3, "missing_bounded")
        base = case["public"]
        cert = extract(base)[0]
        mutations = []
        for path, value in [
            (("context", "roster"), None),
            (("context", "roster"), "1,2,3"),
            (("context", "roster"), [1, 1, 2]),
            (("context", "deadline"), None),
            (("context", "deadline"), []),
            (("context", "read_bound"), True),
            (("context", "group"), None),
            (("context", "sender"), 99),
            (("context", "service"), "best_effort"),
            (("records",), []),
            (("closures",), []),
        ]:
            env = deepcopy(base)
            target = env
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            mutations.append(env)
        env = deepcopy(base); env["records"]["broken"] = None; mutations.append(env)
        env = deepcopy(base); env["closures"]["broken"] = None; mutations.append(env)
        env = deepcopy(base); env["unexpected"] = True; mutations.append(env)
        for index, env in enumerate(mutations):
            with self.subTest(index=index):
                self.assertFalse(verify(env, cert))
                self.assertFalse(replay(env, cert))
                self.assertEqual(extract(env), [])

    def test_replay_independence(self):
        source = Path(__file__).resolve().parents[1] / "src" / "compiler_replay.py"
        tree = ast.parse(source.read_text())
        imported = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        self.assertNotIn("compiler_checker", imported)
        self.assertNotIn("compiler_cases", imported)


if __name__ == "__main__":
    unittest.main()
