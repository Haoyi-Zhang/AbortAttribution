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


def _refresh_closures(env):
    """Recompute each retained snapshot from record receipt times."""
    ctx = env["context"]
    for snap in env["closures"].values():
        cutoff = snap["cutoff"]
        snap["records"] = sorted(
            name for name, record in env["records"].items()
            if record.get("context") == ctx["id"]
            and type(record.get("time")) is int
            and record["time"] <= cutoff
        )


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


    def test_deadline_and_d_plus_one_are_separate_from_content_fault(self):
        at_deadline = fixture(5, 2, 3, "honest_delayed")
        self.assertEqual(at_deadline["public"]["records"]["envelope"]["time"], 12)
        self.assertEqual(extract(at_deadline["public"]), [])

        late = fixture(5, 2, 3, "honest_valid")
        env = deepcopy(late["public"])
        env["records"]["envelope"]["time"] = 13
        _refresh_closures(env)
        certs = extract(env)
        self.assertEqual([c["kind"] for c in certs], ["nonopening"])
        self.assertNotIn("bad_entry", [c["kind"] for c in certs])
        self.both(env, certs[0], True)

        censorable = deepcopy(env)
        censorable["context"]["service"] = "censorable"
        self.assertEqual(extract(censorable), [])

        late_ready = deepcopy(env)
        late_ready["records"]["ready"]["time"] = 7
        _refresh_closures(late_ready)
        self.assertEqual(extract(late_ready), [])

        missing = fixture(5, 2, 3, "missing_bounded")
        self.assertEqual([c["kind"] for c in extract(missing["public"])], ["nonopening"])

    def test_late_malformed_content_and_deadline_nonfulfilment_are_distinct(self):
        case = fixture(5, 2, 3, "malformed_entry")
        env = deepcopy(case["public"])
        env["records"]["envelope"]["time"] = 13
        _refresh_closures(env)
        certs = extract(env)
        self.assertEqual([c["kind"] for c in certs], ["bad_entry", "nonopening"])
        for cert in certs:
            self.both(env, cert, True)

    def test_extractor_discovers_renamed_references_and_chooses_canonical_pair(self):
        case = fixture(5, 2, 3, "missing_bounded")
        env = deepcopy(case["public"])
        env["records"]["a1"] = env["records"].pop("accept")
        env["records"]["r1"] = env["records"].pop("ready")
        env["records"]["r2"] = deepcopy(env["records"]["r1"])
        env["records"]["r2"]["time"] = 5
        env["closures"]["b1"] = env["closures"].pop("final")
        env["closures"]["b2"] = deepcopy(env["closures"]["b1"])
        _refresh_closures(env)
        certs = extract(env)
        self.assertEqual(certs, [{
            "kind": "nonopening", "context": env["context"]["id"], "actor": 2,
            "accept": "a1", "ready": "r1", "closure": "b1",
        }])
        self.both(env, certs[0], True)

    def test_nonstring_closure_references_fail_closed_in_both_paths(self):
        case = fixture(5, 2, 3, "missing_bounded")
        env = case["public"]
        base = extract(env)[0]
        for value in ([], {}):
            with self.subTest(value=type(value).__name__):
                cert = deepcopy(base)
                cert["closure"] = value
                self.both(env, cert, False)

    def test_transcript_field_regressions_are_not_certificate_mutations(self):
        honest = fixture(5, 2, 3, "honest_valid")
        hash_env = deepcopy(honest["public"])
        hash_env["records"]["envelope"]["body"]["entry_proof_statement"] = "0" * 64
        certs = extract(hash_env)
        self.assertEqual([c["kind"] for c in certs], ["bad_entry"])
        self.both(hash_env, certs[0], True)

        proof_env = deepcopy(honest["public"])
        proof_env["records"]["envelope"]["body"]["entry_proof_valid"] = False
        certs = extract(proof_env)
        self.assertEqual([c["kind"] for c in certs], ["bad_entry"])
        self.both(proof_env, certs[0], True)

        missing = fixture(5, 2, 3, "missing_bounded")
        closure_env = deepcopy(missing["public"])
        closure_env["closures"]["final"]["records"].remove("ready")
        cert = {"kind": "nonopening", "context": closure_env["context"]["id"],
                "actor": 2, "accept": "accept", "ready": "ready", "closure": "final"}
        self.both(closure_env, cert, False)

    def test_replay_independence(self):
        source = Path(__file__).resolve().parents[1] / "src" / "compiler_replay.py"
        tree = ast.parse(source.read_text())
        imported = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        self.assertNotIn("compiler_checker", imported)
        self.assertNotIn("compiler_cases", imported)


if __name__ == "__main__":
    unittest.main()
