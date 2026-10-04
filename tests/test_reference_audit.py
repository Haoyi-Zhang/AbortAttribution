"""Regression tests for the offline bibliography audit."""
from __future__ import annotations
from pathlib import Path
import sys
import unittest

ARTIFACT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT))
import audit_references as audit


class ReferenceAuditTests(unittest.TestCase):
    def test_retained_inventory_is_closed_and_large_enough(self):
        rows = audit.read_inventory(ARTIFACT / "reference_audit.csv")
        self.assertEqual(audit.validate_inventory(rows), [])
        self.assertEqual(len(rows), 73)
        self.assertGreaterEqual(
            sum(row["verification_status"] == "primary-record-checked" for row in rows), 9
        )

    def test_parser_handles_nested_tex_and_same_line_fields(self):
        source = r"""
@article{x,
  author={A. Author}, title={{Nested} Title}, year={2024},
  doi={10.1000/example.1}
}
@book{y, author={B. Author}, title={Book}, year={2004}, isbn={978-0-521-83084-3}}
"""
        entries = audit.parse_bibtex(source)
        self.assertEqual([entry.key for entry in entries], ["x", "y"])
        self.assertEqual(entries[0].fields["title"], "{Nested} Title")
        self.assertEqual(audit.validate_entries(entries, {"x", "y"}, minimum=0), [])

    def test_uncited_and_unknown_keys_fail(self):
        source = r"""@article{x, author={A}, title={T}, year={2024}, doi={10.1000/x}}"""
        entries = audit.parse_bibtex(source)
        failures = audit.validate_entries(entries, {"y"}, minimum=0)
        self.assertTrue(any("uncited" in item for item in failures))
        self.assertTrue(any("unknown citation" in item for item in failures))

    def test_nocite_is_forbidden(self):
        with self.assertRaises(ValueError):
            audit.cited_keys(r"\\nocite{*}")


if __name__ == "__main__":
    unittest.main()
