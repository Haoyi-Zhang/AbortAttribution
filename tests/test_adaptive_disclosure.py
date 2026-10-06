"""Exact small-field checks of the public-history-only opening policy."""
from collections import Counter, defaultdict
from itertools import product
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from linear_oracle import rank


def run_adaptive_audit():
    q = 3
    vectors = list(product(range(q), repeat=2))
    checks = samples = transcripts = 0
    for random_policy in (False, True):
        cells = defaultdict(Counter)
        for a in vectors:
            for coin in range(q if random_policy else 1):
                # Read a[0] first. Both next-row choice and stopping depend
                # only on that disclosed value and independent policy coins.
                trace = [((1, 0), a[0])]
                choice = (a[0] + coin) % q
                if choice:
                    row = (0, 1) if choice == 1 else (1, 1)
                    trace.append((row, sum(x * y for x, y in zip(row, a)) % q))
                cells[tuple(trace)][a] += 1
                samples += 1
        for trace, counts in cells.items():
            rows = [list(row) for row, _ in trace]
            compatible = {a for a in vectors if all(
                sum(x * y for x, y in zip(row, a)) % q == value
                for row, value in trace)}
            if set(counts) != compatible:
                raise AssertionError("policy transcript has an incorrect coefficient support")
            if len(set(counts.values())) != 1:
                raise AssertionError("policy transcript is not uniform on its solution coset")
            checks += 2
            for target in ([[1, 0]], [[0, 1]], [[1, 0], [0, 1]]):
                observed = Counter(tuple(sum(x * y for x, y in zip(row, a)) % q
                                         for row in target) for a in counts)
                expected_size = q ** (rank(rows + target, q, 2) - rank(rows, q, 2))
                if len(observed) != expected_size:
                    raise AssertionError("rank and enumerated target support disagree")
                if len(set(observed.values())) != 1:
                    raise AssertionError("enumerated target is not uniform")
                checks += 2
            transcripts += 1
    return {"field_order": q, "coefficient_vectors": len(vectors),
            "policy_samples": samples, "transcripts": transcripts,
            "elementary_assertions": checks}


class AdaptiveDisclosureTests(unittest.TestCase):
    def test_public_policy_has_uniform_solution_cosets(self):
        result = run_adaptive_audit()
        self.assertEqual(result["coefficient_vectors"], 9)
        self.assertEqual(result["policy_samples"], 36)
        self.assertGreater(result["transcripts"], 0)

    def test_hidden_state_selection_is_outside_rank_corollary(self):
        # A private selector publishes the zero equation only if a[0] == 0.
        # The equation alone imposes no constraint; the selection event does.
        vectors = list(product(range(3), repeat=2))
        selected = [a for a in vectors if a[0] == 0]
        self.assertEqual(rank([[0, 0]], 3, 2), 0)
        self.assertEqual(len(vectors), 9)
        self.assertEqual(len(selected), 3)
        self.assertEqual({a[0] for a in selected}, {0})


if __name__ == "__main__":
    unittest.main()
