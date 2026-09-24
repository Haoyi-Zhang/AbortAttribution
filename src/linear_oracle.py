"""Exact finite disclosure and timing oracles. No cryptographic security test."""
from __future__ import annotations
from collections import Counter, defaultdict
from itertools import combinations, product
from typing import Any


def rank(rows: list[list[int]], q: int, width: int) -> int:
    matrix = [[x % q for x in row] for row in rows]
    if any(len(row) != width for row in matrix):
        raise ValueError("inconsistent row width")
    pivot = 0
    for col in range(width):
        selected = next((i for i in range(pivot, len(matrix)) if matrix[i][col]), None)
        if selected is None:
            continue
        matrix[pivot], matrix[selected] = matrix[selected], matrix[pivot]
        scale = pow(matrix[pivot][col], -1, q)
        matrix[pivot] = [(scale*x) % q for x in matrix[pivot]]
        for r in range(len(matrix)):
            if r == pivot:
                continue
            factor = matrix[r][col]
            matrix[r] = [(a-factor*b) % q for a, b in zip(matrix[r], matrix[pivot])]
        pivot += 1
        if pivot == len(matrix):
            break
    return pivot


def dot(u: tuple[int, ...] | list[int], v: tuple[int, ...], q: int) -> int:
    return sum(x*y for x, y in zip(u, v)) % q


def run_disclosure_oracle(q: int = 11, degree_bound: int = 3, n: int = 5) -> dict[str, Any]:
    """Compare rank predictions with distributions from enumerated coefficients.

    'degree_bound' is the number of coefficients (the reconstruction threshold).
    Public exponent encodings are deliberately NOT conditioned on here.
    """
    if (q, degree_bound, n) != (11, 3, 5):
        raise ValueError("Only the preregistered finite pilot is implemented")
    rows = {i: tuple(pow(i, k, q) for k in range(degree_bound)) for i in range(1, n+1)}
    targets = [("constant", (1, 0, 0)), ("share-5", rows[5])]
    vectors = list(product(range(q), repeat=degree_bound))
    coefficient_target_evaluations = 0
    posterior_cells = 0
    comparisons = []
    failures = []
    for size in range(n+1):
        for subset in combinations(range(1, n+1), size):
            observed = [rows[i] for i in subset]
            r = rank([list(x) for x in observed], q, degree_bound)
            for target_name, target in targets:
                predicted_known = rank([list(x) for x in observed] + [list(target)],
                                       q, degree_bound) == r
                distributions: dict[tuple[int, ...], Counter[int]] = defaultdict(Counter)
                for a in vectors:
                    key = tuple(dot(row, a, q) for row in observed)
                    distributions[key][dot(target, a, q)] += 1
                    coefficient_target_evaluations += 1
                known = True
                uniform = True
                for counts in distributions.values():
                    posterior_cells += 1
                    known &= len(counts) == 1
                    uniform &= len(counts) == q and len(set(counts.values())) == 1
                passed = known if predicted_known else uniform
                if not passed:
                    failures.append({"subset": list(subset), "target": target_name})
                comparisons.append({"subset": list(subset), "target": target_name,
                                    "rank": r, "predicted": "determined" if predicted_known else "uniform",
                                    "fibres": len(distributions), "passed": passed})
    # Explicit accidental disclosure: two corrupt shares plus one scalar complaint.
    shares = {str(i): dot(rows[i], (7, 4, 2), q) for i in (1, 2, 3)}
    reconstructed = (3*shares["1"] - 3*shares["2"] + shares["3"]) % q
    if reconstructed != 7:
        failures.append({"explicit_reconstruction": reconstructed})
    return {"q": q, "threshold": degree_bound, "n": n,
            "coefficient_vectors": len(vectors), "revealed_subsets": 2**n,
            "targets": len(targets), "rank_distribution_comparisons": len(comparisons),
            "coefficient_target_evaluations": coefficient_target_evaluations,
            "posterior_cells_checked": posterior_cells,
            "failures": failures, "comparisons": comparisons,
            "reconstruction_example": {"coefficients": [7, 4, 2], "shares": shares,
                                       "weights": [3, -3, 1], "reconstructed_constant": reconstructed}}


def run_timing_oracle() -> dict[str, Any]:
    deadline, rho, kappa, delta = 20, 3, 2, 3
    cutoff = deadline-rho-kappa-delta
    rows = []
    failures = []
    total = 0
    for enabled in range(deadline+1):
        arrivals = []
        for read in range(rho+1):
            for compute in range(kappa+1):
                for delivery in range(delta+1):
                    arrivals.append(enabled+read+compute+delivery)
                    total += 1
        universally_on_time = max(arrivals) <= deadline
        predicted = enabled <= cutoff
        if universally_on_time != predicted:
            failures.append(enabled)
        rows.append({"ready_publication": enabled, "histories": len(arrivals),
                     "latest_receipt": max(arrivals), "all_on_time": universally_on_time})
    return {"deadline": deadline, "read_bound": rho, "compute_bound": kappa,
            "delivery_bound": delta, "latest_safe_ready": cutoff,
            "enumerated_histories": total, "rows": rows, "failures": failures,
            "one_tick_late_control": {"ready": 13, "observed": 16, "computed": 18, "received": 21}}


def run_exponent_oracle() -> dict[str, Any]:
    p, q, g = 23, 11, 2
    table = [{"scalar": y, "tag": pow(g, y, p)} for y in range(q)]
    reverse = {row["tag"]: row["scalar"] for row in table}
    return {"p": p, "q": q, "g": g, "group_order_checked": pow(g,q,p)==1 and g != 1,
            "distinct_tags": len(reverse), "all_scalars_recovered": len(reverse)==q,
            "table": table,
            "interpretation": "Finite discrete-log lookup is a negative control, not an eVRF security experiment."}
