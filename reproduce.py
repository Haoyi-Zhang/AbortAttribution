#!/usr/bin/env python3
"""Run the bounded, deterministic pilot. Python standard library only.

The output directory must not already contain files. No source, network,
external model, signature key, or private user data is acquired or executed.
"""
from __future__ import annotations
import argparse
import ast
from collections import Counter, defaultdict
from copy import deepcopy
import json
from pathlib import Path
import resource
import signal
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
from cases import generate
from checker import accepted, extract, ready_record, verify
from replay import replay
from linear_oracle import run_disclosure_oracle, run_exponent_oracle, run_timing_oracle
from compiler_cases import generate as generate_compiler_cases
from compiler_checker import extract as extract_compiler, verify as verify_compiler
from compiler_replay import replay as replay_compiler
from schnorr_bridge import (GROUP_G as SCHNORR_G, GROUP_P as SCHNORR_P, PAILLIER_N,
                            envelope_status as schnorr_status, generate_cases as generate_schnorr_cases,
                            paillier_decrypt, response_equation as schnorr_equation,
                            tiny_challenge_negative_control,
                            verdict as schnorr_verdict)
from schnorr_replay import binding as replay_binding, replay as replay_schnorr
from schema_audit import run_schema_audit
from setup_boundary_audit import run_setup_boundary_audit


def dump(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def lines(path: Path, objects: list[Any]) -> None:
    path.write_text("".join(json.dumps(x, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n"
                            for x in objects), encoding="utf-8")


def mutations(cert: dict[str, Any], env: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    out = []
    def change(reason: str, field: str, value: Any) -> None:
        changed = deepcopy(cert)
        changed[field] = value
        out.append((reason, changed))
    for field in sorted(cert):
        c = deepcopy(cert)
        del c[field]
        out.append(("missing_" + field, c))
    change("foreign_context", "context", "another-ceremony")
    change("unlisted_subject", "actor", 6)
    change("boolean_subject", "actor", True)
    change("unknown_duty_receipt", "accept", "unknown-duty")
    other = next(i for i in env["context"]["roster"] if i != cert["actor"])
    change("another_subjects_duty", "accept", f"accept-{other}")
    change("unknown_rule", "kind", "unregistered-rule")
    change("self_asserted_reliability", "service", "bounded_delivery")
    if cert["kind"] == "bad_opening":
        change("unknown_opening", "opening", "unknown-opening")
        change("another_subjects_opening", "opening", f"open-{other}")
        change("duty_is_not_opening", "opening", cert["accept"])
        change("nonstring_opening_reference", "opening", [])
    else:
        change("premature_snapshot", "closure", "early")
        change("foreign_snapshot", "closure", "foreign")
        change("unknown_snapshot", "closure", "unknown-snapshot")
        change("unknown_readiness", "ready", "unknown-ready")
    return out



def compiler_mutations(cert: dict[str, Any], env: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Bounded invalid-certificate mutations for the compiler campaign."""
    out: list[tuple[str, dict[str, Any]]] = []
    for field in sorted(cert):
        changed = deepcopy(cert)
        del changed[field]
        out.append(("missing_" + field, changed))
    def change(reason: str, field: str, value: Any) -> None:
        changed = deepcopy(cert)
        changed[field] = value
        out.append((reason, changed))
    change("foreign_context", "context", "foreign")
    change("boolean_actor", "actor", True)
    change("out_of_roster_actor", "actor", len(env["context"]["roster"]) + 1)
    change("unknown_rule", "kind", "unknown")
    if cert["kind"] in {"bad_entry", "bad_message"}:
        change("unknown_envelope", "envelope", "unknown-envelope")
    if cert["kind"] == "bad_message":
        change("unknown_complaint", "complaint", "unknown-complaint")
        change("duty_as_complaint", "complaint", "accept")
    if cert["kind"] == "nonopening":
        change("premature_closure", "closure", "early")
        change("unknown_readiness", "ready", "unknown-ready")
        change("unknown_duty", "accept", "unknown-duty")
    changed = deepcopy(cert)
    changed["self_asserted_service"] = "bounded_delivery"
    out.append(("extra_self_asserted_service", changed))
    return out


def run_compiler_campaign(out: Path, failures: list[dict[str, Any]]) -> dict[str, Any]:
    cases = generate_compiler_cases()
    if len(cases) != 3328:
        raise AssertionError("compiler campaign inclusion count changed")
    families = Counter(case["family"] for case in cases)
    certificates: list[dict[str, Any]] = []
    mutation_results: list[dict[str, Any]] = []
    probes: list[dict[str, Any]] = []
    comparisons = 0
    max_encoding = 0
    cert_kinds: Counter[str] = Counter()
    for case in cases:
        env = case["public"]
        max_encoding = max(max_encoding, len(json.dumps(env, sort_keys=True, separators=(",", ":")).encode("ascii")))
        actual = extract_compiler(env)
        summary = [[c["actor"], c["kind"]] for c in actual]
        if summary != case["expected"]:
            failures.append({"case": case["case"], "failure": "compiler_certificate_set",
                             "expected": case["expected"], "observed": summary})
        for cert in actual:
            left, right = verify_compiler(env, cert), replay_compiler(env, cert)
            comparisons += 1
            cert_kinds[cert["kind"]] += 1
            certificates.append({"case": case["case"], "certificate": cert})
            if not left or not right:
                failures.append({"case": case["case"], "failure": "compiler_valid_certificate_rejected"})
            for reason, mutant in compiler_mutations(cert, env):
                left, right = verify_compiler(env, mutant), replay_compiler(env, mutant)
                comparisons += 1
                mutation_results.append({"case": case["case"], "reason": reason,
                                         "certificate": mutant, "producer_accepts": left,
                                         "replay_accepts": right, "expected": False})
                if left or right:
                    failures.append({"case": case["case"], "failure": "compiler_mutant_accepted", "reason": reason})
        actor = env["context"]["sender"]
        candidates = [
            {"kind": "bad_entry", "context": env["context"]["id"], "actor": actor, "envelope": "envelope"},
            {"kind": "bad_message", "context": env["context"]["id"], "actor": actor,
             "envelope": "envelope", "complaint": "complaint"},
            {"kind": "nonopening", "context": env["context"]["id"], "actor": actor,
             "accept": "accept", "ready": "ready", "closure": "final"},
        ]
        expected_pairs = {(who, kind) for who, kind in case["expected"]}
        for candidate in candidates:
            expected = (actor, candidate["kind"]) in expected_pairs
            left, right = verify_compiler(env, candidate), replay_compiler(env, candidate)
            comparisons += 1
            probes.append({"case": case["case"], "kind": candidate["kind"], "expected": expected,
                           "producer_accepts": left, "replay_accepts": right})
            if left != expected or right != expected:
                failures.append({"case": case["case"], "failure": "compiler_probe", "kind": candidate["kind"]})
    tree = ast.parse((ROOT / "src" / "compiler_replay.py").read_text(encoding="utf-8"))
    imports: list[str | None] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module)
    if set(imports) & {"compiler_checker", "compiler_cases"}:
        failures.append({"failure": "compiler_replay_imports_producer"})
    obligations = len(cases) + comparisons + len(mutation_results)
    result = {
        "model": "ideal signature/NIZK verification and bounded-delivery transcript; not a cryptographic implementation",
        "case_count": len(cases),
        "families": dict(sorted(families.items())),
        "supported_certificates": len(certificates),
        "certificate_kinds": dict(sorted(cert_kinds.items())),
        "invalid_certificate_mutations": len(mutation_results),
        "candidate_probes": len(probes),
        "producer_replay_comparisons": comparisons,
        "max_public_encoding_bytes": max_encoding,
        "counted_elementary_obligations": obligations,
        "replay_imports": sorted(str(x) for x in set(imports) if x),
    }
    lines(out / "compiler-cases.jsonl", cases)
    lines(out / "compiler-certificates.jsonl", certificates)
    lines(out / "compiler-mutations.jsonl", mutation_results)
    lines(out / "compiler-probes.jsonl", probes)
    dump(out / "compiler-outcomes.json", result)
    return result


def _schnorr_producer(case: dict[str, Any]) -> str:
    return schnorr_verdict(
        case["context"], case["envelope"], case["auth_public"],
        service=case["service"], accepted_duty=case["accepted_duty"],
        ready_on_time=case["ready_on_time"], complete_closure=case["complete_closure"],
        envelope_present=case["envelope_present"],
    )


def _schnorr_invalid_mutations(case: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Mutations that must remove an otherwise positive attribution."""
    if case["expected"] == "none":
        return []
    out: list[tuple[str, dict[str, Any]]] = []
    if case["expected"] == "qualified_nonopening":
        for reason, field, value in (
            ("censorable_service", "service", "censorable"),
            ("no_accepted_duty", "accepted_duty", False),
            ("late_readiness", "ready_on_time", False),
            ("incomplete_closure", "complete_closure", False),
            ("nonboolean_accepted_duty", "accepted_duty", 1),
            ("nonboolean_readiness", "ready_on_time", "yes"),
            ("nonboolean_closure", "complete_closure", 1),
        ):
            changed = deepcopy(case)
            changed[field] = value
            out.append((reason, changed))
        changed = deepcopy(case)
        changed["envelope_present"] = True
        out.append(("inconsistent_presence_flag", changed))
        return out
    changed = deepcopy(case)
    changed["context"] = {**changed["context"], "variant": "mutation"}
    out.append(("foreign_judge_context", changed))
    changed = deepcopy(case)
    changed["envelope"]["signature"]["response"] = (changed["envelope"]["signature"]["response"] + 1) % 233
    out.append(("corrupt_authentication", changed))
    changed = deepcopy(case)
    changed["envelope_present"] = False
    out.append(("inconsistent_presence_flag", changed))
    return out


def run_schnorr_campaign(out: Path, failures: list[dict[str, Any]]) -> dict[str, Any]:
    cases = generate_schnorr_cases()
    if len(cases) != 4160:
        raise AssertionError("Schnorr bridge inclusion count changed")
    families = Counter(case["family"] for case in cases)
    verdicts: Counter[str] = Counter()
    comparisons = 0
    mutations_out: list[dict[str, Any]] = []
    algebraic_checks = 0
    max_encoding = 0
    for case in cases:
        max_encoding = max(max_encoding, len(json.dumps(case, sort_keys=True, separators=(",", ":")).encode("ascii")))
        producer, replayed = _schnorr_producer(case), replay_schnorr(case)
        comparisons += 1
        verdicts[producer] += 1
        if producer != case["expected"] or replayed != case["expected"]:
            failures.append({"case": case["case"], "failure": "schnorr_verdict",
                             "expected": case["expected"], "producer": producer, "replay": replayed})
        if case["envelope_present"]:
            body = case["envelope"]["body"]
            status = schnorr_status(case["context"], case["envelope"], case["auth_public"])
            algebraic_checks += 1
            if case["family"] == "honest" and (status != "accepted" or not schnorr_equation(body)):
                failures.append({"case": case["case"], "failure": "schnorr_honest_equation"})
            if case["family"] in {"honest", "bad_response", "bad_challenge", "bad_evrf_proof",
                                  "replay_context", "bad_signature"}:
                plain = paillier_decrypt(body["ciphertext"])
                algebraic_checks += 2
                if pow(SCHNORR_G, plain, SCHNORR_P) != body["response_tag"]:
                    failures.append({"case": case["case"], "failure": "schnorr_plaintext_tag_mismatch"})
        for reason, mutant in _schnorr_invalid_mutations(case):
            p, r = _schnorr_producer(mutant), replay_schnorr(mutant)
            comparisons += 1
            mutations_out.append({"case": case["case"], "reason": reason,
                                  "producer": p, "replay": r, "expected": "none"})
            if p != "none" or r != "none":
                failures.append({"case": case["case"], "failure": "schnorr_mutation_accepted", "reason": reason})
    negative_control = tiny_challenge_negative_control()
    negative_control["replay_accepts"] = replay_binding(
        negative_control["context"], negative_control["ciphertext"],
        negative_control["tag"], negative_control["proof"]
    )
    if negative_control["relation_holds"] is not False:
        failures.append({"failure": "toy_binding_negative_control_relation_true"})
    if negative_control["producer_accepts"] is not True or negative_control["replay_accepts"] is not True:
        failures.append({"failure": "toy_binding_negative_control_not_accepted"})
    negative_obligations = negative_control["challenge_evaluations"] + 3
    negative_control["counted_elementary_obligations"] = negative_obligations

    tree = ast.parse((ROOT / "src" / "schnorr_replay.py").read_text(encoding="utf-8"))
    imports: list[str | None] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module)
    if "schnorr_bridge" in imports:
        failures.append({"failure": "schnorr_replay_imports_producer"})
    obligations = len(cases) + comparisons + len(mutations_out) + algebraic_checks + negative_obligations
    result = {
        "model": "toy prime-order group and Paillier arithmetic; imported eVRF verification bit; honest-equation conformance plus an explicit tiny-challenge forgery negative control; not production cryptography",
        "case_count": len(cases),
        "families": dict(sorted(families.items())),
        "verdicts": dict(sorted(verdicts.items())),
        "invalid_attribution_mutations": len(mutations_out),
        "producer_replay_comparisons": comparisons,
        "algebraic_consistency_checks": algebraic_checks,
        "tiny_challenge_negative_control": {
            "challenge_space": negative_control["challenge_space"],
            "challenge_evaluations": negative_control["challenge_evaluations"],
            "false_relation": not negative_control["relation_holds"],
            "producer_accepts": negative_control["producer_accepts"],
            "replay_accepts": negative_control["replay_accepts"],
            "counted_elementary_obligations": negative_obligations,
        },
        "max_case_encoding_bytes": max_encoding,
        "counted_elementary_obligations": obligations,
        "group": {"p": SCHNORR_P, "q": 233, "g": SCHNORR_G},
        "paillier_modulus": PAILLIER_N,
        "replay_imports": sorted(str(x) for x in set(imports) if x),
    }
    lines(out / "schnorr-cases.jsonl", cases)
    lines(out / "schnorr-mutations.jsonl", mutations_out)
    dump(out / "binding-negative-control.json", negative_control)
    dump(out / "schnorr-outcomes.json", result)
    return result

def run(out: Path) -> dict[str, Any]:
    cases = generate()
    if len(cases) != 84:
        raise AssertionError("Fixture inclusion count changed; repair the specification first")
    families = Counter(x["family"] for x in cases)
    failures: list[dict[str, Any]] = []
    certificates, mutation_results, case_results, probes = [], [], [], []
    pair_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    replay_decisions = 0
    supported = 0
    max_size = 0
    max_receipts = 0
    positive_kinds: Counter[str] = Counter()
    for case in cases:
        env = case["public"]
        raw = json.dumps(env, sort_keys=True, separators=(",", ":")).encode("ascii")
        max_size = max(max_size, len(raw))
        max_receipts = max(max_receipts, len(env["receipts"]))
        actual = extract(env)
        summary = [[c["actor"], c["kind"]] for c in actual]
        if summary != case["expected"]:
            failures.append({"case": case["case"], "failure": "unexpected_certificate_set",
                             "expected": case["expected"], "observed": summary})
        for c in actual:
            left, right = verify(env, c), replay(env, c)
            replay_decisions += 1
            supported += 1
            positive_kinds[c["kind"]] += 1
            if not left or not right:
                failures.append({"case": case["case"], "failure": "valid_certificate_rejected"})
            certificates.append({"case": case["case"], "certificate": c})
            for reason, mutant in mutations(c, env):
                v, r = verify(env, mutant), replay(env, mutant)
                replay_decisions += 1
                mutation_results.append({"case": case["case"], "reason": reason,
                                         "certificate": mutant, "producer_accepts": v,
                                         "replay_accepts": r, "expected": False})
                if v or r:
                    failures.append({"case": case["case"], "failure": "invalid_mutant_accepted", "reason": reason})
        # Out-of-class negative candidates are checked even when extraction is empty.
        for who in env["context"]["roster"]:
            a = accepted(env, who)
            if a is None:
                continue
            c = {"kind": "nonopening", "context": env["context"]["id"], "actor": who,
                 "accept": a, "closure": "final", "ready": ready_record(env) or "ready"}
            expected = [who, "nonopening"] in case["expected"]
            v, r = verify(env, c), replay(env, c)
            replay_decisions += 1
            probes.append({"case": case["case"], "actor": who, "expected": expected,
                           "producer_accepts": v, "replay_accepts": r})
            if v != expected or r != expected:
                failures.append({"case": case["case"], "actor": who, "failure": "omission_probe"})
        case_results.append({"case": case["case"], "family": case["family"],
                             "expected": case["expected"], "observed": summary,
                             "public_encoding_bytes": len(raw), "receipt_records": len(env["receipts"])})
        if case["pair"]:
            pair_groups[case["pair"]].append(case)
    pair_results = []
    naive_false_accusations = 0
    for pair_name, members in sorted(pair_groups.items()):
        if len(members) != 2:
            raise AssertionError("A coupled-history control must have exactly two histories")
        left, right = members
        equality = left["public"] == right["public"]
        if not equality:
            failures.append({"pair": pair_name, "failure": "public_views_differ"})
        # Deliberately weak judge: missing required on-board action => accuse.
        who = left["private_history_annotation"]["actor"]
        stage = "open" if pair_name.startswith("after") else "accept"
        decisions = []
        for m in members:
            deadline = 20 if stage == "open" else 5
            decisions.append(not any(r["actor"] == who and r["kind"] == stage
                                     and r["time"] <= deadline
                                     for r in m["public"]["receipts"].values()))
        if decisions != [True, True]:
            failures.append({"pair": pair_name, "failure": "weak_judge_control_changed"})
        naive_false_accusations += int(decisions[1])
        pair_results.append({"pair": pair_name, "cases": [m["case"] for m in members],
                             "public_equal": equality, "weak_judge_accuses": decisions,
                             "second_history_honest": True})
    compiler = run_compiler_campaign(out, failures)
    schnorr = run_schnorr_campaign(out, failures)
    schema = run_schema_audit()
    failures.extend({"failure": "schema_audit", "detail": f} for f in schema["failures"])
    setup_boundary = run_setup_boundary_audit()
    failures.extend({"failure": "setup_boundary_audit", "detail": f}
                    for f in setup_boundary["failures"])
    disclosure = run_disclosure_oracle()
    timing = run_timing_oracle()
    exponent = run_exponent_oracle()
    failures.extend({"failure": "disclosure_oracle", "detail": f} for f in disclosure["failures"])
    failures.extend({"failure": "timing_oracle", "detail": f} for f in timing["failures"])
    if not exponent["group_order_checked"] or not exponent["all_scalars_recovered"]:
        failures.append({"failure": "tiny_exponent_control"})
    # Dependency separation checked from source syntax, not by running arbitrary input code.
    tree = ast.parse((ROOT / "src" / "replay.py").read_text(encoding="utf-8"))
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module)
    if set(imports) & {"checker", "cases", "linear_oracle"}:
        failures.append({"failure": "replay_imports_producer"})
    elementary = (disclosure["coefficient_target_evaluations"] + disclosure["posterior_cells_checked"]
                  + timing["enumerated_histories"] + exponent["q"] + len(cases)
                  + replay_decisions + len(pair_results) + compiler["counted_elementary_obligations"]
                  + schnorr["counted_elementary_obligations"]
                  + schema["counted_elementary_obligations"]
                  + setup_boundary["counted_elementary_obligations"])
    if elementary > 300_000:
        failures.append({"failure": "pilot_enumeration_reserve_exceeded", "count": elementary})
    if max_receipts > 12 or max_size > 32768:
        failures.append({"failure": "fixture_encoding_cap"})
    outcomes = {"model": "ideal-receipt exponent-tag evidence model; not an exponent-VRF implementation",
                "status": "finite_checks_passed" if not failures else "failed",
                "case_count": len(cases), "families": dict(sorted(families.items())),
                "supported_certificates": supported, "certificate_kinds": dict(positive_kinds),
                "invalid_certificate_mutations": len(mutation_results),
                "omission_probes": len(probes), "producer_replay_comparisons": replay_decisions,
                "paired_public_observations": len(pair_results),
                "deliberately_weak_judge_false_accusations": naive_false_accusations,
                "max_public_encoding_bytes": max_size, "max_receipt_records": max_receipts,
                "rank_distribution_comparisons": disclosure["rank_distribution_comparisons"],
                "coefficient_target_evaluations": disclosure["coefficient_target_evaluations"],
                "posterior_cells_checked": disclosure["posterior_cells_checked"],
                "timing_histories": timing["enumerated_histories"],
                "compiler_case_count": compiler["case_count"],
                "compiler_supported_certificates": compiler["supported_certificates"],
                "compiler_invalid_certificate_mutations": compiler["invalid_certificate_mutations"],
                "compiler_candidate_probes": compiler["candidate_probes"],
                "compiler_producer_replay_comparisons": compiler["producer_replay_comparisons"],
                "compiler_certificate_kinds": compiler["certificate_kinds"],
                "schnorr_case_count": schnorr["case_count"],
                "schnorr_verdicts": schnorr["verdicts"],
                "schnorr_invalid_attribution_mutations": schnorr["invalid_attribution_mutations"],
                "schnorr_producer_replay_comparisons": schnorr["producer_replay_comparisons"],
                "schnorr_algebraic_consistency_checks": schnorr["algebraic_consistency_checks"],
                "schnorr_tiny_challenge_negative_control": schnorr["tiny_challenge_negative_control"],
                "schema_valid_vectors": len(schema["valid_vectors"]),
                "schema_invalid_vectors": len(schema["invalid_vectors"]),
                "schema_checks": schema["counted_elementary_obligations"],
                "setup_boundary_mutations": (setup_boundary["compiler_mutations"]
                                             + setup_boundary["ideal_receipt_mutations"]
                                             + setup_boundary["schnorr_mutations"]),
                "setup_boundary_api_calls": setup_boundary["public_api_calls"],
                "setup_boundary_exceptions": setup_boundary["exceptions"],
                "setup_boundary_unsafe_results": setup_boundary["unsafe_results"],
                "counted_elementary_obligations": elementary,
                "replay_imports": sorted(set(imports)), "failures": failures}
    lines(out / "cases.jsonl", cases)
    lines(out / "certificates.jsonl", certificates)
    lines(out / "mutations.jsonl", mutation_results)
    lines(out / "omission-probes.jsonl", probes)
    dump(out / "case-outcomes.json", case_results)
    dump(out / "negative-controls.json", pair_results)
    dump(out / "disclosure.json", disclosure)
    dump(out / "timing.json", timing)
    dump(out / "exponents.json", exponent)
    dump(out / "schema-audit.json", schema)
    dump(out / "setup-boundary-audit.json", setup_boundary)
    dump(out / "outcomes.json", outcomes)
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="new or empty local output directory")
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() and any(out.iterdir()):
        parser.error("output directory is nonempty; choose a new directory to avoid stale results")
    out.mkdir(parents=True, exist_ok=True)
    def timeout(_signal: int, _frame: Any) -> None:
        raise TimeoutError("180-second pilot wall-time limit exceeded")
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(180)
    resource.setrlimit(resource.RLIMIT_AS, (3 * 1024**3, 3 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (180, 180))
    start_wall, start_cpu = time.perf_counter(), time.process_time()
    try:
        result = run(out)
        measured = {"wall_seconds": time.perf_counter()-start_wall,
                    "cpu_seconds": time.process_time()-start_cpu,
                    "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                    "workers": 1, "measurement_scope": "pilot checks and raw-result writes, before final measurement serialization",
                    "wall_limit_seconds": 180, "address_space_limit_bytes": 3*1024**3,
                    "enumeration_limit_this_run": 300000}
        dump(out / "measurements.json", measured)
        print(json.dumps({"status": result["status"], "cases": result["case_count"],
                          "obligations": result["counted_elementary_obligations"],
                          "failures": len(result["failures"]), **measured}, sort_keys=True))
        return 0 if not result["failures"] else 1
    except Exception as exc:
        dump(out / "execution-failure.json", {"type": type(exc).__name__, "message": str(exc)})
        print(f"pilot failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    raise SystemExit(main())
