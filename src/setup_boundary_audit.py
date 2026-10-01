"""Deterministic fail-closed audit for damaged trusted-context encodings.

The theorem treats the public context and board registry as setup inputs.  This
module therefore does *not* use any producer-side setup validator to select its
negative cases.  Each vector is independently annotated with the schema rule it
violates, then presented unchanged to every public verification, replay, and
extraction entry point.  The expected result is rejection/empty extraction,
never an exception or attribution.

This remains implementation hardening for serialized inputs, not a
cryptographic security experiment and not a proof about arbitrary parsers.
"""
from __future__ import annotations
from copy import deepcopy
from typing import Any, Callable

from cases import fixture as base_fixture
from checker import extract as base_extract, verify as base_verify
from replay import replay as base_replay
from compiler_cases import fixture as compiler_fixture
from compiler_checker import extract as compiler_extract, verify as compiler_verify
from compiler_replay import replay as compiler_replay
from schnorr_bridge import make_case as schnorr_case, verdict as schnorr_verdict
from schnorr_replay import replay as schnorr_replay


Vector = tuple[str, str, dict[str, Any]]


def _set_path(obj: dict[str, Any], path: tuple[Any, ...], value: Any) -> dict[str, Any]:
    altered = deepcopy(obj)
    target: Any = altered
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return altered


def _vector(base: dict[str, Any], label: str, rule: str,
            path: tuple[Any, ...], value: Any) -> Vector:
    return label, rule, _set_path(base, path, value)


def _add_key(base: dict[str, Any], label: str, rule: str,
             path: tuple[Any, ...], key: Any, value: Any) -> Vector:
    altered = deepcopy(base)
    target: Any = altered
    for part in path:
        target = target[part]
    target[key] = value
    return label, rule, altered


def _common_top_vectors(base: dict[str, Any], record_table: str) -> list[Vector]:
    vectors: list[Vector] = []
    for field in ("context", record_table, "closures"):
        for label, value in (
            ("null", None), ("bool", True), ("integer", 0), ("float", 1.5),
            ("string", "x"), ("list", []), ("bytes", b"x"), ("tuple", (1,)),
        ):
            vectors.append(_vector(
                base, f"top.{field}:{label}", f"{field} must be a JSON object",
                (field,), value,
            ))
    vectors.extend([
        _add_key(base, f"{record_table}.nonstring-key", "record identifiers must be strings",
                 (record_table,), 1, {}),
        _add_key(base, f"{record_table}.nondict-value", "record values must be objects",
                 (record_table,), "broken", None),
        _add_key(base, "closures.nonstring-key", "closure identifiers must be strings",
                 ("closures",), 1, {}),
        _add_key(base, "closures.nondict-value", "closure values must be objects",
                 ("closures",), "broken", None),
        _add_key(base, "top.unexpected-key", "top-level object has an exact key set",
                 (), "unexpected", True),
    ])
    return vectors


def _compiler_vectors(base: dict[str, Any]) -> list[Vector]:
    ctx = base["context"]
    vectors = _common_top_vectors(base, "records")
    vectors.extend([
        _vector(base, "context.id:empty", "context id must be a nonempty canonical string",
                ("context", "id"), ""),
        _vector(base, "context.id:surrogate", "context id must be canonical JSON",
                ("context", "id"), "\ud800"),
        _vector(base, "context.roster:null", "roster must be a bounded list of positive exact integers",
                ("context", "roster"), None),
        _vector(base, "context.roster:tuple", "roster must be a JSON list",
                ("context", "roster"), (1, 2, 3)),
        _vector(base, "context.roster:empty", "roster must be nonempty",
                ("context", "roster"), []),
        _vector(base, "context.roster:boolean-member", "roster members must be exact integers, not booleans",
                ("context", "roster"), [True, 2, 3, 4, 5]),
        _vector(base, "context.roster:duplicate", "roster members must be unique",
                ("context", "roster"), [1, 1, 2]),
        _vector(base, "context.roster:nonpositive", "roster members must be positive",
                ("context", "roster"), [0, 2, 3]),
        _vector(base, "context.roster:oversize", "roster length is at most ten",
                ("context", "roster"), list(range(1, 12))),
        _vector(base, "context.round:boolean", "round must be an exact integer",
                ("context", "round"), True),
        _vector(base, "context.round:zero", "round lies in 1..8",
                ("context", "round"), 0),
        _vector(base, "context.round:too-large", "round lies in 1..8",
                ("context", "round"), 9),
        _vector(base, "context.round:float", "round must be an exact integer",
                ("context", "round"), 3.0),
        _vector(base, "context.sender:boolean", "sender must be an exact roster integer",
                ("context", "sender"), True),
        _vector(base, "context.sender:outside", "sender must be in the roster",
                ("context", "sender"), 99),
        _vector(base, "context.recipient:boolean", "recipient must be an exact roster integer",
                ("context", "recipient"), True),
        _vector(base, "context.recipient:outside", "recipient must be in the roster",
                ("context", "recipient"), 99),
        _vector(base, "context.group:null", "group must be an exact object",
                ("context", "group"), None),
        _vector(base, "context.group.p:boolean", "group parameters must be exact integers",
                ("context", "group", "p"), True),
        _vector(base, "context.group.q:zero", "group order must be nontrivial",
                ("context", "group", "q"), 0),
        _vector(base, "context.group.g:identity", "generator must be nonidentity",
                ("context", "group", "g"), 1),
        _vector(base, "context.accept_by:boolean", "timing bounds must be exact integers",
                ("context", "accept_by"), True),
        _vector(base, "context.accept_by:negative", "acceptance time is nonnegative",
                ("context", "accept_by"), -1),
        _vector(base, "context.deadline:string", "deadline must be an exact integer",
                ("context", "deadline"), "12"),
        _vector(base, "context.deadline:before-accept", "deadline cannot precede acceptance",
                ("context", "deadline"), ctx["accept_by"] - 1),
        _vector(base, "context.read-bound:boolean", "delay bounds must be exact integers",
                ("context", "read_bound"), True),
        _vector(base, "context.compute-bound:negative", "delay bounds are nonnegative",
                ("context", "compute_bound"), -1),
        _vector(base, "context.delivery-bound:too-large", "deadline must cover all declared delay bounds",
                ("context", "delivery_bound"), ctx["deadline"] + 1),
        _vector(base, "context.service:boolean", "service label must be a string enum",
                ("context", "service"), True),
        _vector(base, "context.service:unknown", "service label must be declared",
                ("context", "service"), "best_effort"),
        _add_key(base, "context.unexpected-key", "context has an exact key set",
                 ("context",), "unexpected", True),
    ])
    return vectors


def _base_vectors(base: dict[str, Any]) -> list[Vector]:
    ctx = base["context"]
    vectors = _common_top_vectors(base, "receipts")
    vectors.extend([
        _vector(base, "context.id:empty", "context id must be nonempty",
                ("context", "id"), ""),
        _vector(base, "context.roster:boolean-member", "roster members must be exact integers, not booleans",
                ("context", "roster"), [True, 2, 3, 4, 5]),
        _vector(base, "context.roster:duplicate", "roster members must be unique",
                ("context", "roster"), [1, 1, 2]),
        _vector(base, "context.roster:empty", "roster must be nonempty",
                ("context", "roster"), []),
        _vector(base, "context.group:null", "group must be an exact object",
                ("context", "group"), None),
        _vector(base, "context.group.p:boolean", "group parameters must be exact integers",
                ("context", "group", "p"), True),
        _vector(base, "context.threshold:boolean", "threshold must be an exact integer",
                ("context", "threshold"), True),
        _vector(base, "context.threshold:zero", "threshold is at least one",
                ("context", "threshold"), 0),
        _vector(base, "context.threshold:too-large", "threshold is at most roster size",
                ("context", "threshold"), len(ctx["roster"]) + 1),
        _vector(base, "context.coefficient-tags:null", "coefficient tags must be a list",
                ("context", "coefficient_tags"), None),
        _vector(base, "context.coefficient-tags:boolean", "tags must be exact subgroup integers",
                ("context", "coefficient_tags"), [True] * ctx["threshold"]),
        _vector(base, "context.coefficient-tags:wrong-length", "tag count equals threshold",
                ("context", "coefficient_tags"), ctx["coefficient_tags"][:-1]),
        _vector(base, "context.accept-by:boolean", "timing bounds must be exact integers",
                ("context", "accept_by"), True),
        _vector(base, "context.deadline:before-accept", "deadline cannot precede acceptance",
                ("context", "deadline"), ctx["accept_by"] - 1),
        _vector(base, "context.read-bound:negative", "delay bounds are nonnegative",
                ("context", "read_bound"), -1),
        _vector(base, "context.compute-bound:boolean", "delay bounds must be exact integers",
                ("context", "compute_bound"), True),
        _vector(base, "context.delivery-bound:too-large", "deadline must cover all declared delay bounds",
                ("context", "delivery_bound"), ctx["deadline"] + 1),
        _vector(base, "context.service:unknown", "service label must be declared",
                ("context", "service"), "best_effort"),
        _add_key(base, "context.unexpected-key", "context has an exact key set",
                 ("context",), "unexpected", True),
    ])
    return vectors


def _schnorr_vectors(base: dict[str, Any]) -> list[Vector]:
    context = base["context"]
    seed = context["seed_context"]
    vectors: list[Vector] = []
    for label, value in (
        ("null", None), ("bool", True), ("integer", 0), ("float", 1.5),
        ("string", "x"), ("list", []), ("bytes", b"x"), ("tuple", (1,)),
    ):
        vectors.append(_vector(base, f"top.context:{label}", "context must be an exact object",
                               ("context",), value))
    vectors.extend([
        _vector(base, "top.auth-public:boolean", "outer authentication key must equal the registered key",
                ("auth_public",), True),
        _vector(base, "top.auth-public:mismatch", "outer authentication key must equal the registered key",
                ("auth_public",), 1),
        _vector(base, "top.service:boolean", "service label must be a string enum",
                ("service",), True),
        _vector(base, "top.service:unknown", "service label must be declared",
                ("service",), "best_effort"),
        _vector(base, "context.seed:null", "seed context must be an exact object",
                ("context", "seed_context"), None),
        _vector(base, "context.seed.roster:boolean-member", "seed roster members must be exact integers",
                ("context", "seed_context", "roster"), [True, 2, 3, 4, 5]),
        _vector(base, "context.seed.roster:duplicate", "seed roster is the canonical ordered roster",
                ("context", "seed_context", "roster"), [1, 2, 2, 4, 5]),
        _vector(base, "context.seed.roster:noncanonical", "seed roster is exactly 1..n",
                ("context", "seed_context", "roster"), [2, 3, 4, 5, 6]),
        _vector(base, "context.seed.round:boolean", "round must be an exact integer",
                ("context", "seed_context", "round"), True),
        _vector(base, "context.seed.round:zero", "round lies in 1..8",
                ("context", "seed_context", "round"), 0),
        _vector(base, "context.seed.ceremony:empty", "ceremony domain is nonempty",
                ("context", "seed_context", "ceremony"), ""),
        _vector(base, "context.seed.message:surrogate", "seed strings must be canonical JSON",
                ("context", "seed_context", "message"), "\ud800"),
        _vector(base, "context.verification-shares:null", "registered share table must be a list",
                ("context", "verification_shares"), None),
        _vector(base, "context.verification-shares:short", "share table length equals roster length",
                ("context", "verification_shares"), context["verification_shares"][:-1]),
        _vector(base, "context.verification-shares:boolean", "registered shares are exact subgroup integers",
                ("context", "verification_shares"), [True] + context["verification_shares"][1:]),
        _vector(base, "context.nonce-tags:null", "nonce-tag vector must be a list",
                ("context", "nonce_tags"), None),
        _vector(base, "context.nonce-tags:short", "nonce-tag vector length equals roster length",
                ("context", "nonce_tags"), context["nonce_tags"][:-1]),
        _vector(base, "context.nonce-tags:boolean", "nonce tags are exact subgroup integers",
                ("context", "nonce_tags"), [True] + context["nonce_tags"][1:]),
        _vector(base, "context.sender:boolean", "sender must be an exact roster integer",
                ("context", "sender"), True),
        _vector(base, "context.sender:outside", "sender must be in the seed roster",
                ("context", "sender"), len(seed["roster"]) + 1),
        _vector(base, "context.auth-public:boolean", "registered authentication key is an exact subgroup element",
                ("context", "auth_public"), True),
        _vector(base, "context.auth-public:identity", "registered authentication key is a valid subgroup encoding",
                ("context", "auth_public"), 1),
        _add_key(base, "context.unexpected-key", "context has an exact key set",
                 ("context",), "unexpected", True),
        _add_key(base, "context.seed.unexpected-key", "seed context has an exact key set",
                 ("context", "seed_context"), "unexpected", True),
    ])
    return vectors


def _exercise(
    model: str,
    vectors: list[Vector],
    certificate: dict[str, Any],
    verify: Callable[[dict[str, Any], dict[str, Any]], bool],
    replay: Callable[[dict[str, Any], dict[str, Any]], bool],
    extract: Callable[[dict[str, Any]], list[dict[str, Any]]],
) -> tuple[int, list[dict[str, Any]]]:
    calls = 0
    failures: list[dict[str, Any]] = []
    for label, rule, env in vectors:
        for api, fn, args, expected in (
            ("verify", verify, (env, certificate), False),
            ("replay", replay, (env, certificate), False),
            ("extract", extract, (env,), []),
        ):
            calls += 1
            try:
                observed = fn(*args)
            except Exception as exc:  # record parser crashes instead of masking them
                failures.append({
                    "model": model, "vector": label, "schema_rule": rule,
                    "api": api, "failure": "exception",
                    "exception_type": type(exc).__name__, "message": str(exc),
                })
                continue
            if observed != expected:
                failures.append({
                    "model": model, "vector": label, "schema_rule": rule,
                    "api": api, "failure": "did_not_fail_closed", "observed": observed,
                })
    return calls, failures


def _exercise_schnorr(vectors: list[Vector]) -> tuple[int, list[dict[str, Any]]]:
    calls = 0
    failures: list[dict[str, Any]] = []
    for label, rule, case in vectors:
        kwargs = {k: case.get(k) for k in (
            "context", "envelope", "auth_public", "service", "accepted_duty",
            "ready_on_time", "complete_closure", "envelope_present",
        )}
        for api, fn in (("verdict", schnorr_verdict), ("replay", schnorr_replay)):
            calls += 1
            try:
                observed = fn(**kwargs) if api == "verdict" else fn(case)
            except Exception as exc:
                failures.append({
                    "model": "schnorr-specialization", "vector": label, "schema_rule": rule,
                    "api": api, "failure": "exception",
                    "exception_type": type(exc).__name__, "message": str(exc),
                })
                continue
            if observed != "none":
                failures.append({
                    "model": "schnorr-specialization", "vector": label, "schema_rule": rule,
                    "api": api, "failure": "did_not_fail_closed", "observed": observed,
                })
    return calls, failures


def run_setup_boundary_audit() -> dict[str, Any]:
    compiler_env = compiler_fixture(5, 2, 3, "missing_bounded")["public"]
    compiler_cert = compiler_extract(compiler_env)[0]
    compiler_vectors = _compiler_vectors(compiler_env)
    compiler_calls, compiler_failures = _exercise(
        "compiler", compiler_vectors, compiler_cert,
        compiler_verify, compiler_replay, compiler_extract,
    )

    base_env = base_fixture(2, "nonopening")
    base_cert = base_extract(base_env)[0]
    base_vectors = _base_vectors(base_env)
    base_calls, base_failures = _exercise(
        "ideal-receipt", base_vectors, base_cert,
        base_verify, base_replay, base_extract,
    )

    schnorr_env = schnorr_case(5, 2, 3, "missing_bounded")
    schnorr_vectors = _schnorr_vectors(schnorr_env)
    schnorr_calls, schnorr_failures = _exercise_schnorr(schnorr_vectors)

    failures = compiler_failures + base_failures + schnorr_failures
    exceptions = sum(1 for item in failures if item["failure"] == "exception")
    unsafe_results = len(failures) - exceptions
    manifest = [
        {"model": model, "vector": label, "schema_rule": rule}
        for model, vectors in (
            ("compiler", compiler_vectors),
            ("ideal-receipt", base_vectors),
            ("schnorr-specialization", schnorr_vectors),
        )
        for label, rule, _ in vectors
    ]
    return {
        "model": "independently annotated parser-boundary vectors for damaged trusted-context encodings; no producer validator prefilter; not a cryptographic security experiment",
        "selection_method": "each negative vector is constructed from an explicit schema rule before invoking any public API",
        "compiler_mutations": len(compiler_vectors),
        "ideal_receipt_mutations": len(base_vectors),
        "schnorr_mutations": len(schnorr_vectors),
        "public_api_calls": compiler_calls + base_calls + schnorr_calls,
        "manifest": manifest,
        "exceptions": exceptions,
        "unsafe_results": unsafe_results,
        "counted_elementary_obligations": compiler_calls + base_calls + schnorr_calls,
        "failures": failures,
    }
