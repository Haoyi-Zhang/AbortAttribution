"""Deterministic fail-closed audit for damaged trusted-context encodings.

The paper's theorems treat the public context and board registry as setup
inputs.  This audit is an implementation-hardening check, not a change to that
model: each public verification/replay/extraction API must reject or return an
empty result, never crash or create attribution, when its serialized setup is
malformed.
"""
from __future__ import annotations
from copy import deepcopy
from typing import Any, Callable

from cases import fixture as base_fixture
from checker import extract as base_extract, valid_environment as base_environment_valid, verify as base_verify
from replay import replay as base_replay
from compiler_cases import fixture as compiler_fixture
from compiler_checker import (extract as compiler_extract, valid_environment as compiler_environment_valid,
                              verify as compiler_verify)
from compiler_replay import replay as compiler_replay
from schnorr_bridge import make_case as schnorr_case, valid_context as schnorr_context_valid, verdict as schnorr_verdict
from schnorr_replay import replay as schnorr_replay


_BAD_VALUES: tuple[tuple[str, Any], ...] = (
    ("null", None),
    ("true", True),
    ("false", False),
    ("zero", 0),
    ("float", 1.5),
    ("string", "x"),
    ("empty-list", []),
    ("list", [1]),
    ("empty-object", {}),
    ("object", {"x": 1}),
    ("bytes", b"x"),
    ("tuple", (1,)),
)


def _set_path(obj: dict[str, Any], path: tuple[str, ...], value: Any) -> dict[str, Any]:
    altered = deepcopy(obj)
    target: Any = altered
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return altered


def _mutations(
    base: dict[str, Any], registry: str, validator: Callable[[Any], bool]
) -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for field in base["context"]:
        for label, value in _BAD_VALUES:
            out.append((f"context.{field}:{label}", _set_path(base, ("context", field), value)))
    for field in ("context", registry, "closures"):
        for label, value in _BAD_VALUES:
            out.append((f"top.{field}:{label}", _set_path(base, (field,), value)))
    for table in (registry, "closures"):
        for label, value in _BAD_VALUES:
            altered = deepcopy(base)
            altered[table]["broken"] = value
            out.append((f"{table}.value:{label}", altered))
    # Some universal mutations remain well-formed alternative setups (for
    # example a zero delay bound or an empty registry).  This audit is only
    # about malformed serialized setup, so retain exactly the candidates that
    # the producer-side parser rejects; the independently restated replay
    # parser must then reject the same set.
    return [(label, env) for label, env in out if not validator(env)]


def _exercise(
    model: str,
    mutations: list[tuple[str, dict[str, Any]]],
    certificate: dict[str, Any],
    verify: Callable[[dict[str, Any], dict[str, Any]], bool],
    replay: Callable[[dict[str, Any], dict[str, Any]], bool],
    extract: Callable[[dict[str, Any]], list[dict[str, Any]]],
) -> tuple[int, list[dict[str, Any]]]:
    calls = 0
    failures: list[dict[str, Any]] = []
    for mutation, env in mutations:
        for api, fn, args, expected in (
            ("verify", verify, (env, certificate), False),
            ("replay", replay, (env, certificate), False),
            ("extract", extract, (env,), []),
        ):
            calls += 1
            try:
                observed = fn(*args)
            except Exception as exc:  # audit records the crash rather than hiding it
                failures.append({
                    "model": model,
                    "mutation": mutation,
                    "api": api,
                    "failure": "exception",
                    "exception_type": type(exc).__name__,
                    "message": str(exc),
                })
                continue
            if observed != expected:
                failures.append({
                    "model": model,
                    "mutation": mutation,
                    "api": api,
                    "failure": "did_not_fail_closed",
                    "observed": observed,
                })
    return calls, failures


def _schnorr_setup_mutations(base: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for field in base["context"]:
        for label, value in _BAD_VALUES:
            altered = deepcopy(base)
            altered["context"][field] = value
            if not schnorr_context_valid(altered["context"]):
                out.append((f"context.{field}:{label}", altered))
    for label, value in _BAD_VALUES:
        altered = deepcopy(base); altered["context"] = value
        out.append((f"top.context:{label}", altered))
        altered = deepcopy(base); altered["auth_public"] = value
        if value != base["context"]["auth_public"]:
            out.append((f"top.auth_public:{label}", altered))
        altered = deepcopy(base); altered["service"] = value
        out.append((f"top.service:{label}", altered))
    return out


def _exercise_schnorr(
    mutations: list[tuple[str, dict[str, Any]]]
) -> tuple[int, list[dict[str, Any]]]:
    calls = 0
    failures: list[dict[str, Any]] = []
    for mutation, case in mutations:
        kwargs = {k: case.get(k) for k in (
            "context", "envelope", "auth_public", "service", "accepted_duty",
            "ready_on_time", "complete_closure", "envelope_present"
        )}
        for api, fn, args in (
            ("verdict", schnorr_verdict, kwargs),
            ("replay", schnorr_replay, case),
        ):
            calls += 1
            try:
                observed = fn(**args) if api == "verdict" else fn(args)
            except Exception as exc:
                failures.append({
                    "model": "schnorr-specialization", "mutation": mutation,
                    "api": api, "failure": "exception",
                    "exception_type": type(exc).__name__, "message": str(exc),
                })
                continue
            if observed != "none":
                failures.append({
                    "model": "schnorr-specialization", "mutation": mutation,
                    "api": api, "failure": "did_not_fail_closed",
                    "observed": observed,
                })
    return calls, failures


def run_setup_boundary_audit() -> dict[str, Any]:
    compiler_env = compiler_fixture(5, 2, 3, "missing_bounded")["public"]
    compiler_cert = compiler_extract(compiler_env)[0]
    compiler_mutations = _mutations(compiler_env, "records", compiler_environment_valid)
    compiler_calls, compiler_failures = _exercise(
        "compiler", compiler_mutations, compiler_cert,
        compiler_verify, compiler_replay, compiler_extract,
    )

    base_env = base_fixture(2, "nonopening")
    base_cert = base_extract(base_env)[0]
    base_mutations = _mutations(base_env, "receipts", base_environment_valid)
    base_calls, base_failures = _exercise(
        "ideal-receipt", base_mutations, base_cert,
        base_verify, base_replay, base_extract,
    )

    schnorr_env = schnorr_case(5, 2, 3, "missing_bounded")
    schnorr_mutations = _schnorr_setup_mutations(schnorr_env)
    schnorr_calls, schnorr_failures = _exercise_schnorr(schnorr_mutations)

    failures = compiler_failures + base_failures + schnorr_failures
    exceptions = sum(1 for item in failures if item["failure"] == "exception")
    unsafe_results = len(failures) - exceptions
    return {
        "model": "parser-boundary hardening for damaged trusted-context encodings; not a cryptographic security experiment",
        "bad_value_classes": [name for name, _ in _BAD_VALUES],
        "compiler_mutations": len(compiler_mutations),
        "ideal_receipt_mutations": len(base_mutations),
        "schnorr_mutations": len(schnorr_mutations),
        "public_api_calls": compiler_calls + base_calls + schnorr_calls,
        "exceptions": exceptions,
        "unsafe_results": unsafe_results,
        "counted_elementary_obligations": compiler_calls + base_calls + schnorr_calls,
        "failures": failures,
    }
