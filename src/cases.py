"""Deterministic benign fixtures, with explicit non-public history annotations."""
from __future__ import annotations
from copy import deepcopy
from typing import Any
from checker import commitment

P, Q, G = 23, 11, 2
COEFFICIENTS = (7, 4, 2)


def scalar_share(actor: int) -> int:
    # Independent of the public coefficient-product verifier.
    value = 0
    for coefficient in reversed(COEFFICIENTS):
        value = (value * actor + coefficient) % Q
    return value


def fixture(actor: int | None = None, fault: str = "none", delay: int = 0,
            service: str = "bounded_delivery", context_id: str = "ceremony") -> dict[str, Any]:
    ctx = {"id": context_id, "roster": [1, 2, 3, 4, 5],
           "group": {"p": P, "q": Q, "g": G}, "threshold": 3,
           "coefficient_tags": [pow(G, a, P) for a in COEFFICIENTS],
           "service": service, "accept_by": 5, "deadline": 20,
           "compute_bound": 2, "delivery_bound": 3, "read_bound": 3}
    recs: dict[str, Any] = {}
    ready_time = 13 if fault == "late_ready" else 12
    recs["ready"] = {"context": context_id, "actor": 0, "kind": "ready",
                     "time": ready_time, "body": {"round": "open"}}
    for who in ctx["roster"]:
        value = pow(G, scalar_share(who), P)
        nonce = "fixture-nonce-" + str(who)
        selected = who == actor
        if fault == "precommit_absence" and selected:
            continue
        committed_tag = value * G % P if fault == "tag_mismatch" and selected else value
        recs[f"accept-{who}"] = {
            "context": context_id, "actor": who, "kind": "accept", "time": 2,
            "body": {"commitment": commitment(context_id, who, committed_tag, nonce),
                     "deadline": 20, "round": "open"}}
        if selected and fault == "nonopening":
            continue
        body: Any = {"tag": committed_tag, "nonce": nonce}
        if selected:
            if fault == "bad_shape":
                body = {"unrecognized": value}
            elif fault == "bad_zero":
                body["tag"] = 0
            elif fault == "bad_noninteger":
                body["tag"] = True  # Python bool must not be mistaken for a scalar.
            elif fault == "commitment_mismatch":
                body["nonce"] = nonce + "-wrong"
        arrival = 17 + (delay if selected else 0)
        if fault == "late_ready":
            arrival = 21 if selected else 18
        recs[f"open-{who}"] = {"context": context_id, "actor": who, "kind": "open",
                              "time": arrival, "body": body}
    if fault == "foreign_context" and actor is not None:
        recs["foreign-open"] = {"context": "different-ceremony", "actor": actor,
                                "kind": "open", "time": 18, "body": {"tag": 0, "nonce": "x"}}
    closures = {}
    for name, cutoff in [("early", 19), ("final", 20)]:
        closures[name] = {"context": context_id, "cutoff": cutoff,
                          "records": sorted(k for k, r in recs.items()
                                            if r["context"] == context_id and r["time"] <= cutoff)}
    closures["foreign"] = {"context": "different-ceremony", "cutoff": 20,
                           "records": ["foreign-open"] if "foreign-open" in recs else []}
    return {"context": ctx, "receipts": recs, "closures": closures}


def generate() -> list[dict[str, Any]]:
    cases = []
    def add(family: str, env: dict[str, Any], expected: list[list[Any]],
            history: dict[str, Any], pair: str | None = None) -> None:
        cases.append({"case": f"case-{len(cases)+1:03d}", "family": family,
                      "public": env, "expected": expected,
                      "private_history_annotation": history, "pair": pair})
    for d in range(4):
        env = fixture()
        for r in env["receipts"].values():
            if r["kind"] == "open":
                r["time"] = 17 + d
        for s in env["closures"].values():
            s["records"] = sorted(k for k, r in env["receipts"].items()
                                  if r["context"] == s["context"] and r["time"] <= s["cutoff"])
        add("all_honest", env, [], {"all_honest": True, "delay": d})
    for who in range(1, 6):
        for f in ("bad_shape", "bad_zero", "bad_noninteger"):
            add("malformed_opening", fixture(who, f), [[who, "bad_opening"]],
                {"corrupt": [who], "fault": f})
        for f in ("tag_mismatch", "commitment_mismatch"):
            add(f, fixture(who, f), [[who, "bad_opening"]], {"corrupt": [who], "fault": f})
        add("nonopening_reliable", fixture(who, "nonopening"), [[who, "nonopening"]],
            {"corrupt": [who], "opening_submitted": False})
        for stage, fault in (("after_accept", "nonopening"), ("before_accept", "precommit_absence")):
            env = fixture(who, fault, service="censorable")
            pair = f"{stage}-{who}"
            add("censorable_" + stage, deepcopy(env), [],
                {"corrupt": [who], "actor": who, "submitted": False}, pair)
            add("censorable_" + stage, deepcopy(env), [],
                {"corrupt": [], "actor": who, "submitted": True, "delivery": "suppressed"}, pair)
        add("late_prerequisite", fixture(who, "late_ready"), [],
            {"corrupt": [], "ready": 13, "send": 18, "delivery": 21})
        for d in range(4):
            add("honest_delay", fixture(who, "none", d), [],
                {"corrupt": [], "actor": who, "send": 17, "delivery": 17+d})
        add("foreign_context", fixture(who, "foreign_context"), [],
            {"corrupt": [], "active_context_honest": True})
    return cases
