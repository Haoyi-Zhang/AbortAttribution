"""Finite setup/continuation conformance checks, not a cryptographic simulator.

All signatures here use the existing deliberately small Schnorr fixture.  The
state checks test matching keys, not secure key generation or unforgeability.
The dependency manifest checks explicit annotations, not arbitrary Python code.
Exact salt distributions falsify stale replay; they do not test IND-CPA security.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import json
from types import MappingProxyType
from typing import Any

from schnorr_bridge import GROUP_G, GROUP_P, GROUP_Q, canonical, schnorr_sign, schnorr_verify


@dataclass(frozen=True)
class AuthState:
    """Retained fixture state. No encryption secret keys or ceremony scalars."""
    registration: str
    secrets: Mapping[str, int]

    def __post_init__(self) -> None:
        if type(self.registration) is not str or not self.registration:
            raise ValueError("registration identifier must be a nonempty string")
        if not isinstance(self.secrets, Mapping) or not self.secrets:
            raise ValueError("retained state must contain at least one signing key")
        snapshot: dict[str, int] = {}
        for actor, secret in self.secrets.items():
            if type(actor) is not str or not actor or type(secret) is not int:
                raise ValueError("signing credentials require exact string/integer types")
            if not 0 < secret < GROUP_Q:
                raise ValueError("fixture signing secret must be canonical and nonzero")
            snapshot[actor] = secret
        object.__setattr__(self, "secrets", MappingProxyType(snapshot))


def fixture_setup() -> tuple[dict[str, Any], AuthState, AuthState]:
    """Fixed owned toy credentials: one registration, two separate private states."""
    identifier = "fixed-authentication-setup"
    honest = AuthState(identifier, {"honest": 17})
    corrupt = AuthState(identifier, {"corrupt": 29})
    public = {
        "registration": identifier,
        "auth_registry": {
            actor: pow(GROUP_G, secret, GROUP_P)
            for state in (honest, corrupt) for actor, secret in state.secrets.items()
        },
    }
    return public, honest, corrupt


def _validate_public(public: Any) -> None:
    if type(public) is not dict or set(public) != {"registration", "auth_registry"}:
        raise ValueError("malformed public setup")
    if type(public["registration"]) is not str or not public["registration"]:
        raise ValueError("malformed registration name")
    registry = public["auth_registry"]
    if type(registry) is not dict or not registry:
        raise ValueError("malformed authentication registry")
    for actor, key in registry.items():
        if type(actor) is not str or not actor or type(key) is not int:
            raise ValueError("authentication registry has inexact field types")
        if not 1 < key < GROUP_P or pow(key, GROUP_Q, GROUP_P) != 1:
            raise ValueError("authentication key is not a nonidentity subgroup member")


def require_matching_state(public: Any, state: Any, actor: str) -> AuthState:
    """Refuse missing/mismatched state; never manufacture a new signing pair."""
    _validate_public(public)
    if type(state) is not AuthState or state.registration != public["registration"]:
        raise ValueError("matching retained setup state is required")
    if type(actor) is not str or actor not in state.secrets:
        raise ValueError("requested signing credential is not in retained state")
    for name, secret in state.secrets.items():
        if public["auth_registry"].get(name) != pow(GROUP_G, secret, GROUP_P):
            raise ValueError("retained signing key does not match the registered public key")
    return state


def sign_record(public: dict[str, Any], state: AuthState, actor: str,
                payload: dict[str, Any]) -> dict[str, Any]:
    matched = require_matching_state(public, state, actor)
    # Round-trip creates a detached canonical body; no reference to caller mutables.
    canonical(payload)
    body = {"registration": public["registration"], "actor": actor,
            "payload": json.loads(canonical(payload))}
    return {"body": body, "signature": schnorr_sign(body, matched.secrets[actor])}


def verify_record(public: Any, record: Any) -> bool:
    """Boolean public toy validator; malformed values fail closed."""
    try:
        _validate_public(public)
        if type(record) is not dict or set(record) != {"body", "signature"}:
            return False
        body = record["body"]
        if type(body) is not dict or set(body) != {"registration", "actor", "payload"}:
            return False
        if body["registration"] != public["registration"] or type(body["actor"]) is not str:
            return False
        canonical(body)
        return schnorr_verify(body, public["auth_registry"].get(body["actor"]), record["signature"]) is True
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


PublicResponder = Callable[[bytes], dict[str, Any]]


def render_prefixes(public: dict[str, Any], state: AuthState,
                    ciphertexts: Sequence[bytes], responder: PublicResponder) -> list[dict[str, Any]]:
    """Render frozen envelopes and regenerate responses from each *actual* prefix.

    Ciphertexts are supplied fixture bytes, not produced by a crypto simulator.
    Only immutable serialized prefixes go to the callback. The callback cannot
    alter the frozen ciphertext vector. It has no semantic/decryption oracle.
    """
    require_matching_state(public, state, "honest")
    if type(ciphertexts) not in (tuple, list) or len(ciphertexts) > 16:
        raise ValueError("finite rendering requires at most 16 frozen ciphertexts")
    if any(type(value) is not bytes or len(value) > 1024 for value in ciphertexts):
        raise ValueError("ciphertexts must be bounded immutable bytes")
    frozen = tuple(ciphertexts)
    public = json.loads(canonical(public))  # Freeze registration against callback-side aliasing.
    output: list[dict[str, Any]] = []
    for index, ciphertext in enumerate(frozen):
        output.append(sign_record(public, state, "honest", {
            "kind": "envelope", "slot": index, "ciphertext": ciphertext.hex(),
        }))
        response = responder(canonical(output))
        if type(response) is not dict:
            raise ValueError("public response must be a canonical object")
        # Parser failure is not a hidden semantic branch: append bytes as supplied.
        output.append(json.loads(canonical(response)))
    return output


def hash_responder(public: dict[str, Any], corrupt: AuthState) -> PublicResponder:
    """A fixture corrupt party signs an echo and hash of the observed prefix."""
    seen = 0

    def respond(prefix: bytes) -> dict[str, Any]:
        nonlocal seen
        if type(prefix) is not bytes:
            raise ValueError("prefix must be immutable serialized bytes")
        records = json.loads(prefix)
        last = records[-1]["body"]["payload"]
        seen += 1
        return sign_record(public, corrupt, "corrupt", {
            "kind": "causal_response", "call": seen,
            "echo": last["ciphertext"],
            "prefix_digest": hashlib.sha256(prefix).hexdigest(),
        })
    return respond


def check_causal_links(public: dict[str, Any], records: Sequence[dict[str, Any]]) -> bool:
    """Check actual-prefix consistency as well as each retained-key signature."""
    try:
        if type(records) not in (list, tuple) or len(records) % 2:
            return False
        for index in range(0, len(records), 2):
            env, response = records[index:index+2]
            if not verify_record(public, env) or not verify_record(public, response):
                return False
            ep = env["body"]["payload"]
            payload = response["body"]["payload"]
            if type(ep) is not dict or type(payload) is not dict:
                return False
            if env["body"]["actor"] != "honest" or response["body"]["actor"] != "corrupt":
                return False
            if set(ep) != {"kind", "slot", "ciphertext"} or ep["kind"] != "envelope":
                return False
            if type(ep["slot"]) is not int or ep["slot"] != index // 2:
                return False
            if set(payload) != {"kind", "call", "echo", "prefix_digest"}:
                return False
            if payload["kind"] != "causal_response" or type(ep["ciphertext"]) is not str:
                return False
            if type(payload["echo"]) is not str or payload["echo"] != ep["ciphertext"]:
                return False
            if type(payload["call"]) is not int or payload["call"] != index // 2 + 1:
                return False
            if type(payload["prefix_digest"]) is not str:
                return False
            if payload["prefix_digest"] != hashlib.sha256(canonical(list(records[:index+1]))).hexdigest():
                return False
        return True
    except (ValueError, TypeError, KeyError, IndexError):
        return False


_ALLOWED_ROOTS = frozenset({"public_setup", "base_semantics", "precompilation_auxiliary",
                           "wrapper_bytes", "wrapper_coins", "honest_decryption_state"})
_FORBIDDEN_SEMANTIC = frozenset({"wrapper_bytes", "wrapper_coins", "honest_decryption_state"})


def check_dependency_manifest(nodes: Sequence[dict[str, Any]]) -> dict[str, list[str]]:
    """Validate an explicitly supplied DAG, not inferred program noninterference.

    Every semantic/leakage node must be independent of compiler bytes/coins and
    honest-decryption state. Public responses may depend on wrapper bytes but
    may not access honest-decryption state. Forward references fail closed.
    """
    if type(nodes) not in (list, tuple) or len(nodes) > 128:
        raise ValueError("dependency manifest must be a bounded sequence")
    taints: dict[str, set[str]] = {}
    for node in nodes:
        if type(node) is not dict or set(node) != {"name", "role", "parents", "origin"}:
            raise ValueError("malformed dependency node")
        name, role, parents, origin = (node[k] for k in ("name", "role", "parents", "origin"))
        if type(name) is not str or not name or name in taints:
            raise ValueError("dependency nodes need unique nonempty string names")
        if type(parents) not in (list, tuple) or any(type(x) is not str for x in parents):
            raise ValueError("parents must be exact string references")
        if len(set(parents)) != len(parents) or any(x not in taints for x in parents):
            raise ValueError("duplicate, unknown, cyclic or forward parent reference")
        if role == "source":
            if type(origin) is not str or origin not in _ALLOWED_ROOTS or parents:
                raise ValueError("invalid source origin")
            inherited = {origin}
        elif role in ("semantic", "leakage", "public_response", "derived"):
            if origin is not None:
                raise ValueError("derived nodes cannot overwrite provenance")
            inherited = set().union(*(taints[x] for x in parents)) if parents else set()
            if role in ("semantic", "leakage") and inherited & _FORBIDDEN_SEMANTIC:
                raise ValueError("wrapper-dependent semantic/leakage value is outside the theorem")
            if role == "public_response" and "honest_decryption_state" in inherited:
                raise ValueError("public renderer has no honest-decryption oracle")
        else:
            raise ValueError("unknown dependency role")
        taints[name] = inherited
    return {name: sorted(origins) for name, origins in taints.items()}


def salt_distributions(size: int) -> dict[str, Any]:
    """Exhaustive finite marginals: resample ciphertext salt, then replay or rerun."""
    if type(size) is not int or not 2 <= size <= 32:
        raise ValueError("salt alphabet must have between 2 and 32 values")
    real = {(salt, salt): Fraction(1, size) for salt in range(size)}
    stale = {(new, old): Fraction(1, size * size) for new in range(size) for old in range(size)}
    regenerated = {(salt, salt): Fraction(1, size) for salt in range(size)}
    tv = lambda a, b: sum((abs(a.get(k, Fraction()) - b.get(k, Fraction()))
                          for k in a.keys() | b.keys()), Fraction()) / 2
    def marginal(distribution: dict[tuple[int, int], Fraction]) -> dict[int, Fraction]:
        result: dict[int, Fraction] = {}
        for (ciphertext, _), mass in distribution.items():
            result[ciphertext] = result.get(ciphertext, Fraction()) + mass
        return result
    return {"alphabet": size, "real_equal_probability": "1",
            "stale_equal_probability": str(Fraction(1, size)),
            "public_salt_marginal_tv": str(tv(marginal(real), marginal(stale))),
            "stale_joint_tv": str(tv(real, stale)),
            "regenerated_joint_tv": str(tv(real, regenerated)),
            "real_support": len(real), "stale_support": len(stale)}


def run_composition_audit() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    def check(name: str, expected: Any, observed: Any) -> None:
        row = {"name": name, "expected": expected, "observed": observed}
        checks.append(row)
        if expected != observed:
            failures.append(row)
    def refuse(name: str, callback: Callable[[], Any]) -> None:
        try:
            callback()
        except (ValueError, TypeError):
            check(name, "refused", "refused")
        except Exception as exc:
            check(name, "refused", type(exc).__name__)
        else:
            check(name, "refused", "accepted")

    public, honest, corrupt = fixture_setup()
    initial_public = canonical(public)
    for i, payload in enumerate(({"ciphertext": "00"}, {"ciphertext": "01"}, {"ciphertext": "ffff"})):
        check(f"retained-key-signs-current-body-{i}", True,
              verify_record(public, sign_record(public, honest, "honest", payload)))
    refuse("public-keys-alone-have-no-signing-state", lambda: sign_record(public, None, "honest", {}))
    refuse("new-key-for-old-registration", lambda: sign_record(
        public, AuthState(honest.registration, {"honest": 18}), "honest", {}))
    refuse("wrong-registration-state", lambda: sign_record(
        public, AuthState("other-registration", {"honest": 17}), "honest", {}))
    refuse("corrupt-key-does-not-sign-for-honest", lambda: sign_record(public, corrupt, "honest", {}))
    for i, secret in enumerate((True, False, 0, GROUP_Q, 17.0, None)):
        refuse(f"inexact-or-invalid-signing-state-{i}", lambda x=secret: AuthState(honest.registration, {"honest": x}))
    key_source = {"honest": 17}
    immutable = AuthState(honest.registration, key_source)
    key_source["honest"] = 18
    check("retained-state-is-detached-from-caller", 17, immutable.secrets["honest"])
    check("registration-not-mutated-by-signing", initial_public.hex(), canonical(public).hex())

    real = render_prefixes(public, honest, [b"real-1", b"real-2"], hash_responder(public, corrupt))
    fresh = render_prefixes(public, honest, [b"new--1", b"new--2"], hash_responder(public, corrupt))
    stale = [fresh[0], real[1], fresh[2], real[3]]
    check("real-causal-chain-valid", True, check_causal_links(public, real))
    check("new-prefix-causal-chain-valid", True, check_causal_links(public, fresh))
    check("replayed-corrupt-signatures-still-valid", True, all(verify_record(public, x) for x in stale))
    check("replayed-corrupt-records-break-correlation", False, check_causal_links(public, stale))
    check("dependent-corrupt-records-actually-change", True, real[1] != fresh[1] and real[3] != fresh[3])
    check("public-keys-stable-through-both-renderings", initial_public.hex(), canonical(public).hex())
    altered = json.loads(canonical(real[:2]))
    altered[1]["body"]["payload"]["call"] = True
    altered[1] = sign_record(public, corrupt, "corrupt", altered[1]["body"]["payload"])
    check("signed-boolean-counter-is-not-an-integer", False, check_causal_links(public, altered))
    wrong_actor = [real[0], sign_record(public, honest, "honest", real[1]["body"]["payload"])]
    check("valid-signature-under-wrong-role-is-refused", False, check_causal_links(public, wrong_actor))
    wrong_kind = json.loads(canonical(real[:2]))
    wrong_kind[1]["body"]["payload"]["kind"] = "other"
    wrong_kind[1] = sign_record(public, corrupt, "corrupt", wrong_kind[1]["body"]["payload"])
    check("signed-wrong-record-kind-is-refused", False, check_causal_links(public, wrong_kind))
    refuse("mutable-ciphertext-fixture-refused", lambda: render_prefixes(
        public, honest, [bytearray(b"x")], hash_responder(public, corrupt)))

    nodes = [
        {"name": "P", "role": "source", "parents": [], "origin": "public_setup"},
        {"name": "base", "role": "source", "parents": [], "origin": "base_semantics"},
        {"name": "ciphertext", "role": "source", "parents": [], "origin": "wrapper_bytes"},
        {"name": "coins", "role": "source", "parents": [], "origin": "wrapper_coins"},
        {"name": "decryption", "role": "source", "parents": [], "origin": "honest_decryption_state"},
        {"name": "alpha", "role": "source", "parents": [], "origin": "precompilation_auxiliary"},
        {"name": "schedule", "role": "semantic", "parents": ["P", "base"], "origin": None},
        {"name": "response", "role": "public_response", "parents": ["ciphertext", "alpha"], "origin": None},
        {"name": "L", "role": "leakage", "parents": ["base", "alpha"], "origin": None},
    ]
    parsed = check_dependency_manifest(nodes)
    check("causal-public-copy-is-admissible", ["precompilation_auxiliary", "wrapper_bytes"], parsed["response"])
    for parent in ("ciphertext", "coins", "decryption", "response"):
        for role in ("semantic", "leakage"):
            refuse(f"no-{role}-feedback-from-{parent}", lambda p=parent, r=role:
                   check_dependency_manifest(nodes + [{"name": "bad", "role": r, "parents": [p], "origin": None}]))
    refuse("public-response-cannot-use-decryption", lambda: check_dependency_manifest(nodes + [
        {"name": "bad", "role": "public_response", "parents": ["decryption"], "origin": None}]))
    refuse("forward-or-cycle-reference", lambda: check_dependency_manifest([
        {"name": "self", "role": "semantic", "parents": ["self"], "origin": None}]))
    refuse("duplicate-node-name", lambda: check_dependency_manifest(nodes + [nodes[0]]))
    refuse("unregistered-root-provenance", lambda: check_dependency_manifest([
        {"name": "unknown", "role": "source", "parents": [], "origin": "old_corrupt_records"}]))
    refuse("provenance-laundering", lambda: check_dependency_manifest(nodes + [
        {"name": "bad", "role": "leakage", "parents": ["ciphertext"], "origin": "base_semantics"}]))

    distributions = []
    for size in (2, 4, 8, 16):
        row = salt_distributions(size)
        distributions.append(row)
        check(f"identical-public-salt-marginal-{size}", "0", row["public_salt_marginal_tv"])
        check(f"stale-replay-joint-distance-{size}", str(Fraction(size - 1, size)), row["stale_joint_tv"])
        check(f"rerun-preserves-joint-distribution-{size}", "0", row["regenerated_joint_tv"])
    return {
        "model": "finite retained-authentication and non-feedback causal-renderer contracts",
        "scope": "not a cryptographic simulator, privacy experiment, or implementation of a production proof system",
        "checks": checks, "failures": failures,
        "counted_elementary_obligations": len(checks),
        "salt_distributions": distributions,
        "signed_response_examples": {"real": real, "regenerated": fresh, "stale_replay": stale},
        "dependency_manifest": nodes,
        "private_state_exported": False,
        "attribution_predicates_changed": False,
    }
