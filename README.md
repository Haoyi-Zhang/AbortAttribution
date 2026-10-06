# Non-frameable abort attribution artifact

This standalone repository reproduces deterministic finite checks for the paper's delivery boundary, tag-bound attribution compiler, and static eVRF-driven Schnorr-response bridge.

The artifact has six layers:

1. an ideal authenticated-receipt model for malformed openings and qualified non-openings;
2. an ideal signature/NIZK state machine for the generic compiler;
3. a concrete toy-arithmetic bridge that checks a common aggregate-nonce Schnorr challenge, immutable registered verification shares, the partial-response equation, Paillier ciphertext-to-exponent equations, authentication, context binding, and qualified omission;
4. canonical-encoding and independently annotated malformed-setup audits that require every public verification, replay, or extraction API to fail closed;
5. a separate leakage-manifest, public-length/dummy, and fixed-width Paillier codec audit, including omitted-length and marginal-only boundaries;
6. retained-authentication and causal-rendering conformance checks with exact stale-replay counterexamples and an independently declared dependency graph.

The arithmetic bridge is deliberately **not** a production eVRF, NIZK, signature, consensus, or network implementation. Its eVRF verification result is an imported ideal bit. Its small group, Paillier modulus, and 251-value challenge space provide exact conformance and falsification checks rather than cryptographic security. The paper theorem instead imports complete and sound real-setup verification for the exact bounded plaintext/tag relation; compiled-view privacy is separately restricted to generated setup with retained matching signing state and a non-feedback semantic trace. It requires lawful same-length dummies, causal regeneration of public responses, a joint base simulator with the retained auxiliary state, and a joint simulated-CRS/proof interface. Static corruption or simulation soundness alone does not imply these conditions.

## Supported execution environment

The retained runner intentionally uses Unix process controls: `signal.SIGALRM`, `resource.setrlimit`, `resource.getrusage`, a POSIX shell, and `mktemp`. The supported path is:

- Linux, including a Linux distribution running under WSL2;
- CPython 3.10 or newer;
- `sh` or `bash` for the documented command sequence.

The retained run was validated on Linux x86_64 with Bash and CPython 3.13.5. Native Windows Python is not supported because it does not expose the required Unix `resource` and alarm interfaces; use WSL2 rather than treating an unbounded native-Windows run as equivalent. macOS has related APIs but is outside the declared supported and measured path. The runner exits with an explicit platform error before starting if the required Linux/Unix interfaces are unavailable.

The paper build additionally requires `pdflatex`, BibTeX, and `pdfinfo`. No network service or shell escape is used.

## Reproduce

From this standalone repository root on Linux or WSL2:

```sh
python3 -m unittest discover -s tests -v
out=$(mktemp -d)
python3 reproduce.py --out "$out"
python3 compare_results.py results/pilot "$out"
python3 audit_references.py --inventory reference_audit.csv
```

Expected high-level result:

- 107 unit tests pass (99 present before these edits plus eight arithmetic-domain/adaptive-policy regressions; the historical run recorded 95);
- the runner exits 0 with `status = finite_checks_passed`;
- all 25 deterministic scientific output files match the retained pilot byte for byte;
- `measurements.json` is process metadata and is intentionally excluded from byte comparison.

`reproduce.py` refuses a nonempty output directory and enforces a 180-second wall/CPU bound, a 3 GiB address-space limit, one worker, and a 300,000-obligation cap through Linux resource interfaces.

## Components

- `src/cases.py`, `src/checker.py`, `src/replay.py`: ideal-board boundary histories and two certificate implementations.
- `src/compiler_cases.py`: 3,328 generic compiler transcript fixtures; the delayed-honest class is received exactly at the inclusive deadline `D = 12`.
- `src/compiler_checker.py`, `src/compiler_replay.py`: independently written judges for malformed content, invalid bound messages, and service-qualified non-opening. Receipt time is not part of `bad_entry`; `D+1` is tested separately.
- `src/schnorr_bridge.py`: pre-nonce seed context, common post-nonce transcript context, sender/key-bound proof context, toy-group common-challenge Schnorr response, Paillier encryption, immutable share-registry lookup, honest equality-equation fixtures, private relation oracle, deterministic false-statement control, authentication, and context binding.
- `src/schnorr_replay.py`: independently restated bridge judge; it does not import the producer.
- `src/linear_oracle.py`: exact timing, linear-disclosure, and tiny-exponent controls.
- `src/schema_audit.py`: canonical-JSON vectors and malformed-input refusal checks.
- `src/setup_boundary_audit.py`: independently annotated malformed-context vectors across all public APIs. It does not use a producer validator to prefilter candidates.
- `src/privacy_lengths.py`: non-vacuous leakage-manifest, exact encoding-length, legal-dummy and joint-view distribution checks; no cryptographic security or new attribution predicate.
- `audit_references.py`, `reference_audit.csv`: bibliography structure, stable-identifier, uniqueness, and citation-closure audit.
- `tests/`: boundary, compiler, arithmetic, registered-share, challenge-binding, replay-independence, parser, bibliography, mutation, and refusal tests.
- `proofs/`: proof maps and explicit non-claims.
- `results/pilot/`: retained deterministic outputs and measured process metadata.
- `claim_evidence_ledger.csv`: claim-to-proof/check mapping.
- `external_resources.csv`: external-source and access notes.

## Current arithmetic-domain checks

The ideal-receipt and generic compiler parsers require prime modulus and prime
subgroup order. Exact trial division is limited to 16-bit parameters; larger
groups are outside these finite APIs, not claimed mathematically invalid.
The existing nonidentity-generator and subgroup equations then establish exact
prime order. Receipt authors require exact integers, not Boolean/float aliases.
The Schnorr context requires a nonidentity registered authentication key; share
and nonce tags may still be the identity when their scalar is zero.

The eight additional unit tests also enumerate public-history-only adaptive
opening policies over F_3 and distinguish hidden-state selection, which is
outside the manuscript's rank corollary. These regression assertions are
separate from the retained pilot totals below. Existing 25-file pilot outputs
and Linux process measurements are preserved; new local timings do not replace
the historical host measurements.

## Retained campaign

Boundary model:

- 84 histories and 30 supported certificates;
- 485 invalid mutations, 410 omission probes, and 925 producer/replay comparisons;
- ten equal-public-view negative-control pairs;
- 1,008 timing histories and exact small linear-disclosure enumeration.

Generic compiler model:

- 3,328 cases in eight equally sized classes;
- 1,248 certificates;
- 15,392 invalid certificate records generated by exactly 19 certificate-field mutation templates;
- 9,984 candidate probes and 26,624 producer/replay comparisons;
- 12 separately recorded focused regressions with 30 explicit checks covering receipt at `D`, correct receipt at `D+1`, censorable `D+1`, late readiness, genuine qualified missing, late malformed content, statement-digest and proof-bit changes, truncated closure content, renamed references with multiple valid candidates, and non-string closure references.

Static Schnorr-response bridge:

- 4,160 Cartesian cases in ten equally sized families;
- 832 `bad_binding`, 1,248 `bad_response`, 416 `qualified_nonopening`, and 1,664 no-attribution outcomes;
- 9,568 invalid-attribution mutations;
- 13,728 producer/replay comparisons;
- 8,320 decryption, subgroup, aggregate-challenge, response, and honest equality-equation checks;
- one frozen registered-share substitution regression: in `n5-s2-r3`, registered `X = 62`, nonce scalar `r = 206`, and nonce tag `R = 285`; a legitimately signed body substitutes `X = 1`, encrypts 206, and proves the true ciphertext/tag equality for `Z = 285`, while the registered equation requires `Z = 402`. Both paths return `bad_response`;
- a false relation (`Enc(17)` versus `g^18`) accepted by both toy-equation verifiers after 617 challenge evaluations, contributing 620 expected negative-control obligations.

Input boundaries:

- 31 canonical-encoding obligations;
- 140 independently annotated malformed trusted-context encodings exercised through 388 public API calls;
- explicit exact-type roster vectors including `[true,2,3,4,5]`;
- zero exceptions and zero unsafe attributions.

The combined retained run counts **214,915** elementary obligations.

Length interface:

- 319 named expected/observed finite assertions, recorded separately in `privacy-lengths.json`;
- an independently declared leakage manifest that rejects transcript-copy and catch-all leakage fields while permitting declared ideal outputs and precompilation inputs, not realized reactive corrupted records;
- public fixed widths versus explicit per-occurrence length leakage;
- valid same-length domain elements, including structured domains where all-zero strings are invalid;
- full framing/padding and byte length rather than character count;
- distinct profiles with equal totals and absent versus empty messages;
- exact length-only and joint-versus-marginal distribution comparisons;
- all 233 toy scalars and public-modulus width boundaries.

The generic privacy theorem additionally requires matching setup-retained authentication state, a non-feedback semantic trace and causal public regeneration. Its base simulation is joint with that auxiliary state and all permitted leakage; arbitrary ciphertext-driven private continuation is not covered. These checks validate the local interface schema; they do not implement or prove those cryptographic simulators. In the fixed-width Paillier specialization, the profile is a public function of N and message occurrences, so this repair adds no secret-dependent leakage. Existing attribution, deadline, registered-share and weak-proof regressions are retained without changed predicates.

## Retained setup and causal-response checks

`src/privacy_composition.py` is a small contract harness, not a cryptographic simulator. It rejects absent or mismatched signing state, preserves one registered public-key table, and signs regenerated bodies using the matching retained toy keys. It reruns a stateful corrupted responder on each current immutable prefix; echoes, prefix hashes and the responder's own signatures are recomputed. Old responses can remain signature-valid while failing correlation checks.

The exact public-salt model has unchanged public-salt marginals but stale-replay joint distance 3/4 for an alphabet of size four; causal regeneration gives zero. A declared DAG refuses wrapper-byte, wrapper-coin and honest-decryption dependencies into semantic/leakage nodes. It checks annotations only, not arbitrary code or external implementations. The old nonempty `declared_adversary_outputs` argument is rejected; the distinct `declared_precompilation_inputs` field cannot establish independence merely by naming it.

`privacy-composition.json` records 51 separate assertions. See `proofs/privacy-composition.md` for setup order, simulator state, the complete restricted hybrid argument and exclusions. Real rendering must agree with the actual protocol in the admitted class; forcing a dependent semantic outcome to remain fixed is not sufficient.

## Interpretation limits

Successful execution establishes consistency of the finite encodings with the written specification. It does not prove the mathematical theorems by enumeration, instantiate the imported eVRF theorem or production NIZK, establish concrete cryptographic security, realize complete board closures, or measure deployment performance. The registered-share regression checks immutable lookup in two finite judges. The false-statement control positively demonstrates that the toy Fiat--Shamir transcript must not be used as the production proof system. The second judge reduces shared implementation structure but is not independent human review or mechanized verification.
