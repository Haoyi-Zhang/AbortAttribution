# Non-frameable abort attribution artifact

This standalone repository reproduces deterministic finite checks for the paper's delivery boundary, tag-bound attribution compiler, and static eVRF-driven Schnorr-response bridge.

The artifact has four layers:

1. an ideal authenticated-receipt model for malformed openings and qualified non-openings;
2. an ideal signature/NIZK state machine for the generic compiler;
3. a concrete toy-arithmetic bridge that checks a common aggregate-nonce Schnorr challenge, partial-response equation, Paillier ciphertext-to-exponent equations, authentication, context binding, and qualified omission;
4. canonical-encoding and malformed-setup audits that require every public verification, replay, or extraction API to fail closed.

The arithmetic bridge is deliberately **not** a production eVRF, NIZK, signature, consensus, or network implementation. Its eVRF verification result is an imported ideal bit. Its small group, Paillier modulus, and 251-value challenge space provide exact conformance and falsification checks rather than cryptographic security. The paper theorem instead imports complete and sound real-setup verification for the exact bounded plaintext/tag relation; compiled-view privacy separately requires simulated setup, statement simulation, multi-theorem zero knowledge, and simulation soundness when adversarial proofs follow simulated proofs.

## Reproduce

Python 3 standard library is sufficient.

```sh
python3 -m unittest discover -s tests -v
out=$(mktemp -d)
python3 reproduce.py --out "$out"
python3 compare_results.py results/pilot "$out"
python3 audit_references.py --inventory reference_audit.csv
```

Expected high-level result:

- 53 unit tests pass;
- the runner exits 0 with `status = finite_checks_passed`;
- all 21 deterministic scientific output files match the retained pilot byte for byte;
- `measurements.json` is process metadata and is intentionally excluded from byte comparison.

`reproduce.py` refuses a nonempty output directory and enforces a 180-second bound, a 3 GiB address-space limit, one worker, and a 300,000-obligation cap.

## Components

- `src/cases.py`, `src/checker.py`, `src/replay.py`: ideal-board boundary histories and two certificate implementations.
- `src/compiler_cases.py`: 3,328 generic compiler transcript fixtures.
- `src/compiler_checker.py`, `src/compiler_replay.py`: independently written judges for malformed entry, invalid bound message, and bounded-service non-opening.
- `src/schnorr_bridge.py`: toy-group common-challenge Schnorr response, Paillier encryption, honest equality-equation fixtures, private relation oracle, deterministic false-statement control, authentication, and context binding.
- `src/schnorr_replay.py`: independently restated bridge judge; it does not import the producer.
- `src/linear_oracle.py`: exact timing, linear-disclosure, and tiny-exponent controls.
- `src/schema_audit.py`: canonical-JSON vectors and malformed-input refusal checks.
- `src/setup_boundary_audit.py`: deterministic malformed-context mutations across all public APIs.
- `audit_references.py`, `reference_audit.csv`: bibliography structure, stable-identifier, uniqueness, and citation-closure audit.
- `tests/`: boundary, compiler, arithmetic, challenge-binding, replay-independence, parser, bibliography, mutation, and refusal tests.
- `proofs/`: proof maps and explicit non-claims.
- `results/pilot/`: retained deterministic outputs and measured process metadata.
- `claim_evidence_ledger.csv`: claim-to-proof/check mapping.
- `external_resources.csv`: external-source and access notes.

## Retained campaign

Boundary model:

- 84 histories and 30 supported certificates;
- 485 invalid mutations, 410 omission probes, and 925 producer/replay comparisons;
- ten equal-public-view negative-control pairs;
- 1,008 timing histories and exact small linear-disclosure enumeration.

Generic compiler model:

- 3,328 cases in eight equally sized classes;
- 1,248 certificates, 15,392 invalid mutations, 9,984 candidate probes, and 26,624 producer/replay comparisons.

Static Schnorr-response bridge:

- 4,160 cases in ten equally sized families;
- 832 `bad_binding`, 1,248 `bad_response`, 416 `qualified_nonopening`, and 1,664 no-attribution outcomes;
- 9,568 invalid-attribution mutations;
- 13,728 producer/replay comparisons;
- 8,320 decryption, subgroup, aggregate-challenge, response, and honest equality-equation checks;
- a false relation (`Enc(17)` versus `g^18`) accepted by both toy-equation verifiers after 617 challenge evaluations, contributing 620 expected negative-control obligations.

Input boundaries:

- 31 canonical-encoding obligations;
- 503 malformed trusted-context encodings exercised through 1,380 public API calls;
- zero exceptions and zero unsafe attributions.

The combined retained run counts **215,497** elementary obligations.

## Interpretation limits

Successful execution establishes consistency of the finite encodings with the written specification. It does not prove the mathematical theorems by enumeration, instantiate the imported eVRF theorem or production NIZK, establish concrete cryptographic security, realize complete board closures, or measure deployment performance. The negative control positively demonstrates that the toy Fiat-Shamir transcript must not be used as the production proof system. The second judge reduces shared implementation structure but is not independent human review or mechanized verification.
