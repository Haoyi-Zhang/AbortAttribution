# Deterministic pilot specification

## Purpose

The pilot is a falsifiable finite check of five declared interfaces: the ideal receipt boundary, the generic tag-bound compiler, a toy arithmetic Schnorr bridge, canonical signed/hash encodings, and fail-closed parsing of damaged setup inputs. It is not a production cryptographic benchmark or deployed-board experiment.

## Supported platform and fixed limits

The documented execution path is CPython 3.10+ on Linux, including Linux under WSL2, with a POSIX shell. The retained run was produced on Linux x86_64 with CPython 3.13.5. Native Windows Python is unsupported because `resource.setrlimit`, `resource.getrusage`, and `SIGALRM` are part of the enforced experiment contract.

- one worker and Python standard library only;
- 180 seconds wall/CPU and 3 GiB address space through Linux/Unix resource interfaces;
- at most 300,000 counted elementary obligations;
- fresh empty output directory;
- no network, private data, external service, model API, GPU, live ceremony, or random sampling.

## Boundary-model inclusion

Exactly 84 histories: 4 all-honest, 15 malformed openings, 5 public-tag mismatches, 5 commitment mismatches, 5 bounded-service non-openings, 10 censorable post-acceptance, 10 censorable pre-acceptance, 5 late-readiness, 20 honest-delay, and 5 foreign-context histories. The ten censorable pairs have identical public observations but different local send histories. The runner also enumerates 1,008 timing histories and all `11^3` coefficient vectors for 32 observation subsets and two target forms.

## Generic compiler inclusion

The fixed Cartesian product ranges over roster sizes 3-10, rounds 1-8, every sender, and eight classes. It yields 3,328 cases, 1,248 positive certificates, 15,392 invalid certificate records from 19 certificate-field mutation templates, 9,984 candidate probes, and 26,624 producer/replay comparisons.

The delayed-honest class is received exactly at the inclusive deadline `D = 12`. Transcript-level edge conditions are not attributed to the 15,392-record field-mutation count. They are retained separately in 12 focused regression rows with 30 checks:

1. correct envelope at `D`;
2. correct envelope at `D+1` under bounded delivery;
3. correct envelope at `D+1` under censorable delivery;
4. `D+1` with late readiness;
5. genuine qualified missing;
6. late malformed content, which may yield both `bad_entry` and `nonopening`;
7. statement-digest mismatch;
8. false entry-proof bit;
9. truncated closure content;
10. renamed `a1/r1/b1` references with multiple valid readiness/closure candidates and canonical selection;
11. list-valued closure reference;
12. object-valued closure reference.

The final two must reject without exceptions in both implementations.

## Concrete Schnorr-response inclusion

The arithmetic layer fixes `p = 467`, `q = 233`, `g = 4` and Paillier modulus `N = 1,022,117`. For every roster size 3-10, round 1-8, and sender, it evaluates ten Cartesian families: honest; invalid response; attacker-selected challenge with otherwise self-consistent arithmetic; bad ciphertext/tag proof; proof bound to a foreign context; failed imported eVRF verification; invalid signature; replayed context; missing under bounded service; and missing under censorable service.

The context order is explicit: a common pre-nonce seed, a common post-nonce transcript containing the ordered nonce vector, and a sender/key-bound proof context containing the immutable verification-share table. Both judges recompute the aggregate nonce and common challenge; a sender-carried challenge is never trusted. Before the response equation, both compare the body share against the registered table.

The Cartesian product contains 4,160 cases, 9,568 semantic attribution mutations, 13,728 producer/replay comparisons, and 8,320 exact algebraic checks. Expected outcomes are 1,664 no-attribution, 832 `bad_binding`, 1,248 `bad_response`, and 416 `qualified_nonopening`.

A separate frozen `n5-s2-r3` regression substitutes body share `1` for registered share `62`, encrypts nonce scalar `206`, uses response tag `285`, regenerates a true binding proof and legitimate sender signature, and checks that the registered equation requires `402`. Both paths must return `bad_response`. It contributes 10 focused obligations.

The retained false-statement control encrypts 17 but uses tag `g^18`. A deterministic search over the 251-value challenge space finds an accepting toy transcript after 617 evaluations. This is the expected falsification of the toy proof system, not an attack on a production NIZK.

## Input-boundary inclusion

Canonical encoding checks include accepted vectors, rejected non-JSON types, malformed Unicode, and a frozen digest. The setup audit constructs 140 independently annotated parser-invalid contexts or registries without consulting a producer validator, then submits them to 388 public verification, replay, and extraction calls across the ideal model, generic compiler, and Schnorr bridge. The manifest includes exact-type roster failures such as `[true,2,3,4,5]`. Every call must return fail-closed without exception or accusation.

## Falsification conditions

The run fails on any unexpected verdict; valid certificate rejection; specified invalid mutation acceptance; producer/replay disagreement; unauthenticated or off-context attribution; tag-only delivery attribution; censorable-silence attribution; a correct late envelope classified as `bad_entry`; a registered-share substitution accepted; common-challenge, response, subgroup, decryption, timing, or disclosure mismatch; missing negative-control acceptance; producer implementation imported by a replay module; malformed encoding accepted; public API crash on a declared damaged setup; or resource-cap breach.

## Outputs

The runner writes canonical sorted JSON/JSONL. `measurements.json` is process metadata and excluded from exact comparison. The other 23 scientific files, including `compiler-regressions.json`, `schnorr-share-substitution.json`, `binding-negative-control.json`, `schema-audit.json`, and `setup-boundary-audit.json`, are compared byte for byte by `compare_results.py`.
