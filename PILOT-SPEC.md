# Deterministic pilot specification

## Purpose

The pilot is a falsifiable finite check of five declared interfaces: the ideal receipt boundary, the generic tag-bound compiler, a toy arithmetic Schnorr bridge, canonical signed/hash encodings, and fail-closed parsing of damaged setup inputs. It is not a production cryptographic benchmark or deployed-board experiment.

## Fixed limits

- one worker and Python standard library only;
- 180 seconds wall/CPU and 3 GiB address space;
- at most 300,000 counted elementary obligations;
- fresh empty output directory;
- no network, private data, external service, model API, GPU, live ceremony, or random sampling.

## Boundary-model inclusion

Exactly 84 histories: 4 all-honest, 15 malformed openings, 5 public-tag mismatches, 5 commitment mismatches, 5 bounded-service non-openings, 10 censorable post-acceptance, 10 censorable pre-acceptance, 5 late-readiness, 20 honest-delay, and 5 foreign-context histories. The ten censorable pairs have identical public observations but different local send histories. The runner also enumerates 1,008 timing histories and all `11^3` coefficient vectors for 32 observation subsets and two target forms.

## Generic compiler inclusion

The fixed Cartesian product ranges over roster sizes 3-10, rounds 1-8, every sender, and eight classes. It yields 3,328 cases, 1,248 positive certificates, 15,392 invalid-certificate mutations, 9,984 candidate probes, and 26,624 producer/replay comparisons.

## Concrete Schnorr-response inclusion

The arithmetic layer fixes `p = 467`, `q = 233`, `g = 4` and Paillier modulus `N = 1,022,117`. For every roster size 3-10, round 1-8, and sender, it evaluates ten families:

1. honest;
2. invalid response;
3. attacker-selected challenge with otherwise self-consistent arithmetic;
4. bad ciphertext/tag proof;
5. proof bound to a foreign context;
6. failed imported eVRF verification;
7. invalid signature;
8. replayed context;
9. missing under bounded service;
10. missing under censorable service.

The context contains the full public nonce-tag vector. Both judges recompute the aggregate nonce and common challenge; a sender-carried challenge is never trusted. The product contains 4,160 cases, 9,568 semantic attribution mutations, 13,728 producer/replay comparisons, and 8,320 exact algebraic checks. Expected outcomes are 1,664 no-attribution, 832 `bad_binding`, 1,248 `bad_response`, and 416 `qualified_nonopening`.

The retained false-statement control encrypts 17 but uses tag `g^18`. A deterministic search over the 251-value challenge space finds an accepting toy transcript after 617 evaluations. This is the expected falsification of the toy proof system, not an attack on a production NIZK.

## Input-boundary inclusion

Canonical encoding checks include accepted vectors, rejected non-JSON types, malformed Unicode, and a frozen digest. The setup audit applies 503 parser-invalid contexts or registries to 1,380 public verification, replay, and extraction calls across the ideal model, generic compiler, and Schnorr bridge. Every call must return fail-closed without an exception or accusation.

## Falsification conditions

The run fails on any unexpected verdict; valid certificate rejection; specified invalid mutation acceptance; producer/replay disagreement; unauthenticated or off-context attribution; tag-only delivery attribution; censorable-silence attribution; common-challenge, response, subgroup, decryption, timing, or disclosure mismatch; missing negative-control acceptance; producer implementation imported by a replay module; malformed encoding accepted; public API crash on a declared damaged setup; or resource-cap breach.

## Outputs

The runner writes canonical sorted JSON/JSONL. `measurements.json` is process metadata and excluded from exact comparison. The other 21 scientific files, including `binding-negative-control.json`, `schema-audit.json`, and `setup-boundary-audit.json`, are compared byte for byte by `compare_results.py`.
