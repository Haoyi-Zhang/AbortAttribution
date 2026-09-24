# Boundary proof map

This file summarizes the paper proofs for artifact readers. The manuscript is authoritative.

## Observation-fibre criterion

For an attainable public observation `t`, intersect the legitimate blame sets over all admissible histories that project to `t`. A deterministic public rule is sound exactly when every named subject belongs to that intersection. The proof is direct in both directions.

## Statistical tradeoff

For withholding and honest histories whose public-observation distributions have total-variation distance at most `tau`, any randomized accusation test with completeness error `delta` and framing error `epsilon` satisfies:

`epsilon + delta >= 1 - tau`.

This follows by applying the variational characterization of total variation to the accusation probability as a bounded test function.

## Censorable omission impossibility

Couple two post-acceptance histories:

- corrupt participant accepts and never submits;
- honest participant accepts, computes, and submits, but the censorable transport suppresses the submission.

All public records are equal. The statistical tradeoff with `tau=0` gives `epsilon + delta >= 1`. Commitment binding does not change the observation.

## Timing boundary

If readiness is published at `E`, honest observation takes at most `rho`, local computation at most `kappa`, and successful board delivery at most `Delta`, then every honest receipt is on time when:

`E + rho + kappa + Delta <= D`.

When each upper bound is independently attainable and the inequality fails, selecting all maximum delays gives an admissible late honest receipt. The result is sharp only for this declared delay model.

## Ideal-board certificate rules

A malformed-opening certificate resolves an authenticated opening and accepts exactly when the public opening predicate rejects. A non-opening certificate resolves a unique accepted duty, qualifying readiness, bounded-service context, and complete closure at `D`, then checks absence of an opening receipt.

Honest completeness of the opening predicate rules out malformed-opening framing. The timing theorem and closure completeness rule out non-opening framing.

## Unbound private delivery

If a public exponent tag is independent of the privately delivered scalar and the payload is absent from the public observation, two histories can fix every public object while changing the private scalar. Tag consistency therefore cannot distinguish correct from incorrect private delivery.

## Public postprocessing

If a base transcript has a simulator and a fixed extractor uses only that transcript and public coins, sample the simulated transcript once and apply the same extractor. Data processing preserves the base distinguishing bound. The lemma does not create a missing base simulator or hide new public inputs.

## Linear disclosure

For uniform coefficient vector `a`, fixed scalar observations `Aa=b`, and target `Ua`, the target is determined exactly when `row(U)` is contained in `row(A)`. Otherwise its conditional support size is:

`|F|^(rank([A;U]) - rank(A))`.

The proof uses the affine solution coset of `ker(A)` and the image of that kernel under `U`. Conditioning on an adaptively selected realized matrix gives the same statement for that transcript, while the selection event itself remains leakage.

## Relation to compiler proof

The compiler's tag/ciphertext binding and zero-knowledge complaint relations are summarized separately in `compiler.md`. The finite runner checks bounded encodings of these rules; it does not prove the general theorems.
