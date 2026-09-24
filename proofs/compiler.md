# Tag-bound compiler proof map

## Imported base interface

For each fixed-context private action `(i,j,r)`, the base ceremony defines:

- message domain `M(i,j,r)`;
- public tag `Tag(ctx,i,j,r,m)`;
- semantic relation `R_base(ctx,tau,i,j,r,m,T)`;
- honest correctness;
- a simulator for the base public/corrupted-party view from declared leakage.

The generic theorem is stated at this interface. The repository also contains one static Schnorr-response specialization in `schnorr-bridge.md`; it imports the eVRF verification theorem and does not replace the generic interface with a production eVRF implementation.

## Envelope relation

Public statement:

`(ctx, tau, i, j, r, pk_j, C, T)`.

Witness:

`(m, rho)` satisfying:

- `C = Enc(pk_j,m;rho)`;
- `m` is in the declared message domain;
- `T = Tag(ctx,i,j,r,m)`.

This relation binds ciphertext and tag to one plaintext. It intentionally does not assert `R_base = 1`, so an invalid but well-bound delivered message remains complainable.

## Complaint relation

Public statement:

`(ctx, tau, i, j, r, pk_j, C, T, hash(envelope))`.

Witness:

`(sk_j,m)` satisfying:

- the fixed key registry binds `sk_j` to `pk_j`;
- `Dec(sk_j,C) = m`;
- `T = Tag(ctx,i,j,r,m)`;
- `R_base(ctx,tau,i,j,r,m,T) = 0`.

The proof reveals complaint truth and public identities, but not the scalar witness.

## Public rules

1. `bad_entry`: a received sender-authenticated envelope fails canonical shape, context, deadline, or envelope-proof verification.
2. `bad_message`: an accepted envelope and exact bound recipient complaint verify.
3. `nonopening`: a unique accepted duty, early enough readiness, bounded-delivery context, and complete deadline closure contain no attributable envelope.

Malformed and missing are disjoint: any attributable sender envelope prevents `nonopening`, even if the envelope is malformed.

## Relative non-frameability proof

An honest envelope satisfies canonical validation and real-setup proof completeness, so `bad_entry` rejects. A valid bad-message complaint against an honest sender would, by complaint-proof soundness, key binding, decryption correctness, and the accepted envelope relation, produce the same plaintext with both `R_base = 0` and honest correctness `R_base = 1`, a contradiction. Qualified bounded delivery forces an honest envelope into the complete deadline closure, contradicting `nonopening`.

Concrete framing is bounded by the union of:

- honest-signature forgery;
- ambiguous or incorrect key registration;
- envelope- or complaint-proof soundness failure;
- context or envelope-digest collision;
- board receipt or closure failure;
- declared observation, computation, or delivery service failure.

## Completeness boundary

Completeness covers:

- received sender-authenticated malformed entries;
- invalid accepted messages delivered to an honest complaint-capable recipient whose complaint reaches the board;
- non-openings meeting the bounded-service and complete-closure premises.

A corrupt recipient may suppress the only complaint witness. Censorable absence remains unattributed.

## Public-view privacy proof

Hybrid outline:

1. replace the real CRS by an indistinguishable simulated setup, then replace honest proofs with the statement simulator;
2. replace honest-to-honest ciphertexts by encryptions of fixed same-length domain elements using IND-CPA;
3. generate exponent tags and other base-public values with the imported base simulator;
4. generate identities, timing, certificate class, and complaint truth from attribution leakage;
5. sign simulated records using the honest setup state available in the simulation experiment.

Plaintexts received by corrupted recipients and all explicitly public complaint facts remain in leakage. If adversarial proofs can be submitted after simulated proofs are exposed, simulation soundness is required. Attribution uses proof soundness under the accepted real CRS and does not use witness extraction.

## Non-claims

No claim is made about:

- an end-to-end production eVRF construction or reduction;
- NIZK circuit size or production performance;
- production signature/encryption parameter choices;
- a real complete-board construction or network latency distribution;
- dynamic roster/key changes, recovery, fairness, robust completion, or adaptive corruption;
- independent mechanized or human proof review.
