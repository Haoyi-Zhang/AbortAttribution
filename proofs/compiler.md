# Tag-bound compiler proof map

## Imported base interface

For each fixed-context private action `(i,j,r)`, the base ceremony defines a message domain, public tag, semantic relation, honest correctness, and a simulator for the base public/corrupted-party view from declared leakage. The generic theorem is stated at this interface. The repository contains one static Schnorr-response specialization, but it imports eVRF verification and does not claim a production eVRF implementation.

## Envelope and complaint relations

The envelope statement is `(ctx, tau, i, j, r, pk_j, C, T)` with witness `(m,rho)` satisfying encryption, message-domain, and tag-binding relations. It binds ciphertext and tag to one plaintext; it deliberately does not assert that the base semantic relation is true.

The complaint statement is `(ctx, tau, i, j, r, pk_j, C, T, hash(envelope))` with witness `(sk_j,m)` satisfying key registration, decryption, tag binding, and rejection by the base semantic relation. The proof reveals complaint truth and public identities, but not the scalar witness.

## Content and timing are separate predicates

A sender-authenticated envelope is **content-valid** when its active context, canonical encoding, signed actor/round/recipient/duty metadata, registered references, and envelope proof verify. Receipt time is not part of this predicate.

Timely fulfilment is the distinct fact that an attributable envelope occurs in the complete board closure at the inclusive deadline `D`. Consequently:

- a correct envelope at `D` is timely and is not `bad_entry`;
- a correct envelope first observed at `D+1` is not `bad_entry` merely because it is late;
- under verified early readiness, bounded delivery, and a complete closure at `D`, that `D+1` record may coexist with a `nonopening` certificate for the missed deadline;
- under censorable delivery or late readiness, the same absence at `D` is not attributable;
- a malformed signed envelope at or before `D` is `bad_entry` and defeats `nonopening` because it is present in the closure;
- a malformed signed envelope first observed after `D` may support both `bad_entry` (content) and `nonopening` (service-qualified deadline failure), because the two certificates establish different facts.

## Public rules

1. `bad_entry`: a received sender-authenticated envelope fails the content predicate. Receipt at `D+1` alone is never a reason.
2. `bad_message`: a content-valid envelope and exact bound recipient complaint verify.
3. `nonopening`: a unique accepted duty, qualifying readiness for the enabling transcript prefix, bounded-delivery context, and complete closure at `D` contain no attributable envelope by `D`.

All certificate fields are registry references. The extractor scans actual valid acceptance, readiness, and closure records; it does not depend on literal names such as `accept`, `ready`, or `final`. If several valid readiness/closure records exist, it selects the lexicographically least valid tuple after enforcing a unique acceptance.

## Relative non-frameability proof

An honest envelope satisfies the content predicate and real-setup proof completeness, so `bad_entry` rejects independently of receipt time. A valid bad-message complaint against an honest sender would, by complaint-proof soundness, key binding, decryption correctness, and the accepted envelope relation, produce the same plaintext with both rejection and honest correctness of the base relation, a contradiction. Qualified bounded delivery forces an honest timely envelope into the complete deadline closure; if a correct honest envelope appears only at `D+1`, the interpretation lies in the declared service bad event rather than in content malformation.

Concrete framing is bounded by the union of signature forgery, ambiguous key registration, proof-soundness failure, context/digest collision, board failure, and declared readiness/computation/delivery service failure.

## Completeness boundary

Completeness covers received sender-authenticated malformed content, invalid content-valid messages delivered to an honest complaint-capable recipient whose complaint reaches the board, and omissions meeting all bounded-service premises. A corrupt recipient may suppress the only complaint witness. Censorable absence remains unattributed.

## Executable mapping

The Cartesian campaign's 15,392 invalid records arise from 19 certificate-field templates only. Statement-digest, proof-bit, closure-content, `D`/`D+1`, late-readiness, renamed-reference, multiple-candidate, and non-string closure-reference obligations are retained in the separate `compiler-regressions.json` output. The two judges reject list/object closure references without raising an exception.

## Public-view privacy proof

Theorem 5.3 is separately restricted to generated setup and a non-feedback semantic trace. Its two-stage simulator retains authentication keys matching the published registry and a proof-simulation trapdoor. It does not receive arbitrary existing public keys and manufacture matching secret keys. The base simulator is joint with this auxiliary state and all declared semantic/length leakage.

A causal public renderer reruns the corrupted program on the actual prefix in every hybrid. Copying, hashing or signing a changed ciphertext therefore changes the dependent corrupted record as required. Such public responses may not affect private message values, semantic schedules or honest decryption. Actual corrupted wrapper records are excluded from fixed leakage. Arbitrary private feedback is not covered.

Legal equal-length dummy replacements, the joint simulated-CRS/proof interface and multi-key IND-CPA hybrids are all explicit. See proofs/privacy-composition.md for the complete setup and hybrid map and proofs/privacy-lengths.md for length boundaries. The new finite modules check interface examples, not computational security. No attribution judge or existing certificate predicate changes.

## Non-claims

No claim is made about an end-to-end production eVRF construction, production NIZK performance, a real complete-board construction, a network latency distribution, dynamic roster/key changes, recovery, fairness, robust completion, adaptive corruption, or independent mechanized/human proof review.
