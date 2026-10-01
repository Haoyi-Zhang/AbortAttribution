# Static eVRF-driven Schnorr-response bridge

The manuscript is authoritative. This file maps the specialized equations to the executable conformance model.

## Ordered contexts and common challenge

The bridge separates three objects.

1. The pre-nonce **seed context** fixes common ceremony data: domain, ordered roster/signer set, message, round, and fixture variant. It contains no nonce output.
2. Each signer's imported eVRF statement is domain-separated as a nonce derivation from the seed context and signer identity. The executable model imports the verification outcome; it does not implement an eVRF.
3. After the ordered nonce-tag vector is fixed, the common **transcript context** contains the seed context and that vector. The subject-specific **proof context** then adds the immutable registered verification-share table, sender, registered authentication key, fixed toy Paillier key identifier, and purpose tag.

Both implementations compute the same aggregate nonce and challenge from the common seed/nonce data. Subject and key fields are deliberately absent from that challenge input but are present in the signed body and proof context. This removes the circular definition while retaining per-sender/key binding.

For signer `i`, the public response relation is

`z_i = r_i + c lambda_i x_i mod q`

and

`Z_i = g^z_i = R_i X_i^(c lambda_i)`.

Before evaluating it, both judges require the body field `X_i` to equal the immutable registered table entry for signer `i`. A body-supplied share is never authoritative.

## Ciphertext-to-exponent relation

For Paillier modulus `N` and canonical `0 <= z < q < N`, the exact relation is

`rho in Z_N^*`, `C = (1+N)^z rho^N mod N^2`, and `Z = g^z`.

The full statement fixes the proof context, recipient key, group/Paillier encodings, sender, round, and purpose. No out-of-range witness is silently reduced. The executable Fiat--Shamir equations are used only for honest algebra and the explicit negative control. The theorem instead assumes a complete and sound production NIZK under the real setup; privacy separately assumes simulated setup, statement simulation, multi-theorem zero knowledge, and simulation soundness when required.

## Registered-share substitution regression

The retained `n5-s2-r3` regression freezes the actual toy values:

- registered verification share `X = 62`;
- substituted body field `X' = 1`;
- nonce scalar `r = 206` and nonce tag `R = 285`;
- ciphertext encrypting 206;
- response tag `Z' = 285` and a true equality proof for that ciphertext/tag pair;
- a valid signature by the legitimate fixture sender;
- registered equation result `Z = 402`.

The equality proof is accepted, but the immutable registry comparison and registered response equation reject the substitution as `bad_response` in both independently written paths. This is a finite conformance regression, not a production attack result.

## Deliberate proof-system negative control

A separate retained control uses a ciphertext of 17 and tag `g^18`. Private toy decryption establishes that the exact relation is false. A fixed-point search nevertheless finds a transcript accepted by both toy verifiers after 617 challenge evaluations. This falsifies any claim that the toy equations provide soundness or knowledge; it does not falsify the relative theorem, which assumes a production proof system.

## Specialized public judge

An authenticated envelope is classified as:

- `bad_binding` when the canonical binding-proof or proof-context predicate fails;
- `bad_response` when imported eVRF verification, nonce-vector membership, immutable registered-share lookup, recomputed common challenge, or the response equation fails;
- `qualified_nonopening` only when duty, readiness, bounded delivery, and complete closure all verify;
- no attribution for well-formed, unauthenticated, off-context, replayed, or censorable-absence inputs.

The theorem is a specialization of the generic compiler. Signatures and production proof soundness support positive evidence; the omission theorem supplies the service-dependent branch; simulated proofs, IND-CPA hybrids, and the imported base simulator support compiled-view privacy.

## Finite evidence and boundaries

The retained Cartesian product contains 4,160 cases in ten families. The independently restated judges agree on 13,728 decisions, reject 9,568 attribution mutations, and perform 8,320 exact arithmetic checks. The registered-share regression adds 10 focused obligations. The false-statement control adds 620 obligations.

The specialization is static and fixed-context. It does not implement a production eVRF or NIZK, solve adaptive PRF-to-random commitment after key exposure, realize a complete board, prove dynamic membership or key rotation, guarantee fairness/output delivery, or establish unique causal responsibility for a global abort.
