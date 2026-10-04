# Length-compatible replacement and leakage interfaces

## Scope and relation to setup-aware simulation

This document concerns only the encoded-length and lawful-dummy premises of Theorem 5.3. The full generated-setup and causal-correlation proof is in proofs/privacy-composition.md and manuscript Section 5.10. Length compatibility does not supply signing keys, justify replay of dependent corrupted records, or make arbitrary reactive private protocols simulatable.

## Encoding and indexed leakage

For an honest-to-honest occurrence a, enc_a is a canonical injective encoding of its lawful message domain. Its length is the complete encryption-input byte length after framing and padding, not the payload size, decimal digits, ciphertext length or total across occurrences. L_len is the ordered sequence (a, |enc_a(m_a)|). An absent message has no entry; an empty message has length zero.

Either lengths are public functions of (P0,a), or the indexed profile is explicitly allowed leakage. Every attainable length must have an efficiently computable legal Dummy(P0,a,length) of that same encoded length, with no access to hidden messages or witnesses. Nonempty domains do not imply efficient dummy generation; all-zero bytes are not lawful in every structured domain. The dummy need not match its exponent tag: the separately assumed proof simulator handles the changed statement.

## Leakage partition and dependency restriction

L=(Leak_Pi,Leak_att^meta,L_len) is sampled from a non-feedback semantic trace before compiler CRS/encryption/proof/signature randomness. It contains allowed ideal outputs, corrupt-recipient plaintexts, frozen occurrence/receipt metadata and semantic complaint facts. It excludes actual wrapper bytes and reactive corrupted responses. Public parser/proof acceptance is recomputed from the current view, not replayed as fixed leakage.

checked_leakage_partition rejects transcript containers, catch-all field names, undeclared overlaps and nonempty declared_adversary_outputs. An independently fixed corrupted input can be labeled declared_precompilation_inputs; this is not permission to rename a post-ciphertext response. Field labels alone cannot prove program independence. The separate dependency DAG rejects declared wrapper/coin/decryption dependencies into semantic/leakage nodes.

## Joint premise and lawful CPA hybrids

The required base relation is (P0,eta,L,T_Pi) ~= (P0,eta,L,Sim_Pi(P0,eta,L)), where eta contains matching retained authentication state and registration-time corrupted state, not an honest decryption key. A marginal simulator can match a public tag while breaking its correlation with secret-dependent lengths. The retained exact two-point example has distance 1/2 for marginal reconstruction and zero for the correct joint reconstruction.

Each CPA challenge uses (enc_a(m_a),enc_a(Dummy(P0,a,ell_a))) with both domain validity and equal length established. The reduction may know m_a to form the challenge; the final simulator uses only allowed length and the dummy algorithm. The challenge key is embedded before registration is published. All causal public responses and downstream signatures/proofs are regenerated. The proof neither holds old reactive corrupted records fixed nor assumes a simulator can sign for arbitrary given public keys.

## Omitted-length boundary

Appending the input length to a length-respecting IND-CPA ciphertext preserves equal-length security. Two messages of distinct encoded lengths and otherwise identical leakage have disjoint public length observations. Any common simulation is at distance at least 1/2 from one of them. This explains the need for the premise; it is not a Paillier failure or an attribution counterexample.

## Fixed-width Paillier

For public N and q<N, encode z in [0,q) in w_N=ceil(log_256 N) big-endian bytes, retaining leading zeros, with zero as lawful same-width dummy. Decode and range-check before Paillier arithmetic. Ciphertexts may be serialized at width ceil(log_256 N^2). Width then depends on public N, not on z. This discharges only the length premise: matching setup state, the non-feedback restriction, joint base simulation and production proof interface remain necessary.

The audit checks all 233 toy scalar encodings, domain and type boundaries, structured lawful dummies, framing, UTF-8 bytes, occurrence order, equal totals with different profiles, empty versus absent records, exact distributions and leakage-field refusal cases. Named assertions in results/pilot/privacy-lengths.json are separate from the certificate mutation count. No production encryption, eVRF or NIZK is implemented by this module.

## Source

Dan Boneh and Victor Shoup, A Graduate Course in Applied Cryptography, version 0.6, January 2023, Remark 2.1 and Section 11.3.2 (Attack Game 11.2), https://toc.cryptobook.us/book.pdf. The cited source defines equal-length public-key CPA security, not the project-specific theorem.
