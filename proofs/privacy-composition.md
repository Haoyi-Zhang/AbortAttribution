# Setup-aware non-feedback public-view simulation

## Exact scope

Theorem 5.3 concerns a generated-setup ensemble and a non-feedback semantic trace with causal public rendering. It is not a simulator receiving an arbitrary existing registry without its matching signing state. Static corruption alone does not imply the non-feedback condition. The attribution theorems retain their original scope and real-setup assumptions.

## Two-stage setup

Registration generates every honest authentication pair once. P0 contains the fixed registry, encryption public keys, groups, codecs and service contract but no compiler CRS. The private authentication state sigma_auth retains the corresponding signing keys, including honest board/service credentials needed to authenticate regenerated records. Authentication keys are independent of encryption keys and protected ceremony scalars. Alpha is the corrupted program's registration-time state, sampled before the base trace and compiler messages. Eta = (sigma_auth, alpha) contains neither honest decryption keys nor hidden honest ceremony scalars.

The real setup samples a real compiler CRS omega and publishes P=(P0,omega). Simulated setup uses the same registration law, generates (omega_tilde,t) from the CRS simulator, publishes P_tilde=(P0,omega_tilde), and retains sigma=(eta,t). View generation is Sim_view(P_tilde,sigma,L). Coupling registration coins makes public verification keys identical; no key is regenerated after publication. Retained setup state is not public leakage. External pre-existing keys require a supplied matching state or an explicitly modeled signing interface; they are not covered by public input alone.

## Semantic trace and causal continuation

Before compiler randomness is drawn, a base experiment determines its public trace, honest messages, occurrence schedule, lengths, receipt/absence pattern and semantic complaint facts. These may depend on P0, base inputs and alpha but not on compiler CRS, ciphertexts, proofs or signatures. The base sampler must execute with the recipient public encryption keys, so an IND-CPA reduction can insert a challenger key without its secret key. Real proof generation can use private witnesses later; simulated proofs cannot require them.

L consists of declared base/ideal outputs (including corrupt-recipient plaintexts), frozen semantic metadata, and indexed encoded lengths. It must not contain realized compiler ciphertexts, proofs, signatures, their digests or reactive corrupted records. A manifest declaration is not evidence of this independence.

The renderer emits honest records using retained signing state and invokes the same PPT corrupted program A on each actual public prefix. A may echo the current ciphertext, hash the whole prefix, sign its response under its own key, and reference earlier records. These outputs are recomputed in every hybrid. They cannot feed back into hidden message values, base semantics, lengths, semantic receipt schedule, complaint truth, or honest decryption. Reactive public records therefore cannot become new private inputs to honest protocol continuation. All public acceptance decisions are recomputed rather than stored as fixed leakage. An instantiation must show real rendering agrees with its actual protocol on the admitted class; forcibly freezing a naturally byte-dependent outcome is not a valid instantiation.

Precommitted corrupted inputs chosen before wrapper randomness may be retained as such, with all base correlations covered by the joint assumption. Actual corrupted outputs produced after seeing a real ciphertext may not be renamed as those inputs. The code rejects the old nonempty declared_adversary_outputs interface and requires a separately labeled declared_precompilation_inputs interface.

## Relative theorem and hybrid map

The base premise is joint with the retained auxiliary state:

(P0,eta,L,T_Pi) ~= (P0,eta,L,Sim_Pi(P0,eta,L)).

The proof-system premise is a joint real-CRS/real-honest-proof to simulated-CRS/stateful-simulated-honest-proof transformation in this renderer. It must support every well-formed hybrid statement, including false tag-binding statements after replacement. The bound epsilon_nizk may only be split into setup and proof terms if the selected proof definition actually supplies that split. Simulation soundness, when separately required, does not recover signing keys or fix stale replay.

1. H0 is real generated setup and real rendering. H1 retains the same registration state, uses simulated CRS and honest proofs, and runs A on the actual generated prefixes. Cost: epsilon_nizk.
2. For each frozen honest-to-honest occurrence, replace its encrypted message by an in-domain dummy of equal encoded length. The CPA reduction embeds the challenge public key before registration is published, generates independent authentication keys itself, and samples semantic messages without the challenged decryption key. It knows the real message for the challenge pair; the final view simulator does not. Later proof generation uses the simulation trapdoor. Costs sum to epsilon_enc, including any recipient/slot reduction loss.
3. Following each replacement, continue A and all honest public operations from the changed prefix. Recompute hashes, signatures, proof statements, references and decisions. Old corrupted records are not fixed auxiliary inputs to this transition. The entire efficient continuation is part of the CPA distinguisher.
4. After all honest-to-honest ciphertexts encrypt dummies, rendering depends only on (P0,eta,L,T_Pi) and independently generated CRS simulation state and coins. Apply the joint base premise to this entire probabilistic function, including A. Cost: epsilon_Pi. This is the two-stage simulated experiment.

Marginalizing private state gives the bound epsilon_nizk + epsilon_enc + epsilon_Pi. Arbitrary reactive MPC, ciphertext-dependent hidden decisions, decryption responses and online/UC security require another theorem. The chosen eVRF construction is not asserted to meet these extra interfaces merely because it supplies nonce tags.

## Correlation boundary

Append an independent uniform k-bit public salt to an IND-CPA ciphertext. A corrupted record copies the salt. Real agreement is 1; independent re-encryption followed by stale replay gives agreement 2^-k. The distinguishability gap is 1-2^-k despite unchanged public-salt marginals. Regenerating the corrupted record on the new prefix restores this correlation. This counterexample concerns the invalid hybrid operation, not a break of public-key encryption.

## Executable mapping and limitations

src/privacy_composition.py implements retained toy authentication state, exact registry checks, a frozen input vector, immutable-prefix callbacks, and a current-prefix echo/hash/signature response. It refuses missing or mismatched state without regenerating keys. check_causal_links verifies both signatures and prefix relationships, distinguishing stale-but-valid signatures from valid causal transcripts. Public inputs are detached from mutable caller aliases during rendering. Exact integer counters and signer roles are checked.

A declared dependency DAG propagates wrapper-byte, wrapper-randomness and honest-decryption provenance. Semantic/leakage nodes reject such dependencies, including indirect ones. Cycles, unknown sources and provenance overriding reject. This checks supplied annotations, not arbitrary Python code, sandbox isolation or semantic noninterference. The code is a small contract harness, not a cryptographic simulator or production key generator.

results/pilot/privacy-composition.json records named assertions, signed illustrative traces and exact rational salt distributions for alphabets 2,4,8,16. No private retained key state is exported in that result. The deliberately public tiny fixture keys are not secrets or production credentials. Existing attribution checkers and the weak toy-proof negative control are untouched.

## Source boundary

Boneh and Shoup, A Graduate Course in Applied Cryptography, Section 11.3.2, supplies the equal-length public-key CPA game and adversary-continuation convention. It does not prove this compiler theorem. The new setup and non-feedback assumptions and their conditional proof are specified here and in the manuscript.
