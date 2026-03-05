# Umbra Adversary Model

Version: 0.1.0-draft
Status: Living document
Last updated: 2026-03-03

---

## Table of Contents

1. [Purpose](#1-purpose)
2. [Adversary Dimensions](#2-adversary-dimensions)
3. [Consensus Adversary](#3-consensus-adversary)
4. [Network Adversary](#4-network-adversary)
5. [Cryptographic Adversary](#5-cryptographic-adversary)
6. [Privacy Adversary](#6-privacy-adversary)
7. [Application-Level Adversary](#7-application-level-adversary)
8. [Adversary Goals and What the Protocol Guarantees](#8-adversary-goals-and-what-the-protocol-guarantees)
9. [Out-of-Scope Threats](#9-out-of-scope-threats)

---

## 1. Purpose

This document defines the classes of adversaries that Umbra is designed to resist, the assumptions made about each class, and the properties guaranteed or not guaranteed against each. Understanding the adversary model is prerequisite to reasoning about protocol security.

---

## 2. Adversary Dimensions

Adversaries are characterized along four axes:

| Axis | Values |
|---|---|
| **Computational power** | Polynomial-time (PPT) / Unbounded |
| **Network control** | None / Partial / Full |
| **Position** | External / Participating validator / Compromised node |
| **Coordination** | Single party / Colluding coalition |

Unless stated otherwise, adversaries are assumed to be:
- Computationally bounded (PPT).
- Aware of all protocol messages (passive network observer).
- Capable of colluding with a bounded fraction of validators.

Post-quantum security is specifically claimed against adversaries equipped with a large-scale quantum computer (Grover/Shor attacks), subject to the hardness of the underlying PQC primitives.

---

## 3. Consensus Adversary

### 3.1 Assumed Capabilities

The consensus adversary may:

- Control up to `f = floor((K-1)/3)` of the `K = 21` committee members per epoch.
  - For K = 21: at most `f = 6` Byzantine committee members are tolerated.
- Adaptively corrupt validators (before or during an epoch).
- Coordinate all Byzantine validators.
- Withhold, delay, duplicate, or reorder messages to and from Byzantine validators.
- Observe all protocol messages.
- Attempt to equivocate (cast conflicting votes).
- Attempt to build a longer or heavier alternative DAG branch.

### 3.2 Not Assumed Capabilities

The adversary may NOT:
- Control more than `f` committee members simultaneously.
- Forge signatures of honest validators (signature unforgeability assumption).
- Predict or control VRF outputs of honest validators.
- Deny service to an unbounded number of honest validators (network adversary is limited, see §4).

### 3.3 Guarantees Against Consensus Adversary

| Property | Guarantee | Condition |
|---|---|---|
| **Safety** | No two conflicting vertices are both certified | ≤ f Byzantine committee members; computationally bounded adversary |
| **Liveness** | Valid vertices proposed by honest leaders are eventually certified | ≤ f Byzantine; partial synchrony (eventual message delivery) |
| **Finality** | Certified vertices are never reverted | Safety holds |
| **Equivocation detection** | Slashable evidence is produced | Equivocation leaves detectable on-chain trace |

### 3.4 Long-Range Attack Resistance

A long-range attack occurs when an adversary accumulates old validator keys and rewrites the history from a past epoch. Umbra mitigates this through:
- **Checkpoint anchoring**: certified vertices are persisted in `SledStorage` and cannot be silently replaced.
- **VRF committee selection**: an attacker cannot retroactively select a favorable committee for a past epoch, as the epoch seed is derived from the finalized state root.
- **Static validator set at each epoch**: committee membership for a given epoch is fixed once computed and is stored in `committee_history`.

Long-range attacks remain a theoretical concern for any PoS-like system. Full mitigation requires either trusted checkpoints or social consensus on the canonical chain head.

### 3.5 Sybil Attack

An adversary attempting to register a large number of validators faces:
- **Superlinear bond cost**: `required_bond(n) = 1,000,000 × (1 + n/100)` — registering the 101st validator costs 2× the base bond.
- **VRF randomness**: even with many registered validators, committee membership per epoch is random — purchasing many validator slots does not guarantee proportional committee representation.
- **Slashing cooldown**: during `SLASH_REGISTRATION_COOLDOWN_EPOCHS = 10` epochs after a slashing event, new registrations cost `3 ×` the normal bond.

---

## 4. Network Adversary

### 4.1 Assumed Capabilities

The network adversary may:
- Observe all plaintext network traffic (passive eavesdropping).
- Control the network between nodes (delay, drop, reorder messages).
- Inject arbitrary messages at the network layer (active attacker).
- Attempt to partition the network.
- Attempt to identify transaction originators by timing and traffic analysis.
- Attempt to eclipse individual nodes (monopolize their peer connections).

### 4.2 Protections in Place

| Attack | Protection |
|---|---|
| Passive eavesdropping | ChaCha20-Poly1305 AEAD encryption on all P2P sessions |
| Message injection | Session authenticated with Dilithium5; AEAD with per-session keys |
| Man-in-the-middle | Mutual authentication: both parties sign the KEM handshake transcript |
| Traffic fingerprinting | Frames padded to `P2P_PADDING_BUCKET = 1024` byte multiples |
| Transaction linkability | Dandelion++ multi-hop stem relay: `StemTransaction` messages traverse up to `DANDELION_STEM_HOPS` (2) random relay nodes before fluffing (best-effort; may fluff earlier if no peers are available or the stem queue is saturated) |
| DoS via message flood | Token bucket rate limiting: 100 msg/s, 200 burst per peer |
| DoS via large messages | Hard message size cap: 16 MiB deserialization limit |
| DoS via invalid structs | Structural validation before cryptographic verification |
| Sybil peer attack | `MAX_PEERS = 50`; peer reputation scoring |
| Eclipse attack | Peer diversity requirements; bootstrap from multiple seeds |
| NatPunch amplification | Sanitized NatInfo fields; UTF-8 safe truncation |

### 4.3 Known Limitations

- **Hello message is plaintext**: the node's KEM public key is revealed before the encrypted channel is established. This leaks peer identity at connection time. A Noise-protocol handshake would mitigate this.
- **Static KEM keypair**: the node's KEM keypair does not rotate per connection. Compromise of the static KEM secret key allows decryption of all past session transcripts. Periodic rekeying provides post-compromise security (new sessions are protected) but not full forward secrecy.
- **Peer reputation not persisted**: reputation scores reset on node restart, giving misbehaving peers a clean slate.
- **Dandelion++ provides probabilistic anonymity**: a well-positioned network adversary who controls a fraction *p* of relay nodes can identify the origin only if all *h* = `DANDELION_STEM_HOPS` relays in the stem path are compromised, with probability *p^h* per transaction. For example, with *h* = 2 and 64 peers where the adversary controls one, *p* = 1/64 and the probability is (1/64)^2 ≈ 2.4 × 10⁻⁴. See [privacy-threat-model.md](./privacy-threat-model.md) for the detailed analysis.

---

## 5. Cryptographic Adversary

### 5.1 Quantum Adversary

Umbra is designed to resist a quantum adversary with a Grover or Shor oracle.

| Algorithm | Classical security | Quantum security | Threat |
|---|---|---|---|
| Dilithium5 | 256-bit | 256-bit | NIST PQC, module lattice; Shor does not apply to lattices |
| SPHINCS+-SHAKE-256s | 256-bit | 128-bit (Grover on hash) | Used as redundant second layer |
| Kyber1024 | 256-bit | 256-bit | NIST PQC, module lattice |
| BLAKE3 | 256-bit | 128-bit (Grover) | Used for general hashing only; 128-bit quantum resistance considered sufficient |
| Rescue Prime | ~256-bit | ~128-bit | STARK circuit hash; follows same Grover analysis |
| ChaCha20-Poly1305 | 256-bit key | 128-bit (Grover on key) | AEAD layer |

**Hybrid signature AND composition**: the hybrid Dilithium5 + SPHINCS+ signature scheme requires an adversary to break BOTH:
- Dilithium5 (lattice-based)
- SPHINCS+ (hash-based)

Breaking either scheme alone is insufficient to forge signatures. This provides cryptographic diversity: if a classical attack is found against one scheme, the other remains as the last line of defense.

### 5.2 Pre-Quantum Adversary

A pre-quantum adversary (classical computer) faces:
- Signature forgery requires breaking Dilithium5 or SPHINCS+ — both computationally infeasible at current state of the art.
- KEM security requires breaking Kyber1024 (NIST security level 5).
- Commitment opening requires inverting Rescue Prime — hard for an efficient field hash.
- STARK soundness: the probability of a cheating prover producing an accepting proof is negligible.

### 5.3 Adversary Against zk-STARKs

The STARK prover must convince the verifier that:
- The commitment correctly encodes the claimed value.
- The balance equation holds.
- All values are in range.
- The nullifier is correctly derived.
- The commitment is a leaf in the Merkle tree.

**STARK soundness**: the probability that a cheating prover (for a false statement) generates a valid proof is at most `2^{-λ}` where `λ ≈ 100` bits for the production proof options. The soundness error is dominated by the query complexity of the FRI protocol.

**STARK zero-knowledge**: the proof reveals nothing about private witnesses (committed values, blinding factors, spend authorization keys, Merkle paths). The verifier learns only that a valid proof exists for the public inputs.

No trusted setup is required. The only "setup" is the choice of public parameters (Rescue Prime constants, Goldilocks field modulus, AIR constraints), all of which are fixed, public, and derivable from the code.

---

## 6. Privacy Adversary

This section describes adversary capabilities with respect to transaction privacy. The full analysis is in [privacy-threat-model.md](./privacy-threat-model.md); this section summarizes the adversary model.

### 6.1 Passive Observer (Blockchain Analyst)

An adversary who:
- Reads all committed data from all finalized vertices.
- Knows all public parameters.
- Does not control any validators or nodes.

**What they can see**:
- All `Nullifier` values (which commitments were spent, not what they committed to).
- All `StealthAddress.one_time_key` values (output identifiers, not linked to recipients).
- All `StealthAddress.kem_ciphertext` values (1568 bytes of opaque ciphertext).
- All `proof_link` values (one-way blinded links between inputs and outputs).
- Transaction fees (plaintext).
- Vertex timestamps and proposer identities (validator pseudonyms).

**What they cannot see**:
- Transaction amounts.
- Sender identity (no linking of outputs to input owners).
- Recipient identity (one-time stealth addresses per output).
- Relationship between any specific input and any specific output.

### 6.2 Active Network Observer

An adversary who additionally:
- Monitors network-layer traffic (even through encryption via timing analysis).
- Controls some fraction of network peers.

Additional capabilities:
- Timing-correlate transaction broadcast with originating peer (mitigated by Dandelion++).
- Traffic analysis on P2P sessions (mitigated by frame padding).

### 6.3 Validator Adversary

A Byzantine validator may:
- Observe all transactions in the mempool before inclusion.
- Choose to exclude specific transactions from their vertices (censorship).
- Attempt to link nullifiers to known outputs through transaction graph analysis.

The validator adversary has no additional cryptographic access to private data — they see the same public data as any observer.

### 6.4 Recipient-Colluding Adversary

If the recipient of a transaction cooperates with an adversary:
- The adversary learns the amount and blinding factor for that output.
- The adversary can verify that a specific sender owns a specific input if the sender reveals their stealth spend key.
- The adversary cannot learn about other transactions involving the sender.

---

## 7. Application-Level Adversary

### 7.1 Fee Manipulation

An adversary may submit transactions with manipulated fees to:
- Starve other transactions (fee flooding attack): mitigated by rate limiting.
- Front-run high-value transactions: mempool ordering by fee rate means higher-fee transactions are included first. This is transparent by design (no guaranteed ordering beyond fee rate).

### 7.2 Mempool Probing

By submitting transactions and observing inclusion patterns, an adversary may infer mempool state. This is inherent to any public mempool and is not a security concern for Umbra's privacy model (transaction content is private; only inclusion is observable).

### 7.3 Timing Attacks

Umbra uses `constant_time_eq` for security-sensitive equality comparisons: VRF output and proof-commitment verification, commitment and nullifier derivation checks, tx-binding and chain-id validation, and stealth address one-time key matching. Data-structure membership lookups — nullifier spent checks (sled `contains_key`) and validator map lookups — are variable-time; these operate on hashed public data rather than secret values and are not protected by `constant_time_eq`.

---

## 8. Adversary Goals and What the Protocol Guarantees

| Adversary Goal | Protocol Response | Guaranteed? |
|---|---|---|
| Forge a transaction | Requires forging hybrid signature (EUF-CMA) | Yes, under crypto assumptions |
| Double-spend a UTXO | Nullifier set prevents reuse; STARK proves correctness | Yes |
| Create money out of thin air | Balance STARK requires sum(inputs) = sum(outputs) + fee | Yes |
| Certify two conflicting vertices | Quorum intersection; ≤ f Byzantine | Yes, under f bound |
| Prevent vertex certification | Requires >f Byzantine committee members | Under partial synchrony |
| Identify transaction sender | Stealth addresses; Dandelion++ routing | Probabilistic (see §6.2) |
| Identify transaction receiver | One-time stealth addresses per output | Computational assumption |
| Learn transaction amounts | Commitments; STARK proofs | Computational assumption |
| Link inputs to outputs | `proof_link` is one-way; commitment never published | Yes, unconditionally |
| Eclipse a node | Peer diversity; reputation; max peers | Partial mitigation |
| Conduct a 51% attack | No majority concept; requires >f committee control | Under f bound |
| Conduct a Sybil attack on validators | Superlinear bond curve | Economic deterrent |
| Retroactively rewrite history | Instant finality; checkpoint persistence | Yes |

---

## 9. Out-of-Scope Threats

The following threats are explicitly out of scope for the current protocol version:

| Threat | Reason Out of Scope |
|---|---|
| **Endpoint compromise** | If a user's device is compromised, all key material is compromised. No protocol can prevent this. |
| **Social engineering** | Out of scope for a cryptographic protocol. |
| **Consensus with >f Byzantine validators** | Provably impossible for any BFT protocol. |
| **Traffic analysis against a global passive adversary** | Dandelion++ provides partial mitigation but not full unlinkability against a global observer. Requires a mix network or DC-net for full protection. |
| **Denial of service against the internet** | Physical network infrastructure attacks are out of scope. |
| **Implementation bugs** | The adversary model assumes a correct implementation. The code undergoes iterative audit but formal verification is not yet performed. |
| **Side-channel attacks on cryptographic implementations** | The PQClean reference implementations used by `pqcrypto-*` crates aim for constant-time operation but are not formally verified. |
| **Trusted setup compromise** | There is no trusted setup; this category does not apply. |
