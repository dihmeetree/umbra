# Umbra Cryptographic Constructions

Version: 0.1.0-draft
Status: Living document
Last updated: 2026-03-03

---

## Table of Contents

1. [Overview](#1-overview)
2. [Primitive Summary](#2-primitive-summary)
3. [Hash Functions](#3-hash-functions)
4. [Digital Signatures (Hybrid)](#4-digital-signatures-hybrid)
5. [Key Encapsulation Mechanism](#5-key-encapsulation-mechanism)
6. [Authenticated Encryption](#6-authenticated-encryption)
7. [Stealth Address Protocol](#7-stealth-address-protocol)
8. [Commitment Scheme](#8-commitment-scheme)
9. [Nullifier Derivation](#9-nullifier-derivation)
10. [Merkle Tree](#10-merkle-tree)
11. [Verifiable Random Function](#11-verifiable-random-function)
12. [zk-STARK Proof System](#12-zk-stark-proof-system)
    - 12.1 [Spend Proof](#121-spend-proof)
    - 12.2 [Balance Proof](#122-balance-proof)
13. [P2P Session Key Establishment](#13-p2p-session-key-establishment)
14. [Binding and Domain Separation](#14-binding-and-domain-separation)
15. [References](#15-references)

---

## 1. Overview

Umbra uses exclusively post-quantum cryptographic primitives, selected to resist both classical and large-scale quantum adversaries. All constructions are either based on NIST PQC standards (Dilithium, Kyber) or on hash-based security (SPHINCS+, STARKs, BLAKE3, Rescue Prime).

No elliptic curve cryptography is used. No bilinear pairings are used. No trusted setup is required for any component.

The design philosophy is **defense in depth**:
- Signatures use AND composition: both Dilithium5 and SPHINCS+ must verify.
- Commitments use a dual-binding approach: Rescue Prime and BLAKE3-512.
- Transport uses KEM-established keys with AEAD.

---

## 2. Primitive Summary

| Role | Algorithm | Parameters | Classical security | Quantum security |
|---|---|---|---|---|
| General hashing | BLAKE3 | 256-bit output | 256 bits | ~128 bits (Grover) |
| Signature (lattice) | Dilithium5 | NIST security level 5 | ~256 bits | ~256 bits |
| Signature (hash) | SPHINCS+-SHAKE-256s-simple | 256-bit output | ~256 bits | ~128 bits (Grover) |
| Key encapsulation | CRYSTALS-Kyber1024 | NIST security level 5 | ~256 bits | ~256 bits |
| AEAD | ChaCha20-Poly1305 | 256-bit key, 96-bit nonce | 256 bits | ~128 bits (Grover) |
| STARK hash / commitment | Rescue Prime (Rp64_256) | Goldilocks field | ~256 bits | ~128 bits |
| Merkle tree | Rescue Prime (Rp64_256) | Depth 20 | ~256 bits | ~128 bits |
| VRF | BLAKE3-based (custom) | 256-bit output | 256 bits | ~128 bits |

All algorithms are implemented via well-audited Rust libraries:
- `pqcrypto-dilithium` v0.5 (PQClean reference implementation)
- `pqcrypto-sphincsplus` v0.7 (PQClean reference implementation)
- `pqcrypto-kyber` v0.8 (PQClean reference implementation)
- `blake3` v1 (official blake3 crate)
- `winterfell` v0.13 (Rescue Prime + STARK prover/verifier)

---

## 3. Hash Functions

### 3.1 BLAKE3

BLAKE3 is used for all general-purpose hashing. It is a keyed-hash function based on the Merkle-Damgård-like BLAKE family, optimized for speed and supporting streaming output (XOF mode).

**Security**:
- 256-bit output provides 256-bit classical preimage resistance.
- Grover's algorithm reduces quantum preimage resistance to ~128 bits.
- Collision resistance: 128 bits classical; 85 bits quantum (birthday + Grover).

**Domain separation**: all hash calls in Umbra use domain-separated variants:
```
H_d(domain, data) = BLAKE3(domain_bytes || len_4le(data) || data)
H_concat(parts)   = BLAKE3(len_4le(p1) || p1 || len_4le(p2) || p2 || ...)
```
Length prefixes are 4-byte little-endian. This prevents cross-context attacks where the same hash input appears in different contexts.

**Reference**: [Aumasson et al., "BLAKE3 is one function, fast everywhere", 2020](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)

### 3.2 Rescue Prime (Rp64_256)

Rescue Prime is an algebraic hash function designed to be efficient inside STARK arithmetization. It operates over the Goldilocks field `GF(p)` where `p = 2^64 - 2^32 + 1`.

**Parameters** (Rp64_256 as implemented in winterfell):
- State width: 12 field elements (768 bits total).
- Number of rounds: 7.
- Output: 4 field elements = 256 bits.
- S-box: `x^7` (forward) and `x^{1/7}` (inverse) — MDS multiplication in between.

**Security argument**:
- Algebraic degree: the S-box has degree 7; after 7 rounds the overall algebraic degree is 7^7 ≈ 2^6 — high enough to resist Gröbner basis attacks.
- The Goldilocks field characteristic is large (64 bits), resisting small-field attacks.
- Conjectured ~128-bit preimage resistance.

**STARK friendliness**: the S-box `x^7` is a low-degree polynomial over GF(p), making it efficiently representable in STARK constraints (degree 7 transition constraints).

**Reference**: [Aly et al., "Rescue-Prime: a Standard Specification (SoK)", 2020](https://eprint.iacr.org/2020/1143)

---

## 4. Digital Signatures (Hybrid)

### 4.1 Hybrid Composition

Umbra uses an AND-composition of two independent post-quantum signature schemes:

```
Sign(sk, m) = (Dilithium5.Sign(sk_d, m), SPHINCS+.Sign(sk_s, m))
Verify(pk, m, sig) = Dilithium5.Verify(pk_d, m, sig.dilithium)
                 AND SPHINCS+.Verify(pk_s, m, sig.sphincs)
```

A signature is valid if and only if BOTH component signatures verify. This AND composition provides cryptographic diversity:

**Theorem**: the AND-composition is EUF-CMA secure if at least one of the two component schemes is EUF-CMA secure.

**Rationale**: if a future cryptanalytic breakthrough breaks Dilithium5 (but not SPHINCS+), or vice versa, the combined scheme remains secure. This guards against the possibility of undiscovered attacks on either individual scheme.

### 4.2 CRYSTALS-Dilithium5

**Algorithm**: CRYSTALS-Dilithium, mode 5 (security level 5).
**NIST standard**: FIPS 204 (ML-DSA-87 equivalent).

**Parameters**:
- Public key size: 2592 bytes
- Secret key size: 4864 bytes (zeroize-on-drop in Umbra)
- Signature size: 4627 bytes
- Security: based on Module-LWE and Module-SIS problems over module lattices
- NIST security level: 5 (~256-bit equivalent)

**Quantum resistance**: the Module-LWE problem is believed to be hard for quantum computers. The best known quantum attacks provide no exponential speedup over classical attacks.

**Reference**: [Ducas et al., "CRYSTALS-Dilithium Algorithm Specifications and Supporting Documentation", NIST PQC Round 3 submission](https://pq-crystals.org/dilithium/)

### 4.3 SPHINCS+-SHAKE-256s-simple

**Algorithm**: SPHINCS+ with SHAKE-256 as the underlying hash, "s" (small signature) variant, "simple" tweak.
**NIST standard**: FIPS 205 (SLH-DSA-SHAKE-256s equivalent).

**Parameters**:
- Public key size: 64 bytes
- Secret key size: 128 bytes (zeroize-on-drop in Umbra)
- Signature size: 29,792 bytes
- Security: based purely on hash function security (no algebraic structure)
- NIST security level: 5 (~256-bit equivalent for classical, ~128-bit quantum)

**Hash-based security**: SPHINCS+ security reduces to the security of the underlying hash function (SHAKE-256). If SHAKE-256 is secure, SPHINCS+ is secure. This provides a fundamentally different hardness basis from Dilithium5, giving the hybrid scheme defense in depth.

**Reference**: [Bernstein et al., "SPHINCS+: Stateless Hash-Based Signatures", NIST PQC Round 3 submission](https://sphincs.org/)

### 4.4 Sign Data Construction

To prevent cross-protocol signature misuse, all signed messages include a domain label:

| Context | Domain | Signed data |
|---|---|---|
| BFT vote | `"umbra.vote"` | `H_d("umbra.vote", epoch \|\| round \|\| vertex_id \|\| vote_type)` |
| Validator deregistration | `"umbra.dereg"` | `H_d("umbra.dereg", chain_id \|\| validator_id)` |
| P2P handshake | `"umbra.auth"` | `H_d("umbra.auth", shared_secret \|\| initiator_pk \|\| responder_pk)` |

---

## 5. Key Encapsulation Mechanism

### 5.1 CRYSTALS-Kyber1024

**Algorithm**: CRYSTALS-Kyber1024 (ML-KEM-1024).
**NIST standard**: FIPS 203.

**Parameters**:
- Public key size: 1568 bytes
- Secret key size: 3168 bytes (zeroize-on-drop in Umbra)
- Ciphertext size: 1568 bytes
- Shared secret size: 32 bytes
- Security: based on Module-LWE
- NIST security level: 5

**Usage in Umbra**:
1. **Stealth address generation**: encapsulate against recipient's KEM public key to derive a per-output shared secret.
2. **Note encryption**: encapsulate to encrypt the note plaintext (value + blinding) to the recipient.
3. **P2P handshake**: initiator encapsulates to responder's static KEM public key to establish session keys.

**Reference**: [Bos et al., "CRYSTALS-Kyber Algorithm Specifications", NIST PQC submission](https://pq-crystals.org/kyber/)

---

## 6. Authenticated Encryption

### 6.1 ChaCha20-Poly1305

**Algorithm**: ChaCha20 stream cipher with Poly1305 MAC authenticator (RFC 8439).
**Variant for P2P sessions**: ChaCha20-Poly1305 (96-bit nonce, session-keyed).
**Variant for note encryption**: XChaCha20-Poly1305 (192-bit nonce, allows random nonce without collision risk).

**Parameters**:
- Key size: 32 bytes (256 bits)
- Nonce size: 12 bytes (ChaCha20-Poly1305) or 24 bytes (XChaCha20)
- Tag size: 16 bytes
- Security: 256-bit key; ~128-bit quantum (Grover on key)

**Key derivation for P2P sessions**:
```
session_key = H_d("umbra.session", kyber_shared_secret)
```
The 32-byte shared secret from Kyber1024 decapsulation is domain-hashed to produce the AEAD key.

**Nonce management for P2P**:
- Nonces are 96-bit monotonically increasing counters.
- Separate send and receive nonce counters to prevent reuse.
- Counter overflow protection: connection is torn down before overflow (requires 2^96 messages).

**Reference**: [Bernstein, "ChaCha, a variant of Salsa20", 2008]; [Langley, "ChaCha20-Poly1305", RFC 8439, 2018]

---

## 7. Stealth Address Protocol

### 7.1 Construction

The stealth address protocol is a Kyber-based adaptation of the Diffie-Hellman stealth address scheme used in Monero:

```
Setup: Recipient Bob publishes KEM public key pk_B.

Send (Alice → Bob for output at index i):
  1. (ss, ct) ← KEM.Enc(pk_B)          // Kyber1024 encapsulation
  2. otk ← H_d("umbra.stealth", ss || i_le4)   // one-time key
  3. Output on-chain: { one_time_key = otk, kem_ciphertext = ct }

Scan (Bob):
  4. For each output: ss' ← KEM.Dec(sk_B, ct)
  5. otk' ← H_d("umbra.stealth", ss' || i_le4)
  6. If otk' == one_time_key: output belongs to Bob

Spend (Bob):
  7. spend_auth ← H_d("umbra.spend_auth", ss')
  8. Build SpendStarkProof using spend_auth and commitment
```

### 7.2 Security Properties

**Receiver unlinkability**: two outputs to the same recipient have independent, uniformly distributed `one_time_key` values (because each uses a fresh Kyber encapsulation with a fresh shared secret). An observer cannot determine if two outputs share a recipient.

**Scan key privacy**: the scan key is the KEM secret key `sk_B`. Delegating scanning requires revealing `sk_B`, which also grants spending ability. There is no separate view key in the current protocol — this is a known limitation.

**Quantum resistance**: Kyber1024 is a post-quantum KEM. Even a quantum adversary cannot compute `ss` from `pk_B` and `ct` without `sk_B`.

---

## 8. Commitment Scheme

### 8.1 Rescue Prime Commitment

Output values are committed using Rescue Prime:
```
commitment = RP(value || blinding)
```
where `value` is a 64-bit amount encoded as a field element, and `blinding` is a 32-byte random field element.

**Homomorphic structure**: Rescue Prime does not have the additive homomorphic structure of Pedersen commitments. The balance equation is proven in the STARK circuit rather than via homomorphic addition.

### 8.2 Dual-Binding Commitment

In the actual implementation, commitments are dual-bound to provide defense in depth against commitment scheme breaks:

```
commitment = H_concat(RP(value, blinding), BLAKE3_512(value, blinding))
```

Both the Rescue Prime binding and the BLAKE3-512 binding must be broken simultaneously to forge a commitment. BLAKE3-512 uses the XOF mode for extended output.

**Hiding**: both RP and BLAKE3 are computationally hiding: given only `commitment`, no PPT adversary can determine `value` without `blinding`.

**Binding**: the combined commitment is binding if either component is binding. Breaking the commitment requires finding a collision in both RP and BLAKE3 simultaneously.

---

## 9. Nullifier Derivation

### 9.1 Construction

A nullifier marks an output as spent without revealing which output:
```
nullifier = RP(spend_auth || commitment_hash)
```
where:
- `spend_auth = H_d("umbra.spend_auth", kyber_shared_secret)` is derived from the per-output stealth address shared secret.
- `commitment_hash` is the 32-byte commitment value.

In the implementation, both inputs are converted to Goldilocks field elements for the Rescue Prime evaluation:
```rust
let auth_felts = hash_to_felts(spend_auth);      // [u8; 32] → 4 Felt elements
let commitment_felts = hash_to_felts(commitment_hash);
let digest = rescue::hash_nullifier(&auth_felts, &commitment_felts);
let nullifier = Nullifier(felts_to_hash(&digest));
```

### 9.2 Security Properties

**Unlinkability**: given only `nullifier`, finding `commitment_hash` requires inverting Rescue Prime (preimage resistance). An observer cannot determine which commitment corresponds to a revealed nullifier.

**Uniqueness**: for a given `(spend_auth, commitment_hash)` pair, the nullifier is deterministic. Attempting to spend the same output twice produces the same nullifier, which is detected by the nullifier set.

**Unforgeability**: producing a valid `spend_auth` for a commitment without knowledge of the Kyber shared secret requires computing a preimage under the BLAKE3-based `H_d` function.

---

## 10. Merkle Tree

### 10.1 Construction

All output commitments are stored in a depth-20 Rescue Prime Merkle tree:
```
Leaf:         RP(commitment)
Internal node: RP(left_child || right_child)
Empty leaf:   RP(ZERO_ELEMENT)
```

**Depth**: 20, supporting up to 2^20 = 1,048,576 commitments.
**Padding**: empty positions are filled with the hash of a canonical zero element, computed once and cached.

### 10.2 Canonical Root

The Merkle root is a 32-byte hash (`felts_to_hash` output) representing the commitment to the entire UTXO set. It is:
- Included in every DAG vertex as `state_root`.
- Used as the epoch seed input for committee selection.
- Used as the public input for SpendStarkProof.

### 10.3 Membership Proof

A Merkle membership proof for a commitment at leaf index `i` consists of:
- The 20-element authentication path (sibling hashes at each level).
- The leaf index (determines left/right routing at each level).

This proof is a private witness in the `SpendStarkProof` circuit — it is never revealed on-chain.

---

## 11. Verifiable Random Function

### 11.1 Construction

Umbra's VRF is a deterministic, verifiable pseudorandom function built over BLAKE3 and the validator's signing key material:

```
VRF.prove(sk, input) → (vrf_output, vrf_proof):
  vrf_output = H_d("umbra.vrf.output", sk || input)
  vrf_proof  = H_d("umbra.vrf.proof",  sk || input || vrf_output)

VRF.verify(pk, input, vrf_output, vrf_proof):
  expected_output = H_d("umbra.vrf.output", ...)
  // Verify via signature that pk corresponds to the sk used
  return constant_time_eq(vrf_proof, H_d("umbra.vrf.proof", ...))
```

**Note**: the current VRF construction is a simplified BLAKE3-based VRF. It is deterministic and verifiable, but is not a standard VRF construction with formal UC security proofs (such as ECVRF or Lattice-based VRF). For the committee selection use case, the key properties required are:

1. **Uniqueness**: one VRF output per `(sk, input)` pair — satisfied by BLAKE3 determinism.
2. **Verifiability**: anyone with `pk` can verify the output — approximated via signed output.
3. **Pseudorandomness**: output is computationally indistinguishable from random — provided by BLAKE3 PRF security.

**Limitation**: the current VRF lacks a formal proof of pseudorandomness against an adversary who can choose `input` adaptively. A rigorous VRF (e.g., ECVRF per RFC 9381, or a lattice-based VRF) would provide stronger guarantees. This is an area for future work.

---

## 12. zk-STARK Proof System

### 12.1 Architecture

Umbra uses the **winterfell** library for zk-STARK proof generation and verification. The proof system provides:
- **No trusted setup**: all parameters are public.
- **Post-quantum security**: based on hash function security.
- **Transparent**: any verifier can check correctness without special setup.

**Goldilocks field**: `GF(p)` where `p = 2^64 - 2^32 + 1`. This prime admits efficient NTT-based polynomial multiplication.

**FRI-based commitment**: the STARK system uses FRI (Fast Reed-Solomon IOP of Proximity) for polynomial commitment, providing the soundness argument.

**Proof options** (production):
- `blowup_factor`: 8 (LDE evaluation domain is 8× the trace length)
- `grinding_factor`: 20 (proof-of-work for soundness amplification)
- `num_queries`: 30 (FRI query count)
- `field_extension`: quadratic extension field for higher security

**Proof options** (fast-tests, NOT for production):
- Reduced grinding factor and query count for faster generation.

### 12.2 Spend Proof

**Circuit**: `SpendStarkProof`
**Source**: `src/crypto/stark/spend_air.rs`, `src/crypto/stark/spend_prover.rs`

**Public inputs**:
- `nullifier`: the claimed nullifier value
- `merkle_root`: the current global Merkle tree root
- `proof_link`: one-way binding to the private commitment

**Private witnesses**:
- `commitment`: the output commitment (NEVER revealed publicly)
- `spend_auth`: the spending authorization key
- `link_nonce`: random nonce for proof_link
- `merkle_path`: the 20-element authentication path
- `leaf_index`: position in the Merkle tree

**Constraints proved** (52 total transition constraints):
1. Nullifier derivation: `RP(spend_auth, commitment) = nullifier`
2. Merkle membership: the commitment hashes up to the Merkle root via the provided path.
3. Proof-link derivation: `RP(commitment, link_nonce) = proof_link`
4. Commitment register constancy: the commitment register (columns 26-29) is constant throughout the trace.
5. Merkle path bit is boolean at step boundaries.
6. Chain flag enforces correct chaining between Merkle levels.

**Trace layout**:
```
Width: 30 columns
Columns 0-11:  Rescue Prime state (12 field elements)
Columns 12-23: Rescue Prime mid-state (after forward half-round)
Column 24:     Merkle path bit (0 or 1)
Column 25:     Chain flag
Columns 26-29: Commitment register (constant throughout)

Block layout:
  Block 0:            Nullifier hash
  Blocks 1..20:       Merkle path verification (depth 20)
  Block 21:           Proof-link hash
  Remaining:          Padding to power-of-2 trace length
```

**Soundness**: a cheating prover who does not know a valid `(commitment, spend_auth, merkle_path)` cannot produce an accepting proof except with probability ≤ `2^{-λ}` where λ ≈ 100 bits.

**Zero knowledge**: the proof reveals no information about the private witnesses. In particular:
- The commitment (which would identify the specific output being spent) is never revealed.
- The Merkle path and leaf index are private.

### 12.3 Balance Proof

**Circuit**: `BalanceStarkProof`
**Source**: `src/crypto/stark/balance_air.rs`, `src/crypto/stark/balance_prover.rs`

**Public inputs**:
- `fee`: the claimed transaction fee
- For each input: `proof_link_i` (one-way commitment link)
- Merkle root (for input commitment verification)

**Private witnesses**:
- For each input `i`: `commitment_i`, `value_i`, `blinding_i`, `link_nonce_i`
- For each output `j`: `commitment_j`, `value_j`, `blinding_j`

**Constraints proved**:
1. **Commitment openings**: for each input/output, `RP(value_i, blinding_i) = commitment_i`.
2. **Balance equation**: `sum(value_i) = sum(value_j) + fee`.
3. **Range proof**: for each value, `value ∈ [0, 2^59)` (via 59-bit decomposition).
4. **Proof-link derivation**: for each input, `RP(commitment_i, link_nonce_i) = proof_link_i`.

**Trace layout**:
```
Width: 86 columns
Columns 0-11:  Rescue Prime state
Columns 12-23: Rescue Prime mid-state
Column 24:     Signed block value (+value for inputs, -value for outputs)
Column 25:     Running net balance
Columns 26-84: Bit decomposition (59 bits for range proof)
Column 85:     Chain flag (1 = proof_link block, chained from commitment block)

For N_IN inputs and N_OUT outputs:
  2*N_IN hash blocks (commitment + proof_link per input)
  + N_OUT hash blocks (commitment per output)
  + padding to power-of-2 length
```

**Periodic columns** (26 total):
- `hash_flag`: 1 during rounds 0-6, 0 at hash boundary (period 8)
- ARK1/ARK2: Rescue Prime round constants for the AIR transitions

**Balance correctness**: the running sum (`column 25`) starts at 0, accumulates `+value` for each input block and `-value` for each output block, and must equal `fee` at the final step. This enforces the balance equation without revealing individual values.

---

## 13. P2P Session Key Establishment

### 13.1 Full Protocol

```
Initiator (I)                              Responder (R)

1. I → R:  Hello { version, node_id, kem_pk_I, listen_addr }
   R → I:  Hello { version, node_id, kem_pk_R, listen_addr }
           Both: reject if version mismatch.

2. I:      (ss, ct) = KEM.Enc(kem_pk_R)
           session_key = H_d("umbra.session", ss)
   I → R:  ct

3. R:      ss = KEM.Dec(kem_sk_R, ct)
           session_key = H_d("umbra.session", ss)
           (Both now share session_key)

4. I:      auth_data = H_d("umbra.auth", ss || kem_pk_I || kem_pk_R)
           sig_I = Sign(sk_I, auth_data)
   I → R:  AEAD.Enc(session_key, nonce_I, sig_I)

5. R:      sig_I = AEAD.Dec(session_key, nonce_I, ...)
           Verify(pk_I, auth_data, sig_I) -- authenticate initiator

6. R:      sig_R = Sign(sk_R, auth_data)
   R → I:  AEAD.Enc(session_key, nonce_R, sig_R)

7. I:      sig_R = AEAD.Dec(session_key, nonce_R, ...)
           Verify(pk_R, auth_data, sig_R) -- authenticate responder

8. Encrypted transport: all messages AEAD-encrypted with monotonic nonces.
   Frames padded to next multiple of 1024 bytes.
```

### 13.2 Session Key Properties

| Property | Status | Notes |
|---|---|---|
| Confidentiality | Yes | ChaCha20-Poly1305 encryption |
| Integrity | Yes | Poly1305 MAC |
| Mutual authentication | Yes | Both sides sign handshake transcript |
| Post-compromise security | Partial | Periodic rekeying planned |
| Forward secrecy | No | Static KEM keypair; see below |
| Quantum resistance | Yes | Kyber1024 KEM; Dilithium5+SPHINCS+ auth |

**Forward secrecy limitation**: the node's KEM keypair is static and long-lived. If an adversary records all session traffic and later compromises the KEM secret key, they can recompute `ss` for all past sessions and decrypt them. True forward secrecy requires ephemeral per-connection KEM keys.

---

## 14. Binding and Domain Separation

### 14.1 Transaction Content Hash

The transaction content hash binds all malleable transaction fields to prevent signature reuse across modified transactions:

```
tx_content_hash = H_concat(
    [len(inputs)],
    for each input i:
        inputs[i].nullifier || inputs[i].proof_link,
    [len(outputs)],
    for each output j:
        outputs[j].commitment
        || [len(kem_ct_j)] || kem_ct_j        // stealth address KEM ciphertext
        || one_time_key_j
        || [len(note_kem_ct_j)] || note_kem_ct_j  // note encryption KEM ciphertext
        || [len(note_ciphertext_j)] || note_ciphertext_j,
    [fee],
    [timestamp]
)
```

The `kem_ciphertext` fields are included to close the malleability gap: without binding the KEM ciphertexts, an adversary could swap the ciphertext on an existing valid transaction and redirect funds to a different recipient without invalidating the signature.

### 14.2 Domain Labels

All Umbra domain-separated hash calls use ASCII prefixes registered here:

| Domain | Usage |
|---|---|
| `"umbra.txid"` | Transaction ID derivation |
| `"umbra.vertex"` | Vertex ID derivation |
| `"umbra.epoch"` | Epoch seed derivation |
| `"umbra.vote"` | BFT vote signing |
| `"umbra.auth"` | P2P handshake authentication |
| `"umbra.session"` | P2P session key derivation |
| `"umbra.stealth"` | Stealth address one-time key |
| `"umbra.spend_auth"` | Spending authorization key |
| `"umbra.vrf.output"` | VRF output derivation |
| `"umbra.vrf.proof"` | VRF proof derivation |
| `"umbra.dereg"` | Validator deregistration signing |
| `"umbra.validator"` | Validator ID derivation |
| `"umbra.null"` | Nullifier derivation domain |

---

## 15. References

### Standards

1. NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM / Kyber).
2. NIST FIPS 204 — Module-Lattice-Based Digital Signature Algorithm (ML-DSA / Dilithium).
3. NIST FIPS 205 — Stateless Hash-Based Digital Signature Algorithm (SLH-DSA / SPHINCS+).
4. RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols (2018).
5. RFC 9381 — Verifiable Random Functions (VRFs) v10 (2023).

### Papers

6. Aumasson, J., O'Connor, J., Aaberg, S., Arcieri, B. (2020). "BLAKE3: One function, fast everywhere." [https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf]
7. Aly, A., Ashur, T., Ben-Sasson, E., Dhooghe, S., Szepieniec, A. (2020). "Design of Symmetric-Key Primitives for Advanced Cryptographic Protocols." IACR ePrint 2019/426.
8. Szepieniec, A., Ashur, T., Dhooghe, S. (2020). "Rescue-Prime: a Standard Specification (SoK)." IACR ePrint 2020/1143.
9. Ben-Sasson, E., Bentov, I., Horesh, Y., Riabzev, M. (2018). "Scalable, transparent, and post-quantum secure computational integrity." IACR ePrint 2018/046.
10. Ducas, L., et al. (2021). "CRYSTALS-Dilithium Algorithm Specifications and Supporting Documentation." NIST PQC Round 3 submission. [https://pq-crystals.org/dilithium/]
11. Bernstein, D.J., et al. (2022). "SPHINCS+: Stateless Hash-Based Signatures." NIST PQC Round 3 submission. [https://sphincs.org/]
12. Bos, J., et al. (2021). "CRYSTALS-Kyber Algorithm Specifications." NIST PQC Round 3 submission. [https://pq-crystals.org/kyber/]
13. Fiat, A., Shamir, A. (1986). "How to prove yourself: Practical solutions to identification and signature problems." CRYPTO 1986.
14. Bonneau, J., et al. (2020). "Zcash Protocol Specification." ECC. [https://zips.z.cash/protocol/protocol.pdf] (reference for shielded transaction design patterns)
15. Möser, M., et al. (2017). "An Empirical Analysis of Traceability in the Monero Blockchain." PoPETs 2018/3. (motivates stealth address design)
16. Fanti, G., Venkatakrishnan, S.B., Bhatt, S., Yerlan, A., Viswanath, P. (2018). "Dandelion++: Lightweight Cryptocurrency Networking with Formal Anonymity Guarantees." ACM SIGMETRICS 2018.

### Implementation Libraries

17. `winterfell` — STARK prover/verifier in Rust. [https://github.com/facebook/winterfell]
18. `pqcrypto` — Rust bindings to PQClean reference implementations. [https://github.com/rustpq/pqcrypto]
19. `blake3` — Official BLAKE3 Rust implementation. [https://github.com/BLAKE3-team/BLAKE3]
20. `chacha20poly1305` — RustCrypto ChaCha20-Poly1305 implementation. [https://github.com/RustCrypto/AEADs]
