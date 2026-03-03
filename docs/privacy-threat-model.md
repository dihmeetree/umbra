# Umbra Privacy Threat Model

Version: 0.1.0-draft
Status: Living document
Last updated: 2026-03-03

---

## Table of Contents

1. [Privacy Goals](#1-privacy-goals)
2. [What Is On-Chain](#2-what-is-on-chain)
3. [Transaction Graph Privacy](#3-transaction-graph-privacy)
4. [Sender Privacy](#4-sender-privacy)
5. [Receiver Privacy](#5-receiver-privacy)
6. [Amount Privacy](#6-amount-privacy)
7. [Network-Level Privacy](#7-network-level-privacy)
8. [Validator Privacy](#8-validator-privacy)
9. [Metadata Privacy](#9-metadata-privacy)
10. [Privacy Failure Modes](#10-privacy-failure-modes)
11. [Comparison with Other Privacy Protocols](#11-comparison-with-other-privacy-protocols)

---

## 1. Privacy Goals

Umbra's privacy design targets the following properties:

| Goal | Definition |
|---|---|
| **Transaction graph unlinkability** | An observer cannot link a specific input to a specific output |
| **Sender anonymity** | An observer cannot determine which party initiated a transaction |
| **Receiver anonymity** | An observer cannot determine who received funds from a transaction |
| **Amount hiding** | An observer cannot learn the value of any input or output |
| **Network origin privacy** | An observer cannot determine which node first broadcast a transaction |
| **Message privacy** | On-chain encrypted messages are readable only by the intended recipient |

These goals are achieved through a combination of cryptographic constructions, protocol design, and network-layer mechanisms. No single mechanism provides all goals; they compose to form the overall privacy guarantee.

---

## 2. What Is On-Chain

Understanding what an adversary can observe is the foundation of the privacy analysis.

### 2.1 Publicly Visible

The following data is visible to any party who reads the DAG:

| Data | What It Reveals |
|---|---|
| `Nullifier` (32 bytes) | That some output was spent; not which output or by whom |
| `proof_link` (32 bytes) | A one-way binding between a spend proof and a balance proof; not the commitment |
| `StealthAddress.one_time_key` (32 bytes) | A per-output identifier; not linked to any party |
| `StealthAddress.kem_ciphertext` (1568 bytes) | Opaque Kyber ciphertext; reveals nothing without the recipient's secret key |
| `TxOutput.commitment` (32 bytes) | A Rescue Prime commitment to (value, blinding); reveals neither value nor blinding |
| `EncryptedNote.kem_ciphertext` (1568 bytes) | Opaque Kyber ciphertext for note encryption |
| `EncryptedNote.ciphertext` (≤ 256 bytes) | Encrypted (version, value, blinding); opaque without recipient key |
| `transaction.fee` | The fee in base units (plaintext) |
| `BalanceStarkProof` | A validity proof; reveals no private values |
| `SpendStarkProof` | A validity proof per input; reveals no private values |
| Vertex proposer public key | Validator pseudonym (not linked to real-world identity by protocol) |
| Vertex timestamp | Approximate time of vertex creation |
| Vertex parents | DAG structure; provides causal ordering |

### 2.2 Not Visible On-Chain

| Data | Protection Mechanism |
|---|---|
| Transaction amounts | Rescue Prime commitments |
| Blinding factors | Never revealed; proven in STARK |
| Sender identity | No public key or signature links sender to inputs |
| Recipient identity | One-time stealth addresses; KEM ciphertext opaque |
| Input-output links | `commitment` never published; `proof_link` is one-way |
| Message content | XChaCha20-Poly1305 encryption; only recipient can decrypt |

---

## 3. Transaction Graph Privacy

### 3.1 The Core Design

In a transparent cryptocurrency (e.g., Bitcoin), each input explicitly references a prior output, creating a visible directed graph. An analyst can traverse this graph to trace fund flows.

Umbra breaks the transaction graph at two levels:

**Level 1 — Commitment hiding**: an output is represented by a `commitment = RP(value, blinding)`. The commitment does not reveal the value. When an output is spent, its commitment is never revealed — the spender only reveals:
- The `nullifier = RP(spend_auth, commitment)`.
- The `proof_link = RP(commitment, nonce)`.

Neither the nullifier nor the proof_link can be linked to the commitment without knowing `spend_auth` or `nonce`.

**Level 2 — Proof linkage only**: the only on-chain link between an input and the output being spent is through the STARK proof. The STARK proof attests that the prover knows a `commitment` that:
1. Matches the claimed nullifier.
2. Is a leaf in the global Merkle tree.
3. Matches the claimed proof_link.

The commitment itself is a private witness — it never appears in the public inputs of either proof.

### 3.2 Proof-Link Privacy

The `proof_link` links the `SpendStarkProof` (which verifies nullifier correctness and Merkle membership) to the `BalanceStarkProof` (which verifies amount conservation). This linking is necessary for correctness.

The `proof_link` is computed as:
```
proof_link = RP(commitment, link_nonce)
```
where `link_nonce` is a random value chosen by the prover.

Properties:
- Given `proof_link` and `commitment`, one can verify the link.
- Given only `proof_link`, finding `commitment` requires inverting Rescue Prime (computationally infeasible).
- Different spends of the same output produce different `proof_link` values (because `link_nonce` is random).

The result is that the proof_link is a one-way, randomized binding between the two proofs. It prevents double-linking attacks (using the same proof_link for different spend-balance proof pairs) without revealing which output is being spent.

---

## 4. Sender Privacy

### 4.1 No Sender Field

Unlike transparent transactions, Umbra transactions contain no explicit sender public key or address. The `TxInput` contains only:
- `nullifier`: identifies the UTXO being spent (but not the owner).
- `proof_link`: one-way binding.
- `spend_proof`: validity proof.

There is no signature over the transaction from the sender's long-term key.

### 4.2 Spending Authorization

Spending authority is established cryptographically through the STARK proof:
- The prover knows the `spend_auth` key that maps to the claimed nullifier.
- The `spend_auth` key is derived from the stealth address shared secret, which is unique per output.
- The prover knows the Merkle path to the commitment.

No long-term signing key is ever used in a transaction input — the signing keys are used only for validator operations.

### 4.3 Sender Anonymity Set

An observer who sees a nullifier `N` cannot determine which commitment was spent without enumerating all known commitments and checking `RP(spend_auth_i, C_i) == N`. Since `spend_auth` is a secret derived from a per-output Kyber shared secret, this is computationally infeasible.

**Anonymity set**: the sender's anonymity set consists of all unspent commitments in the global Merkle tree (all outputs ever created). The Merkle tree has depth 20, accommodating up to 2^20 outputs.

---

## 5. Receiver Privacy

### 5.1 Stealth Address Protocol

Each transaction output uses a unique one-time stealth address. The protocol (Kyber-based):

```
Sender (Alice) sends to recipient (Bob) who has KEM public key pk_B:

1. Alice encapsulates: (ss, ct) = KEM.Enc(pk_B)
2. Alice derives one-time key: otk = H_d("umbra.stealth", ss || output_index)
3. On-chain output: { one_time_key=otk, kem_ciphertext=ct, commitment, encrypted_note }

Bob scans:
4. For each output: ss' = KEM.Dec(sk_B, ct)
5. Compute: otk' = H_d("umbra.stealth", ss' || output_index)
6. If otk' == output.one_time_key: this output belongs to Bob
7. Bob derives spend_auth from ss' and uses it to construct SpendStarkProof
```

### 5.2 Receiver Unlinkability

Since `one_time_key` is derived from a per-transaction Kyber shared secret:
- Each output has a unique `one_time_key`.
- Two outputs sent to the same recipient have independent, uncorrelated `one_time_key` values.
- An observer cannot determine that two outputs were sent to the same recipient.

**Receiver anonymity set**: the receiver's anonymity set is all parties whose KEM public key could have been used to derive the observed `kem_ciphertext`. Without the recipient's secret key, an adversary cannot determine if any particular party received the output.

### 5.3 Scanning Cost

Recipients must scan all transaction outputs to detect funds sent to them. This is O(n) in the number of outputs. For light clients, this is performed offline against downloaded output data. Scanning cannot be delegated without revealing the scanning key.

---

## 6. Amount Privacy

### 6.1 Rescue Prime Commitments

Output values are committed using Rescue Prime:
```
commitment = RP(value, blinding_factor)
```
where `blinding_factor` is a 32-byte random value chosen by the sender.

Properties:
- **Hiding**: given `commitment`, no PPT adversary can learn `value` without `blinding_factor` (computational hiding).
- **Binding**: no PPT adversary can find `(value', r')` with `RP(value', r') == RP(value, r)` and `(value', r') != (value, r)` (computational binding).

A hybrid commitment approach is used: the commitment is dual-bound using both Rescue Prime (for STARK circuit compatibility) and BLAKE3-512 (for classical preimage hardness). Both bindings must be broken to forge a commitment.

### 6.2 Balance Proof

The `BalanceStarkProof` proves in zero knowledge:
1. Each input commitment opens to a value `v_i` with blinding `r_i`.
2. Each output commitment opens to a value `w_j` with blinding `s_j`.
3. The balance equation holds: `sum(v_i) = sum(w_j) + fee`.
4. All values lie in `[0, 2^59)` — range proof.

The STARK proof reveals no information about individual values. The verifier learns only that the balance equation holds for some valid (private) values.

### 6.3 Range Proof

The range constraint `v ∈ [0, 2^59)` is enforced by bit decomposition in the STARK trace (59-bit range). This prevents:
- **Field overflow**: a commitment to a negative value (via field arithmetic) that, when added to other commitments, equals a valid sum.
- **Inflation**: creating outputs whose sum exceeds the sum of inputs by exploiting field wrap-around.

### 6.4 Fee Visibility

Transaction fees are plaintext — validators must be able to evaluate fee rate for mempool ordering without access to private data. The fee is included in the balance proof, so it is correctly subtracted from the output sum.

---

## 7. Network-Level Privacy

### 7.1 Dandelion++ Transaction Routing

Transactions are broadcast using Dandelion++ to prevent network-level linkability of transactions to their originating node:

```
Stem phase (2 hops):
  Node A (originator) → forwards to random peer B
  Peer B → forwards to random peer C (with random delay 100-500ms)
  After DANDELION_TIMEOUT_MS (5s) without acknowledgment: C fluffs

Fluff phase:
  C broadcasts transaction to all peers normally
```

**Privacy model**: a passive observer who sees a transaction broadcast during the fluff phase cannot easily determine whether the broadcasting node (C) or one of the stem nodes (A, B) is the originator.

**Limitations**:
- A global passive adversary who observes all network traffic can correlate timing: if A → B timing is observed shortly before B → C, and then C fluffs, the adversary can infer A is the originator.
- The 2-hop stem is a probabilistic mechanism: it provides plausible deniability rather than cryptographic anonymity.
- An adversary who controls a stem-phase hop (peer B or C) learns the transaction before it is broadcast, but cannot identify A without observing the A → B message.

### 7.2 Frame Padding

All P2P frames are padded to the next multiple of `P2P_PADDING_BUCKET = 1024` bytes. This prevents an adversary from classifying message types by size alone.

**Limitations**: padding reduces but does not eliminate size fingerprinting. An adversary may still distinguish, for example, a vertex (which includes STARK proofs) from a simple ping based on the number of frames.

### 7.3 Encryption

All session traffic is encrypted with ChaCha20-Poly1305 AEAD. An adversary with passive network access cannot read message contents. Combined with frame padding, traffic analysis is limited to:
- Connection timing and frequency.
- Approximate message sizes (within 1024-byte buckets).

---

## 8. Validator Privacy

### 8.1 Validator Pseudonymity

Validators are identified by their signing public key (`validator_id = H(pk_dilithium || pk_sphincs)`). This key is:
- Required for committee participation (proposing and voting).
- Visible on-chain in all vertices produced by that validator.

**Validator pseudonymity**: validator identities are pseudonymous — not linked to real-world identities by the protocol. However, if a validator's IP address or operational patterns are observed, real-world identity may be inferable through external means.

### 8.2 Validator Transactions

When a validator registers or deregisters, the on-chain record reveals:
- The `validator_id` (public key hash).
- The bond commitment (not the bond amount directly; amount is proven in STARK).

The bond amount is not directly revealed — it is committed in the standard output format and proven correct via `BalanceStarkProof`. However, the required bond amount is a public function of the validator count `n`, so an observer who knows `n` at registration time can infer the bond amount within a small range.

---

## 9. Metadata Privacy

### 9.1 Encrypted Attachments

Transactions may carry up to 16 encrypted messages (up to 1 MiB each), encrypted to a recipient's KEM public key using XChaCha20-Poly1305. All metadata (routing tags, message type) is inside the ciphertext — no plaintext metadata is exposed on-chain.

**Recipient identification**: the message's `EncryptedNote.kem_ciphertext` serves as the recipient indicator. Only the holder of the corresponding KEM secret key can decrypt. An observer cannot determine the recipient without the recipient's secret key.

### 9.2 Timestamp Leakage

Vertex timestamps are approximate (within `MAX_VERTEX_TIMESTAMP_DRIFT_SECS = 60s` of the local clock). They reveal when a vertex was proposed but not when constituent transactions were created (a transaction may sit in the mempool for some time before inclusion).

### 9.3 Fee Information

Transaction fees are plaintext. An observer may infer rough transaction priorities or urgency from fee rates. No other metadata about the transaction is exposed.

---

## 10. Privacy Failure Modes

### 10.1 Reuse of Scanning Key

If a recipient reuses their KEM public key across multiple identities (e.g., a single `pk_B` for multiple accounts), an observer who knows `pk_B` can link all outputs to the same party. **Each identity should use a unique KEM key pair.**

### 10.2 Timing Correlation

If Alice sends a transaction immediately after receiving funds (and no other user does the same), a timing analyst may correlate the incoming and outgoing transactions. This is a fundamental limitation of any UTXO-based system.

### 10.3 Amount Correlation

Even without seeing amounts, an adversary may correlate transactions by fee:
- If Alice consistently uses a fee of exactly 1000 base units, her transactions may be distinguishable from those of other users.
- No protocol-level countermeasure currently exists for fee-based fingerprinting.

### 10.4 Graph Analysis with Known Parties

If an adversary knows that Alice sent 100 coins to Bob, and they can observe:
- When outputs appeared in the DAG.
- When nullifiers were revealed.

They may narrow the transaction graph significantly. Complete privacy is only achieved if the anonymity set is large.

### 10.5 Compromised Recipient Key

If a recipient's KEM secret key is compromised, an adversary can:
- Retroactively decrypt all `EncryptedNote` payloads for outputs addressed to that key.
- Derive `spend_auth` for those outputs (since it is derived from the KEM shared secret).
- Identify which outputs belong to that recipient.

Compromising the signing key does not additionally compromise transaction privacy (signing keys are used only for validator operations, not for spending UTXOs).

### 10.6 Adversary Controlling Multiple Stem Nodes

In Dandelion++ with only 2 stem hops, an adversary who controls all peers of the originating node controls the first stem hop. If they also control all peers of the first stem hop, they control both hops and can trivially identify the originator. This is an eclipse attack combined with Dandelion++ correlation.

---

## 11. Comparison with Other Privacy Protocols

| Property | Transparent (Bitcoin) | Confidential (Monero RingCT) | zk-SNARK (Zcash Sapling) | Umbra |
|---|---|---|---|---|
| Amount hiding | No | Yes | Yes | Yes |
| Sender anonymity | No (UTXO graph) | Yes (ring signatures) | Yes | Yes |
| Receiver anonymity | No | Yes (stealth) | Yes (diversified addr) | Yes (stealth via Kyber) |
| Graph unlinkability | No | Probabilistic (ring) | Yes | Yes |
| Quantum resistant | No | No | No (pairing-based) | Yes |
| Trusted setup | No | No | Yes (Sapling MPC) | No |
| ZK proof type | None | Ring/Bulletproofs | zk-SNARKs (Groth16) | zk-STARKs |
| Network privacy | Basic gossip | Basic gossip | Basic gossip | Dandelion++ |
| On-chain amounts | Visible | Hidden | Hidden | Hidden |
| Sender key exposure | On-chain | Not exposed | Not exposed | Not exposed |
