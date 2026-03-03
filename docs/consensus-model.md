# Umbra Consensus Model

Version: 0.1.0-draft
Status: Living document
Last updated: 2026-03-03

---

## Table of Contents

1. [Overview](#1-overview)
2. [System Model](#2-system-model)
3. [Proof of Verifiable Participation (PoVP)](#3-proof-of-verifiable-participation-povp)
4. [DAG Structure](#4-dag-structure)
5. [BFT Voting Protocol](#5-bft-voting-protocol)
6. [Safety Argument](#6-safety-argument)
7. [Liveness Argument](#7-liveness-argument)
8. [Epoch Rotation](#8-epoch-rotation)
9. [Slashing and Incentives](#9-slashing-and-incentives)
10. [Comparison with Other Mechanisms](#10-comparison-with-other-mechanisms)
11. [Known Limitations and Open Questions](#11-known-limitations-and-open-questions)

---

## 1. Overview

Umbra consensus is called **Proof of Verifiable Participation (PoVP)**. It combines:

- **Bonded validator set**: validators post a Sybil-resistance bond to join the active set.
- **VRF committee selection**: each epoch a committee of `K = 21` validators is chosen uniformly at random via a Verifiable Random Function.
- **DAG structure**: the ledger is a Directed Acyclic Graph allowing parallel vertex production.
- **Asynchronous BFT**: the committee runs an asynchronous Byzantine Fault Tolerant protocol to finalize vertices with instant deterministic finality.

The key invariant is:

> **A certified vertex is final.** No two certified vertices in the same epoch and round can conflict.

---

## 2. System Model

### 2.1 Participants

- `N`: total registered validators (1 ≤ N ≤ MAX_VALIDATORS = 10,000).
- `K`: BFT committee size per epoch (K = 21 normally; see §3.3).
- `f`: maximum Byzantine faults tolerated, `f = floor((K-1)/3)`.
- For K = 21: `f = 6`, so the protocol tolerates up to 6 Byzantine committee members.

### 2.2 Network Model

Umbra uses an **asynchronous network model** for correctness proofs:

- Messages may be arbitrarily delayed, reordered, or dropped.
- No bound on message delivery time is assumed (pure asynchrony).
- **Safety** (no two conflicting vertices certified) holds under asynchrony.
- **Liveness** (eventual progress) requires that eventually messages between honest nodes are delivered — the standard partial synchrony assumption.

This matches the standard result that deterministic BFT in a fully asynchronous network cannot guarantee both safety and liveness (FLP impossibility). Umbra's design is safe under asynchrony and live under partial synchrony.

### 2.3 Validator Behavior

Validators are classified as:

| Type | Behavior |
|---|---|
| **Honest** | Follow the protocol exactly |
| **Byzantine** | May behave arbitrarily: send conflicting votes, withhold messages, collude |

The protocol guarantees safety when at most `f` of the `K` committee members are Byzantine.

### 2.4 Cryptographic Assumptions

- VRF outputs are computationally indistinguishable from random (see [cryptographic-constructions.md]).
- Signatures are existentially unforgeable under adaptive chosen-message attack (EUF-CMA).
- Under these assumptions, Byzantine validators cannot forge votes from honest validators, and committee membership is verifiable.

---

## 3. Proof of Verifiable Participation (PoVP)

### 3.1 Bond Curve

Validators must post a bond to join the active set. The bond amount scales superlinearly with the number of active validators:

```
required_bond(n) = VALIDATOR_BASE_BOND × (1 + n / BOND_SCALING_FACTOR)
                 = 1,000,000 × (1 + n / 100)
```

For example:
- 0 validators registered: bond = 1,000,000
- 100 validators: bond = 2,000,000
- 1000 validators: bond = 11,000,000
- 10,000 validators: bond = 101,000,000

**Sybil cost**: registering `m` additional validators when `n` are already registered costs:
```
cost(n, m) = sum_{i=n}^{n+m-1} required_bond(i)
           ≈ 1,000,000 × m × (1 + (n + m/2) / 100)
```
This is superlinear in `m`: doubling the validator set requires more than doubling the total bond, making large-scale Sybil attacks increasingly expensive.

**Slashing cooldown**: after any slashing event, new registrations for `SLASH_REGISTRATION_COOLDOWN_EPOCHS = 10` epochs require `SLASH_BOND_MULTIPLIER = 3 × required_bond(n)`. This discourages immediately registering new validators to replace a slashed one.

### 3.2 Why Not Stake-Weighted Power

In Umbra, consensus power is **not** proportional to bond size. The bond is solely a Sybil resistance mechanism:

- Each registered validator has equal probability of joining the committee.
- A validator with 10× the minimum bond does not have 10× the voting power.
- All committee members have 1 vote.

This is a deliberate design choice to avoid the "rich get richer" dynamic of standard Proof of Stake.

### 3.3 Committee Selection via VRF

At the start of each epoch, the epoch seed is computed from the previous epoch's finalized state:

```
epoch_seed = H_d("umbra.epoch", prev_epoch_state_root)
```

Each active validator `v` with signing key `sk_v` evaluates:
```
(vrf_output_v, vrf_proof_v) = VRF.prove(sk_v, epoch_seed)
```

The VRF satisfies:
- **Uniqueness**: for a given `sk_v` and `epoch_seed`, there is exactly one `vrf_output_v`.
- **Verifiability**: `vrf_proof_v` convinces any verifier with `pk_v` that `vrf_output_v` is correct.
- **Pseudorandomness**: `vrf_output_v` is computationally indistinguishable from random to anyone who does not know `sk_v`.

**Threshold**: validators with `vrf_output_v < threshold` are committee members, where:
```
threshold = 2^256 / COMMITTEE_SIZE × min(N, COMMITTEE_SIZE)
```
(adjusted to get an expected committee size of exactly `COMMITTEE_SIZE`).

**If fewer than `MIN_COMMITTEE_SIZE = 7` qualify**: all active validators form the committee. This ensures liveness even with a small validator set.

**Properties of VRF selection**:
- **Unpredictability**: before the epoch seed is published, no validator can predict their own or others' committee status.
- **Non-manipulability**: the epoch seed is derived from the finalized state root — no single party controls it.
- **Verifiability**: any node can verify committee membership by checking the VRF proof.
- **Bias resistance**: the VRF output is uniform; no relationship between committee selection and bond size.

---

## 4. DAG Structure

### 4.1 DAG vs. Blockchain

A traditional blockchain is a linear chain: each block has exactly one parent. Umbra uses a DAG: each vertex may reference 1 to `MAX_PARENTS = 8` parent vertices. This has several implications:

| Property | Blockchain | Umbra DAG |
|---|---|---|
| Parallelism | Serial (one block at a time) | Parallel (multiple vertices per round) |
| Throughput | Limited by block interval | Higher (parallel proposal) |
| Ordering | Implicit in chain | Explicit via BFT |
| Forks | Resolved by longest chain | Impossible (instant finality) |

### 4.2 Vertex Structure

Each DAG vertex contains:
- `1 ≤ len(parents) ≤ MAX_PARENTS = 8`: causal references to previous vertices.
- `0 ≤ len(transactions) ≤ MAX_TXS_PER_VERTEX = 10,000` transactions.
- A `state_root`: the Merkle tree root after applying all transactions.
- A `signature` over the vertex ID.
- A `vrf_proof` demonstrating committee membership.

### 4.3 Causality and Ordering

The DAG naturally encodes causal ordering: vertex `A` causally precedes vertex `B` if `A` is an ancestor of `B` in the DAG. BFT finalization assigns a total order over the DAG's partial order.

**DAG finalization** (`Dag::finalize`): when a vertex is certified, it and all its causal ancestors are transitively finalized. The function returns `true` if newly finalized, `false` if already finalized — callers must handle both cases.

### 4.4 Pruning

Finalized vertices and their transactions may be pruned from memory once they have been persisted to storage. The DAG retains a sufficient window of recent vertices for ancestor resolution.

---

## 5. BFT Voting Protocol

### 5.1 Protocol Rounds

Within each epoch, consensus proceeds in rounds. Each round corresponds to a vertex being proposed by a committee leader.

```
Round r in epoch e:
  1. Leader (determined by round-robin over sorted committee) broadcasts vertex V.
  2. Committee members validate V:
     a. VRF proof verifies (proposer in committee).
     b. All parent vertices are known.
     c. State root matches computed root after applying transactions.
     d. All transactions pass validation.
     e. Timestamp within MAX_VERTEX_TIMESTAMP_DRIFT_SECS.
  3. Each validating member broadcasts:
     Vote { vertex_id=V.id, epoch=e, round=r, vote_type=VOTE, sig=Sign(sk, sign_data) }
     sign_data = H_d("umbra.vote", e || r || V.id || vote_type)
  4. When any node collects q = dynamic_quorum(K) valid votes for V.id:
     Certificate { vertex_id=V.id, epoch=e, votes=[...] }
     → vertex V is certified (final).
```

### 5.2 Quorum Function

```
dynamic_quorum(k) = floor(2k/3) + 1
```

For the standard committee size K = 21: `q = floor(42/3) + 1 = 15`.

This quorum ensures that any two quorum sets have at least `f + 1 = 7` honest members in common (by pigeonhole), which is the key to BFT safety.

### 5.3 Vote Validation

A vote is valid iff:
1. `voter` is a current committee member with a valid VRF proof on file.
2. `epoch` and `round` match the expected values.
3. `vote_type` is VOTE or COMMIT (both are included in `sign_data` to prevent type confusion).
4. `signature` verifies under `voter.signing_pk`.
5. No prior vote from this `voter` for this `(epoch, round)` pair exists in the local vote table.

Duplicate votes (same voter, same round) are silently dropped. They do not constitute equivocation unless they vote for **different** vertex IDs.

### 5.4 Certificate Validation

A certificate is valid iff:
1. It contains at least `q` valid votes.
2. All votes are for the same `vertex_id`.
3. All votes are from distinct committee members.
4. All votes satisfy §5.3.

---

## 6. Safety Argument

**Theorem**: No two conflicting vertices can both be certified in the same epoch and round.

**Proof sketch**:

Suppose for contradiction that two distinct vertices `V` and `V'` (with `V.id ≠ V'.id`) both receive certificates in epoch `e`, round `r`.

Let `Q` be the set of validators who voted for `V` (|Q| ≥ q).
Let `Q'` be the set who voted for `V'` (|Q'| ≥ q).

By the quorum intersection property:
```
|Q ∩ Q'| ≥ |Q| + |Q'| - K ≥ 2q - K = 2(floor(2K/3)+1) - K ≥ floor(K/3) + 2 > f
```

So at least `f + 1` validators voted for both `V` and `V'`. Since at most `f` are Byzantine, at least one honest validator voted for both — a contradiction, since honest validators cast at most one vote per `(epoch, round)` pair.

Therefore, no two conflicting vertices can both be certified. ∎

**Corollary**: the certified total order over vertices is consistent — no two certified vertices contradict each other.

---

## 7. Liveness Argument

**Theorem**: Under partial synchrony, if ≤ f committee members are Byzantine, the protocol eventually certifies every vertex proposed by an honest leader.

**Argument**:

Partial synchrony guarantees that after some unknown Global Stabilization Time (GST), all messages between honest nodes are delivered within some bound `Δ`.

After GST:
1. An honest leader proposes a valid vertex `V` and broadcasts it.
2. By time `GST + Δ`, all honest committee members receive `V`.
3. All honest members validate `V` (which succeeds, since the leader is honest).
4. All honest members broadcast their votes.
5. By time `GST + 2Δ`, all honest members receive all honest votes.
6. Since there are at least `K - f ≥ K - floor((K-1)/3)` honest members, and `K - floor((K-1)/3) ≥ q`, every honest node collects a quorum.
7. Every honest node forms and broadcasts a certificate.

Therefore, every vertex proposed by an honest leader is eventually certified after GST. ∎

**Note on FLP**: In a fully asynchronous network, no deterministic protocol can guarantee both safety and liveness. Umbra accepts this: safety holds unconditionally; liveness requires partial synchrony.

---

## 8. Epoch Rotation

### 8.1 Rotation Trigger

After `EPOCH_LENGTH = 1000` finalized vertices, the epoch rotates.

### 8.2 Rotation Procedure

The rotation order is strictly defined to avoid race conditions:

1. **Compute new committee** for epoch `N+1` using the current state root as the new epoch seed.
2. **Preserve committee history**: store the epoch `N` committee in `committee_history` for cross-epoch equivocation detection.
3. **Clear epoch caches**: reset vote tables and per-epoch seen sets.
4. **Activate new committee**: the epoch `N+1` committee begins proposing and voting.

**Critical ordering constraint**: step 1 (new committee computation) must complete before step 3 (cache clearing). Computing the committee requires the old state root, which would be unavailable after clearing.

### 8.3 Cross-Epoch Equivocation

Equivocation evidence may be submitted for votes cast in a previous epoch. The `committee_history` map retains committee membership for past epochs, allowing validators to verify that the equivocating voter was indeed on the relevant committee.

---

## 9. Slashing and Incentives

### 9.1 Slashable Offenses

| Offense | Evidence | Consequence |
|---|---|---|
| Equivocation (double vote) | `EquivocationEvidence` | Bond destroyed, permanent ban |

No other offenses currently trigger slashing. In particular:
- Liveness failures (not voting) are not currently slashed.
- Proposing an invalid vertex causes the vertex to be rejected, not slashing.

### 9.2 Honest Validator Incentives

Honest validators:
- Earn coinbase rewards (block rewards) by producing vertices.
- Earn a share of transaction fees included in their vertices.
- Risk bond loss only if they equivocate.

### 9.3 Validator Lifecycle

```
[Registered] → [Active/Committee-Eligible] → [Deregistering] → [Bond Returned]
                         ↓
               [Equivocation detected]
                         ↓
                    [Slashed/Banned]
```

A slashed validator's bond is permanently burned. They cannot deregister or reregister. Their bond commitment is nullified.

---

## 10. Comparison with Other Mechanisms

| Property | PoW | PoS | PoVP (Umbra) |
|---|---|---|---|
| Energy waste | High | None | None |
| Finality | Probabilistic | Probabilistic or instant | Instant, deterministic |
| Wealth proportionality | Compute-proportional | Stake-proportional | None (uniform random) |
| Sybil resistance | Hardware cost | Capital cost | Superlinear bond curve |
| Quantum resistance | No (hashcash) | No (ECDSA) | Yes (Dilithium5, SPHINCS+, Kyber) |
| Censorship resistance | Moderate | Moderate | Strong (random committee) |
| Committee predictability | N/A | Variable | Unpredictable before epoch |
| Trust required | Mining pools | Large stakers | Bond holders |

---

## 11. Known Limitations and Open Questions

### 11.1 VRF-Based Selection Bias

The VRF threshold selection provides a uniform expected committee size but has variance. In epochs where fewer than `MIN_COMMITTEE_SIZE` validators qualify, all validators serve — reducing unpredictability.

### 11.2 Nothing-at-Stake for Non-Equivocation

Validators who simply do not vote suffer no penalty. An extended liveness failure (many validators going offline) is not addressed by slashing. The protocol relies on social/economic incentives (forfeiting rewards) rather than cryptographic enforcement.

### 11.3 Epoch Seed Construction and Residual Predictability

The epoch seed is a two-layer VRF commitment beacon, **not** a plain hash of the state root:

```
bft_mix  = H(sorted validator_id || proof_commitment pairs from all votes in epoch N)
dag_mix  = H(sorted VRF output values from all finalized vertices in epoch N)
vrf_mix  = H("umbra.epoch.combined_mix" || bft_mix || dag_mix)

epoch_seed(N+1).seed = H("umbra.epoch.seed" || N || epoch_seed(N).seed
                          || state_root(N) || vrf_mix)
```

**BFT mix**: each validator who votes must submit their `proof_commitment = H(dilithium_sig)` before their proof is accepted. This is a commit-reveal: the commitment is bound before the epoch ends, and the validator cannot retroactively choose a different VRF output.

**DAG mix**: each finalized vertex proposer's VRF output value is included. VRF values are deterministic given the proposer's key and the epoch seed — proposers cannot choose a different value, only choose to not propose (which forfeits rewards). Values are sorted before hashing, so the result is independent of DAG traversal order.

**Residual grinding surface**: the last vertex proposer of epoch N can choose which transactions to include, affecting `state_root`. Since `state_root` is one input among several in the epoch seed, this influence is bounded and diluted by the VRF mixes. Coordinating the `state_root`, `bft_mix`, and `dag_mix` simultaneously to steer the next epoch seed requires controlling a large fraction of the epoch's committee — a much higher bar than controlling a single proposer.

**Residual predictability**: immediately after the last vertex of epoch N is certified, the full epoch seed for epoch N+1 is determined. The next committee is then computable by any observer. This brief predictability window is inherent to any deterministic randomness beacon derived from finalized state. A future improvement would incorporate external entropy (e.g., a threshold BLS beacon or a commit-reveal over multiple epochs).

### 11.4 Synchrony Assumption for Liveness

Liveness requires partial synchrony (eventual message delivery). Under sustained network partition or adversarial delay, the protocol may halt. This is unavoidable for any BFT protocol (FLP impossibility).

### 11.5 Committee Size Trade-off

The fixed committee size K = 21 was chosen to balance:
- Security: larger K → more Byzantine fault tolerance.
- Efficiency: BFT message complexity is O(K²).
- Decentralization: small K limits who participates per epoch.

With K = 21 and f = 6, the committee can tolerate up to 28.6% Byzantine members.

### 11.6 PoVP Committee Capture Probability

This section quantifies the relationship between the fraction α of Byzantine validators in the total set and the probability of adverse committee compositions in any given epoch.

**Model**: For large N (total validators), the number of Byzantine committee members X follows a Binomial distribution:

```
X ~ Binomial(k = 21, α)
```

Two thresholds matter:

| Threshold | Value | Meaning |
|---|---|---|
| Safety threshold f | 6 | BFT safety fails if X > f |
| Capture threshold t | 15 (= quorum) | Attacker has supermajority; can certify any vertex |

**Per-epoch probabilities** (Binomial(k=21, α) approximation):

| α (Byzantine fraction) | E[X] | P(X ≤ 6) = P(safe) | P(X ≥ 15) = P(capture) |
|---|---|---|---|
| 0.10 | 2.1 | ~99.9% | ~0% |
| 0.15 | 3.15 | ~99.5% | ~0% |
| 0.20 | 4.2 | ~97.4% | ~0% |
| 0.25 | 5.25 | ~92.0% | ~0% |
| 0.33 | 6.93 | ~41.4% | ~4 × 10⁻⁷ |
| 0.50 | 10.5 | ~6.8% | ~3.9% |
| 0.67 | 14.1 | ~0.8% | ~43.6% |

**Key observation at α = 1/3**: the expected Byzantine count (6.93) slightly exceeds f = 6. The probability of a safe epoch is only ~41%. This means the traditional BFT claim "safe if α < 1/3 of total validators" provides weaker per-epoch guarantees than the absolute "≤ f Byzantine committee members" assumption of standard BFT. **Effective security requires α ≪ 1/3** — approximately α ≤ 0.15 for 99%+ per-epoch safety.

**Multi-epoch analysis**: assuming independent epoch sampling (see caveat below), the probability of at least one safety failure across E consecutive epochs is:

```
P(failure in E epochs) = 1 - P(safe)^E
```

| α | P(safe) per epoch | E for 1% cumulative failure risk |
|---|---|---|
| 0.10 | 99.9% | ~1,000 epochs |
| 0.15 | 99.5% | ~200 epochs |
| 0.20 | 97.4% | ~39 epochs |
| 0.25 | 92.0% | ~12 epochs |
| 0.33 | 41.4% | ~1 epoch |

**Independence caveat**: epoch seeds are chained — `seed(N+1)` depends on `seed(N)`. Epochs are therefore not fully independent. The two-layer VRF mix (§11.3) substantially improves independence by making each epoch seed depend on many validators' VRF contributions rather than a single state root, but perfect independence is not achieved. Under VRF aggregation, an attacker biasing seed(N) must control many contributors simultaneously, making correlated multi-epoch advantage negligible for α ≪ 1/3.

**Practical guidance**: for the current committee size K = 21, meaningful long-run security requires keeping the Byzantine fraction of the total validator set below approximately 15%. The superlinear bonding curve (§3.1) makes sustained high-α control economically costly but does not provide a cryptographic guarantee.

### 11.7 Registration Timing Attack and Mitigation

**Attack**: without a minimum bonding period, an attacker can transiently spike their fraction α of the validator set:

1. Wait until `EPOCH_LENGTH - 1` vertices before a target epoch T.
2. Register `m` new validators in the last vertex of epoch T-1 (they are eligible at epoch T under a 1-epoch delay).
3. Participate in epoch T with an elevated α, increasing the probability of adverse committee composition.
4. Deregister after epoch T, recovering bonds minus fees.

The attacker needs only to sustain the elevated stake for **one epoch** (~500 seconds at current target throughput). The bonding curve raises the cost of registering many validators, but if the expected gain from controlling a single epoch (e.g., biasing the epoch T+1 seed) exceeds the bond cost, the attack is economically rational.

**Mitigation**: `COMMITTEE_ELIGIBILITY_DELAY_EPOCHS = 2`.

A validator registered in epoch N has:
```
activation_epoch = N + COMMITTEE_ELIGIBILITY_DELAY_EPOCHS = N + 2
```

The validator is ineligible for committee selection in epochs N and N+1. To participate in epoch T, an attacker must register by epoch T-2. They must sustain the elevated validator count for at least 2 full epochs (~2,000 vertices, ~17 minutes at 500ms/vertex) before benefiting. This increases the capital cost of a transient spike by 2× and forces the attacker to commit earlier when the target is less certain.

**Remaining limitation**: the delay extends the attack window but does not eliminate it. A patient attacker who can maintain elevated stake across 2+ epochs remains a concern. Full mitigation would require a longer delay or a mechanism that makes validator set changes visible well in advance of their eligibility, enabling social detection.
