//! BFT (Byzantine Fault Tolerant) consensus for instant finality.
//!
//! Each epoch, a committee of validators runs BFT to agree on vertex ordering.
//! A vertex achieves finality once it receives BFT_QUORUM (2f+1) certifications.
//!
//! Protocol rounds:
//! 1. PROPOSE: Committee leader proposes a vertex
//! 2. VOTE: Committee members validate and vote
//! 3. CERTIFY: Once quorum votes received, vertex is certified (final)
//!
//! Properties:
//! - Safety: No two conflicting vertices can both be certified
//! - Liveness: Progress guaranteed with <= f Byzantine validators (f = (K-1)/3)
//! - Finality: Instant and deterministic once certified
//!
//! Security:
//! - Votes are bound to (epoch, round, vertex_id, vote_type) preventing cross-epoch replay
//! - Duplicate votes from the same validator are rejected
//! - Committee selection guarantees MIN_COMMITTEE_SIZE members for BFT safety

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::consensus::dag::VertexId;
use crate::crypto::keys::{KemPublicKey, Signature, SigningKeypair, SigningPublicKey};
use crate::crypto::vrf::{EpochSeed, VrfOutput};
use crate::Hash;

/// Evidence of equivocation: a validator voted for different vertices in the same round.
///
/// This is slashable misbehaviour. Honest validators produce at most one vote per round.
/// Both conflicting signatures are included so the evidence is independently verifiable
/// by any node without trusting the reporter.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    /// The misbehaving validator
    pub voter_id: Hash,
    /// Epoch in which equivocation occurred
    pub epoch: u64,
    /// Round in which equivocation occurred
    pub round: u64,
    /// The first vertex the validator voted for
    pub first_vertex: VertexId,
    /// The conflicting second vertex
    pub second_vertex: VertexId,
    /// Vote type of the first vote (needed for signature verification)
    pub first_vote_type: VoteType,
    /// Vote type of the second vote (needed for signature verification)
    pub second_vote_type: VoteType,
    /// Signature on the first vote (proves the validator signed for first_vertex)
    pub first_signature: Signature,
    /// Signature on the second vote (proves the validator signed for second_vertex)
    pub second_signature: Signature,
}

/// A validator registered in the system.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Validator {
    /// The validator's signing public key
    pub public_key: SigningPublicKey,
    /// KEM public key for receiving coinbase reward outputs.
    #[serde(default)]
    pub kem_public_key: Option<KemPublicKey>,
    /// The validator's unique ID (fingerprint of signing key)
    pub id: Hash,
    /// Whether currently active (bonded)
    pub active: bool,
    /// Epoch in which this validator becomes eligible for committee selection.
    /// Validators registered in epoch N have activation_epoch = N+1.
    /// Genesis validators have activation_epoch = 0.
    #[serde(default)]
    pub activation_epoch: u64,
}

impl Validator {
    pub fn new(public_key: SigningPublicKey) -> Self {
        let id = public_key.fingerprint();
        Validator {
            public_key,
            kem_public_key: None,
            id,
            active: true,
            activation_epoch: 0,
        }
    }

    pub fn with_kem(public_key: SigningPublicKey, kem_public_key: KemPublicKey) -> Self {
        let id = public_key.fingerprint();
        Validator {
            public_key,
            kem_public_key: Some(kem_public_key),
            id,
            active: true,
            activation_epoch: 0,
        }
    }

    /// Create a validator with a specified activation epoch.
    pub fn with_activation(
        public_key: SigningPublicKey,
        kem_public_key: KemPublicKey,
        activation_epoch: u64,
    ) -> Self {
        let id = public_key.fingerprint();
        Validator {
            public_key,
            kem_public_key: Some(kem_public_key),
            id,
            active: true,
            activation_epoch,
        }
    }
}

/// A vote from a committee member on a proposed vertex.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    /// The vertex being voted on
    pub vertex_id: VertexId,
    /// The voter's validator ID
    pub voter_id: Hash,
    /// The epoch number (prevents cross-epoch replay)
    pub epoch: u64,
    /// The round number
    pub round: u64,
    /// Vote type
    pub vote_type: VoteType,
    /// Signature over (epoch || vertex_id || round || vote_type)
    pub signature: Signature,
    /// VRF proof showing the voter was selected for this epoch's committee.
    #[serde(default)]
    pub vrf_proof: Option<VrfOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    /// Accept the proposed vertex
    Accept,
    /// Reject the proposed vertex
    Reject,
}

/// A finality certificate: proof that a vertex achieved BFT quorum.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Certificate {
    /// The certified vertex
    pub vertex_id: VertexId,
    /// The round in which certification occurred
    pub round: u64,
    /// The epoch
    pub epoch: u64,
    /// Signatures from quorum of committee members
    pub signatures: Vec<(Hash, Signature)>, // (validator_id, signature)
}

impl Certificate {
    /// Verify that the certificate has sufficient valid signatures.
    pub fn verify(&self, committee: &[Validator], chain_id: &Hash) -> bool {
        let committee_ids: HashSet<Hash> = committee.iter().map(|v| v.id).collect();
        let quorum = dynamic_quorum(committee.len());

        if self.signatures.len() < quorum {
            return false;
        }

        // L8: Reject certificates with an unreasonable number of signature entries.
        // A valid certificate can have at most committee.len() signatures (one per
        // member). Allow 2x as a generous upper bound to reject obvious spam without
        // risking false negatives from rounding.
        if self.signatures.len() > committee.len() * 2 {
            return false;
        }

        let mut valid_count = 0;
        let mut seen = HashSet::new();

        for (vid, sig) in &self.signatures {
            // Check voter is in committee and not duplicate
            if !committee_ids.contains(vid) || !seen.insert(*vid) {
                continue;
            }

            // Find the validator's public key
            if let Some(validator) = committee.iter().find(|v| v.id == *vid) {
                let msg = vote_sign_data(
                    &self.vertex_id,
                    self.epoch,
                    self.round,
                    &VoteType::Accept,
                    chain_id,
                );
                if validator.public_key.verify(&msg, sig) {
                    valid_count += 1;
                }
            }
        }

        valid_count >= quorum
    }
}

/// The BFT consensus state machine for one epoch.
pub struct BftState {
    /// Current epoch
    pub epoch: u64,
    /// Current round within the epoch
    pub round: u64,
    /// Chain identifier (prevents cross-chain vote replay)
    pub chain_id: Hash,
    /// The committee for this epoch
    pub committee: Vec<Validator>,
    /// Our validator keypair (if we're on the committee)
    our_keypair: Option<SigningKeypair>,
    /// Our validator ID
    our_id: Option<Hash>,
    /// Our VRF proof for this epoch (if we were selected)
    our_vrf_proof: Option<VrfOutput>,
    /// Votes collected for each vertex
    votes: HashMap<VertexId, Vec<Vote>>,
    /// Certificates issued
    certificates: HashMap<VertexId, Certificate>,
    /// Tracks (voter_id, round) -> VertexId for equivocation detection.
    /// An honest validator votes for exactly one vertex per round.
    round_votes: HashMap<(Hash, u64), VertexId>,
    /// Detected equivocation evidence (slashable misbehaviour)
    equivocations: Vec<EquivocationEvidence>,
    /// Epoch seed for VRF verification of votes (H1).
    epoch_seed: Option<EpochSeed>,
    /// Total validators for VRF is_selected check.
    total_validators: usize,
    /// VRF proof commitments for this epoch: validator_id -> proof_commitment.
    /// Once a validator's VRF commitment is first observed, subsequent VRF
    /// proofs from the same validator must match. This provides first-seen
    /// binding to prevent grinding after the initial commitment is locked in.
    vrf_commitments: HashMap<Hash, Hash>,
}

impl BftState {
    /// Create a new BFT state for an epoch.
    pub fn new(epoch: u64, committee: Vec<Validator>, chain_id: Hash) -> Self {
        BftState {
            epoch,
            round: 0,
            chain_id,
            committee,
            our_keypair: None,
            our_id: None,
            our_vrf_proof: None,
            votes: HashMap::new(),
            certificates: HashMap::new(),
            round_votes: HashMap::new(),
            equivocations: Vec::new(),
            epoch_seed: None,
            total_validators: 0,
            vrf_commitments: HashMap::new(),
        }
    }

    /// Set our keypair if we're a committee member.
    pub fn set_our_keypair(&mut self, keypair: SigningKeypair) {
        self.our_id = Some(keypair.public.fingerprint());
        self.our_keypair = Some(keypair);
    }

    /// Set our VRF proof for this epoch.
    pub fn set_our_vrf_proof(&mut self, vrf: VrfOutput) {
        self.our_vrf_proof = Some(vrf);
    }

    /// Set the epoch seed and total validators for VRF verification (H1).
    pub fn set_epoch_context(&mut self, epoch_seed: EpochSeed, total_validators: usize) {
        self.epoch_seed = Some(epoch_seed);
        self.total_validators = total_validators;
    }

    /// Register a VRF proof commitment for a validator (first-seen binding).
    ///
    /// Once registered, all subsequent VRF proofs from this validator in the
    /// current epoch must match this commitment. Returns false if a different
    /// commitment was already registered for this validator.
    pub fn register_vrf_commitment(&mut self, validator_id: Hash, commitment: Hash) -> bool {
        match self.vrf_commitments.get(&validator_id) {
            Some(existing) => crate::constant_time_eq(existing, &commitment),
            None => {
                self.vrf_commitments.insert(validator_id, commitment);
                true
            }
        }
    }

    /// Get the stored VRF commitment for a validator, if any.
    pub fn vrf_commitment(&self, validator_id: &Hash) -> Option<&Hash> {
        self.vrf_commitments.get(validator_id)
    }

    /// Get our VRF proof for this epoch.
    pub fn our_vrf_proof(&self) -> Option<&VrfOutput> {
        self.our_vrf_proof.as_ref()
    }

    /// Check if we're on the committee.
    pub fn is_committee_member(&self) -> bool {
        self.our_id
            .map(|id| self.committee.iter().any(|v| v.id == id))
            .unwrap_or(false)
    }

    /// Get the leader for the current round (round-robin among committee).
    ///
    /// **L9: Known trade-off -- predictable selection.** Round-robin leader
    /// rotation is deterministic and predictable: any observer who knows the
    /// committee order can predict which validator will propose in each round.
    /// This was chosen for simplicity and guaranteed liveness over unpredictable
    /// leader election. A VRF-based per-round leader election would improve
    /// unpredictability but adds complexity and latency. The committee itself
    /// is already selected via VRF, limiting the window of predictability to
    /// within a single epoch.
    pub fn leader(&self) -> Option<&Validator> {
        if self.committee.is_empty() {
            return None;
        }
        let idx = self.round as usize % self.committee.len();
        Some(&self.committee[idx])
    }

    /// Cast a vote on a vertex.
    pub fn vote(&mut self, vertex_id: VertexId, accept: bool) -> Option<Vote> {
        let keypair = self.our_keypair.as_ref()?;
        let our_id = self.our_id?;

        let vote_type = if accept {
            VoteType::Accept
        } else {
            VoteType::Reject
        };

        let msg = vote_sign_data(
            &vertex_id,
            self.epoch,
            self.round,
            &vote_type,
            &self.chain_id,
        );
        let signature = keypair.sign(&msg);

        let vote = Vote {
            vertex_id,
            voter_id: our_id,
            epoch: self.epoch,
            round: self.round,
            vote_type,
            signature,
            vrf_proof: self.our_vrf_proof.clone(),
        };

        self.receive_vote(vote.clone());
        Some(vote)
    }

    /// Process a received vote. Returns a Certificate if quorum is reached.
    pub fn receive_vote(&mut self, vote: Vote) -> Option<Certificate> {
        // Reject votes from wrong epoch
        if vote.epoch != self.epoch {
            return None;
        }

        // Reject votes from wrong round (prevents future-round vote injection)
        if vote.round != self.round {
            return None;
        }

        // Verify the voter is on the committee
        let voter = self.committee.iter().find(|v| v.id == vote.voter_id)?;

        // H1: Verify VRF proof on the vote to confirm the voter was genuinely selected.
        // Uses full verify() with commitment tracking to prevent VRF grinding.
        if let Some(seed) = &self.epoch_seed {
            if self.total_validators > self.committee.len() {
                // VRF mandatory — committee is a subset
                let vrf = match &vote.vrf_proof {
                    Some(v) => v,
                    None => return None,
                };
                let vrf_input = seed.vrf_input(&vote.voter_id);

                // Check against stored commitment (first-seen binding)
                match self.vrf_commitments.get(&vote.voter_id) {
                    Some(commitment) => {
                        // Subsequent VRF: must match pre-registered commitment
                        if !vrf.verify(&voter.public_key, &vrf_input, commitment) {
                            return None;
                        }
                    }
                    None => {
                        // First-seen: verify cryptographically, then lock commitment
                        if !vrf.verify_proof_only(&voter.public_key, &vrf_input) {
                            return None;
                        }
                        self.vrf_commitments
                            .insert(vote.voter_id, vrf.proof_commitment);
                    }
                }

                if !vrf.is_selected(crate::constants::COMMITTEE_SIZE, self.total_validators) {
                    return None;
                }
            } else if let Some(vrf) = &vote.vrf_proof {
                // VRF optional but verify if present (all validators on committee)
                let vrf_input = seed.vrf_input(&vote.voter_id);
                match self.vrf_commitments.get(&vote.voter_id) {
                    Some(commitment) => {
                        if !vrf.verify(&voter.public_key, &vrf_input, commitment) {
                            return None;
                        }
                    }
                    None => {
                        if !vrf.verify_proof_only(&voter.public_key, &vrf_input) {
                            return None;
                        }
                        self.vrf_commitments
                            .insert(vote.voter_id, vrf.proof_commitment);
                    }
                }
            }
        }

        // Verify the signature (bound to chain_id + epoch + round + vertex + vote_type)
        let msg = vote_sign_data(
            &vote.vertex_id,
            vote.epoch,
            vote.round,
            &vote.vote_type,
            &self.chain_id,
        );
        if !voter.public_key.verify(&msg, &vote.signature) {
            return None;
        }

        let vid = vote.vertex_id;

        // Check for equivocation: same voter, same round, different vertex.
        // An honest validator must vote for at most one vertex per round.
        let round_key = (vote.voter_id, vote.round);
        if let Some(&prev_vertex) = self.round_votes.get(&round_key) {
            if prev_vertex != vote.vertex_id {
                // H10: Only record one evidence per validator (one is enough to slash)
                let already_recorded = self
                    .equivocations
                    .iter()
                    .any(|e| e.voter_id == vote.voter_id);
                if !already_recorded {
                    // Retrieve the first signature and vote type from stored votes.
                    // Only produce evidence if the first signature is available;
                    // evidence with an empty signature is non-verifiable and useless
                    // for network-wide slashing.
                    if let Some(first_vote) = self
                        .votes
                        .get(&prev_vertex)
                        .and_then(|vs| vs.iter().find(|v| v.voter_id == vote.voter_id))
                    {
                        self.equivocations.push(EquivocationEvidence {
                            voter_id: vote.voter_id,
                            epoch: vote.epoch,
                            round: vote.round,
                            first_vertex: prev_vertex,
                            second_vertex: vote.vertex_id,
                            first_vote_type: first_vote.vote_type.clone(),
                            second_vote_type: vote.vote_type.clone(),
                            first_signature: first_vote.signature.clone(),
                            second_signature: vote.signature.clone(),
                        });
                    }
                }
                return None; // Reject equivocating vote
            }
        } else {
            self.round_votes.insert(round_key, vote.vertex_id);
        }

        let votes = self.votes.entry(vid).or_default();

        // Don't accept duplicate votes from the same validator
        if votes.iter().any(|v| v.voter_id == vote.voter_id) {
            return None;
        }

        votes.push(vote);

        // Check if we have quorum of Accept votes
        self.try_certify(&vid)
    }

    /// Try to certify a vertex if it has enough Accept votes.
    ///
    /// Design note (L6): Only `Accept` votes count toward quorum. `Reject` votes
    /// are recorded but do not prevent or contribute to finalization. This is
    /// intentional — rejections serve as advisory signals (observable via
    /// `rejection_count()`), and the proposer should re-propose if rejections
    /// are high. A vertex can only be finalized through positive quorum.
    fn try_certify(&mut self, vertex_id: &VertexId) -> Option<Certificate> {
        if self.certificates.contains_key(vertex_id) {
            return None; // Already certified
        }

        let votes = self.votes.get(vertex_id)?;
        let accept_votes: Vec<_> = votes
            .iter()
            .filter(|v| v.vote_type == VoteType::Accept)
            .collect();

        if accept_votes.len() < dynamic_quorum(self.committee.len()) {
            return None;
        }

        let signatures: Vec<(Hash, Signature)> = accept_votes
            .iter()
            .map(|v| (v.voter_id, v.signature.clone()))
            .collect();

        let cert = Certificate {
            vertex_id: *vertex_id,
            round: self.round,
            epoch: self.epoch,
            signatures,
        };

        self.certificates.insert(*vertex_id, cert.clone());
        Some(cert)
    }

    /// Check if a vote was accepted (exists in the vote set).
    /// Used to decide whether to re-broadcast a vote.
    pub fn is_vote_accepted(&self, vote: &Vote) -> bool {
        self.votes
            .get(&vote.vertex_id)
            .map(|votes| votes.iter().any(|v| v.voter_id == vote.voter_id))
            .unwrap_or(false)
    }

    /// Advance to the next round, clearing stale vote data from previous rounds.
    pub fn advance_round(&mut self) {
        // M10: Clear votes and round_votes from the completed round to prevent
        // unbounded memory growth.
        self.votes.clear();
        self.round_votes.clear();
        self.round += 1;
    }

    /// Clear processed equivocation evidence (call after slashing).
    pub fn clear_equivocations(&mut self) {
        self.equivocations.clear();
    }

    /// Verify equivocation evidence received from the network.
    ///
    /// Returns true if the evidence is cryptographically valid: epoch matches,
    /// voter is a committee member, vertices differ, and both signatures verify.
    pub fn verify_equivocation_evidence(&self, evidence: &EquivocationEvidence) -> bool {
        // Epoch must match current
        if evidence.epoch != self.epoch {
            return false;
        }
        // Voter must be a current committee member
        let voter = match self.committee.iter().find(|v| v.id == evidence.voter_id) {
            Some(v) => v,
            None => return false,
        };
        // Must be two different vertices (same vertex is not equivocation)
        if evidence.first_vertex == evidence.second_vertex {
            return false;
        }
        // Verify first signature
        let msg1 = vote_sign_data(
            &evidence.first_vertex,
            evidence.epoch,
            evidence.round,
            &evidence.first_vote_type,
            &self.chain_id,
        );
        if !voter.public_key.verify(&msg1, &evidence.first_signature) {
            return false;
        }
        // Verify second signature
        let msg2 = vote_sign_data(
            &evidence.second_vertex,
            evidence.epoch,
            evidence.round,
            &evidence.second_vote_type,
            &self.chain_id,
        );
        voter.public_key.verify(&msg2, &evidence.second_signature)
    }

    /// Advance to a new epoch, clearing all per-epoch state.
    pub fn advance_epoch(&mut self, epoch: u64, committee: Vec<Validator>) {
        self.epoch = epoch;
        self.round = 0;
        self.committee = committee;
        self.votes.clear();
        self.certificates.clear();
        self.round_votes.clear();
        self.equivocations.clear();
        self.our_vrf_proof = None;
        self.epoch_seed = None;
        self.total_validators = 0;
        self.vrf_commitments.clear();
    }

    /// Clear per-epoch caches without resetting round (preserves monotonicity).
    ///
    /// Used during epoch transitions in `finalize_vertex_inner` where we cannot
    /// call `advance_epoch()` because it resets the round to 0.
    pub fn clear_epoch_caches(&mut self) {
        self.votes.clear();
        self.certificates.clear();
        self.round_votes.clear();
        self.equivocations.clear();
        self.vrf_commitments.clear();
    }

    /// Get a certificate for a vertex.
    pub fn get_certificate(&self, vertex_id: &VertexId) -> Option<&Certificate> {
        self.certificates.get(vertex_id)
    }

    /// Get all certificates.
    pub fn all_certificates(&self) -> Vec<&Certificate> {
        self.certificates.values().collect()
    }

    /// Get all detected equivocation evidence.
    pub fn equivocations(&self) -> &[EquivocationEvidence] {
        &self.equivocations
    }

    /// Check how many reject votes a vertex has received.
    ///
    /// Note: rejections don't finalize — they're advisory only.
    /// Only `Accept` votes contribute to quorum and certification.
    /// The proposer or other validators should re-propose if rejection is high.
    pub fn rejection_count(&self, vertex_id: &VertexId) -> usize {
        self.votes
            .get(vertex_id)
            .map(|votes| {
                votes
                    .iter()
                    .filter(|v| v.vote_type == VoteType::Reject)
                    .count()
            })
            .unwrap_or(0)
    }
}

/// Select the committee for an epoch using VRF.
///
/// **Testing/simulation only.** This function requires secret keys for all
/// validators to evaluate VRF proofs locally. In production, use
/// [`select_committee_from_proofs`] which accepts already-verified VRF
/// outputs received over the network.
///
/// If VRF-based selection produces fewer than `MIN_COMMITTEE_SIZE` members,
/// all active validators are included (sorted by VRF output) to guarantee
/// BFT safety.
pub fn select_committee(
    epoch_seed: &EpochSeed,
    validators: &[(SigningKeypair, Validator)],
    committee_size: usize,
) -> Vec<(Validator, VrfOutput)> {
    let total = validators.len();
    let mut candidates: Vec<(Validator, VrfOutput)> = Vec::new();

    let current_epoch = epoch_seed.epoch;
    for (keypair, validator) in validators {
        if !validator.active || validator.activation_epoch > current_epoch {
            continue;
        }
        let input = epoch_seed.vrf_input(&validator.id);
        let vrf_output = VrfOutput::evaluate(keypair, &input);

        if vrf_output.is_selected(committee_size, total) {
            candidates.push((validator.clone(), vrf_output));
        }
    }

    // Ensure minimum committee size for BFT safety
    let used_fallback = candidates.len() < crate::constants::MIN_COMMITTEE_SIZE;
    if used_fallback {
        // Fall back: include all eligible validators sorted by VRF
        candidates.clear();
        for (keypair, validator) in validators {
            if !validator.active || validator.activation_epoch > current_epoch {
                continue;
            }
            let input = epoch_seed.vrf_input(&validator.id);
            let vrf_output = VrfOutput::evaluate(keypair, &input);
            candidates.push((validator.clone(), vrf_output));
        }
    }

    // Sort by VRF output to get deterministic ordering
    candidates.sort_by_key(|(_, vrf)| vrf.sort_key());

    // Only truncate if we had enough from VRF (not fallback).
    // In fallback mode, all eligible validators must be included to
    // guarantee MIN_COMMITTEE_SIZE for BFT safety.
    if !used_fallback {
        candidates.truncate(committee_size);
    }
    candidates
}

/// Select the committee from already-verified VRF proofs.
///
/// Unlike [`select_committee`], this function does not require secret keys.
/// Each caller is responsible for verifying VRF proofs (via
/// [`VrfOutput::verify`] or [`Vertex::validate_vrf`]) before passing them
/// in. This is the production-ready API for committee selection from
/// network-received VRF outputs.
///
/// `proofs` contains `(Validator, VrfOutput)` pairs for all validators that
/// submitted VRF proofs for this epoch. Only active validators whose
/// activation epoch has passed and whose VRF output selects them will be
/// included.
///
/// If VRF-based selection produces fewer than `MIN_COMMITTEE_SIZE` members,
/// all eligible validators are included (sorted by VRF output) to guarantee
/// BFT safety.
pub fn select_committee_from_proofs(
    epoch_seed: &EpochSeed,
    proofs: &[(Validator, VrfOutput)],
    committee_size: usize,
) -> Vec<(Validator, VrfOutput)> {
    let total = proofs.len();
    let mut candidates: Vec<(Validator, VrfOutput)> = Vec::new();

    let current_epoch = epoch_seed.epoch;
    for (validator, vrf_output) in proofs {
        if !validator.active || validator.activation_epoch > current_epoch {
            continue;
        }
        if vrf_output.is_selected(committee_size, total) {
            candidates.push((validator.clone(), vrf_output.clone()));
        }
    }

    // Ensure minimum committee size for BFT safety
    let used_fallback = candidates.len() < crate::constants::MIN_COMMITTEE_SIZE;
    if used_fallback {
        // Fall back: include all eligible validators sorted by VRF
        candidates.clear();
        for (validator, vrf_output) in proofs {
            if !validator.active || validator.activation_epoch > current_epoch {
                continue;
            }
            candidates.push((validator.clone(), vrf_output.clone()));
        }
    }

    // Sort by VRF output to get deterministic ordering
    candidates.sort_by_key(|(_, vrf)| vrf.sort_key());

    // Only truncate if we had enough from VRF (not fallback).
    if !used_fallback {
        candidates.truncate(committee_size);
    }
    candidates
}

/// Create a vote for a vertex.
///
/// This is a convenience function for use by the node when it needs to
/// vote on an incoming vertex without going through BftState.
pub fn create_vote(
    vertex_id: VertexId,
    keypair: &SigningKeypair,
    epoch: u64,
    round: u64,
    accept: bool,
    chain_id: &Hash,
    vrf_proof: Option<VrfOutput>,
) -> Vote {
    let vote_type = if accept {
        VoteType::Accept
    } else {
        VoteType::Reject
    };
    let msg = vote_sign_data(&vertex_id, epoch, round, &vote_type, chain_id);
    let signature = keypair.sign(&msg);
    Vote {
        vertex_id,
        voter_id: keypair.public.fingerprint(),
        epoch,
        round,
        vote_type,
        signature,
        vrf_proof,
    }
}

/// Compute the dynamic BFT quorum for a given committee size: 2/3 + 1.
pub fn dynamic_quorum(committee_size: usize) -> usize {
    (committee_size * 2) / 3 + 1
}

/// Data signed for a vote (epoch-bound and chain-bound to prevent replay).
///
/// Uses manual concatenation rather than `hash_concat()` because:
/// 1. All fields are fixed-size (domain tag, chain_id 32B, epoch 8B, vertex_id 32B,
///    round 8B, vote_type 1B), so length-prefix framing is unnecessary.
/// 2. The result is used as raw sign input for `keypair.sign()`, not as a hash
///    input to `hash_domain()`. Signing already handles its own hashing internally.
pub fn vote_sign_data(
    vertex_id: &VertexId,
    epoch: u64,
    round: u64,
    vote_type: &VoteType,
    chain_id: &crate::Hash,
) -> Vec<u8> {
    let type_byte = match vote_type {
        VoteType::Accept => 1u8,
        VoteType::Reject => 0u8,
    };
    let mut data = Vec::with_capacity(93);
    data.extend_from_slice(b"umbra.vote");
    data.extend_from_slice(chain_id);
    data.extend_from_slice(&epoch.to_le_bytes());
    data.extend_from_slice(&vertex_id.0);
    data.extend_from_slice(&round.to_le_bytes());
    data.push(type_byte);
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::SigningKeypair;

    fn make_committee(n: usize) -> (Vec<SigningKeypair>, Vec<Validator>) {
        let mut keypairs = Vec::new();
        let mut validators = Vec::new();
        for _ in 0..n {
            let kp = SigningKeypair::generate();
            let v = Validator::new(kp.public.clone());
            keypairs.push(kp);
            validators.push(v);
        }
        (keypairs, validators)
    }

    fn test_chain_id() -> crate::Hash {
        crate::hash_domain(b"umbra.chain_id", b"umbra-test")
    }

    #[test]
    fn bft_quorum_certification() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();

        let mut bft = BftState::new(0, validators.clone(), chain_id);
        let vertex_id = VertexId([1u8; 32]);

        // Dynamic quorum for committee of 4 = (4*2)/3 + 1 = 3
        assert_eq!(dynamic_quorum(4), 3);

        // Collect votes from 3 out of 4 (meets quorum)
        let mut cert = None;
        for (i, kp) in keypairs.iter().enumerate().take(3) {
            let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
            let sig = kp.sign(&msg);
            let vote = Vote {
                vertex_id,
                voter_id: validators[i].id,
                epoch: 0,
                round: 0,
                vote_type: VoteType::Accept,
                signature: sig,
                vrf_proof: None,
            };
            if let Some(c) = bft.receive_vote(vote) {
                cert = Some(c);
            }
        }

        // Certificate should have been issued at quorum
        let cert = cert.expect("should have certified at quorum");
        assert_eq!(cert.vertex_id, vertex_id);
        assert!(cert.verify(&validators, &chain_id));
    }

    #[test]
    fn leader_rotation() {
        let (_keypairs, validators) = make_committee(3);
        let mut bft = BftState::new(0, validators.clone(), test_chain_id());

        assert_eq!(bft.leader().unwrap().id, validators[0].id);
        bft.advance_round();
        assert_eq!(bft.leader().unwrap().id, validators[1].id);
        bft.advance_round();
        assert_eq!(bft.leader().unwrap().id, validators[2].id);
        bft.advance_round();
        assert_eq!(bft.leader().unwrap().id, validators[0].id); // Wraps
    }

    #[test]
    fn duplicate_vote_rejected() {
        let (keypairs, validators) = make_committee(2);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        let vertex_id = VertexId([1u8; 32]);

        let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
        let sig = keypairs[0].sign(&msg);
        let vote = Vote {
            vertex_id,
            voter_id: validators[0].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: sig.clone(),
            vrf_proof: None,
        };

        bft.receive_vote(vote.clone());
        bft.receive_vote(vote); // Duplicate — should be ignored

        assert_eq!(bft.votes[&vertex_id].len(), 1);
    }

    #[test]
    fn wrong_epoch_vote_rejected() {
        let (keypairs, validators) = make_committee(2);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(5, validators.clone(), chain_id);
        let vertex_id = VertexId([1u8; 32]);

        // Vote signed for epoch 3 (wrong)
        let msg = vote_sign_data(&vertex_id, 3, 0, &VoteType::Accept, &chain_id);
        let sig = keypairs[0].sign(&msg);
        let vote = Vote {
            vertex_id,
            voter_id: validators[0].id,
            epoch: 3,
            round: 0,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };

        assert!(bft.receive_vote(vote).is_none());
        assert!(!bft.votes.contains_key(&vertex_id));
    }

    #[test]
    fn equivocation_detected() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);

        let vertex_a = VertexId([1u8; 32]);
        let vertex_b = VertexId([2u8; 32]);

        // Validator 0 votes for vertex A
        let msg_a = vote_sign_data(&vertex_a, 0, 0, &VoteType::Accept, &chain_id);
        let sig_a = keypairs[0].sign(&msg_a);
        let vote_a = Vote {
            vertex_id: vertex_a,
            voter_id: validators[0].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: sig_a,
            vrf_proof: None,
        };
        bft.receive_vote(vote_a);

        // Same validator votes for vertex B in the same round — equivocation!
        let msg_b = vote_sign_data(&vertex_b, 0, 0, &VoteType::Accept, &chain_id);
        let sig_b = keypairs[0].sign(&msg_b);
        let vote_b = Vote {
            vertex_id: vertex_b,
            voter_id: validators[0].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: sig_b,
            vrf_proof: None,
        };
        assert!(bft.receive_vote(vote_b).is_none()); // Rejected

        // Equivocation evidence should be recorded with both signatures
        assert_eq!(bft.equivocations().len(), 1);
        let ev = &bft.equivocations()[0];
        assert_eq!(ev.voter_id, validators[0].id);
        assert_eq!(ev.first_vertex, vertex_a);
        assert_eq!(ev.second_vertex, vertex_b);
        // Both signatures must be non-empty (independently verifiable evidence)
        assert!(
            !ev.first_signature.as_bytes().is_empty(),
            "first_signature should be present in equivocation evidence"
        );
        assert!(
            !ev.second_signature.as_bytes().is_empty(),
            "second_signature should be present in equivocation evidence"
        );
        // Vote types must be recorded
        assert_eq!(ev.first_vote_type, VoteType::Accept);
        assert_eq!(ev.second_vote_type, VoteType::Accept);
        // Verify the signatures actually validate (evidence is independently verifiable)
        let msg_a_check = vote_sign_data(&vertex_a, 0, 0, &VoteType::Accept, &chain_id);
        let msg_b_check = vote_sign_data(&vertex_b, 0, 0, &VoteType::Accept, &chain_id);
        assert!(validators[0]
            .public_key
            .verify(&msg_a_check, &ev.first_signature));
        assert!(validators[0]
            .public_key
            .verify(&msg_b_check, &ev.second_signature));
    }

    #[test]
    fn committee_selection_works() {
        let mut validators = Vec::new();
        for _ in 0..50 {
            let kp = SigningKeypair::generate();
            let v = Validator::new(kp.public.clone());
            validators.push((kp, v));
        }

        let seed = EpochSeed::genesis();
        let committee = select_committee(&seed, &validators, 7);

        // Should select at least MIN_COMMITTEE_SIZE validators
        assert!(committee.len() >= crate::constants::MIN_COMMITTEE_SIZE);
        assert!(committee.len() <= 50);
    }

    #[test]
    fn committee_selection_small_pool() {
        // When fewer validators than MIN_COMMITTEE_SIZE, all are included
        let mut validators = Vec::new();
        for _ in 0..3 {
            let kp = SigningKeypair::generate();
            let v = Validator::new(kp.public.clone());
            validators.push((kp, v));
        }

        let seed = EpochSeed::genesis();
        let committee = select_committee(&seed, &validators, 7);

        // All 3 should be included (fallback triggers)
        assert_eq!(committee.len(), 3);
    }

    #[test]
    fn vote_produces_signed_vote() {
        let (keypairs, validators) = make_committee(3);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        bft.set_our_keypair(keypairs[0].clone());

        let vertex_id = VertexId([5u8; 32]);
        let vote = bft.vote(vertex_id, true);
        assert!(vote.is_some());
        let vote = vote.unwrap();
        assert_eq!(vote.vertex_id, vertex_id);
        assert_eq!(vote.voter_id, validators[0].id);
        assert_eq!(vote.epoch, 0);
        assert!(matches!(vote.vote_type, VoteType::Accept));
    }

    #[test]
    fn is_committee_member_when_in_committee() {
        let (keypairs, validators) = make_committee(3);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        bft.set_our_keypair(keypairs[1].clone());
        assert!(bft.is_committee_member());
    }

    #[test]
    fn get_certificate_after_quorum() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        let vertex_id = VertexId([7u8; 32]);

        for (i, kp) in keypairs.iter().enumerate().take(3) {
            let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
            let sig = kp.sign(&msg);
            let vote = Vote {
                vertex_id,
                voter_id: validators[i].id,
                epoch: 0,
                round: 0,
                vote_type: VoteType::Accept,
                signature: sig,
                vrf_proof: None,
            };
            bft.receive_vote(vote);
        }

        let cert = bft.get_certificate(&vertex_id);
        assert!(cert.is_some());
        assert_eq!(cert.unwrap().vertex_id, vertex_id);
    }

    #[test]
    fn all_certificates_returns_all() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);

        // Certify vertex in round 0
        let vertex_a = VertexId([10u8; 32]);
        for (i, kp) in keypairs.iter().enumerate().take(3) {
            let msg = vote_sign_data(&vertex_a, 0, 0, &VoteType::Accept, &chain_id);
            let sig = kp.sign(&msg);
            bft.receive_vote(Vote {
                vertex_id: vertex_a,
                voter_id: validators[i].id,
                epoch: 0,
                round: 0,
                vote_type: VoteType::Accept,
                signature: sig,
                vrf_proof: None,
            });
        }

        // Advance round and certify another vertex
        bft.advance_round();
        let vertex_b = VertexId([20u8; 32]);
        for (i, kp) in keypairs.iter().enumerate().take(3) {
            let msg = vote_sign_data(&vertex_b, 0, 1, &VoteType::Accept, &chain_id);
            let sig = kp.sign(&msg);
            bft.receive_vote(Vote {
                vertex_id: vertex_b,
                voter_id: validators[i].id,
                epoch: 0,
                round: 1,
                vote_type: VoteType::Accept,
                signature: sig,
                vrf_proof: None,
            });
        }

        assert_eq!(bft.all_certificates().len(), 2);
    }

    #[test]
    fn advance_round_increments() {
        let (_keypairs, validators) = make_committee(3);
        let mut bft = BftState::new(0, validators, test_chain_id());
        assert_eq!(bft.round, 0);
        bft.advance_round();
        assert_eq!(bft.round, 1);
        bft.advance_round();
        assert_eq!(bft.round, 2);
    }

    #[test]
    fn clear_equivocations_empties() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);

        // Create equivocation
        let vertex_a = VertexId([1u8; 32]);
        let vertex_b = VertexId([2u8; 32]);
        let msg_a = vote_sign_data(&vertex_a, 0, 0, &VoteType::Accept, &chain_id);
        bft.receive_vote(Vote {
            vertex_id: vertex_a,
            voter_id: validators[0].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: keypairs[0].sign(&msg_a),
            vrf_proof: None,
        });
        let msg_b = vote_sign_data(&vertex_b, 0, 0, &VoteType::Accept, &chain_id);
        bft.receive_vote(Vote {
            vertex_id: vertex_b,
            voter_id: validators[0].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: keypairs[0].sign(&msg_b),
            vrf_proof: None,
        });

        assert!(!bft.equivocations().is_empty());
        bft.clear_equivocations();
        assert!(bft.equivocations().is_empty());
    }

    #[test]
    fn wrong_round_vote_rejected() {
        let (keypairs, validators) = make_committee(3);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        // BftState is at round 0
        let vertex_id = VertexId([1u8; 32]);

        // Create a vote signed for round 1 (wrong — BftState is at round 0)
        let msg = vote_sign_data(&vertex_id, 0, 1, &VoteType::Accept, &chain_id);
        let sig = keypairs[0].sign(&msg);
        let vote = Vote {
            vertex_id,
            voter_id: validators[0].id,
            epoch: 0,
            round: 1,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };

        assert!(bft.receive_vote(vote).is_none());
        assert!(!bft.votes.contains_key(&vertex_id));
    }

    #[test]
    fn non_committee_voter_rejected() {
        let (_keypairs, validators) = make_committee(3);
        let chain_id = test_chain_id();
        // Committee contains only validators A, B, C
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        let vertex_id = VertexId([1u8; 32]);

        // Generate a vote from validator D (not in committee)
        let outsider_kp = SigningKeypair::generate();
        let outsider_id = outsider_kp.public.fingerprint();
        let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
        let sig = outsider_kp.sign(&msg);
        let vote = Vote {
            vertex_id,
            voter_id: outsider_id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };

        assert!(bft.receive_vote(vote).is_none());
        assert!(!bft.votes.contains_key(&vertex_id));
    }

    #[test]
    fn invalid_signature_vote_rejected() {
        let (keypairs, validators) = make_committee(3);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        let vertex_id = VertexId([1u8; 32]);

        // Create a properly signed vote, then tamper with the signature
        let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
        let mut sig = keypairs[0].sign(&msg);
        // Tamper with signature bytes
        if !sig.0.is_empty() {
            sig.0[0] ^= 0xFF;
        }
        let vote = Vote {
            vertex_id,
            voter_id: validators[0].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };

        assert!(bft.receive_vote(vote).is_none());
        assert!(!bft.votes.contains_key(&vertex_id));
    }

    #[test]
    fn reject_vote_does_not_reach_quorum() {
        // Committee of 4, quorum = 3
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        let vertex_id = VertexId([1u8; 32]);

        // Submit 4 Reject votes (exceeds quorum count of 3)
        for (i, kp) in keypairs.iter().enumerate() {
            let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Reject, &chain_id);
            let sig = kp.sign(&msg);
            let vote = Vote {
                vertex_id,
                voter_id: validators[i].id,
                epoch: 0,
                round: 0,
                vote_type: VoteType::Reject,
                signature: sig,
                vrf_proof: None,
            };
            let result = bft.receive_vote(vote);
            // Reject votes should never produce a certificate
            assert!(result.is_none());
        }

        // No certificate should have been issued
        assert!(bft.get_certificate(&vertex_id).is_none());
    }

    #[test]
    fn committee_of_one_certifies() {
        // Committee with only 1 validator; quorum = (1*2)/3 + 1 = 1
        let (keypairs, validators) = make_committee(1);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        let vertex_id = VertexId([1u8; 32]);

        assert_eq!(dynamic_quorum(1), 1);

        let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
        let sig = keypairs[0].sign(&msg);
        let vote = Vote {
            vertex_id,
            voter_id: validators[0].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };

        let cert = bft.receive_vote(vote);
        assert!(cert.is_some());
        assert_eq!(cert.unwrap().vertex_id, vertex_id);
    }

    #[test]
    fn used_fallback_preserves_all_validators() {
        // Create fewer validators than COMMITTEE_SIZE to trigger fallback
        let count = crate::constants::MIN_COMMITTEE_SIZE - 1; // e.g. 3, which is < MIN_COMMITTEE_SIZE
        let mut validators = Vec::new();
        for _ in 0..count {
            let kp = SigningKeypair::generate();
            let v = Validator::new(kp.public.clone());
            validators.push((kp, v));
        }

        let seed = crate::crypto::vrf::EpochSeed::genesis();
        let committee = select_committee(&seed, &validators, crate::constants::COMMITTEE_SIZE);

        // In fallback mode, ALL validators must be included (not truncated)
        assert_eq!(committee.len(), count);
    }

    #[test]
    fn rejection_count_works() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        let vertex_id = VertexId([1u8; 32]);

        // 2 Accept votes
        for i in 0..2 {
            let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
            let sig = keypairs[i].sign(&msg);
            bft.receive_vote(Vote {
                vertex_id,
                voter_id: validators[i].id,
                epoch: 0,
                round: 0,
                vote_type: VoteType::Accept,
                signature: sig,
                vrf_proof: None,
            });
        }

        // 2 Reject votes
        for i in 2..4 {
            let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Reject, &chain_id);
            let sig = keypairs[i].sign(&msg);
            bft.receive_vote(Vote {
                vertex_id,
                voter_id: validators[i].id,
                epoch: 0,
                round: 0,
                vote_type: VoteType::Reject,
                signature: sig,
                vrf_proof: None,
            });
        }

        assert_eq!(bft.rejection_count(&vertex_id), 2);
    }

    #[test]
    fn advance_epoch_clears_state() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        let vertex_id = VertexId([1u8; 32]);

        // Add votes and reach quorum to produce a certificate
        for (i, kp) in keypairs.iter().enumerate().take(3) {
            let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
            let sig = kp.sign(&msg);
            bft.receive_vote(Vote {
                vertex_id,
                voter_id: validators[i].id,
                epoch: 0,
                round: 0,
                vote_type: VoteType::Accept,
                signature: sig,
                vrf_proof: None,
            });
        }

        // Verify we have votes and a certificate before advancing
        assert!(!bft.votes.is_empty());
        assert!(bft.get_certificate(&vertex_id).is_some());

        // Advance to epoch 1 with a new (same) committee
        let (_, new_validators) = make_committee(3);
        bft.advance_epoch(1, new_validators.clone());

        // Everything should be cleared
        assert_eq!(bft.epoch, 1);
        assert_eq!(bft.round, 0);
        assert!(bft.votes.is_empty());
        assert!(bft.certificates.is_empty());
        assert_eq!(bft.committee.len(), new_validators.len());
    }

    #[test]
    fn vrf_commitment_first_seen_binding() {
        // Test that once a VRF commitment is registered, subsequent
        // VRFs from the same validator must match.
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);

        let epoch_seed = crate::crypto::vrf::EpochSeed::genesis();
        bft.set_epoch_context(epoch_seed.clone(), 100); // force VRF mandatory

        // Evaluate VRF for validator 0
        let vrf_input = epoch_seed.vrf_input(&validators[0].id);
        let vrf = crate::crypto::vrf::VrfOutput::evaluate(&keypairs[0], &vrf_input);

        // Register the commitment
        assert!(bft.register_vrf_commitment(validators[0].id, vrf.proof_commitment));

        // Same commitment should be accepted
        assert!(bft.register_vrf_commitment(validators[0].id, vrf.proof_commitment));

        // Different commitment should be rejected
        let fake_commitment = [0xFF; 32];
        assert!(!bft.register_vrf_commitment(validators[0].id, fake_commitment));

        // Lookup should return the original commitment
        assert_eq!(
            bft.vrf_commitment(&validators[0].id),
            Some(&vrf.proof_commitment)
        );
    }

    #[test]
    fn advance_epoch_clears_vrf_commitments() {
        let (_keypairs, validators) = make_committee(3);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);

        // Register a VRF commitment
        let commitment = [42u8; 32];
        bft.register_vrf_commitment(validators[0].id, commitment);
        assert!(bft.vrf_commitment(&validators[0].id).is_some());

        // Advance epoch
        let (_, new_validators) = make_committee(3);
        bft.advance_epoch(1, new_validators);

        // VRF commitments should be cleared
        assert!(bft.vrf_commitment(&validators[0].id).is_none());
    }

    /// Helper: create equivocation evidence from a committee with real signatures.
    fn make_equivocation_evidence(
        keypairs: &[SigningKeypair],
        validators: &[Validator],
        chain_id: &crate::Hash,
        epoch: u64,
        round: u64,
    ) -> EquivocationEvidence {
        let vertex_a = VertexId([1u8; 32]);
        let vertex_b = VertexId([2u8; 32]);
        let msg_a = vote_sign_data(&vertex_a, epoch, round, &VoteType::Accept, chain_id);
        let msg_b = vote_sign_data(&vertex_b, epoch, round, &VoteType::Accept, chain_id);
        EquivocationEvidence {
            voter_id: validators[0].id,
            epoch,
            round,
            first_vertex: vertex_a,
            second_vertex: vertex_b,
            first_vote_type: VoteType::Accept,
            second_vote_type: VoteType::Accept,
            first_signature: keypairs[0].sign(&msg_a),
            second_signature: keypairs[0].sign(&msg_b),
        }
    }

    #[test]
    fn verify_equivocation_evidence_valid() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let bft = BftState::new(0, validators.clone(), chain_id);
        let evidence = make_equivocation_evidence(&keypairs, &validators, &chain_id, 0, 0);
        assert!(bft.verify_equivocation_evidence(&evidence));
    }

    #[test]
    fn verify_equivocation_evidence_wrong_epoch() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let bft = BftState::new(0, validators.clone(), chain_id);
        // Evidence claims epoch 5, but BFT is at epoch 0
        let evidence = make_equivocation_evidence(&keypairs, &validators, &chain_id, 5, 0);
        assert!(!bft.verify_equivocation_evidence(&evidence));
    }

    #[test]
    fn verify_equivocation_evidence_non_committee() {
        let (_keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let bft = BftState::new(0, validators.clone(), chain_id);

        // Create evidence from a keypair NOT in the committee
        let outsider_kp = SigningKeypair::generate();
        let outsider = Validator::new(outsider_kp.public.clone());
        let evidence = make_equivocation_evidence(&[outsider_kp], &[outsider], &chain_id, 0, 0);
        assert!(!bft.verify_equivocation_evidence(&evidence));
    }

    #[test]
    fn verify_equivocation_evidence_same_vertex() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let bft = BftState::new(0, validators.clone(), chain_id);

        let vertex = VertexId([1u8; 32]);
        let msg = vote_sign_data(&vertex, 0, 0, &VoteType::Accept, &chain_id);
        let evidence = EquivocationEvidence {
            voter_id: validators[0].id,
            epoch: 0,
            round: 0,
            first_vertex: vertex,
            second_vertex: vertex, // Same vertex — not real equivocation
            first_vote_type: VoteType::Accept,
            second_vote_type: VoteType::Accept,
            first_signature: keypairs[0].sign(&msg),
            second_signature: keypairs[0].sign(&msg),
        };
        assert!(!bft.verify_equivocation_evidence(&evidence));
    }

    #[test]
    fn verify_equivocation_evidence_bad_signature() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let bft = BftState::new(0, validators.clone(), chain_id);

        let mut evidence = make_equivocation_evidence(&keypairs, &validators, &chain_id, 0, 0);
        // Tamper with second signature
        evidence.second_signature = keypairs[1].sign(b"garbage");
        assert!(!bft.verify_equivocation_evidence(&evidence));
    }

    #[test]
    fn evidence_serialization_roundtrip() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let evidence = make_equivocation_evidence(&keypairs, &validators, &chain_id, 3, 7);

        let bytes = crate::serialize(&evidence).unwrap();
        let restored: EquivocationEvidence = crate::deserialize(&bytes).unwrap();
        assert_eq!(restored.voter_id, evidence.voter_id);
        assert_eq!(restored.epoch, 3);
        assert_eq!(restored.round, 7);
        assert_eq!(restored.first_vertex, evidence.first_vertex);
        assert_eq!(restored.second_vertex, evidence.second_vertex);
        assert_eq!(restored.first_vote_type, VoteType::Accept);
        assert_eq!(restored.second_vote_type, VoteType::Accept);
    }

    #[test]
    fn create_vote_standalone() {
        let kp = SigningKeypair::generate();
        let chain_id = test_chain_id();
        let vertex_id = VertexId([42u8; 32]);

        let vote = create_vote(vertex_id, &kp, 5, 3, true, &chain_id, None);
        assert_eq!(vote.vertex_id, vertex_id);
        assert_eq!(vote.voter_id, kp.public.fingerprint());
        assert_eq!(vote.epoch, 5);
        assert_eq!(vote.round, 3);
        assert!(matches!(vote.vote_type, VoteType::Accept));
        assert!(vote.vrf_proof.is_none());

        // Verify the signature is valid
        let msg = vote_sign_data(&vertex_id, 5, 3, &VoteType::Accept, &chain_id);
        assert!(kp.public.verify(&msg, &vote.signature));
    }

    #[test]
    fn create_vote_reject() {
        let kp = SigningKeypair::generate();
        let chain_id = test_chain_id();
        let vertex_id = VertexId([42u8; 32]);

        let vote = create_vote(vertex_id, &kp, 0, 0, false, &chain_id, None);
        assert!(matches!(vote.vote_type, VoteType::Reject));

        let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Reject, &chain_id);
        assert!(kp.public.verify(&msg, &vote.signature));
    }

    #[test]
    fn is_vote_accepted_tracks_received_votes() {
        let (keypairs, validators) = make_committee(3);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        let vertex_id = VertexId([1u8; 32]);

        let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
        let sig = keypairs[0].sign(&msg);
        let vote = Vote {
            vertex_id,
            voter_id: validators[0].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };

        assert!(!bft.is_vote_accepted(&vote));
        bft.receive_vote(vote.clone());
        assert!(bft.is_vote_accepted(&vote));
    }

    #[test]
    fn leader_none_for_empty_committee() {
        let bft = BftState::new(0, vec![], test_chain_id());
        assert!(bft.leader().is_none());
    }

    #[test]
    fn is_committee_member_false_without_keypair() {
        let (_keypairs, validators) = make_committee(3);
        let bft = BftState::new(0, validators, test_chain_id());
        assert!(!bft.is_committee_member());
    }

    #[test]
    fn vote_returns_none_without_keypair() {
        let (_keypairs, validators) = make_committee(3);
        let mut bft = BftState::new(0, validators, test_chain_id());
        let vertex_id = VertexId([1u8; 32]);
        assert!(bft.vote(vertex_id, true).is_none());
    }

    #[test]
    fn dynamic_quorum_values() {
        assert_eq!(dynamic_quorum(1), 1);
        assert_eq!(dynamic_quorum(3), 3); // (3*2)/3+1 = 3
        assert_eq!(dynamic_quorum(4), 3); // (4*2)/3+1 = 3
        assert_eq!(dynamic_quorum(7), 5); // (7*2)/3+1 = 5
        assert_eq!(dynamic_quorum(10), 7); // (10*2)/3+1 = 7
        assert_eq!(dynamic_quorum(21), 15); // (21*2)/3+1 = 15
    }

    #[test]
    fn validator_with_activation_epoch() {
        let kp = SigningKeypair::generate();
        let kem_kp = crate::crypto::keys::KemKeypair::generate();
        let v = Validator::with_activation(kp.public.clone(), kem_kp.public.clone(), 5);
        assert_eq!(v.activation_epoch, 5);
        assert!(v.active);
        assert!(v.kem_public_key.is_some());
        assert_eq!(v.id, kp.public.fingerprint());
    }

    #[test]
    fn inactive_validators_excluded_from_committee() {
        let mut validators = Vec::new();
        for i in 0..5 {
            let kp = SigningKeypair::generate();
            let mut v = Validator::new(kp.public.clone());
            if i == 2 {
                v.active = false; // Mark one inactive
            }
            validators.push((kp, v));
        }

        let seed = EpochSeed::genesis();
        let committee = select_committee(&seed, &validators, 100);

        // Inactive validator should not be in the committee
        let inactive_id = validators[2].1.id;
        assert!(!committee.iter().any(|(v, _)| v.id == inactive_id));
    }

    #[test]
    fn certificate_verify_insufficient_signatures() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let vertex_id = VertexId([1u8; 32]);

        // Quorum for committee of 4 = 3. Provide only 2 signatures.
        let mut signatures = Vec::new();
        for (i, kp) in keypairs.iter().enumerate().take(2) {
            let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
            let sig = kp.sign(&msg);
            signatures.push((validators[i].id, sig));
        }

        let cert = Certificate {
            vertex_id,
            round: 0,
            epoch: 0,
            signatures,
        };

        assert!(!cert.verify(&validators, &chain_id));
    }

    #[test]
    fn certificate_verify_duplicate_voters() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let vertex_id = VertexId([1u8; 32]);

        // Create 3 signatures but the first voter appears twice
        let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
        let sig0 = keypairs[0].sign(&msg);
        let sig1 = keypairs[1].sign(&msg);

        let signatures = vec![
            (validators[0].id, sig0.clone()),
            (validators[0].id, sig0), // Duplicate voter
            (validators[1].id, sig1),
        ];

        let cert = Certificate {
            vertex_id,
            round: 0,
            epoch: 0,
            signatures,
        };

        // Only 2 unique valid voters, which is less than quorum of 3
        assert!(!cert.verify(&validators, &chain_id));
    }

    #[test]
    fn certificate_verify_non_committee_voter() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let vertex_id = VertexId([1u8; 32]);

        // Create signatures from 2 committee members + 1 outsider
        let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
        let outsider_kp = SigningKeypair::generate();
        let outsider_id = outsider_kp.public.fingerprint();

        let signatures = vec![
            (validators[0].id, keypairs[0].sign(&msg)),
            (validators[1].id, keypairs[1].sign(&msg)),
            (outsider_id, outsider_kp.sign(&msg)), // Not in committee
        ];

        let cert = Certificate {
            vertex_id,
            round: 0,
            epoch: 0,
            signatures,
        };

        // Only 2 valid committee signatures, less than quorum of 3
        assert!(!cert.verify(&validators, &chain_id));
    }

    #[test]
    fn certificate_verify_too_many_signatures() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let vertex_id = VertexId([1u8; 32]);

        let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);

        // Create > 2 * committee.len() = 8 signatures (use 9)
        let mut signatures = Vec::new();
        for i in 0..9 {
            let idx = i % keypairs.len();
            signatures.push((validators[idx].id, keypairs[idx].sign(&msg)));
        }

        let cert = Certificate {
            vertex_id,
            round: 0,
            epoch: 0,
            signatures,
        };

        // Should be rejected because signatures.len() > 2 * committee.len()
        assert!(!cert.verify(&validators, &chain_id));
    }

    #[test]
    fn receive_vote_wrong_epoch() {
        let (keypairs, validators) = make_committee(3);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(5, validators.clone(), chain_id);
        let vertex_id = VertexId([1u8; 32]);

        // Vote with epoch 0 (BftState is at epoch 5)
        let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
        let sig = keypairs[0].sign(&msg);
        let vote = Vote {
            vertex_id,
            voter_id: validators[0].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };

        assert!(bft.receive_vote(vote).is_none());
    }

    #[test]
    fn receive_vote_wrong_round() {
        let (keypairs, validators) = make_committee(3);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        // BftState is at round 0
        let vertex_id = VertexId([1u8; 32]);

        // Vote with round 5 (BftState is at round 0)
        let msg = vote_sign_data(&vertex_id, 0, 5, &VoteType::Accept, &chain_id);
        let sig = keypairs[0].sign(&msg);
        let vote = Vote {
            vertex_id,
            voter_id: validators[0].id,
            epoch: 0,
            round: 5,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };

        assert!(bft.receive_vote(vote).is_none());
    }

    #[test]
    fn receive_vote_non_committee_voter() {
        let (_keypairs, validators) = make_committee(3);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        let vertex_id = VertexId([1u8; 32]);

        // Vote from a validator not in the committee
        let outsider_kp = SigningKeypair::generate();
        let outsider_id = outsider_kp.public.fingerprint();
        let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
        let sig = outsider_kp.sign(&msg);
        let vote = Vote {
            vertex_id,
            voter_id: outsider_id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };

        assert!(bft.receive_vote(vote).is_none());
    }

    #[test]
    fn try_certify_quorum_minus_one() {
        // Committee of 4, quorum = 3. Send only 2 Accept votes.
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        let vertex_id = VertexId([1u8; 32]);

        for (i, kp) in keypairs.iter().enumerate().take(2) {
            let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
            let sig = kp.sign(&msg);
            let vote = Vote {
                vertex_id,
                voter_id: validators[i].id,
                epoch: 0,
                round: 0,
                vote_type: VoteType::Accept,
                signature: sig,
                vrf_proof: None,
            };
            let result = bft.receive_vote(vote);
            assert!(result.is_none());
        }

        // No certificate should exist
        assert!(bft.get_certificate(&vertex_id).is_none());
    }

    #[test]
    fn try_certify_exact_quorum() {
        // Committee of 4, quorum = 3. Send exactly 3 Accept votes.
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        let vertex_id = VertexId([1u8; 32]);

        let mut cert_result = None;
        for (i, kp) in keypairs.iter().enumerate().take(3) {
            let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
            let sig = kp.sign(&msg);
            let vote = Vote {
                vertex_id,
                voter_id: validators[i].id,
                epoch: 0,
                round: 0,
                vote_type: VoteType::Accept,
                signature: sig,
                vrf_proof: None,
            };
            if let Some(c) = bft.receive_vote(vote) {
                cert_result = Some(c);
            }
        }

        // Certificate should have been issued
        let cert = cert_result.expect("certificate should be issued at exact quorum");
        assert_eq!(cert.vertex_id, vertex_id);
        assert_eq!(cert.signatures.len(), 3);

        // Also accessible via get_certificate
        assert!(bft.get_certificate(&vertex_id).is_some());
    }

    #[test]
    fn select_committee_deterministic() {
        let mut validators = Vec::new();
        for _ in 0..20 {
            let kp = SigningKeypair::generate();
            let v = Validator::new(kp.public.clone());
            validators.push((kp, v));
        }

        let seed = EpochSeed::genesis();
        let committee1 = select_committee(&seed, &validators, 7);
        let committee2 = select_committee(&seed, &validators, 7);

        assert_eq!(committee1.len(), committee2.len());
        for (a, b) in committee1.iter().zip(committee2.iter()) {
            assert_eq!(a.0.id, b.0.id);
        }
    }

    #[test]
    fn dynamic_quorum_small_committees() {
        // dynamic_quorum(n) = (n*2)/3 + 1
        assert_eq!(dynamic_quorum(2), 2); // (2*2)/3 + 1 = 1 + 1 = 2
        assert_eq!(dynamic_quorum(3), 3); // (3*2)/3 + 1 = 2 + 1 = 3
        assert_eq!(dynamic_quorum(4), 3); // (4*2)/3 + 1 = 2 + 1 = 3
    }

    #[test]
    fn advance_epoch_clears_round_votes() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        let vertex_id = VertexId([1u8; 32]);

        // Add a vote so that votes and round_votes are populated
        let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
        let sig = keypairs[0].sign(&msg);
        let vote = Vote {
            vertex_id,
            voter_id: validators[0].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };
        bft.receive_vote(vote);

        // Verify votes exist
        assert!(!bft.votes.is_empty());
        assert!(!bft.round_votes.is_empty());

        // Advance epoch
        let (_, new_validators) = make_committee(3);
        bft.advance_epoch(1, new_validators);

        // Votes and round_votes should be cleared
        assert!(bft.votes.is_empty());
        assert!(bft.round_votes.is_empty());
        assert_eq!(bft.epoch, 1);
        assert_eq!(bft.round, 0);
    }

    #[test]
    fn certificate_verify_empty_signatures() {
        let (_keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let vertex_id = VertexId([1u8; 32]);

        let cert = Certificate {
            vertex_id,
            round: 0,
            epoch: 0,
            signatures: vec![], // Empty
        };

        assert!(!cert.verify(&validators, &chain_id));
    }

    #[test]
    fn equivocation_across_rounds() {
        // Validator votes at round 1 on vertex A, then at round 3 on vertex B.
        // Equivocation is tracked per (voter_id, round), so votes in different
        // rounds are independent and should NOT trigger equivocation detection.
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);

        let vertex_a = VertexId([1u8; 32]);
        let vertex_b = VertexId([2u8; 32]);

        // Vote at round 0 (BftState starts at round 0) for vertex_a
        let msg_a = vote_sign_data(&vertex_a, 0, 0, &VoteType::Accept, &chain_id);
        let sig_a = keypairs[0].sign(&msg_a);
        bft.receive_vote(Vote {
            vertex_id: vertex_a,
            voter_id: validators[0].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: sig_a,
            vrf_proof: None,
        });

        // Advance to round 1, then round 2, then round 3
        bft.advance_round();
        bft.advance_round();
        bft.advance_round();
        assert_eq!(bft.round, 3);

        // Vote at round 3 for vertex_b -- different round, so not equivocation
        let msg_b = vote_sign_data(&vertex_b, 0, 3, &VoteType::Accept, &chain_id);
        let sig_b = keypairs[0].sign(&msg_b);
        let _result = bft.receive_vote(Vote {
            vertex_id: vertex_b,
            voter_id: validators[0].id,
            epoch: 0,
            round: 3,
            vote_type: VoteType::Accept,
            signature: sig_b,
            vrf_proof: None,
        });

        // No equivocation should be detected (different rounds)
        assert!(bft.equivocations().is_empty());
        // The vote should be accepted (not rejected as equivocation)
        // It won't produce a certificate with only 1 vote, but it should be stored
        assert!(bft.votes.contains_key(&vertex_b));
    }

    #[test]
    fn equivocation_with_different_vote_types() {
        // Validator votes Accept on vertex A and Reject on vertex B in the same round.
        // This is still equivocation (same voter, same round, different vertex).
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);

        let vertex_a = VertexId([1u8; 32]);
        let vertex_b = VertexId([2u8; 32]);

        // Accept vote on vertex A
        let msg_a = vote_sign_data(&vertex_a, 0, 0, &VoteType::Accept, &chain_id);
        let sig_a = keypairs[0].sign(&msg_a);
        bft.receive_vote(Vote {
            vertex_id: vertex_a,
            voter_id: validators[0].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: sig_a,
            vrf_proof: None,
        });

        // Reject vote on vertex B (same round, different vertex)
        let msg_b = vote_sign_data(&vertex_b, 0, 0, &VoteType::Reject, &chain_id);
        let sig_b = keypairs[0].sign(&msg_b);
        let result = bft.receive_vote(Vote {
            vertex_id: vertex_b,
            voter_id: validators[0].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Reject,
            signature: sig_b,
            vrf_proof: None,
        });

        // Equivocation detected
        assert!(result.is_none());
        assert_eq!(bft.equivocations().len(), 1);
        let ev = &bft.equivocations()[0];
        assert_eq!(ev.first_vote_type, VoteType::Accept);
        assert_eq!(ev.second_vote_type, VoteType::Reject);
        assert_eq!(ev.first_vertex, vertex_a);
        assert_eq!(ev.second_vertex, vertex_b);
    }

    #[test]
    fn leader_selection_wraps_beyond_committee_size() {
        // When round > committee size, leader should wrap via modulo.
        let (_keypairs, validators) = make_committee(3);
        let mut bft = BftState::new(0, validators.clone(), test_chain_id());

        // Advance to round 100 (well beyond committee size of 3)
        for _ in 0..100 {
            bft.advance_round();
        }
        assert_eq!(bft.round, 100);

        // 100 % 3 == 1, so leader should be validators[1]
        assert_eq!(bft.leader().unwrap().id, validators[100 % 3].id);

        // Advance to round 101: 101 % 3 == 2
        bft.advance_round();
        assert_eq!(bft.leader().unwrap().id, validators[101 % 3].id);

        // Advance to round 102: 102 % 3 == 0
        bft.advance_round();
        assert_eq!(bft.leader().unwrap().id, validators[102 % 3].id);
    }

    #[test]
    fn vote_sign_data_binding() {
        // Changing any field in vote_sign_data must produce a different output.
        let chain_id = test_chain_id();
        let vertex_id = VertexId([1u8; 32]);
        let epoch = 5u64;
        let round = 3u64;
        let vote_type = VoteType::Accept;

        let base = vote_sign_data(&vertex_id, epoch, round, &vote_type, &chain_id);

        // Changing epoch
        let diff_epoch = vote_sign_data(&vertex_id, epoch + 1, round, &vote_type, &chain_id);
        assert_ne!(base, diff_epoch);

        // Changing round
        let diff_round = vote_sign_data(&vertex_id, epoch, round + 1, &vote_type, &chain_id);
        assert_ne!(base, diff_round);

        // Changing vertex_id
        let other_vertex = VertexId([2u8; 32]);
        let diff_vertex = vote_sign_data(&other_vertex, epoch, round, &vote_type, &chain_id);
        assert_ne!(base, diff_vertex);

        // Changing vote_type
        let diff_type = vote_sign_data(&vertex_id, epoch, round, &VoteType::Reject, &chain_id);
        assert_ne!(base, diff_type);

        // Changing chain_id
        let other_chain = crate::hash_domain(b"umbra.chain_id", b"other-chain");
        let diff_chain = vote_sign_data(&vertex_id, epoch, round, &vote_type, &other_chain);
        assert_ne!(base, diff_chain);
    }

    #[test]
    fn certificate_verify_mixed_valid_and_invalid_signatures() {
        // Certificate with 3 signatures: 2 valid + 1 invalid (tampered).
        // Quorum for committee of 4 is 3, so this should fail.
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let vertex_id = VertexId([1u8; 32]);

        let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);

        // Two valid signatures
        let sig0 = keypairs[0].sign(&msg);
        let sig1 = keypairs[1].sign(&msg);

        // One invalid (tampered) signature from validator 2
        let mut sig2 = keypairs[2].sign(&msg);
        if !sig2.0.is_empty() {
            sig2.0[0] ^= 0xFF;
        }

        let cert = Certificate {
            vertex_id,
            round: 0,
            epoch: 0,
            signatures: vec![
                (validators[0].id, sig0),
                (validators[1].id, sig1),
                (validators[2].id, sig2), // Invalid
            ],
        };

        // Only 2 valid signatures, less than quorum of 3
        assert!(!cert.verify(&validators, &chain_id));
    }

    #[test]
    fn round_advancement_at_high_numbers() {
        let (_keypairs, validators) = make_committee(3);
        let mut bft = BftState::new(0, validators, test_chain_id());

        // Advance to a high round number
        for _ in 0..10_000 {
            bft.advance_round();
        }
        assert_eq!(bft.round, 10_000);

        // Leader should still work correctly at high round numbers
        // 10_000 % 3 == 1
        assert!(bft.leader().is_some());

        // Continue advancing
        bft.advance_round();
        assert_eq!(bft.round, 10_001);
    }

    #[test]
    fn select_committee_from_proofs_basic() {
        let epoch_seed = crate::crypto::vrf::EpochSeed::genesis();
        let mut proofs = Vec::new();
        for _ in 0..10 {
            let kp = SigningKeypair::generate();
            let v = Validator::new(kp.public.clone());
            let vrf_input = epoch_seed.vrf_input(&v.id);
            let vrf_output = VrfOutput::evaluate(&kp, &vrf_input);
            proofs.push((v, vrf_output));
        }
        let committee = select_committee_from_proofs(&epoch_seed, &proofs, 5);
        // Should return at least MIN_COMMITTEE_SIZE members
        assert!(committee.len() >= crate::constants::MIN_COMMITTEE_SIZE);
    }

    #[test]
    fn select_committee_from_proofs_excludes_inactive() {
        let epoch_seed = crate::crypto::vrf::EpochSeed::genesis();
        let mut proofs = Vec::new();
        for i in 0..6 {
            let kp = SigningKeypair::generate();
            let mut v = Validator::new(kp.public.clone());
            if i < 3 {
                v.active = false; // Mark half as inactive
            }
            let vrf_input = epoch_seed.vrf_input(&v.id);
            let vrf_output = VrfOutput::evaluate(&kp, &vrf_input);
            proofs.push((v, vrf_output));
        }
        let committee = select_committee_from_proofs(&epoch_seed, &proofs, 5);
        // All returned validators should be active
        for (v, _) in &committee {
            assert!(v.active);
        }
    }

    #[test]
    fn select_committee_from_proofs_excludes_future_activation() {
        let epoch_seed = crate::crypto::vrf::EpochSeed::genesis(); // epoch 0
        let mut proofs = Vec::new();
        for i in 0..6 {
            let kp = SigningKeypair::generate();
            let kem_kp = crate::crypto::keys::KemKeypair::generate();
            // Half activate at epoch 5 (in the future relative to epoch 0)
            let activation = if i < 3 { 5 } else { 0 };
            let v =
                Validator::with_activation(kp.public.clone(), kem_kp.public.clone(), activation);
            let vrf_input = epoch_seed.vrf_input(&v.id);
            let vrf_output = VrfOutput::evaluate(&kp, &vrf_input);
            proofs.push((v, vrf_output));
        }
        let committee = select_committee_from_proofs(&epoch_seed, &proofs, 5);
        for (v, _) in &committee {
            assert!(v.activation_epoch <= epoch_seed.epoch);
        }
    }

    #[test]
    fn select_committee_from_proofs_deterministic_ordering() {
        let epoch_seed = crate::crypto::vrf::EpochSeed::genesis();
        let mut proofs = Vec::new();
        for _ in 0..10 {
            let kp = SigningKeypair::generate();
            let v = Validator::new(kp.public.clone());
            let vrf_input = epoch_seed.vrf_input(&v.id);
            let vrf_output = VrfOutput::evaluate(&kp, &vrf_input);
            proofs.push((v, vrf_output));
        }
        let c1 = select_committee_from_proofs(&epoch_seed, &proofs, 5);
        let c2 = select_committee_from_proofs(&epoch_seed, &proofs, 5);
        assert_eq!(c1.len(), c2.len());
        for (a, b) in c1.iter().zip(c2.iter()) {
            assert_eq!(a.0.id, b.0.id);
        }
    }

    #[test]
    fn select_committee_from_proofs_empty_input() {
        let epoch_seed = crate::crypto::vrf::EpochSeed::genesis();
        let committee = select_committee_from_proofs(&epoch_seed, &[], 5);
        assert!(committee.is_empty());
    }

    #[test]
    fn select_committee_from_proofs_fallback_when_few_selected() {
        // With very few validators, all should be included via fallback
        let epoch_seed = crate::crypto::vrf::EpochSeed::genesis();
        let mut proofs = Vec::new();
        for _ in 0..3 {
            let kp = SigningKeypair::generate();
            let v = Validator::new(kp.public.clone());
            let vrf_input = epoch_seed.vrf_input(&v.id);
            let vrf_output = VrfOutput::evaluate(&kp, &vrf_input);
            proofs.push((v, vrf_output));
        }
        // With 3 validators and committee_size=21, fallback should include all 3
        let committee = select_committee_from_proofs(&epoch_seed, &proofs, 21);
        assert_eq!(committee.len(), 3);
    }

    #[test]
    fn create_vote_with_vrf_proof() {
        let kp = SigningKeypair::generate();
        let vrf_output = VrfOutput::evaluate(&kp, b"test-epoch-input");
        let vertex_id = VertexId([42u8; 32]);
        let chain_id = test_chain_id();
        let vote = create_vote(
            vertex_id,
            &kp,
            0,
            0,
            true,
            &chain_id,
            Some(vrf_output.clone()),
        );
        assert!(vote.vrf_proof.is_some());
        assert_eq!(vote.vrf_proof.unwrap().value, vrf_output.value);
    }

    #[test]
    fn dynamic_quorum_various_sizes() {
        assert_eq!(dynamic_quorum(1), 1);
        assert_eq!(dynamic_quorum(2), 2);
        assert_eq!(dynamic_quorum(3), 3);
        assert_eq!(dynamic_quorum(4), 3);
        assert_eq!(dynamic_quorum(7), 5);
        assert_eq!(dynamic_quorum(10), 7);
        assert_eq!(dynamic_quorum(21), 15);
        assert_eq!(dynamic_quorum(100), 67);
    }

    #[test]
    fn vote_sign_data_includes_all_fields() {
        let v1 = VertexId([1u8; 32]);
        let v2 = VertexId([2u8; 32]);
        let chain_id = test_chain_id();

        // Different vertex_id
        let d1 = vote_sign_data(&v1, 0, 0, &VoteType::Accept, &chain_id);
        let d2 = vote_sign_data(&v2, 0, 0, &VoteType::Accept, &chain_id);
        assert_ne!(d1, d2);

        // Different epoch
        let d3 = vote_sign_data(&v1, 1, 0, &VoteType::Accept, &chain_id);
        assert_ne!(d1, d3);

        // Different round
        let d4 = vote_sign_data(&v1, 0, 1, &VoteType::Accept, &chain_id);
        assert_ne!(d1, d4);

        // Different vote type
        let d5 = vote_sign_data(&v1, 0, 0, &VoteType::Reject, &chain_id);
        assert_ne!(d1, d5);

        // Different chain_id
        let other_chain = [0xFFu8; 32];
        let d6 = vote_sign_data(&v1, 0, 0, &VoteType::Accept, &other_chain);
        assert_ne!(d1, d6);
    }

    #[test]
    fn advance_epoch_resets_vrf_state() {
        let (_keypairs, validators) = make_committee(3);
        let mut bft = BftState::new(0, validators, test_chain_id());

        // Register a VRF commitment
        let kp = SigningKeypair::generate();
        let vrf = VrfOutput::evaluate(&kp, b"test");
        let validator_id = [99u8; 32];
        bft.register_vrf_commitment(validator_id, vrf.proof_commitment);
        assert!(bft.vrf_commitment(&validator_id).is_some());

        // Advance epoch
        let new_validators = bft.committee.clone();
        bft.advance_epoch(1, new_validators);

        // VRF commitments should be cleared
        assert!(bft.vrf_commitment(&validator_id).is_none());
    }

    #[test]
    fn our_vrf_proof_getter() {
        let (keypairs, validators) = make_committee(3);
        let mut bft = BftState::new(0, validators, test_chain_id());
        bft.set_our_keypair(keypairs[0].clone());

        assert!(bft.our_vrf_proof().is_none());

        let vrf = VrfOutput::evaluate(&keypairs[0], b"test-proof");
        bft.set_our_vrf_proof(vrf.clone());
        assert!(bft.our_vrf_proof().is_some());
        assert_eq!(bft.our_vrf_proof().unwrap().value, vrf.value);
    }

    #[test]
    fn validator_with_kem_key() {
        let kp = SigningKeypair::generate();
        let kem_kp = crate::crypto::keys::KemKeypair::generate();
        let v = Validator::with_kem(kp.public.clone(), kem_kp.public.clone());
        assert!(v.kem_public_key.is_some());
        assert!(v.active);
        assert_eq!(v.activation_epoch, 0);
        assert_eq!(v.id, kp.public.fingerprint());
    }

    #[test]
    fn set_epoch_context_stores_values() {
        let (_keypairs, validators) = make_committee(3);
        let mut bft = BftState::new(0, validators, test_chain_id());

        let seed = EpochSeed::genesis();
        bft.set_epoch_context(seed.clone(), 100);

        assert_eq!(bft.total_validators, 100);
        assert!(bft.epoch_seed.is_some());
        assert_eq!(bft.epoch_seed.as_ref().unwrap().epoch, seed.epoch);
    }

    #[test]
    fn clear_epoch_caches_preserves_committee() {
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);

        // Create some state
        let vertex_id = VertexId([1u8; 32]);
        let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
        let sig = keypairs[0].sign(&msg);
        let vote = Vote {
            vertex_id,
            voter_id: validators[0].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };
        bft.receive_vote(vote);

        // Register a VRF commitment
        bft.register_vrf_commitment([99u8; 32], [88u8; 32]);

        // Clear caches
        bft.clear_epoch_caches();

        // Votes and VRF commitments should be cleared
        assert_eq!(bft.rejection_count(&vertex_id), 0);
        assert!(bft.vrf_commitment(&[99u8; 32]).is_none());
        // But committee should still be there
        assert_eq!(bft.committee.len(), 4);
    }

    #[test]
    fn try_certify_already_certified_returns_none() {
        // Build a scenario where we certify a vertex, then try again
        let (keypairs, validators) = make_committee(4);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);
        let vertex_id = VertexId([1u8; 32]);

        // Send 3 accept votes (quorum for committee of 4)
        for (i, kp) in keypairs.iter().enumerate().take(3) {
            let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
            let sig = kp.sign(&msg);
            let vote = Vote {
                vertex_id,
                voter_id: validators[i].id,
                epoch: 0,
                round: 0,
                vote_type: VoteType::Accept,
                signature: sig,
                vrf_proof: None,
            };
            bft.receive_vote(vote);
        }

        // Should be certified now
        assert!(bft.get_certificate(&vertex_id).is_some());

        // Sending another vote should not create a second certificate
        let msg = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
        let sig = keypairs[3].sign(&msg);
        let vote = Vote {
            vertex_id,
            voter_id: validators[3].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };
        let cert = bft.receive_vote(vote);
        assert!(cert.is_none()); // already certified, returns None
    }

    #[test]
    fn dynamic_quorum_edge_cases() {
        assert_eq!(dynamic_quorum(0), 1); // 0 * 2 / 3 + 1 = 1
        assert_eq!(dynamic_quorum(1), 1); // 1 * 2 / 3 + 1 = 1
        assert_eq!(dynamic_quorum(3), 3); // 3 * 2 / 3 + 1 = 3
        assert_eq!(dynamic_quorum(4), 3); // 4 * 2 / 3 + 1 = 3
        assert_eq!(dynamic_quorum(10), 7); // 10 * 2 / 3 + 1 = 7
        assert_eq!(dynamic_quorum(21), 15); // 21 * 2 / 3 + 1 = 15
    }

    #[test]
    fn leader_wraps_around() {
        let (_keypairs, validators) = make_committee(3);
        let chain_id = test_chain_id();
        let mut bft = BftState::new(0, validators.clone(), chain_id);

        // Leaders should rotate through committee
        let l0 = bft.leader().unwrap().id;
        bft.round = 1;
        let l1 = bft.leader().unwrap().id;
        bft.round = 3;
        let l3 = bft.leader().unwrap().id;

        // l3 should wrap around to l0 (3 % 3 == 0 % 3)
        assert_eq!(l0, l3);
        // Different rounds should have different leaders (committee > 1)
        assert_ne!(l0, l1);
    }

    #[test]
    fn all_certificates_empty_initially() {
        let (_keypairs, validators) = make_committee(3);
        let bft = BftState::new(0, validators, test_chain_id());
        assert!(bft.all_certificates().is_empty());
    }

    #[test]
    fn register_vrf_commitment_duplicate_same_value() {
        let (_keypairs, validators) = make_committee(3);
        let mut bft = BftState::new(0, validators, test_chain_id());
        let vid = [1u8; 32];
        let commitment = [42u8; 32];
        assert!(bft.register_vrf_commitment(vid, commitment));
        // Same commitment should return true
        assert!(bft.register_vrf_commitment(vid, commitment));
    }

    #[test]
    fn register_vrf_commitment_duplicate_different_value() {
        let (_keypairs, validators) = make_committee(3);
        let mut bft = BftState::new(0, validators, test_chain_id());
        let vid = [1u8; 32];
        assert!(bft.register_vrf_commitment(vid, [42u8; 32]));
        // Different commitment should return false
        assert!(!bft.register_vrf_commitment(vid, [99u8; 32]));
    }
}
