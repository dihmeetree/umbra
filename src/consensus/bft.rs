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
#[derive(Clone, Debug)]
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
        // This prevents accepting votes from validators who aren't actually on the
        // committee (e.g., if local committee list is stale or manipulated).
        if let Some(vrf) = &vote.vrf_proof {
            if let Some(seed) = &self.epoch_seed {
                let vrf_input = seed.vrf_input(&vote.voter_id);
                if !vrf.verify_locally(&voter.public_key, &vrf_input) {
                    return None;
                }
                if !vrf.is_selected(crate::constants::COMMITTEE_SIZE, self.total_validators) {
                    return None;
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
                    self.equivocations.push(EquivocationEvidence {
                        voter_id: vote.voter_id,
                        epoch: vote.epoch,
                        round: vote.round,
                        first_vertex: prev_vertex,
                        second_vertex: vote.vertex_id,
                    });
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
}

/// Select the committee for an epoch using VRF.
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
    if candidates.len() < crate::constants::MIN_COMMITTEE_SIZE {
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

    // Take exactly committee_size members (or all if fewer)
    candidates.truncate(committee_size);
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
fn vote_sign_data(
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
    data.extend_from_slice(b"spectra.vote");
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
        crate::hash_domain(b"spectra.chain_id", b"spectra-test")
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

        // Equivocation evidence should be recorded
        assert_eq!(bft.equivocations().len(), 1);
        assert_eq!(bft.equivocations()[0].voter_id, validators[0].id);
        assert_eq!(bft.equivocations()[0].first_vertex, vertex_a);
        assert_eq!(bft.equivocations()[0].second_vertex, vertex_b);
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
}
