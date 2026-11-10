//! Putting a forked member back. The member seals a [`ReAddRequest`] to one
//! other branch's external key; one member of that branch repairs it with
//! `Remove(stale leaf) + Add(fresh KeyPackage)` and sends the Welcome.

use std::collections::VecDeque;

use openmls::key_packages::KeyPackage;
use openmls::prelude::LeafNodeIndex;
use openmls_traits::OpenMlsProvider as _;
use openmls_traits::crypto::OpenMlsCrypto;
use prost::Message as _;
use prost::bytes::Bytes;
use tracing::{debug, info, warn};

use super::GroupV3Convo;
use super::beacons::Beacons;
use super::external::{Branch, GroupV3External};
use super::payloads::to_external_envelope;
use super::sealed::{self, ReAddRequest, SealedKind, SealedMessage, SealedPayload};
use crate::conversation::mls_utils::{EpochFingerprint, fetch_key_packages};
use crate::service_context::{ReAddTarget, ServiceContext};
use crate::{
    AddressedEnvelope, ChatError, ConvoOutcome, DeliveryService, ExternalServices, Observation,
    SignerKey,
};

/// Requests already repaired, so a copy can't remove the fresh leaf.
pub(super) const SERVED_RETAINED: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    Served,
    NotAMember,
    /// We may be the one behind; re-adding the asker would be wrong.
    AskerAhead,
    /// We were in the state the asker names, so it is behind, not forked.
    SameState,
    /// Another member answers, so the group commits one repair.
    NotOurTurn,
    /// The asker's branch outranks ours, so we are the side that moves.
    Outranked,
}

/// What a member knows when judging a request.
pub(super) struct Judging<'a> {
    pub roster: &'a [(LeafNodeIndex, Vec<u8>)],
    pub own: LeafNodeIndex,
    pub epoch: u64,
    /// Who committed `epoch`, if we know.
    pub committer: Option<LeafNodeIndex>,
    /// Our state at the asker's epoch, if we still know it.
    pub ours_at: Option<&'a str>,
    pub served: &'a VecDeque<ReAddRequest>,
    /// Who vouched for which branch, to rank ours against the asker's.
    pub beacons: &'a Beacons,
}

/// The asker's stale leaf if we should repair it. With no record of the
/// asker's epoch we accept, so a real fork is never left stuck. Ranking comes
/// last, so only the answerer verifies the asker's evidence.
pub(super) fn judge(
    crypto: &impl OpenMlsCrypto,
    convo_id: &str,
    req: &ReAddRequest,
    at: &Judging,
) -> Result<LeafNodeIndex, Refusal> {
    let Judging {
        roster,
        own,
        epoch,
        committer,
        ours_at,
        served,
        beacons,
    } = *at;
    if served.iter().any(|s| s.asks_the_same(req)) {
        return Err(Refusal::Served);
    }
    let stale = roster
        .iter()
        .find(|(_, key)| key.as_slice() == req.signer_key.as_ref())
        .map(|(index, _)| *index)
        .ok_or(Refusal::NotAMember)?;
    if req.epoch > epoch {
        return Err(Refusal::AskerAhead);
    }
    if ours_at == Some(req.epoch_id.as_str()) {
        return Err(Refusal::SameState);
    }
    if answerer(roster, committer, stale, req.attempt) != Some(own) {
        return Err(Refusal::NotOurTurn);
    }
    if let Some(ours) = ours_at {
        let branch = |id: &str| Branch {
            epoch: req.epoch,
            epoch_id: id.to_string(),
        };
        let (ours, theirs) = (branch(ours), branch(&req.epoch_id));
        if beacons.yields(crypto, convo_id, &ours, &theirs, &req.evidence) {
            return Err(Refusal::Outranked);
        }
    }
    Ok(stale)
}

/// The committer answers attempt 0, then each next leaf, never the asker.
/// Every member of a branch picks the same one.
fn answerer(
    roster: &[(LeafNodeIndex, Vec<u8>)],
    committer: Option<LeafNodeIndex>,
    asker: LeafNodeIndex,
    attempt: u32,
) -> Option<LeafNodeIndex> {
    let mut leaves: Vec<_> = roster
        .iter()
        .map(|(i, _)| *i)
        .filter(|i| *i != asker)
        .collect();
    leaves.sort();
    let start = committer
        .and_then(|c| leaves.iter().position(|l| *l >= c))
        .unwrap_or(0);
    let len = leaves.len().max(1);
    let turn = (start + attempt as usize % len) % len;
    leaves.get(turn).copied()
}

/// Wraps rather than saturates, so retries keep moving past `u32::MAX`.
fn next_attempt(last: u32, next_answerer: bool) -> u32 {
    last.wrapping_add(u32::from(next_answerer))
}

impl GroupV3Convo {
    /// Seal a re-add request, with the signed beacons we hold at our epoch, to
    /// the one branch our ranking picks. Returns 0 or 1. Asking again reaches
    /// the same answerer; `next_answerer` moves on, and only once a repair
    /// would have landed, or two members repair.
    pub(super) fn request_readd<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        next_answerer: bool,
    ) -> Result<usize, ChatError> {
        let Some((to, vouchers)) = self.beacons.seal_target(&self.sync.log) else {
            return Ok(0);
        };
        let own = self
            .mls_group
            .own_leaf_node()
            .ok_or_else(|| ChatError::generic("not a member of this group"))?;
        let epoch = self.mls_group.epoch().as_u64();
        let epoch_id = EpochFingerprint::from(&self.mls_group).into_string();
        let req = ReAddRequest {
            signer_key: Bytes::copy_from_slice(own.signature_key().as_slice()),
            epoch,
            evidence: self.beacons.evidence(epoch, &epoch_id),
            epoch_id,
            signature: Bytes::new(),
            attempt: next_attempt(self.readd_attempt, next_answerer),
        };
        let attempt = req.attempt;

        let ciphersuite = self.mls_group.ciphersuite();
        let crypto = cx.mls_provider.crypto();
        let signed = sealed::sign_request(req, &self.convo_id, &to, &cx.mls_identity)
            .map_err(ChatError::generic)?;
        let payload = SealedPayload {
            kind: Some(SealedKind::ReAdd(signed)),
        };
        let msg = sealed::seal(crypto, ciphersuite, &self.convo_id, &to, &payload)
            .map_err(ChatError::generic)?;
        let frame = GroupV3External::sealed(msg).encode_to_vec();
        cx.ds
            .publish(to_external_envelope(&self.convo_id, frame))
            .map_err(ChatError::generic)?;

        self.readd_attempt = attempt;
        // The Welcome that answers this replaces the group; see `held_group_to_replace`.
        let target = ReAddTarget {
            epoch: to.epoch,
            vouchers,
        };
        cx.readd_pending.insert(self.convo_id.clone(), target);
        info!(convo = %self.convo_id, "asked to be re-added");
        Ok(1)
    }

    /// Anyone can publish a sealed message, so failing to open one is not an
    /// error. Only our current state opens, so a served request can't replay.
    pub(super) fn receive_sealed<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        msg: SealedMessage,
    ) -> Result<ConvoOutcome, ChatError> {
        let Some(key) = self.beacons.key_for(msg.epoch, &msg.epoch_id) else {
            debug!(convo = %self.convo_id, epoch = msg.epoch, "sealed to a state we do not hold");
            return Ok(self.default_outcome());
        };
        let crypto = cx.mls_provider.crypto();
        let ciphersuite = self.mls_group.ciphersuite();
        let payload = match sealed::open(crypto, ciphersuite, &self.convo_id, key, &msg) {
            Ok(payload) => payload,
            Err(e) => {
                debug!(convo = %self.convo_id, error = %e, "could not open a sealed message");
                return Ok(self.default_outcome());
            }
        };

        match payload.kind {
            Some(SealedKind::ReAdd(req))
                if sealed::verify_request(crypto, &self.convo_id, &req, &msg) =>
            {
                self.answer_readd(cx, req)
            }
            Some(SealedKind::ReAdd(_)) => {
                debug!(convo = %self.convo_id, "refused an unsigned re-add request");
                Ok(self.default_outcome())
            }
            None => Ok(self.default_outcome()),
        }
    }

    fn answer_readd<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        req: ReAddRequest,
    ) -> Result<ConvoOutcome, ChatError> {
        let roster: Vec<_> = self
            .mls_group
            .members()
            .map(|m| (m.index, m.signature_key))
            .collect();
        let at = Judging {
            roster: &roster,
            own: self.mls_group.own_leaf_index(),
            epoch: self.mls_group.epoch().as_u64(),
            committer: self.committer,
            ours_at: self.sync.log.at(req.epoch),
            served: &self.served_readds,
            beacons: &self.beacons,
        };
        let crypto = cx.mls_provider.crypto();
        let verdict = judge(crypto, &self.convo_id, &req, &at);
        let stale = match verdict {
            Ok(stale) => stale,
            Err(refusal) => {
                debug!(convo = %self.convo_id, ?refusal, "re-add request refused");
                return Ok(self.default_outcome());
            }
        };

        let signer = SignerKey::from(req.signer_key.as_ref());
        let key_packages = match fetch_key_packages(cx, std::iter::once(&signer)) {
            Ok(kps) => kps,
            Err(e) => {
                warn!(convo = %self.convo_id, error = %e, "no usable KeyPackage for a re-add");
                return Ok(self.default_outcome());
            }
        };

        self.readd(cx, stale, key_packages)?;
        if self.served_readds.len() == SERVED_RETAINED {
            self.served_readds.pop_front();
        }
        self.served_readds.push_back(req);
        info!(convo = %self.convo_id, %signer, "re-added a forked member");

        Ok(ConvoOutcome {
            observations: vec![Observation::SignersChanged],
            ..self.default_outcome()
        })
    }

    #[cfg(feature = "test-support")]
    pub(super) fn force_readd<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        signer: &SignerKey,
    ) -> Result<(), ChatError> {
        let stale = self
            .mls_group
            .members()
            .find(|m| m.signature_key == signer.as_bytes())
            .ok_or_else(|| ChatError::generic("not a member"))?
            .index;
        let key_packages = fetch_key_packages(cx, std::iter::once(signer))?;
        self.readd(cx, stale, key_packages)
    }

    /// `Remove` and `Add` in one commit, so the member is never out of the
    /// group with nobody bound to put it back.
    fn readd<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        stale: LeafNodeIndex,
        key_packages: Vec<KeyPackage>,
    ) -> Result<(), ChatError> {
        let bundle = self
            .mls_group
            .commit_builder()
            .propose_removals([stale])
            .propose_adds(key_packages.iter().cloned())
            .load_psks(cx.mls_provider.storage())
            .map_err(ChatError::generic)?
            .build(
                cx.mls_provider.rand(),
                cx.mls_provider.crypto(),
                &cx.mls_identity,
                |_| true,
            )
            .map_err(ChatError::generic)?
            .stage_commit(&cx.mls_provider)
            .map_err(ChatError::generic)?;
        let (commit, welcome, _) = bundle.into_messages();
        let welcome = welcome.ok_or_else(|| ChatError::generic("a re-add produced no Welcome"))?;

        let invites = key_packages
            .iter()
            .map(|kp| crate::inbox_v2::create_invite_v3(&SignerKey::from(kp.leaf_node()), &welcome))
            .collect::<Result<Vec<AddressedEnvelope>, _>>()?;
        self.send_pending_commit(cx, commit, invites)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbox_v2::MlsEphemeralPqProvider;

    const ASKER: &[u8] = &[1; 32];

    fn leaf(i: u32) -> LeafNodeIndex {
        LeafNodeIndex::new(i)
    }

    fn request(epoch: u64, epoch_id: &str) -> ReAddRequest {
        ReAddRequest {
            signer_key: Bytes::from_static(ASKER),
            epoch,
            epoch_id: epoch_id.to_string(),
            signature: Bytes::new(),
            attempt: 0,
            evidence: Vec::new(),
        }
    }

    /// Leaves 0, 1 (the asker), 2 and 3; epoch 5, committed by leaf 2.
    fn roster() -> Vec<(LeafNodeIndex, Vec<u8>)> {
        vec![
            (leaf(0), vec![0; 32]),
            (leaf(1), ASKER.to_vec()),
            (leaf(2), vec![2; 32]),
            (leaf(3), vec![3; 32]),
        ]
    }

    fn judge_as(
        own: u32,
        req: &ReAddRequest,
        ours_at: Option<&str>,
        served: &VecDeque<ReAddRequest>,
        beacons: &Beacons,
    ) -> Result<LeafNodeIndex, Refusal> {
        let roster = roster();
        let at = Judging {
            roster: &roster,
            own: leaf(own),
            epoch: 5,
            committer: Some(leaf(2)),
            ours_at,
            served,
            beacons,
        };
        let p = MlsEphemeralPqProvider::new().expect("provider");
        judge(p.crypto(), "convo-a", req, &at)
    }

    fn committer_judges(
        req: &ReAddRequest,
        ours_at: Option<&str>,
    ) -> Result<LeafNodeIndex, Refusal> {
        judge_as(2, req, ours_at, &VecDeque::new(), &Beacons::default())
    }

    /// Beacons with each `(epoch id, signer)` vouched for at epoch 5.
    fn vouched(pairs: &[(&str, u8)]) -> Beacons {
        let mut beacons = Beacons::default();
        for &(id, key) in pairs {
            let branch = Branch {
                epoch: 5,
                epoch_id: id.to_string(),
            };
            beacons.vouch(branch, &[key; 32]);
        }
        beacons
    }

    fn committer_ranks(req: &ReAddRequest, beacons: &Beacons) -> Result<LeafNodeIndex, Refusal> {
        judge_as(2, req, Some("ours"), &VecDeque::new(), beacons)
    }

    #[test]
    fn an_asker_on_a_stronger_branch_is_refused() {
        let beacons = vouched(&[("theirs", 2), ("theirs", 3), ("ours", 0)]);

        assert_eq!(
            committer_ranks(&request(5, "theirs"), &beacons),
            Err(Refusal::Outranked)
        );
    }

    /// Equal signers, and "ours" is the smaller id, so the asker moves.
    #[test]
    fn an_asker_that_loses_the_tie_is_repaired() {
        let beacons = vouched(&[("theirs", 2), ("ours", 0)]);

        assert_eq!(
            committer_ranks(&request(5, "theirs"), &beacons),
            Ok(leaf(1))
        );
    }

    #[test]
    fn the_epochs_committer_repairs_a_forked_member() {
        assert_eq!(
            committer_judges(&request(5, "theirs"), Some("ours")),
            Ok(leaf(1))
        );
    }

    #[test]
    fn with_no_record_of_the_epoch_we_accept() {
        assert_eq!(committer_judges(&request(2, "theirs"), None), Ok(leaf(1)));
    }

    #[test]
    fn an_asker_in_a_state_we_were_in_is_behind() {
        let refused = committer_judges(&request(3, "shared"), Some("shared"));
        assert_eq!(refused, Err(Refusal::SameState));
    }

    #[test]
    fn an_asker_ahead_of_us_is_refused() {
        assert_eq!(
            committer_judges(&request(6, "theirs"), None),
            Err(Refusal::AskerAhead)
        );
    }

    #[test]
    fn a_stranger_is_refused() {
        let mut req = request(5, "theirs");
        req.signer_key = Bytes::from_static(&[9; 32]);
        assert_eq!(
            committer_judges(&req, Some("ours")),
            Err(Refusal::NotAMember)
        );
    }

    #[test]
    fn only_the_answerer_repairs() {
        let req = request(5, "theirs");
        for own in [0, 3] {
            let verdict = judge_as(
                own,
                &req,
                Some("ours"),
                &VecDeque::new(),
                &Beacons::default(),
            );
            assert_eq!(verdict, Err(Refusal::NotOurTurn), "leaf {own}");
        }
    }

    /// The committer first, then each next leaf, wrapping, never the asker.
    #[test]
    fn each_attempt_moves_to_the_next_answerer() {
        let answers: Vec<_> = (0..4)
            .map(|attempt| answerer(&roster(), Some(leaf(2)), leaf(1), attempt))
            .collect();
        assert_eq!(answers, [2, 3, 0, 2].map(|i| Some(leaf(i))));
    }

    #[test]
    fn retries_keep_moving_past_the_last_attempt() {
        let mut attempt = u32::MAX;
        let mut answers = std::collections::BTreeSet::new();
        for _ in 0..4 {
            answers.insert(answerer(&roster(), Some(leaf(2)), leaf(1), attempt));
            attempt = next_attempt(attempt, true);
        }
        assert_eq!(answers.len(), 3, "every other member gets a turn");
    }

    #[test]
    fn the_asker_never_answers_for_itself() {
        let asker = leaf(2);
        assert_ne!(answerer(&roster(), Some(leaf(2)), asker, 0), Some(asker));
        assert_eq!(answerer(&roster(), Some(leaf(2)), asker, 0), Some(leaf(3)));
    }

    #[test]
    fn with_no_known_committer_the_lowest_leaf_answers() {
        assert_eq!(answerer(&roster(), None, leaf(1), 0), Some(leaf(0)));
    }

    /// Copies sealed to different targets carry different signatures, and a
    /// retry a different attempt: neither is a new ask.
    #[test]
    fn a_repeat_of_a_served_ask_is_refused() {
        let served = VecDeque::from([request(5, "theirs")]);
        let mut repeat = request(5, "theirs");
        repeat.signature = Bytes::from_static(&[7; 64]);
        repeat.attempt = 1;
        let verdict = judge_as(3, &repeat, Some("ours"), &served, &Beacons::default());
        assert_eq!(verdict, Err(Refusal::Served));
    }
}
