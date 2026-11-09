//! Putting a forked member back. The member seals a [`ReAddRequest`] to
//! another branch's external key; one member of that branch repairs it with
//! `Remove(stale leaf) + Add(fresh KeyPackage)` and sends the Welcome.

use std::collections::VecDeque;

use openmls::key_packages::KeyPackage;
use openmls::prelude::LeafNodeIndex;
use openmls_traits::OpenMlsProvider as _;
use prost::bytes::Bytes;
use tracing::{debug, info, warn};

use super::GroupV3Convo;
use super::payloads::{GroupV3External, GroupV3Payload};
use super::sealed::{self, ReAddRequest, SealedKind, SealedMessage, SealedPayload};
use crate::conversation::mls_utils::{EpochFingerprint, fetch_key_packages};
use crate::service_context::ServiceContext;
use crate::{ChatError, ConvoOutcome, ExternalServices, Observation, SignerKey};

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
}

/// The asker's stale leaf if we should repair it. With no record of the
/// asker's epoch we accept, so a real fork is never left stuck.
pub(super) fn judge(req: &ReAddRequest, at: &Judging) -> Result<LeafNodeIndex, Refusal> {
    let Judging {
        roster,
        own,
        epoch,
        committer,
        ours_at,
        served,
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

impl GroupV3Convo {
    /// Seal a re-add request to every other branch we heard. Returns how many
    /// went out. Asking again reaches the same answerer; `next_answerer` moves
    /// on, and only once a repair would have landed, or two members repair.
    pub(super) fn request_readd<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        next_answerer: bool,
    ) -> Result<usize, ChatError> {
        let own = self
            .mls_group
            .own_leaf_node()
            .ok_or_else(|| ChatError::generic("not a member of this group"))?;
        let epoch_id = EpochFingerprint::from(&self.mls_group).into_string();
        let req = ReAddRequest {
            signer_key: Bytes::copy_from_slice(own.signature_key().as_slice()),
            epoch: self.mls_group.epoch().as_u64(),
            epoch_id,
            signature: Bytes::new(),
            attempt: self.readd_attempt.saturating_add(u32::from(next_answerer)),
        };

        let ciphersuite = self.mls_group.ciphersuite();
        let crypto = cx.mls_provider.crypto();
        let sealed: Vec<SealedMessage> = self
            .beacons
            .seal_targets()
            .map(|to| {
                let signed =
                    sealed::sign_request(req.clone(), &self.convo_id, to, &cx.mls_identity)?;
                let payload = SealedPayload {
                    kind: Some(SealedKind::ReAdd(signed)),
                };
                sealed::seal(crypto, ciphersuite, &self.convo_id, to, &payload)
            })
            .collect::<Result<_, _>>()
            .map_err(ChatError::generic)?;

        let mut sent = 0;
        let mut failed = None;
        for msg in sealed {
            let payload = GroupV3Payload::external(GroupV3External::sealed(msg));
            match self.publish_payload(cx, payload) {
                Ok(()) => sent += 1,
                Err(e) => failed = Some(e),
            }
        }
        match (sent, failed) {
            (0, Some(e)) => return Err(ChatError::generic(e)),
            (0, None) => return Ok(0),
            _ => {}
        }

        self.readd_attempt = req.attempt;
        // The Welcome that answers this replaces the group; see `held_group_to_replace`.
        cx.readd_pending.insert(self.convo_id.clone());
        info!(convo = %self.convo_id, sent, "asked to be re-added");
        Ok(sent)
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
            ours_at: self.beacons.our_epoch_id(req.epoch),
            served: &self.served_readds,
        };
        let verdict = judge(&req, &at);
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

        let start = self.send_pending_commit(cx, commit)?;
        for kp in &key_packages {
            let invite = crate::inbox_v2::create_invite_v3(
                &SignerKey::from(kp.leaf_node()),
                &welcome,
                &start,
            )?;
            Self::publish_envelope(cx, invite)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    ) -> Result<LeafNodeIndex, Refusal> {
        let roster = roster();
        let at = Judging {
            roster: &roster,
            own: leaf(own),
            epoch: 5,
            committer: Some(leaf(2)),
            ours_at,
            served,
        };
        judge(req, &at)
    }

    fn committer_judges(
        req: &ReAddRequest,
        ours_at: Option<&str>,
    ) -> Result<LeafNodeIndex, Refusal> {
        judge_as(2, req, ours_at, &VecDeque::new())
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
            let verdict = judge_as(own, &req, Some("ours"), &VecDeque::new());
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
        let verdict = judge_as(3, &repeat, Some("ours"), &served);
        assert_eq!(verdict, Err(Refusal::Served));
    }
}
