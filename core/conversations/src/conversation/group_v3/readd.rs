//! Putting a forked member back. The member seals a [`ReAddRequest`] to
//! another branch's external key; one member of that branch repairs it with
//! `Remove(stale leaf) + Add(fresh KeyPackage)` and sends the Welcome.

use std::collections::VecDeque;

use openmls::group::{MlsGroup, StagedCommit};
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

/// Re-adds remembered, so a later request can't remove the fresh leaf.
const READDS_RETAINED: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    NotAMember,
    /// We may be the one behind; re-adding the asker would be wrong.
    AskerAhead,
    /// We were in the state the asker names, so it is behind, not forked.
    SameState,
    /// The asker was re-added after the state it names, so the leaf we hold
    /// for it is the fresh one.
    Readded,
    /// The asker named another member, so the group commits one repair.
    NotOurTurn,
}

/// What a member knows when judging a request.
pub(super) struct Judging<'a> {
    pub roster: &'a [(LeafNodeIndex, Vec<u8>)],
    /// Our leaf signature key.
    pub own: &'a [u8],
    pub epoch: u64,
    /// Our state at the asker's epoch, if we still know it.
    pub ours_at: Option<&'a str>,
    pub readds: &'a VecDeque<(Vec<u8>, u64)>,
}

/// The asker's stale leaf if we should repair it. With no record of the
/// asker's epoch we accept, so a real fork is never left stuck.
pub(super) fn judge(req: &ReAddRequest, at: &Judging) -> Result<LeafNodeIndex, Refusal> {
    let Judging {
        roster,
        own,
        epoch,
        ours_at,
        readds,
    } = *at;
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
    if readds
        .iter()
        .any(|(key, at)| key.as_slice() == req.signer_key.as_ref() && *at > req.epoch)
    {
        return Err(Refusal::Readded);
    }
    if req.answerer.as_ref() != own {
        return Err(Refusal::NotOurTurn);
    }
    Ok(stale)
}

/// Who answers `attempt` among a state's verified signers, never ourselves.
/// The order is fixed, so a retry moves to the next one.
fn answerer<'a>(signers: &'a [Vec<u8>], own: &[u8], attempt: u32) -> Option<&'a [u8]> {
    let mut others: Vec<_> = signers
        .iter()
        .map(Vec::as_slice)
        .filter(|key| *key != own)
        .collect();
    others.sort_unstable();
    let len = others.len();
    (len > 0).then(|| others[attempt as usize % len])
}

/// Signers `commit` re-adds: removed, and added again under the same key.
pub(super) fn readded_signers(group: &MlsGroup, commit: &StagedCommit) -> Vec<Vec<u8>> {
    let removed: Vec<Vec<u8>> = commit
        .remove_proposals()
        .filter_map(|p| group.member_at(p.remove_proposal().removed()))
        .map(|m| m.signature_key)
        .collect();
    commit
        .add_proposals()
        .map(|p| {
            p.add_proposal()
                .key_package()
                .leaf_node()
                .signature_key()
                .as_slice()
                .to_vec()
        })
        .filter(|key| removed.contains(key))
        .collect()
}

impl GroupV3Convo {
    /// Seal a re-add request to the newest other states we heard, each naming
    /// one of that state's verified signers to answer. Returns how many went
    /// out. Asking again names the same answerer; `next_answerer` moves on, and
    /// only once a repair would have landed, or two members repair.
    pub(super) fn request_readd<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        next_answerer: bool,
    ) -> Result<usize, ChatError> {
        let own = self
            .mls_group
            .own_leaf_node()
            .ok_or_else(|| ChatError::generic("not a member of this group"))?;
        let own_key = own.signature_key().as_slice();
        let attempt = self.readd_attempt.saturating_add(u32::from(next_answerer));
        let req = ReAddRequest {
            signer_key: Bytes::copy_from_slice(own_key),
            epoch: self.mls_group.epoch().as_u64(),
            epoch_id: EpochFingerprint::from(&self.mls_group).into_string(),
            signature: Bytes::new(),
            answerer: Bytes::new(),
        };

        let ciphersuite = self.mls_group.ciphersuite();
        let crypto = cx.mls_provider.crypto();
        let sealed: Vec<SealedMessage> = self
            .beacons
            .seal_targets()
            .filter_map(|state| {
                let answerer = answerer(state.signers(), own_key, attempt)?;
                Some((state.beacon(), Bytes::copy_from_slice(answerer)))
            })
            .map(|(to, answerer)| {
                let req = ReAddRequest {
                    answerer,
                    ..req.clone()
                };
                let signed = sealed::sign_request(req, &self.convo_id, to, &cx.mls_identity)?;
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

        self.readd_attempt = attempt;
        // The Welcome that answers this replaces the group; see `held_group_to_replace`.
        cx.readd_pending.insert(self.convo_id.clone());
        info!(convo = %self.convo_id, sent, "asked to be re-added");
        Ok(sent)
    }

    /// Anyone can publish a sealed message, so failing to open one is not an
    /// error. Only our current state opens, so an answered request can't replay.
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
        let own = self
            .mls_group
            .own_leaf_node()
            .ok_or_else(|| ChatError::generic("not a member of this group"))?
            .signature_key()
            .as_slice()
            .to_vec();
        let at = Judging {
            roster: &roster,
            own: &own,
            epoch: self.mls_group.epoch().as_u64(),
            ours_at: self.beacons.our_epoch_id(req.epoch),
            readds: &self.readds,
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
        info!(convo = %self.convo_id, %signer, "re-added a forked member");

        Ok(ConvoOutcome {
            observations: vec![Observation::SignersChanged],
            ..self.default_outcome()
        })
    }

    /// Remember who `readded` names, after merging the commit that re-added
    /// them.
    pub(super) fn note_readds(&mut self, readded: Vec<Vec<u8>>) {
        let epoch = self.mls_group.epoch().as_u64();
        for key in readded {
            if self.readds.len() == READDS_RETAINED {
                self.readds.pop_front();
            }
            self.readds.push_back((key, epoch));
        }
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

    fn key(n: u8) -> Vec<u8> {
        vec![n; 32]
    }

    /// Asks leaf 2 to answer.
    fn request(epoch: u64, epoch_id: &str) -> ReAddRequest {
        ReAddRequest {
            signer_key: Bytes::from_static(ASKER),
            epoch,
            epoch_id: epoch_id.to_string(),
            signature: Bytes::new(),
            answerer: key(2).into(),
        }
    }

    /// Leaves 0, 1 (the asker), 2 and 3, each keyed by its index; epoch 5.
    fn roster() -> Vec<(LeafNodeIndex, Vec<u8>)> {
        vec![
            (leaf(0), key(0)),
            (leaf(1), ASKER.to_vec()),
            (leaf(2), key(2)),
            (leaf(3), key(3)),
        ]
    }

    fn judge_as(
        own: u8,
        req: &ReAddRequest,
        ours_at: Option<&str>,
        readds: &VecDeque<(Vec<u8>, u64)>,
    ) -> Result<LeafNodeIndex, Refusal> {
        let roster = roster();
        let own = key(own);
        let at = Judging {
            roster: &roster,
            own: &own,
            epoch: 5,
            ours_at,
            readds,
        };
        judge(req, &at)
    }

    fn named_judges(req: &ReAddRequest, ours_at: Option<&str>) -> Result<LeafNodeIndex, Refusal> {
        judge_as(2, req, ours_at, &VecDeque::new())
    }

    #[test]
    fn the_named_member_repairs_a_forked_member() {
        assert_eq!(
            named_judges(&request(5, "theirs"), Some("ours")),
            Ok(leaf(1))
        );
    }

    #[test]
    fn with_no_record_of_the_epoch_we_accept() {
        assert_eq!(named_judges(&request(2, "theirs"), None), Ok(leaf(1)));
    }

    #[test]
    fn an_asker_in_a_state_we_were_in_is_behind() {
        let refused = named_judges(&request(3, "shared"), Some("shared"));
        assert_eq!(refused, Err(Refusal::SameState));
    }

    #[test]
    fn an_asker_ahead_of_us_is_refused() {
        assert_eq!(
            named_judges(&request(6, "theirs"), None),
            Err(Refusal::AskerAhead)
        );
    }

    #[test]
    fn a_stranger_is_refused() {
        let mut req = request(5, "theirs");
        req.signer_key = Bytes::from_static(&[9; 32]);
        assert_eq!(named_judges(&req, Some("ours")), Err(Refusal::NotAMember));
    }

    #[test]
    fn only_the_named_member_repairs() {
        let req = request(5, "theirs");
        for own in [0, 3] {
            let verdict = judge_as(own, &req, Some("ours"), &VecDeque::new());
            assert_eq!(verdict, Err(Refusal::NotOurTurn), "leaf {own}");
        }
    }

    /// Any member that merged the re-add refuses, not just the one that
    /// answered: the leaf it holds for the asker is the fresh one.
    #[test]
    fn an_asker_readded_since_its_state_is_refused() {
        let readds = VecDeque::from([(ASKER.to_vec(), 4)]);
        let verdict = judge_as(2, &request(3, "theirs"), Some("ours"), &readds);
        assert_eq!(verdict, Err(Refusal::Readded));
    }

    /// A fork after the re-add is a new one.
    #[test]
    fn an_asker_stuck_after_its_readd_is_repaired() {
        let readds = VecDeque::from([(ASKER.to_vec(), 4)]);
        let verdict = judge_as(2, &request(4, "theirs"), Some("ours"), &readds);
        assert_eq!(verdict, Ok(leaf(1)));
    }

    /// In key order, wrapping, never ourselves.
    #[test]
    fn each_attempt_names_the_next_signer() {
        let signers = [key(3), key(0), ASKER.to_vec(), key(2)];
        let answers: Vec<_> = (0..4)
            .map(|attempt| answerer(&signers, ASKER, attempt).map(<[u8]>::to_vec))
            .collect();
        assert_eq!(answers, [key(0), key(2), key(3), key(0)].map(Some));
    }

    #[test]
    fn a_state_only_we_signed_has_no_answerer() {
        assert_eq!(answerer(&[ASKER.to_vec()], ASKER, 0), None);
    }

    /// Real groups, so the commit is read as a receiver reads it.
    mod readded {
        use openmls::credentials::{BasicCredential, CredentialWithKey};
        use openmls::framing::{
            MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProcessedMessageContent,
        };
        use openmls::prelude::StagedWelcome;
        use openmls::prelude::tls_codec::Deserialize as _;
        use openmls_traits::crypto::OpenMlsCrypto as _;
        use openmls_traits::signatures::{Signer, SignerError};
        use openmls_traits::types::SignatureScheme;

        use super::*;
        use crate::conversation::group_v3::external::tests::{leaf_key, provider};
        use crate::conversation::mls_extensions::capabilities_with_group_metadata;
        use crate::conversation::mls_groups::{group_create_config, group_join_config};
        use crate::inbox_v2::{CIPHER_SUITE, MlsEphemeralPqProvider};

        struct Member {
            p: MlsEphemeralPqProvider,
            private: Vec<u8>,
            public: Vec<u8>,
        }

        impl Signer for Member {
            fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
                self.p
                    .crypto()
                    .sign(SignatureScheme::ED25519, payload, &self.private)
                    .map_err(|_| SignerError::SigningError)
            }

            fn signature_scheme(&self) -> SignatureScheme {
                SignatureScheme::ED25519
            }
        }

        impl Member {
            fn new() -> Self {
                let p = provider();
                let (private, public) = leaf_key(&p);
                Self { p, private, public }
            }

            fn credential(&self) -> CredentialWithKey {
                CredentialWithKey {
                    credential: BasicCredential::new(self.public.clone()).into(),
                    signature_key: self.public.clone().into(),
                }
            }

            fn key_package(&self) -> KeyPackage {
                KeyPackage::builder()
                    .leaf_node_capabilities(capabilities_with_group_metadata())
                    .build(CIPHER_SUITE, &self.p, self, self.credential())
                    .expect("key package")
                    .key_package()
                    .clone()
            }
        }

        fn parse(msg: MlsMessageOut) -> MlsMessageBodyIn {
            let bytes = msg.to_bytes().expect("serialize");
            MlsMessageIn::tls_deserialize_exact(&bytes)
                .expect("deserialize")
                .extract()
        }

        /// Saro commits, and Pax stages the commit as a receiver.
        fn received(
            saro: &Member,
            group: &mut MlsGroup,
            pax: &Member,
            pax_group: &mut MlsGroup,
            removed: &[LeafNodeIndex],
            added: &[KeyPackage],
        ) -> Vec<Vec<u8>> {
            let bundle = group
                .commit_builder()
                .propose_removals(removed.iter().copied())
                .propose_adds(added.iter().cloned())
                .load_psks(saro.p.storage())
                .expect("psks")
                .build(saro.p.rand(), saro.p.crypto(), saro, |_| true)
                .expect("commit")
                .stage_commit(&saro.p)
                .expect("staged");
            let (commit, _, _) = bundle.into_messages();
            group.merge_pending_commit(&saro.p).expect("merged");

            let bytes = commit.to_bytes().expect("serialize");
            let commit = MlsMessageIn::tls_deserialize_exact(&bytes)
                .expect("deserialize")
                .try_into_protocol_message()
                .expect("a commit");
            let processed = pax_group
                .process_message(&pax.p, commit)
                .expect("processed");
            let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content()
            else {
                panic!("a staged commit")
            };
            let readded = readded_signers(pax_group, &staged);
            pax_group
                .merge_staged_commit(&pax.p, *staged)
                .expect("merged");
            readded
        }

        #[test]
        fn a_received_commit_names_only_the_readded_signer() {
            let (saro, raya, pax, mira) =
                (Member::new(), Member::new(), Member::new(), Member::new());
            let mut group = MlsGroup::new(
                &saro.p,
                &saro,
                &group_create_config("", ""),
                saro.credential(),
            )
            .expect("group");
            let (_, welcome, _) = group
                .add_members(&saro.p, &saro, &[raya.key_package(), pax.key_package()])
                .expect("added");
            group.merge_pending_commit(&saro.p).expect("merged");
            let MlsMessageBodyIn::Welcome(welcome) = parse(welcome) else {
                panic!("a Welcome")
            };
            let mut pax_group =
                StagedWelcome::build_from_welcome(&pax.p, &group_join_config(), welcome)
                    .expect("welcome")
                    .build()
                    .expect("staged")
                    .into_group(&pax.p)
                    .expect("joined");
            let raya_leaf = |g: &MlsGroup| {
                g.members()
                    .find(|m| m.signature_key == raya.public)
                    .expect("Raya is a member")
                    .index
            };

            let adds_only = received(
                &saro,
                &mut group,
                &pax,
                &mut pax_group,
                &[],
                &[mira.key_package()],
            );
            assert!(adds_only.is_empty());

            let stale = raya_leaf(&group);
            let readd = received(
                &saro,
                &mut group,
                &pax,
                &mut pax_group,
                &[stale],
                &[raya.key_package()],
            );
            assert_eq!(readd, std::slice::from_ref(&raya.public));

            let stale = raya_leaf(&group);
            let swapped = received(
                &saro,
                &mut group,
                &pax,
                &mut pax_group,
                &[stale],
                &[Member::new().key_package()],
            );
            assert!(swapped.is_empty());
        }
    }
}
