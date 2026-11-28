use openmls::group::StagedCommit;
use tracing::info;

use crate::conversation::mls_groups::HasMlsConvo as _;
use crate::conversation::mls_utils::EpochFingerprint;
use crate::service_context::ServiceContext;
use crate::{AddressedEnvelope, ChatError, ConvoOutcome, ExternalServices, Observation};

use super::{GroupV3Convo, readd, trace};

/// A commit that has been generated, but not applied. Commits are either `Pending` created by this member, or `Staged`.
/// PendingCommits are grouped with the outbound payloads, so that welcomes are not sent until the commit is finalized.
/// openmls holds a `Pending` commit itself, as the group's pending commit.
pub(super) enum DeferredCommit {
    Pending(Vec<AddressedEnvelope>),
    Staged(StagedCommit),
}

impl GroupV3Convo {
    /// Holds the pending commit, and `dependent_msgs` with it, until the commit is finalized.
    pub(super) fn defer_pending_commit<S: ExternalServices>(
        &mut self,
        cx: &ServiceContext<S>,
        dependent_msgs: Vec<AddressedEnvelope>,
    ) -> Result<(), ChatError> {
        let fingerprint = self
            .mls_group
            .pending_commit()
            .and_then(EpochFingerprint::from_staged_commit)
            .ok_or_else(|| ChatError::generic("no pending commit"))?;

        // openmls keeps the commit pending until it is finalized.
        self.defer_commit(cx, fingerprint, DeferredCommit::Pending(dependent_msgs));
        Ok(())
    }

    pub(super) fn defer_commit<S: ExternalServices>(
        &mut self,
        cx: &ServiceContext<S>,
        fingerprint: EpochFingerprint,
        commit: DeferredCommit,
    ) {
        self.finality.defer(fingerprint.clone(), cx.clock.now());
        self.deferred_commits.insert(fingerprint, commit);
    }

    /// Incorporate the commit into the group state, and send out any payloads if necessary.
    ///
    /// Call after there is confidence that all group members will apply the same commit.
    pub(super) fn finalize_deferred_commit<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        fingerprint: &EpochFingerprint,
    ) -> Result<ConvoOutcome, ChatError> {
        let deferred = self
            .deferred_commits
            .remove(fingerprint)
            .ok_or_else(|| ChatError::generic("cannot finalize commit that does not exist"))?;
        let starting_epoch = self.mls_group.epoch().as_u64();

        let payloads = match deferred {
            DeferredCommit::Pending(payloads) => {
                // `merge_pending_commit` silently does nothing once the pending commit is gone.
                let pending = self
                    .mls_group
                    .pending_commit()
                    .and_then(EpochFingerprint::from_staged_commit);
                if pending.as_ref() != Some(fingerprint) {
                    return Err(ChatError::generic("pending commit no longer exists"));
                }
                let readded = self
                    .mls_group
                    .pending_commit()
                    .map(|commit| readd::readded_signers(&self.mls_group, commit))
                    .unwrap_or_default();
                self.mls_group.merge_pending_commit(&cx.mls_provider)?;
                self.note_readds(readded);
                payloads
            }
            DeferredCommit::Staged(commit) => {
                if commit.epoch().as_u64() != starting_epoch + 1 {
                    return Err(ChatError::generic("commit is not for the next epoch"));
                }
                let readded = readd::readded_signers(&self.mls_group, &commit);
                self.mls_group
                    .merge_staged_commit(&cx.mls_provider, commit)
                    .map_err(ChatError::generic)?;
                self.note_readds(readded);
                vec![]
            }
        };
        // Recorded before the sends below, so a failed send cannot skip it.
        trace::epoch(self);

        // Notify Epoch history that we've updated the group state.
        // Record the fingerprint of the final state, to catch any state bugs
        self.epoch_data.advance_to(
            self.mls_group.epoch().as_u64(),
            EpochFingerprint::from_group(self.mls_group()),
        );

        self.drop_expired_deferred_commits();
        self.enter_epoch(cx);
        info!(
            convo = %self.convo_id,
            epoch = starting_epoch,
            new_epoch = self.mls_group.epoch().as_u64(),
            epochfingerprint = %fingerprint,
            "commit merged"
        );

        for env in payloads {
            Self::publish_envelope(cx, env)?;
        }

        Ok(ConvoOutcome {
            observations: vec![Observation::SignersChanged],
            ..self.default_outcome()
        })
    }

    fn drop_expired_deferred_commits(&mut self) {
        let epoch = self.mls_group.epoch();
        self.deferred_commits.retain(|_, v| match v {
            DeferredCommit::Staged(commit) => commit.epoch() > epoch,
            DeferredCommit::Pending(_) => false,
        })
    }
}
