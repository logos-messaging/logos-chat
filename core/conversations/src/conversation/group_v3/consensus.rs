use std::fmt::Debug;

use openmls::group::StagedCommit;

use crate::utils::{blake2b_hex, hash_size};

/// Outcome of a submitted commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitVerdict {
    Merge,
    Discard,
    Failed(String),
}

#[derive(Debug, PartialEq, Clone)]
pub struct CommitFingerprint {
    val: String,
}

impl CommitFingerprint {
    pub fn as_str(&self) -> &str {
        &self.val
    }
}

impl From<&StagedCommit> for CommitFingerprint {
    fn from(value: &StagedCommit) -> Self {
        let authenticator = value.epoch_authenticator().expect("is member");
        let hash = blake2b_hex::<hash_size::EpochFingerprint>(&[
            b"logos-chat|epoch-fingerprint|v1\0",
            authenticator.as_slice(),
        ]);

        Self { val: hash }
    }
}

/// Orders commits. `submit` must not block; the convo polls for the verdict on wakeup.
pub trait CommitValidator: Send + Debug {
    // Am I the steward? Can I make a commit?
    fn can_make_commit(&self) -> bool;

    // Proposes `fingerprint` as the commit leaving `epoch`.
    fn propose_commit(&mut self, epoch: u64, fingerprint: CommitFingerprint);

    // I've received a commit, should I merge it?
    fn can_merge_commit(&self, epoch: u64, fingerprint: CommitFingerprint) -> CommitVerdict;

    // I've recieved an an incomming payload for the Validator
    fn handle_payload(&mut self, bytes: &[u8]) -> Result<(), String>;
}

#[derive(Debug)]
pub struct YoloValidator {}

impl CommitValidator for YoloValidator {
    fn can_make_commit(&self) -> bool {
        true
    }

    fn propose_commit(&mut self, _epoch: u64, _fingerprint: CommitFingerprint) {
        ()
    }

    fn can_merge_commit(&self, _epoch: u64, _fingerprint: CommitFingerprint) -> CommitVerdict {
        CommitVerdict::Merge
    }

    fn handle_payload(&mut self, bytes: &[u8]) -> Result<(), String> {
        Ok(())
    }
}
