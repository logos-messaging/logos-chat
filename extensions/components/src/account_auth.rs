//! The rules an auth client draws from an account log.
//!
//! Shared, so a second client cannot quietly disagree with the first about who
//! is endorsed.

use account_log::{AccountLog, Context, Ed25519VerifyingKey};
use libchat::{AuthResult, SignerKey};

/// Whether `log` endorses `signer` under `context`, has revoked it, or has
/// never carried it at all.
pub(crate) fn verdict(
    log: &AccountLog,
    context: &Context,
    signer: &Ed25519VerifyingKey,
) -> AuthResult {
    if log.ed25519_keys_for(context).contains(signer) {
        AuthResult::Valid
    } else if log.revoked_ed25519_keys_for(context).contains(signer) {
        AuthResult::Revoked
    } else {
        AuthResult::Invalid
    }
}

/// The signers `log` endorses under `context`, as the core spells them.
pub(crate) fn endorsed_signers(log: &AccountLog, context: &Context) -> Vec<SignerKey> {
    log.ed25519_keys_for(context)
        .into_iter()
        .map(|key| SignerKey::from(key.as_ref()))
        .collect()
}
