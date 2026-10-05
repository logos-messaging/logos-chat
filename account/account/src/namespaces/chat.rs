//! Information required to faciliate messaging between accounts.
//!  
//! Contexts are published under the `chat.*` namespace.
//! Given accounts are durable, high frequency data ought to be referrered to
//! indirectly.

use account_log::{AccountRecord, Context, Ed25519VerifyingKey};

use crate::{AccountProvider, AccountPublisher, AccountUpdate};

/// Context definitions
const CHATSIGNER_CONTEXT: Context = Context::literal("chat.signer");

/// Reading an account's chat endorsements.
pub trait ChatRead {
    /// Every installation key the account still endorses, oldest first.
    fn chat_signers(&self) -> Vec<Ed25519VerifyingKey>;

    /// Keys the account endorsed and has since withdrawn.
    fn revoked_chat_signers(&self) -> Vec<Ed25519VerifyingKey>;
}

impl ChatRead for AccountRecord {
    fn chat_signers(&self) -> Vec<Ed25519VerifyingKey> {
        self.log().ed25519_keys_for(&CHATSIGNER_CONTEXT)
    }

    fn revoked_chat_signers(&self) -> Vec<Ed25519VerifyingKey> {
        self.log().revoked_ed25519_keys_for(&CHATSIGNER_CONTEXT)
    }
}

/// Writing your own chat endorsements.
pub trait ChatWrite {
    /// Endorse `key` as an installation this account messages from.
    fn endorse_chat_signer(self, key: &Ed25519VerifyingKey) -> Self;
}

impl<AP: AccountProvider + AccountPublisher> ChatWrite for AccountUpdate<'_, AP> {
    fn endorse_chat_signer(self, key: &Ed25519VerifyingKey) -> Self {
        self.endorse_ed25519_key(CHATSIGNER_CONTEXT, key)
    }
}
