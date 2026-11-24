//! Information required to faciliate messaging between accounts.
//!  
//! Contexts are published under the `chat.*` namespace.
//! Given accounts are durable, high frequency data ought to be referrered to
//! indirectly.

use account_log::{AccountLog, Context, Ed25519VerifyingKey};

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

impl<T: AsRef<AccountLog>> ChatRead for T {
    fn chat_signers(&self) -> Vec<Ed25519VerifyingKey> {
        self.as_ref().ed25519_keys_for(&CHATSIGNER_CONTEXT)
    }

    fn revoked_chat_signers(&self) -> Vec<Ed25519VerifyingKey> {
        self.as_ref().revoked_ed25519_keys_for(&CHATSIGNER_CONTEXT)
    }
}

/// Writing your own chat endorsements.
pub trait ChatWrite {
    /// Endorse `key` as an installation this account messages from.
    fn endorse_chat_signer(self, key: &Ed25519VerifyingKey) -> Self;

    /// Withdraw the endorsement of `key`, so peers stop accepting the
    /// installation and stop adding it to conversations. Publishing fails when
    /// the account does not endorse it.
    fn revoke_chat_signer(self, key: &Ed25519VerifyingKey) -> Self;
}

impl<AP: AccountProvider + AccountPublisher> ChatWrite for AccountUpdate<'_, AP> {
    fn endorse_chat_signer(self, key: &Ed25519VerifyingKey) -> Self {
        self.endorse_ed25519_key(CHATSIGNER_CONTEXT, key)
    }

    fn revoke_chat_signer(self, key: &Ed25519VerifyingKey) -> Self {
        self.revoke_ed25519_key(CHATSIGNER_CONTEXT, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Account;
    use crate::test_support::TestAccountProvider;
    use account_log::Ed25519SigningKey;

    #[test]
    fn a_revoked_signer_moves_to_the_revoked_ones() {
        let mut account = Account::new(TestAccountProvider::default());
        let addr = account.addr();
        let (old, new) = (
            Ed25519SigningKey::generate().verifying_key(),
            Ed25519SigningKey::generate().verifying_key(),
        );

        account
            .update()
            .endorse_chat_signer(&old)
            .publish()
            .unwrap();
        let signed = account
            .update()
            .revoke_chat_signer(&old)
            .endorse_chat_signer(&new)
            .publish()
            .unwrap();

        let log = signed.verify(&addr).unwrap();
        assert_eq!(log.chat_signers(), vec![new]);
        assert_eq!(log.revoked_chat_signers(), vec![old]);
    }
}
