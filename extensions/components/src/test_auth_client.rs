//! The in-memory dual of [`HttpAuthClient`](crate::HttpAuthClient), for tests.

use account_log::{AccountRecord, Ed25519VerifyingKey, SignedAccountLog};
use libchat::{AuthResult, AuthService, ParticipantId, SignerKey};
use logos_account::test_support::TestAccountProvider;
use logos_account::{AccountAddr, AccountProvider, AccountPublisher, ChatRead};

/// Publishes, fetches and validates accounts in memory, as
/// [`HttpAuthClient`](crate::HttpAuthClient) does against its server. Clones
/// share state, so a vault and a client given clones see the same accounts.
#[derive(Clone, Default)]
pub struct TestAuthClient(TestAccountProvider);

impl std::fmt::Debug for TestAuthClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestAuthClient").finish_non_exhaustive()
    }
}

impl TestAuthClient {
    fn get_account(&self, addr: &AccountAddr) -> Result<Option<AccountRecord>, String> {
        let Some(signed_log) = self.fetch(addr)? else {
            return Ok(None);
        };
        AccountRecord::new(addr.to_owned(), signed_log)
            .map(Some)
            .map_err(|e| e.to_string())
    }
}

impl AccountProvider for TestAuthClient {
    type Error = String;

    fn fetch(&self, addr: &AccountAddr) -> Result<Option<SignedAccountLog>, Self::Error> {
        self.0.fetch(addr)
    }
}

impl AccountPublisher for TestAuthClient {
    type Error = String;

    fn publish(&mut self, addr: &AccountAddr, log: &SignedAccountLog) -> Result<(), Self::Error> {
        self.0.publish(addr, log)
    }
}

impl AuthService for TestAuthClient {
    type Error = String;

    fn validate_signer(
        &self,
        signer_key: SignerKey,
        participant_id: ParticipantId,
    ) -> Result<AuthResult, Self::Error> {
        let Ok(addr) = AccountAddr::try_from(participant_id.as_bytes()) else {
            return Ok(AuthResult::Invalid);
        };
        let Ok(signer) = Ed25519VerifyingKey::from_canonical_slice(signer_key.as_bytes()) else {
            return Ok(AuthResult::Invalid);
        };
        let Some(account) = self.get_account(&addr)? else {
            return Ok(AuthResult::Invalid);
        };

        Ok(if account.chat_signers().contains(&signer) {
            AuthResult::Valid
        } else if account.revoked_chat_signers().contains(&signer) {
            AuthResult::Revoked
        } else {
            AuthResult::Invalid
        })
    }

    fn signers_for_participant(
        &self,
        participant_id: &ParticipantId,
    ) -> Result<Vec<SignerKey>, Self::Error> {
        let addr = AccountAddr::try_from(participant_id.as_bytes()).map_err(|e| e.to_string())?;
        let Some(account) = self.get_account(&addr)? else {
            return Err(format!("account not found: {addr}"));
        };

        let signers: Vec<SignerKey> = account
            .chat_signers()
            .into_iter()
            .map(|k| SignerKey::from(k.as_ref()))
            .collect();
        if signers.is_empty() {
            return Err("account has no chat signers".into());
        }
        Ok(signers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_vault::test_support::TestFileKeyVault;

    #[test]
    fn an_installed_key_is_valid_for_its_account() {
        let auth = TestAuthClient::default();
        let vault = TestFileKeyVault::new(auth.clone());

        let key = vault.install("saro").expect("mint saro:1");
        let signer = SignerKey::from(key.signing_key.verifying_key().as_ref());
        let participant = ParticipantId::from(key.account.to_bytes());

        assert_eq!(
            auth.validate_signer(signer.clone(), participant.clone()),
            Ok(AuthResult::Valid)
        );
        assert_eq!(auth.signers_for_participant(&participant), Ok(vec![signer]));
    }
}
