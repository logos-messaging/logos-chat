//! An [`AuthService`] over any [`AccountProvider`] that holds each account's
//! verified log for a TTL.
//!
//! - One fetch answers both methods, `Revoked` included.
//! - A refetched log replaces the held one only if it extends it
//!   ([`AccountResolver`]), so a stale replica cannot undo a revocation.
//! - Only a positive answer is served from the held log: a signer it does not
//!   endorse, or an account with no endorsed signers, is fetched again, so a
//!   fresh endorsement is seen at once. The cost is that a revocation goes
//!   unseen until the TTL expires.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use account_log::{AccountAddrError, AccountRecord, Ed25519VerifyingKey};
use libchat::{AuthResult, AuthService, ParticipantId, SignerKey};
use logos_account::{AccountAddr, AccountError, AccountProvider, AccountResolver, ChatRead};

#[derive(Debug, thiserror::Error)]
pub enum CachedAuthError {
    #[error(transparent)]
    Account(#[from] AccountError),
    #[error(transparent)]
    Addr(#[from] AccountAddrError),
    #[error("No account was found for address {0}")]
    AccountNotFound(AccountAddr),
    #[error("AccountLog contains zero endorsed keys")]
    NotChatEnabled,
}

pub struct CachedAuth<P> {
    ttl: Duration,
    accounts: RefCell<Accounts<P>>,
}

struct Accounts<P> {
    resolver: AccountResolver<P>,
    fetched_at: HashMap<AccountAddr, Instant>,
}

impl<P> fmt::Debug for CachedAuth<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedAuth")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl<P: AccountProvider> CachedAuth<P> {
    pub fn new(provider: P, ttl: Duration) -> Self {
        Self {
            ttl,
            accounts: RefCell::new(Accounts {
                resolver: AccountResolver::new(provider),
                fetched_at: HashMap::new(),
            }),
        }
    }

    /// `read` applied to the log held for `addr`, if fetched within the TTL.
    fn get_cached<T>(
        &self,
        addr: &AccountAddr,
        read: impl FnOnce(&AccountRecord) -> T,
    ) -> Option<T> {
        let accounts = self.accounts.borrow();
        let fresh = accounts
            .fetched_at
            .get(addr)
            .is_some_and(|at| at.elapsed() < self.ttl);
        if !fresh {
            return None;
        }
        accounts.resolver.get(addr).map(read)
    }

    /// Fetches `addr`, then applies `read` to the log held afterwards.
    fn refetch<T>(
        &self,
        addr: &AccountAddr,
        read: impl FnOnce(Option<&AccountRecord>) -> T,
    ) -> Result<T, AccountError> {
        let mut accounts = self.accounts.borrow_mut();
        accounts.resolver.resolve(addr)?;
        accounts.fetched_at.insert(addr.clone(), Instant::now());
        Ok(read(accounts.resolver.get(addr)))
    }
}

impl<P: AccountProvider> AuthService for CachedAuth<P> {
    type Error = CachedAuthError;

    fn validate_signer(
        &self,
        signer_key: SignerKey,
        participant_id: ParticipantId,
    ) -> Result<AuthResult, Self::Error> {
        // A malformed claim is a definite no, not a failure to decide.
        let Ok(addr) = AccountAddr::try_from(participant_id.as_bytes()) else {
            return Ok(AuthResult::Invalid);
        };
        let Ok(signer) = Ed25519VerifyingKey::from_canonical_slice(signer_key.as_bytes()) else {
            return Ok(AuthResult::Invalid);
        };

        if self
            .get_cached(&addr, |record| record.chat_signers().contains(&signer))
            .unwrap_or(false)
        {
            return Ok(AuthResult::Valid);
        }
        let result = self.refetch(&addr, |record| {
            record.map_or(AuthResult::Invalid, |record| verdict(record, &signer))
        })?;
        Ok(result)
    }

    fn signers_for_participant(
        &self,
        participant_id: &ParticipantId,
    ) -> Result<Vec<SignerKey>, Self::Error> {
        let addr = AccountAddr::try_from(participant_id.as_bytes())?;

        if let Some(signers) = self
            .get_cached(&addr, chat_signer_keys)
            .filter(|signers| !signers.is_empty())
        {
            return Ok(signers);
        }
        let signers = self
            .refetch(&addr, |record| record.map(chat_signer_keys))?
            .ok_or_else(|| CachedAuthError::AccountNotFound(addr.clone()))?;
        if signers.is_empty() {
            return Err(CachedAuthError::NotChatEnabled);
        }
        Ok(signers)
    }
}

/// What `record` says of `signer`.
fn verdict(record: &AccountRecord, signer: &Ed25519VerifyingKey) -> AuthResult {
    if record.chat_signers().contains(signer) {
        AuthResult::Valid
    } else if record.revoked_chat_signers().contains(signer) {
        AuthResult::Revoked
    } else {
        AuthResult::Invalid
    }
}

/// The installation keys `record` endorses.
fn chat_signer_keys(record: &AccountRecord) -> Vec<SignerKey> {
    record
        .chat_signers()
        .into_iter()
        .map(SignerKey::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use account_log::{Ed25519SigningKey, SignedAccountLog};
    use logos_account::test_support::TestAccountProvider;
    use logos_account::{Account, ChatWrite};

    use super::*;

    /// Serves the logs it is given and counts fetches.
    #[derive(Default)]
    struct Counting {
        logs: RefCell<HashMap<AccountAddr, SignedAccountLog>>,
        fetches: Cell<u32>,
    }

    impl Counting {
        fn serve(&self, account: &Account<TestAccountProvider>, log: &SignedAccountLog) {
            self.logs.borrow_mut().insert(account.addr(), log.clone());
        }
    }

    impl AccountProvider for &Counting {
        type Error = String;

        fn fetch(&self, addr: &AccountAddr) -> Result<Option<SignedAccountLog>, String> {
            self.fetches.set(self.fetches.get() + 1);
            Ok(self.logs.borrow().get(addr).cloned())
        }
    }

    /// An account that endorses `signer`, and the log that says so.
    fn endorsing(signer: &Ed25519VerifyingKey) -> (Account<TestAccountProvider>, SignedAccountLog) {
        let mut account = Account::new(TestAccountProvider::default());
        let log = account
            .update()
            .endorse_chat_signer(signer)
            .publish()
            .unwrap();
        (account, log)
    }

    fn participant(account: &Account<TestAccountProvider>) -> ParticipantId {
        ParticipantId::from(account.addr().to_bytes())
    }

    /// A provider serving the log of an account that endorses `signer`.
    fn serving(signer: &Ed25519VerifyingKey) -> (Counting, ParticipantId) {
        let (account, log) = endorsing(signer);
        let provider = Counting::default();
        provider.serve(&account, &log);
        (provider, participant(&account))
    }

    #[test]
    fn held_log_answers_without_a_fetch() {
        let signer = Ed25519SigningKey::generate().verifying_key();
        let (provider, id) = serving(&signer);
        let auth = CachedAuth::new(&provider, Duration::from_secs(60));

        let first = auth.validate_signer(SignerKey::from(&signer), id.clone());
        let second = auth.validate_signer(SignerKey::from(&signer), id.clone());
        let signers = auth.signers_for_participant(&id);

        assert!(matches!(first, Ok(AuthResult::Valid)), "{first:?}");
        assert!(matches!(second, Ok(AuthResult::Valid)), "{second:?}");
        assert_eq!(signers.unwrap(), vec![SignerKey::from(&signer)]);
        assert_eq!(provider.fetches.get(), 1);
    }

    #[test]
    fn unendorsed_signer_is_fetched_again() {
        let signer = Ed25519SigningKey::generate().verifying_key();
        let (provider, id) = serving(&signer);
        let auth = CachedAuth::new(&provider, Duration::from_secs(60));

        auth.validate_signer(SignerKey::from(&signer), id.clone())
            .unwrap();
        let other = Ed25519SigningKey::generate().verifying_key();
        let result = auth.validate_signer(SignerKey::from(&other), id);

        assert!(matches!(result, Ok(AuthResult::Invalid)), "{result:?}");
        assert_eq!(provider.fetches.get(), 2);
    }

    #[test]
    fn stale_log_does_not_undo_a_revocation() {
        let signer = Ed25519SigningKey::generate().verifying_key();
        let (mut account, endorsed) = endorsing(&signer);
        let revoked = account.update().revoke(0).publish().unwrap();
        let provider = Counting::default();
        // Fetch on every call.
        let auth = CachedAuth::new(&provider, Duration::ZERO);

        provider.serve(&account, &revoked);
        let before = auth.validate_signer(SignerKey::from(&signer), participant(&account));
        provider.serve(&account, &endorsed);
        let after = auth.validate_signer(SignerKey::from(&signer), participant(&account));

        assert!(matches!(before, Ok(AuthResult::Revoked)), "{before:?}");
        assert!(matches!(after, Ok(AuthResult::Revoked)), "{after:?}");
    }

    #[test]
    fn expired_log_is_fetched_again() {
        let signer = Ed25519SigningKey::generate().verifying_key();
        let (provider, id) = serving(&signer);
        let auth = CachedAuth::new(&provider, Duration::ZERO);

        auth.signers_for_participant(&id).unwrap();
        auth.signers_for_participant(&id).unwrap();

        assert_eq!(provider.fetches.get(), 2);
    }
}
