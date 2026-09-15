use std::collections::HashMap;

use account_log::{AccountAddr, AccountLogError, AccountRecord, LogFreshness, Outcome};

use crate::{AccountError, AccountProvider};

/// Resolves accounts other than your own: the consumer-side counterpart to
/// [`Account`](crate::Account), holding no signing key and only reading.
///
/// A log is adopted only where it extends the one already held for that
/// address, so a stale replica or a second history is refused rather than
/// believed.
pub struct AccountResolver<P> {
    provider: P,
    known: HashMap<AccountAddr, AccountRecord>,
}

impl<P: AccountProvider> AccountResolver<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            known: HashMap::new(),
        }
    }

    /// The record held for `addr`, without fetching.
    pub fn get(&self, addr: &AccountAddr) -> Option<&AccountRecord> {
        self.known.get(addr)
    }

    /// Fetch the log under `addr` and adopt it if it extends what is held.
    /// `Ok(None)` means the account has never published.
    ///
    /// Identical or behind is not an error — a replica may be stale.
    /// Unreadable, unsigned, or a second history is, and the held record
    /// survives it.
    pub fn resolve(&mut self, addr: &AccountAddr) -> Result<Option<&AccountRecord>, AccountError> {
        let fetched = self
            .provider
            .fetch(addr)
            .map_err(|e| AccountError::Provider(e.to_string()))?;

        // A provider that has lost the log does not take with it what we
        // already verified.
        let Some(candidate) = fetched else {
            return Ok(self.known.get(addr));
        };

        let (record, refused) = match self.known.remove(addr) {
            // First contact: nothing to compare against, so the signature is
            // the only check there is, and a failure retains nothing.
            None => (AccountRecord::new(addr.clone(), candidate)?, None),
            Some(held) => {
                let update = held.update(candidate);
                let refused = match update.outcome {
                    Outcome::Unchanged(LogFreshness::Diverged) => Some(AccountError::Forked),
                    Outcome::SignatureInvalid => {
                        Some(AccountError::Log(AccountLogError::SignatureInvalid))
                    }
                    Outcome::Malformed(error) => Some(AccountError::Log(error)),
                    // Identical or behind is a replica doing nothing wrong.
                    // `Newer` cannot appear: `update` reports it as `Updated`.
                    Outcome::Updated | Outcome::Unchanged(_) => None,
                };
                (update.record, refused)
            }
        };

        // The record is always the one to keep, refused candidate or not.
        self.known.insert(addr.clone(), record);
        match refused {
            Some(error) => Err(error),
            None => Ok(self.known.get(addr)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use account_log::{
        AccountLogDraft, Ed25519SigningKey, EntryData, SIGNER_CONTEXT, SignedAccountLog,
    };

    /// Serves whatever it was given, under whatever address it was given.
    #[derive(Debug, Default)]
    struct FakeProvider(HashMap<AccountAddr, SignedAccountLog>);

    impl AccountProvider for FakeProvider {
        type Error = String;
        fn fetch(&self, addr: &AccountAddr) -> Result<Option<SignedAccountLog>, Self::Error> {
            Ok(self.0.get(addr).cloned())
        }
    }

    /// A log of `values`, signed by `key`. Built here rather than through
    /// `Account` so one key can sign two histories.
    fn signed(key: &Ed25519SigningKey, values: &[&str]) -> SignedAccountLog {
        let mut draft = AccountLogDraft::new();
        for value in values {
            draft
                .add(SIGNER_CONTEXT.clone(), EntryData::Text((*value).into()))
                .expect("valid entry");
        }
        let payload = draft.log().encode().expect("within the size limit");
        let signature = key.sign(payload.as_bytes());
        SignedAccountLog { payload, signature }
    }

    fn names(record: &AccountRecord) -> Vec<&str> {
        record.log().text_for(&SIGNER_CONTEXT)
    }

    #[test]
    fn an_account_that_never_published_resolves_to_nothing() {
        let key = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(&key.verifying_key());
        let mut resolver = AccountResolver::new(FakeProvider::default());

        assert!(resolver.resolve(&addr).unwrap().is_none());
        assert!(resolver.get(&addr).is_none());
    }

    #[test]
    fn an_extension_is_adopted() {
        let key = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(&key.verifying_key());
        let mut provider = FakeProvider::default();
        provider.0.insert(addr.clone(), signed(&key, &["alice"]));
        let mut resolver = AccountResolver::new(provider);

        assert_eq!(names(resolver.resolve(&addr).unwrap().unwrap()), ["alice"]);

        resolver
            .provider
            .0
            .insert(addr.clone(), signed(&key, &["alice", "alice j"]));
        assert_eq!(
            names(resolver.resolve(&addr).unwrap().unwrap()),
            ["alice", "alice j"]
        );
    }

    /// The check the retention exists for: a second history under the same
    /// address is refused, and what was already verified survives.
    #[test]
    fn a_forked_history_is_refused() {
        let key = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(&key.verifying_key());
        let mut provider = FakeProvider::default();
        provider.0.insert(addr.clone(), signed(&key, &["alice"]));
        let mut resolver = AccountResolver::new(provider);
        resolver.resolve(&addr).unwrap();

        // Longer, validly signed by the same account — and not an extension.
        resolver
            .provider
            .0
            .insert(addr.clone(), signed(&key, &["bea", "bea j"]));

        assert!(matches!(resolver.resolve(&addr), Err(AccountError::Forked)));
        assert_eq!(names(resolver.get(&addr).unwrap()), ["alice"]);
    }

    /// A replica serving an older copy is ordinary, not an error.
    #[test]
    fn a_stale_replica_leaves_the_held_record_alone() {
        let key = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(&key.verifying_key());
        let mut provider = FakeProvider::default();
        provider
            .0
            .insert(addr.clone(), signed(&key, &["alice", "alice j"]));
        let mut resolver = AccountResolver::new(provider);
        resolver.resolve(&addr).unwrap();

        resolver
            .provider
            .0
            .insert(addr.clone(), signed(&key, &["alice"]));
        assert_eq!(
            names(resolver.resolve(&addr).unwrap().unwrap()),
            ["alice", "alice j"]
        );
    }

    /// A real log, served in answer to a query for someone else.
    #[test]
    fn another_accounts_log_is_refused() {
        let key = Ed25519SigningKey::generate();
        let other = AccountAddr::from(&Ed25519SigningKey::generate().verifying_key());
        let mut provider = FakeProvider::default();
        provider.0.insert(other.clone(), signed(&key, &["alice"]));

        let mut resolver = AccountResolver::new(provider);
        assert!(matches!(
            resolver.resolve(&other),
            Err(AccountError::Log(AccountLogError::SignatureInvalid))
        ));
        assert!(resolver.get(&other).is_none());
    }

    /// Each address is retained separately.
    #[test]
    fn addresses_are_held_apart() {
        let (a, b) = (Ed25519SigningKey::generate(), Ed25519SigningKey::generate());
        let (addr_a, addr_b) = (
            AccountAddr::from(&a.verifying_key()),
            AccountAddr::from(&b.verifying_key()),
        );
        let mut provider = FakeProvider::default();
        provider.0.insert(addr_a.clone(), signed(&a, &["alice"]));
        provider.0.insert(addr_b.clone(), signed(&b, &["bea"]));

        let mut resolver = AccountResolver::new(provider);
        resolver.resolve(&addr_a).unwrap();
        resolver.resolve(&addr_b).unwrap();

        assert_eq!(names(resolver.get(&addr_a).unwrap()), ["alice"]);
        assert_eq!(names(resolver.get(&addr_b).unwrap()), ["bea"]);
    }
}
