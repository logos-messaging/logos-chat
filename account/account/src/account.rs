use crate::{AccountError, AccountProvider, AccountPublisher};
use account_log::{
    AccountAddr, AccountEntry, AccountLogDraft, Context, Ed25519SigningKey, Ed25519VerifyingKey,
    EntryData, SignedAccountLog,
};

/// Authors and publishes updates to an account log.
pub struct Account<AP> {
    signing_key: Ed25519SigningKey,
    provider: AP,
}

impl<AP: AccountProvider + AccountPublisher> Account<AP> {
    pub fn new(provider: AP) -> Self {
        Self {
            signing_key: Ed25519SigningKey::generate(),
            provider,
        }
    }

    /// The account's address.
    pub fn addr(&self) -> AccountAddr {
        AccountAddr::from(&self.signing_key.verifying_key())
    }

    /// Begin an update. Nothing is read or written until `publish`.
    pub fn update(&mut self) -> AccountUpdate<'_, AP> {
        AccountUpdate {
            account: self,
            entries: Vec::new(),
        }
    }

    /// The published log as a draft. Never stored — a held copy goes stale
    /// when another device publishes.
    fn draft(&self) -> Result<AccountLogDraft, AccountError> {
        let addr = self.addr();
        let fetched = self
            .provider
            .fetch(&addr)
            .map_err(|e| AccountError::Provider(e.to_string()))?;

        match fetched {
            // The provider is untrusted; a log we did not sign is not ours.
            Some(signed) => Ok(AccountLogDraft::from_log(&signed.verify(&addr)?)?),
            None => Ok(AccountLogDraft::new()),
        }
    }
}

/// Entries waiting to be appended, in order. Validated at `publish`, against
/// the log they will actually extend.
#[must_use = "entries are not written until `publish` is called"]
pub struct AccountUpdate<'a, AP> {
    account: &'a mut Account<AP>,
    entries: Vec<AccountEntry>,
}

impl<AP: AccountProvider + AccountPublisher> AccountUpdate<'_, AP> {
    /// Endorse `key` under `context`.
    pub fn endorse_ed25519_key(self, context: Context, key: &Ed25519VerifyingKey) -> Self {
        self.add(context, EntryData::Ed25519Key(key.to_bytes()))
    }

    /// Endorse a text record under `context`.
    pub fn endorse_text(self, context: Context, value: impl Into<String>) -> Self {
        self.add(context, EntryData::Text(value.into()))
    }

    /// Endorse `data` under `context`.
    fn add(mut self, context: Context, data: EntryData) -> Self {
        self.entries.push(AccountEntry::add(context, data));
        self
    }

    /// Tombstone the entry at `index`.
    pub fn revoke(mut self, index: u32) -> Self {
        self.entries.push(AccountEntry::Remove { index });
        self
    }

    /// Read the published log, apply every entry, sign and publish. All or
    /// nothing: one rejected entry writes nothing.
    pub fn publish(self) -> Result<SignedAccountLog, AccountError> {
        let mut draft = self.account.draft()?;
        for entry in self.entries {
            draft.push(entry)?;
        }

        let payload = draft.log().encode()?;
        let signature = self.account.signing_key.sign(payload.as_bytes());
        let signed = SignedAccountLog { payload, signature };

        let addr = self.account.addr();
        self.account
            .provider
            .publish(&addr, &signed)
            .map_err(|e| AccountError::Provider(e.to_string()))?;
        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use account_log::{AccountRecord, Outcome, SIGNER_CONTEXT};
    use std::collections::HashMap;

    /// Stores whatever it is given; does not enforce append-only.
    #[derive(Debug, Default)]
    struct FakeProvider(HashMap<AccountAddr, SignedAccountLog>);

    impl AccountProvider for FakeProvider {
        type Error = String;
        fn fetch(&self, addr: &AccountAddr) -> Result<Option<SignedAccountLog>, Self::Error> {
            Ok(self.0.get(addr).cloned())
        }
    }

    impl AccountPublisher for FakeProvider {
        type Error = String;
        fn publish(
            &mut self,
            addr: &AccountAddr,
            log: &SignedAccountLog,
        ) -> Result<(), Self::Error> {
            self.0.insert(addr.clone(), log.clone());
            Ok(())
        }
    }

    fn device() -> Ed25519VerifyingKey {
        Ed25519SigningKey::generate().verifying_key()
    }

    /// A chain of edits lands in one published log, in the order given.
    #[test]
    fn chained_edits_publish_together() {
        let mut account = Account::new(FakeProvider::default());
        let addr = account.addr();
        let (first, second) = (device(), device());

        let signed = account
            .update()
            .endorse_ed25519_key(SIGNER_CONTEXT.clone(), &first)
            .endorse_ed25519_key(SIGNER_CONTEXT.clone(), &second)
            .endorse_text(SIGNER_CONTEXT.clone(), "alice")
            .publish()
            .unwrap();

        let stored = account.provider.fetch(&addr).unwrap().expect("published");
        assert_eq!(stored, signed);

        let log = signed.verify(&addr).unwrap();
        assert_eq!(log.ed25519_keys_for(&SIGNER_CONTEXT), vec![first, second]);
        assert_eq!(log.text_for(&SIGNER_CONTEXT), vec!["alice"]);
    }

    /// Successive publishes extend rather than fork — what a store checks by
    /// byte prefix.
    #[test]
    fn successive_publishes_extend_the_log() {
        let mut account = Account::new(FakeProvider::default());
        let addr = account.addr();

        let first = account
            .update()
            .endorse_ed25519_key(SIGNER_CONTEXT.clone(), &device())
            .publish()
            .unwrap();
        let second = account
            .update()
            .endorse_ed25519_key(SIGNER_CONTEXT.clone(), &device())
            .publish()
            .unwrap();

        assert!(
            second
                .payload
                .as_bytes()
                .starts_with(first.payload.as_bytes()),
            "a publish must not disturb bytes already published"
        );

        let record = AccountRecord::new(addr, first).unwrap();
        assert_eq!(record.update(second).outcome, Outcome::Updated);
    }

    /// The base is read at publish, so another device's write is extended,
    /// not overwritten.
    #[test]
    fn another_device_writing_is_extended_not_forked() {
        let mut account = Account::new(FakeProvider::default());
        let addr = account.addr();
        let ours = device();

        let first = account
            .update()
            .endorse_ed25519_key(SIGNER_CONTEXT.clone(), &ours)
            .publish()
            .unwrap();

        // A second device of the same account publishes in between.
        let theirs = device();
        let mut elsewhere = AccountLogDraft::from_log(&first.verify(&addr).unwrap()).unwrap();
        elsewhere
            .add(
                SIGNER_CONTEXT.clone(),
                EntryData::Ed25519Key(theirs.to_bytes()),
            )
            .unwrap();
        let payload = elsewhere.log().encode().unwrap();
        let signature = account.signing_key.sign(payload.as_bytes());
        account
            .provider
            .publish(&addr, &SignedAccountLog { payload, signature })
            .unwrap();

        // Our next publish reads that first, so all three endorsements survive.
        let mine = device();
        let latest = account
            .update()
            .endorse_ed25519_key(SIGNER_CONTEXT.clone(), &mine)
            .publish()
            .unwrap();

        assert_eq!(
            latest
                .verify(&addr)
                .unwrap()
                .ed25519_keys_for(&SIGNER_CONTEXT),
            vec![ours, theirs, mine]
        );
    }

    /// Revoking appends a tombstone rather than removing the entry.
    #[test]
    fn revoking_publishes_a_tombstone() {
        let mut account = Account::new(FakeProvider::default());
        let addr = account.addr();

        account
            .update()
            .endorse_ed25519_key(SIGNER_CONTEXT.clone(), &device())
            .publish()
            .unwrap();
        let after = account.update().revoke(0).publish().unwrap();

        let log = after.verify(&addr).unwrap();
        assert!(log.ed25519_keys_for(&SIGNER_CONTEXT).is_empty());
        assert_eq!(log.entries_for(&SIGNER_CONTEXT).len(), 0);
    }

    /// One bad entry fails the whole publish; earlier ones are discarded too.
    #[test]
    fn a_rejected_edit_publishes_nothing() {
        let mut account = Account::new(FakeProvider::default());
        let addr = account.addr();
        let key = device();

        let before = account
            .update()
            .endorse_ed25519_key(SIGNER_CONTEXT.clone(), &key)
            .publish()
            .unwrap();

        // The good edit is dropped along with the duplicate that follows it.
        assert!(
            account
                .update()
                .endorse_ed25519_key(SIGNER_CONTEXT.clone(), &device())
                .endorse_ed25519_key(SIGNER_CONTEXT.clone(), &key)
                .publish()
                .is_err()
        );

        assert_eq!(account.provider.fetch(&addr).unwrap().unwrap(), before);
    }
}
