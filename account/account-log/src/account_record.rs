use crate::account_log::{AccountLog, LogFreshness, SignedAccountLog, compare_log_freshness};
use crate::addr::AccountAddr;
use crate::error::AccountLogError;

/// The result of atempting to update an AccountRecord with a candiate SignedAccountLog
///
/// `record` is always the one to keep, so a caller that ignores `outcome` is
/// still correct — it only loses the diagnosis.
#[must_use]
pub struct AccountRecordUpdate {
    pub outcome: Outcome,
    pub record: AccountRecord,
}

/// How a candidate related to the log already held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Log was updated
    Updated,
    /// Log was either the same, older, or diverged; Did not update
    Unchanged(LogFreshness),
    /// Not signed by this record's account.
    SignatureInvalid,
    /// The candidate could not be read as a log.
    Malformed(AccountLogError),
}

impl Outcome {
    pub fn from_error(error: AccountLogError) -> Self {
        if let AccountLogError::SignatureInvalid = error {
            return Outcome::SignatureInvalid;
        }

        Outcome::Malformed(error)
    }
}

/// The newest valid log seen for an account, in both its signed and decoded
/// forms.
///
/// Construction and every update verify the signature and decode the log, so a
/// held record is always one the account signed and this build can read.
/// Applications caching account data should hold one of these rather than a
/// bare log as it adds the temporal verification as well.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRecord {
    addr: AccountAddr,
    signed_log: SignedAccountLog,
    parsed_log: AccountLog,
}

impl AccountRecord {
    /// Creates a new record for the first log seen for `addr`
    pub fn new(addr: AccountAddr, signed_log: SignedAccountLog) -> Result<Self, AccountLogError> {
        let parsed_log = signed_log.verify(&addr)?;
        Ok(Self {
            addr,
            signed_log,
            parsed_log,
        })
    }

    pub fn addr(&self) -> &AccountAddr {
        &self.addr
    }

    pub fn signed_log(&self) -> &SignedAccountLog {
        &self.signed_log
    }

    /// The held log as validated entries.
    pub fn log(&self) -> &AccountLog {
        &self.parsed_log
    }

    /// Attempt to update the record with a new SignedAccountLog
    ///
    /// Accepts only a strict extension; every other outcome returns the existing record
    pub fn update(self, candidate: SignedAccountLog) -> AccountRecordUpdate {
        let candidate_log = match candidate.verify(&self.addr) {
            Ok(v) => v,
            Err(e) => {
                // Short circuit on error
                return AccountRecordUpdate {
                    outcome: Outcome::from_error(e),
                    record: self,
                };
            }
        };

        let candidate_bytes = candidate.payload.as_bytes();
        let current_bytes = self.signed_log.payload.as_bytes();

        let freshness = compare_log_freshness(current_bytes, candidate_bytes);

        // Only update record, if the candidate is a strict extension
        let (outcome, record) = match freshness {
            LogFreshness::Newer => (
                Outcome::Updated,
                AccountRecord {
                    addr: self.addr,
                    signed_log: candidate,
                    parsed_log: candidate_log,
                },
            ),
            other => (Outcome::Unchanged(other), self),
        };

        AccountRecordUpdate { outcome, record }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_log::{AccountEntry, EncodedAccountLog, EntryData};
    use crate::context::SIGNER_CONTEXT;
    use crate::crypto::Ed25519SigningKey;

    fn key_bytes() -> [u8; 32] {
        Ed25519SigningKey::generate()
            .verifying_key()
            .as_ref()
            .try_into()
            .expect("32 bytes")
    }

    /// A log of `n` distinct key endorsements, signed by `account`.
    fn signed_log(account: &Ed25519SigningKey, entries: Vec<AccountEntry>) -> SignedAccountLog {
        let payload = crate::codec::encode_entries(&entries).unwrap();
        let signature = account.sign(payload.as_bytes());
        SignedAccountLog { payload, signature }
    }

    fn entry() -> AccountEntry {
        AccountEntry::add(SIGNER_CONTEXT.clone(), EntryData::Ed25519Key(key_bytes()))
    }

    /// A record holding a one-entry log, plus the account that signed it.
    fn record() -> (Ed25519SigningKey, Vec<AccountEntry>, AccountRecord) {
        let account = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(&account.verifying_key());
        let entries = vec![entry()];
        let log = signed_log(&account, entries.clone());
        (account, entries, AccountRecord::new(addr, log).unwrap())
    }

    /// A strict extension replaces the held log.
    #[test]
    fn extension_is_accepted() {
        let (account, mut entries, record) = record();
        entries.push(entry());
        let candidate = signed_log(&account, entries);

        let update = record.update(candidate.clone());
        assert_eq!(update.outcome, Outcome::Updated);
        assert_eq!(update.record.signed_log(), &candidate);
        assert_eq!(update.record.log().live_indexed().len(), 2);
    }

    /// Re-offering the same log is distinguishable from an older one, so a
    /// caller can treat a refresh differently from a rollback.
    #[test]
    fn identical_and_behind_are_distinct() {
        let (account, mut entries, record) = record();
        let held = record.signed_log().clone();

        let update = record.update(held.clone());
        assert_eq!(update.outcome, Outcome::Unchanged(LogFreshness::Identical));
        assert_eq!(update.record.signed_log(), &held);

        // Grow the record, then offer the original one-entry log back.
        entries.push(entry());
        let longer = signed_log(&account, entries);
        let record = update.record.update(longer).record;

        let update = record.update(held);
        assert_eq!(update.outcome, Outcome::Unchanged(LogFreshness::Behind));
        assert_eq!(update.record.log().live_indexed().len(), 2);
    }

    /// A log that diverges rather than extends keeps the held log and says so.
    #[test]
    fn fork_is_rejected_and_named() {
        let (account, _, record) = record();
        let held = record.signed_log().clone();
        // Longer than the held log, but rewrites entry 0 — so length alone
        // never makes a log newer.
        let candidate = signed_log(&account, vec![entry(), entry()]);

        let update = record.update(candidate);
        assert_eq!(update.outcome, Outcome::Unchanged(LogFreshness::Diverged));
        assert_eq!(update.record.signed_log(), &held);
    }

    /// A valid, longer log signed by a different account is refused on the
    /// signature, never reaching the extension check.
    #[test]
    fn other_accounts_log_is_rejected_before_comparison() {
        let (_, mut entries, record) = record();
        let held = record.signed_log().clone();
        let intruder = Ed25519SigningKey::generate();
        entries.push(entry());
        let candidate = signed_log(&intruder, entries);

        let update = record.update(candidate);
        assert_eq!(update.outcome, Outcome::SignatureInvalid);
        assert_eq!(update.record.signed_log(), &held);
    }

    /// An authentic log this build cannot read is `Malformed`, not
    /// `SignatureInvalid`. The account really did sign it, so a broken
    /// publisher and an impersonator are different problems and must not raise
    /// the same alarm.
    #[test]
    fn authentic_but_unreadable_candidate_is_malformed() {
        let (account, _, record) = record();
        let held = record.signed_log().clone();

        let payload = EncodedAccountLog::from_bytes(b"not a log at all".to_vec()).unwrap();
        let signature = account.sign(payload.as_bytes());
        let candidate = SignedAccountLog { payload, signature };

        let update = record.update(candidate);
        assert!(matches!(update.outcome, Outcome::Malformed(_)));
        assert_eq!(update.record.signed_log(), &held);
    }

    /// A record cannot be built around a log its account did not sign.
    #[test]
    fn new_rejects_an_unsigned_log() {
        let account = Ed25519SigningKey::generate();
        let other = AccountAddr::from(&Ed25519SigningKey::generate().verifying_key());
        let log = signed_log(&account, vec![entry()]);

        assert!(matches!(
            AccountRecord::new(other, log),
            Err(AccountLogError::SignatureInvalid)
        ));
    }
}
