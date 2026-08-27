use crate::EntryData;
use crate::account_log::{AccountEntry, AccountLog, IndexedAccountEntry};
use crate::context::Context;
use crate::error::AccountLogError;

/// An Editable AccountLog used for publishing new entries.
///
/// An AccountDraftLog is always valid, and cannot be put into an invalid state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountLogDraft(AccountLog);

impl Default for AccountLogDraft {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountLogDraft {
    /// A draft for an account that has published nothing.
    pub fn new() -> Self {
        Self(AccountLog::empty())
    }

    /// Create a Draft from an existing log
    pub fn from_log(log: &AccountLog) -> Result<Self, AccountLogError> {
        if let Some(position) = log.first_unreadable() {
            return Err(AccountLogError::Malformed(format!(
                "entry at position {position} is not readable by this build, so the log cannot be re-signed"
            )));
        }
        Ok(Self(log.clone()))
    }

    /// Every entry so far, each carrying the index a [`revoke`](Self::revoke)
    /// would target.
    pub fn entries(&self) -> Vec<IndexedAccountEntry<'_>> {
        self.0.indexed()
    }

    /// The entries no `Remove` has tombstoned — the only ones worth revoking.
    ///
    /// Indices are the original positions, never renumbered: filtering first
    /// and enumerating afterwards is the way to aim a `Remove` at the wrong
    /// entry, so the index is carried rather than derived.
    pub fn live_entries(&self) -> Vec<IndexedAccountEntry<'_>> {
        self.0.live_indexed()
    }

    pub fn add(&mut self, context: Context, data: EntryData) -> Result<(), AccountLogError> {
        self.push(AccountEntry::Add { context, data })
    }

    /// Tombstone the entry at `index`. A revoke is itself an appended entry, so
    /// this extends the log like any other push.
    pub fn revoke(&mut self, index: u32) -> Result<(), AccountLogError> {
        self.push(AccountEntry::Remove { index })
    }

    /// Append `entry`, keeping it only if the result is still a valid log — a
    /// draft that cannot be published is never left behind.
    ///
    /// Refuses an entry this build cannot read. Paired with the same check in
    /// [`from_log`](Self::from_log), that means nothing signed from a draft
    /// contains bytes this build could not interpret: you cannot start from an
    /// unreadable log, and you cannot author an unreadable entry onto one.
    pub fn push(&mut self, entry: AccountEntry) -> Result<(), AccountLogError> {
        if matches!(
            entry,
            AccountEntry::Unknown { .. }
                | AccountEntry::Add {
                    data: EntryData::Unknown { .. },
                    ..
                }
        ) {
            return Err(AccountLogError::Malformed(
                "cannot author an entry this build cannot read".into(),
            ));
        }

        let mut entries = self.0.entries().to_vec();
        entries.push(entry);
        // Assigned only on success, so a rejected push needs no undo.
        self.0 = AccountLog::from_entries(entries)?;
        Ok(())
    }

    /// The log this draft holds.
    pub fn log(&self) -> &AccountLog {
        &self.0
    }

    /// The log this draft holds, taking ownership.
    pub fn into_log(self) -> AccountLog {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_log::EntryData;
    use crate::context::SIGNER_CONTEXT;
    use crate::crypto::Ed25519SigningKey;

    fn key() -> AccountEntry {
        let bytes = Ed25519SigningKey::generate()
            .verifying_key()
            .as_ref()
            .try_into()
            .expect("32 bytes");
        AccountEntry::add(SIGNER_CONTEXT.clone(), EntryData::Ed25519Key(bytes))
    }

    /// A draft carries prior entries over untouched, so what it produces
    /// extends what it started from.
    #[test]
    fn a_draft_extends_the_log_it_came_from() {
        let mut draft = AccountLogDraft::new();
        draft.push(key()).unwrap();
        let first = draft.log();

        let mut draft = AccountLogDraft::from_log(first).unwrap();
        draft.push(key()).unwrap();
        let second = draft.log();

        assert!(second.entries().starts_with(first.entries()));
        assert_eq!(second.entries().len(), 2);
    }

    /// A rejected push leaves the draft exactly as it was, so the next `log`
    /// is unaffected.
    #[test]
    fn a_rejected_push_is_not_kept() {
        let entry = key();
        let mut draft = AccountLogDraft::new();
        draft.push(entry.clone()).unwrap();
        let before = draft.log().clone();

        // The same key twice is not two endorsements.
        assert!(draft.push(entry).is_err());

        assert_eq!(draft.entries().len(), 1);
        assert_eq!(*draft.log(), before);
    }

    /// A log carrying an entry this build cannot read may be held and read,
    /// but not authored on top of — signing it would attest to bytes this
    /// build cannot interpret.
    ///
    /// Built through `from_entries` rather than a draft, because that is the
    /// only way such a log arises: decoded off the wire, never authored.
    #[test]
    fn an_unreadable_log_cannot_be_authored_on() {
        let log = AccountLog::from_entries(vec![
            key(),
            AccountEntry::Unknown {
                opcode: 0x0f,
                body: vec![0xde, 0xad],
            },
        ])
        .unwrap();

        // Reading is unaffected.
        assert_eq!(log.ed25519_keys_for(&SIGNER_CONTEXT).len(), 1);

        assert!(matches!(
            AccountLogDraft::from_log(&log),
            Err(AccountLogError::Malformed(m)) if m.contains("not readable")
        ));
    }

    /// The other half of the same guarantee: an unreadable entry cannot be
    /// authored onto a readable log either. Both `Unknown` shapes are refused —
    /// an opcode this build does not define, and a data tag it cannot parse.
    #[test]
    fn an_unreadable_entry_cannot_be_authored() {
        let mut draft = AccountLogDraft::new();
        draft.push(key()).unwrap();

        for entry in [
            AccountEntry::Unknown {
                opcode: 0x0f,
                body: vec![0xde, 0xad],
            },
            AccountEntry::add(
                SIGNER_CONTEXT.clone(),
                EntryData::Unknown {
                    tag: 0x7f,
                    body: vec![1, 2, 3],
                },
            ),
        ] {
            assert!(matches!(
                draft.push(entry),
                Err(AccountLogError::Malformed(m)) if m.contains("cannot author")
            ));
        }

        // The refused pushes left the draft publishable.
        assert_eq!(draft.entries().len(), 1);
    }
}
