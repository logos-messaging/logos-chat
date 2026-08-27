//! Signed account operation log: the append-only record of the keys and data
//! an account has endorsed.
//!
//! ```text
//! SignedAccountLog          payload + account signature over its exact bytes
//! └── EncodedAccountLog     the log as canonical bytes (wire form — see codec)
//!     └── AccountLog        the log as validated entries (working form)
//!         └── AccountEntry      Add { context, data } | Remove { index } | Unknown
//!             └── EntryData     Ed25519Key | Text | Unknown
//! ```
//!
//! Invariants:
//! - Append-only: a newer log strictly extends the older one
//!   ([`verify_extension`](crate::verify_extension)). There is no version
//!   counter — a longer log is a newer log. A log that is longer but does not
//!   extend the old one has rewritten history: either the signer is showing
//!   different histories to different readers, or the account key is
//!   compromised.
//! - A `Remove` tombstones a strictly earlier, still-live entry that is not
//!   itself a `Remove`; anything else rejects the whole log
//!   ([`AccountLog::from_entries`]).
//! - No Ed25519 key is live twice, whatever contexts the occurrences carry.
//!
//! The entries still live ([`AccountLog::live_entries`]) are the account's
//! current state. Every endorsement is selected by context
//! ([`AccountLog::keys_for`]):
//! there is deliberately no way to ask for every live key at once.

use std::collections::HashSet;

use crate::AccountAddr;
use crate::context::Context;
use crate::crypto::{Ed25519Signature, Ed25519VerifyingKey};
use crate::error::AccountLogError;

/// An [`AccountLog`] in its canonical byte encoding, plus the account's
/// signature over exactly those bytes.
///
/// The account key is not carried: the account address *is* the verifying key,
/// supplied by the caller on verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAccountLog {
    pub payload: EncodedAccountLog,
    pub signature: Ed25519Signature,
}

/// An [`AccountLog`] as canonical bytes — exactly what is signed and
/// transmitted. Construct via [`AccountLog::encode`] or
/// [`from_bytes`](Self::from_bytes). Byte layout: see [`AccountLog::encode`].
///
/// Asserts nothing about whether the bytes decode. Validity is
/// [`decode`](Self::decode)'s answer, so a store can hold, compare and serve
/// payloads without knowing the entry format — which is what lets it enforce
/// append-only with a prefix compare alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedAccountLog(pub(crate) Vec<u8>);

/// The log as a validated entry list. Construction checks every `Remove`, so
/// [`live_entries`](Self::live_entries) cannot fail on a held log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountLog {
    entries: Vec<AccountEntry>,
}

/// One operation in the log. An entry's index is its position — derived, not
/// stored, so an entry cannot lie about where it sits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountEntry {
    /// Endorse `data` under this account, for `context`.
    Add { context: Context, data: EntryData },
    /// Tombstone the entry at position `index`. Must point at a strictly
    /// earlier, still-live entry that is not itself a `Remove`; anything else
    /// rejects the whole log — fail closed, so verifiers can never skip their
    /// way to different sets.
    Remove { index: u32 },
    /// An entry whose opcode this version does not define. Kept as an opaque
    /// live slot: counted, indexed, removable, never surfaced. Dropping it
    /// would shift every later index and retarget every later `Remove`.
    ///
    /// Safe to ignore because `Remove` is the only subtractive operation, so
    /// an unrecognized entry can only be endorsing something.
    Unknown { opcode: u8, body: Vec<u8> },
}

/// Data an account can endorse. Non_exhaustive so new kinds are not a
/// breaking change.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EntryData {
    /// A device (LocalIdentity) verifying key. Canonical and not small-order
    /// — checked in [`AccountLog::from_entries`].
    Ed25519Key([u8; 32]),
    /// A UTF-8 record. What it means is defined by its context.
    Text(String),
    /// An endorsement of a kind this version cannot read. Opaque for the same
    /// reason as [`AccountEntry::Unknown`], but the context still selects it.
    Unknown { tag: u8, body: Vec<u8> },
}

impl SignedAccountLog {
    pub fn verify(&self, addr: &AccountAddr) -> Result<AccountLog, AccountLogError> {
        addr.verifying_key()
            .verify(self.payload.as_bytes(), &self.signature)?;

        self.payload.decode()
    }
}

impl AccountEntry {
    /// Endorse `data` under `context` — the only `Add` constructor, so a
    /// contextless endorsement is unrepresentable.
    pub fn add(context: Context, data: EntryData) -> Self {
        Self::Add { context, data }
    }
}

impl AccountLog {
    /// Create a AccountLog from a list of entries. Returns an error if the created log would be invalid.
    pub(crate) fn from_entries(entries: Vec<AccountEntry>) -> Result<Self, AccountLogError> {
        let live = valid_live_entries(&entries)?;
        ensure_single_use_keys(&live)?;
        ensure_valid_types(&live)?;
        Ok(Self { entries })
    }

    pub(crate) fn entries(&self) -> &[AccountEntry] {
        &self.entries
    }

    /// Every entry with its position, and whether a `Remove` still targets it.
    ///
    /// `u32` because that is what [`AccountEntry::Remove`] carries, so an index
    /// taken from here needs no cast to be used. Safe: [`MAX_PAYLOAD_BYTES`]
    /// caps a payload at 128 KiB and the smallest entry is 3 bytes, so a log
    /// cannot hold more than ~44k entries.
    ///
    /// [`MAX_PAYLOAD_BYTES`]: crate::MAX_PAYLOAD_BYTES
    pub(crate) fn indexed(&self) -> Vec<IndexedAccountEntry<'_>> {
        self.entries
            .iter()
            .enumerate()
            .map(|(index, entry)| IndexedAccountEntry {
                index: index as u32,
                entry,
            })
            .collect()
    }

    /// The entries no `Remove` has tombstoned, with their original positions.
    pub(crate) fn live_indexed(&self) -> Vec<IndexedAccountEntry<'_>> {
        valid_live_entries(&self.entries).expect("validated at construction")
    }

    /// A log with no entries — an account that has endorsed nothing yet.
    /// Crate-private: the way to build a log is to author one through
    /// [`AccountLogDraft`](crate::AccountLogDraft).
    pub(crate) fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// The live entries bearing `context`, in log order, each with the index a
    /// `Remove` targets.
    pub fn entries_for(&self, context: &Context) -> Vec<IndexedAccountEntry<'_>> {
        self.live_indexed()
            .into_iter()
            // Raw byte compare: normalizing or case-folding here would let two
            // implementations disagree on what shares a context.
            .filter(|e| matches!(e.entry, AccountEntry::Add { context: c, .. } if c == context))
            .collect()
    }

    /// The Ed25519 keys live under `context`, in add order.
    ///
    /// There is no way to ask for every live key: a key is endorsed for one
    /// purpose, and an API that could return all of them would eventually be
    /// used that way, with nothing at the call site to show it was wrong.
    pub fn ed25519_keys_for(&self, context: &Context) -> Vec<Ed25519VerifyingKey> {
        self.entries_for(context)
            .into_iter()
            .filter_map(|e| match e.entry {
                AccountEntry::Add {
                    data: EntryData::Ed25519Key(bytes),
                    ..
                } => Some(
                    Ed25519VerifyingKey::from_canonical_bytes(bytes)
                        .expect("validated at construction"),
                ),
                _ => None,
            })
            .collect()
    }

    /// The text records live under `context`, in add order.
    pub fn text_for(&self, context: &Context) -> Vec<&str> {
        self.entries_for(context)
            .into_iter()
            .filter_map(|e| match e.entry {
                AccountEntry::Add {
                    data: EntryData::Text(value),
                    ..
                } => Some(value.as_str()),
                _ => None,
            })
            .collect()
    }

    /// The entries left once every `Remove` is applied — the account's current
    /// state, in add order.
    /// The position of the first entry this build cannot interpret.
    ///
    /// Covers the whole history, not just live entries: encoding writes every
    /// entry, so a tombstoned opaque entry is signed along with the rest.
    pub(crate) fn first_unreadable(&self) -> Option<usize> {
        self.entries.iter().position(|entry| {
            matches!(
                entry,
                AccountEntry::Unknown { .. }
                    | AccountEntry::Add {
                        data: EntryData::Unknown { .. },
                        ..
                    }
            )
        })
    }
}

/// An entry paired with its position in the log — the index a
/// [`AccountEntry::Remove`] targets, never a position within a filtered subset.
///
/// Carrying the index rather than deriving it is what makes filtering safe:
/// selecting the live entries and enumerating afterwards would renumber them
/// and aim a `Remove` at the wrong entry.
///
/// `u32` matches what `Remove` carries, so an index taken from here needs no
/// cast. Safe: [`MAX_PAYLOAD_BYTES`](crate::MAX_PAYLOAD_BYTES) caps a payload
/// at 128 KiB and the smallest entry is 3 bytes, so a log cannot hold more
/// than ~44k entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedAccountEntry<'a> {
    pub index: u32,
    pub entry: &'a AccountEntry,
}

/// Which entries have been tombstoned.
///
/// A `Remove` may only target a strictly earlier position, so every target has
/// already been visited by the time it is read — one pass is enough, and the
/// same check bounds the lookups below.
fn filter_mask_removed(entries: &[AccountEntry]) -> Result<Vec<bool>, AccountLogError> {
    let mut removed = vec![false; entries.len()];
    for (position, entry) in entries.iter().enumerate() {
        let AccountEntry::Remove { index } = entry else {
            continue;
        };
        let target = *index as usize;

        // Tested first: it is what makes `target` a valid index below.
        let fault = if target >= position {
            Some("is not strictly earlier")
        } else if removed[target] {
            Some("is already removed")
        } else if matches!(entries[target], AccountEntry::Remove { .. }) {
            Some("is itself a remove")
        } else {
            None
        };

        if let Some(fault) = fault {
            return Err(AccountLogError::Malformed(format!(
                "remove at position {position} targets entry {index}, which {fault}"
            )));
        }
        removed[target] = true;
    }
    Ok(removed)
}

fn valid_live_entries(
    entries: &[AccountEntry],
) -> Result<Vec<IndexedAccountEntry<'_>>, AccountLogError> {
    let removed = filter_mask_removed(entries)?;
    let entries = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| IndexedAccountEntry {
            index: index as u32,
            entry,
        })
        .filter(|val| {
            !removed[val.index as usize] && !matches!(val.entry, AccountEntry::Remove { .. })
        })
        .collect();

    Ok(entries)
}

/// Every live  key appears only once.
fn ensure_single_use_keys(entries: &[IndexedAccountEntry]) -> Result<(), AccountLogError> {
    let mut seen = HashSet::<&EntryData>::new();
    for val in entries {
        let AccountEntry::Add { data, .. } = val.entry else {
            continue;
        };

        // Text Entries are not required to be unique across contexts
        if matches!(data, EntryData::Text(_)) {
            continue;
        }

        if !seen.insert(data) {
            return Err(malformed(val.index, "is live more than once"));
        }
    }
    Ok(())
}

/// Ensure typed variants are valid.
fn ensure_valid_types(entries: &[IndexedAccountEntry]) -> Result<(), AccountLogError> {
    for val in entries {
        let AccountEntry::Add { data, .. } = val.entry else {
            continue;
        };

        match data {
            EntryData::Ed25519Key(bytes) => _ = Ed25519VerifyingKey::from_canonical_bytes(bytes)?,
            // Strings are valid utf8 by construction
            EntryData::Text(_) => (),
            // Unknown types cannot be validated
            EntryData::Unknown { .. } => (),
        }
    }

    Ok(())
}

fn malformed(position: u32, detail: &str) -> AccountLogError {
    AccountLogError::Malformed(format!("key at position {position} {detail}"))
}

/// How a log compares to another
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogFreshness {
    /// Strictly extends the held log. The only accepting outcome.
    Newer,
    /// Byte-identical to the held log. Whether this is worth acting on — a
    /// retention refresh, say — is the caller's policy, not the log's.
    Identical,
    /// The held log extends the candidate: a stale replica, or a rollback.
    Behind,
    /// Longer or divergent, but not an extension: history was rewritten.
    Diverged,
}

/// Compare two encoded_log_bytes and determine if the new candidate is Newer, Behind, or Diverged
pub(crate) fn compare_log_freshness(existing: &[u8], candidate: &[u8]) -> LogFreshness {
    // Candidate is the same as existing
    if candidate == existing {
        return LogFreshness::Identical;
    }

    // Candidate contains existing, and is longer
    if candidate.starts_with(existing) && candidate.len() > existing.len() {
        return LogFreshness::Newer;
    }

    // Candidate is a subset of existing, then it is not the most recent
    if existing.starts_with(candidate) {
        return LogFreshness::Behind;
    }

    // Candidate does not contain existing, so it has forked at somepoint.
    LogFreshness::Diverged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::SIGNER_CONTEXT;

    /// A fresh usable key. Keys are validated now, so `[byte; 32]` no longer
    /// serves as a stand-in.
    fn key_bytes() -> [u8; 32] {
        crate::crypto::Ed25519SigningKey::generate()
            .verifying_key()
            .as_ref()
            .try_into()
            .expect("32 bytes")
    }

    fn key(bytes: [u8; 32]) -> AccountEntry {
        AccountEntry::add(SIGNER_CONTEXT.clone(), EntryData::Ed25519Key(bytes))
    }

    fn text(value: &str) -> AccountEntry {
        AccountEntry::add(SIGNER_CONTEXT.clone(), EntryData::Text(value.into()))
    }

    /// Tombstones are applied and add order is preserved.
    #[test]
    fn keys_for_applies_removes() {
        let (a, b, c) = (key_bytes(), key_bytes(), key_bytes());
        let log = AccountLog::from_entries(vec![
            key(a),
            key(b),
            AccountEntry::Remove { index: 0 },
            key(c),
        ])
        .unwrap();

        let live = log.ed25519_keys_for(&SIGNER_CONTEXT);
        assert_eq!(live.len(), 2);
        assert_eq!(live[0].as_ref(), &b[..]);
        assert_eq!(live[1].as_ref(), &c[..]);
    }

    /// Selection is by context: an entry under another context is live but
    /// never returned, and never rejected either.
    #[test]
    fn selection_is_scoped_to_one_context() {
        let other = Context::new("storage.vault").unwrap();
        let (a, b) = (key_bytes(), key_bytes());
        let log = AccountLog::from_entries(vec![
            key(a),
            AccountEntry::add(other.clone(), EntryData::Ed25519Key(b)),
        ])
        .unwrap();

        assert_eq!(log.ed25519_keys_for(&SIGNER_CONTEXT).len(), 1);
        assert_eq!(log.ed25519_keys_for(&other).len(), 1);
        assert!(
            log.ed25519_keys_for(&Context::new("chat.other").unwrap())
                .is_empty()
        );
        assert_eq!(log.live_indexed().len(), 2);
    }

    /// Text records select by the same rule, and several may be live at once.
    #[test]
    fn text_records_select_by_context() {
        let log = AccountLog::from_entries(vec![text("alice"), text("alice j")]).unwrap();
        assert_eq!(log.text_for(&SIGNER_CONTEXT), vec!["alice", "alice j"]);
        assert!(log.ed25519_keys_for(&SIGNER_CONTEXT).is_empty());
    }

    /// An unknown opcode holds its slot: it stays live, keeps its index, and
    /// a later `Remove` still lands on the entry it names.
    #[test]
    fn unknown_entries_hold_their_slot() {
        let a = key_bytes();
        let log = AccountLog::from_entries(vec![
            key(a),
            AccountEntry::Unknown {
                opcode: 0x0f,
                body: vec![0xde, 0xad],
            },
            AccountEntry::Remove { index: 0 },
        ])
        .unwrap();

        assert!(log.ed25519_keys_for(&SIGNER_CONTEXT).is_empty());
        assert_eq!(log.live_indexed().len(), 1);
    }

    /// A `Remove` may target an entry the consumer cannot read — every
    /// non-`Remove` opcode is additive, so an unknown entry is removable.
    #[test]
    fn remove_targets_an_unknown_entry() {
        let log = AccountLog::from_entries(vec![
            AccountEntry::Unknown {
                opcode: 0x0f,
                body: vec![],
            },
            AccountEntry::Remove { index: 0 },
        ])
        .unwrap();
        assert!(log.live_indexed().is_empty());
    }

    /// Every malformed remove rejects the whole log: forward and self
    /// references, removing a remove, and removing twice.
    #[test]
    fn new_rejects_invalid_removes() {
        let a = key_bytes();
        // Out of range and self-reference are the same fault: not backwards.
        let dangling = vec![key(a), AccountEntry::Remove { index: 7 }];
        let self_ref = vec![AccountEntry::Remove { index: 0 }];
        let of_remove = vec![
            key(a),
            AccountEntry::Remove { index: 0 },
            AccountEntry::Remove { index: 1 },
        ];
        let twice = vec![
            key(a),
            AccountEntry::Remove { index: 0 },
            AccountEntry::Remove { index: 0 },
        ];

        for (entries, fault) in [
            (dangling, "is not strictly earlier"),
            (self_ref, "is not strictly earlier"),
            (of_remove, "is itself a remove"),
            (twice, "is already removed"),
        ] {
            match AccountLog::from_entries(entries) {
                Err(AccountLogError::Malformed(m)) => {
                    assert!(m.contains("remove at position"), "{m}");
                    assert!(m.contains(fault), "expected {fault:?}, got {m:?}");
                }
                other => panic!("expected a malformed remove, got {other:?}"),
            }
        }
    }

    /// One key live twice rejects the log, whatever contexts it carries —
    /// but re-adding it after a remove is fine.
    #[test]
    fn new_rejects_a_key_live_twice() {
        let a = key_bytes();
        let same_context = vec![key(a), key(a)];
        let two_contexts = vec![
            key(a),
            AccountEntry::add(
                Context::new("storage.vault").unwrap(),
                EntryData::Ed25519Key(a),
            ),
        ];
        for entries in [same_context, two_contexts] {
            assert!(matches!(
                AccountLog::from_entries(entries),
                Err(AccountLogError::Malformed(m)) if m.contains("live more than once")
            ));
        }

        let readded = vec![key(a), AccountEntry::Remove { index: 0 }, key(a)];
        assert_eq!(
            AccountLog::from_entries(readded)
                .unwrap()
                .ed25519_keys_for(&SIGNER_CONTEXT)
                .len(),
            1
        );
    }

    /// An unusable key rejects the log rather than being skipped at lookup:
    /// skipping would give two implementations different live sets.
    #[test]
    fn new_rejects_unusable_keys() {
        // All-zero: small order (the identity point), canonically encoded.
        assert!(matches!(
            AccountLog::from_entries(vec![key([0u8; 32])]),
            Err(AccountLogError::Malformed(m)) if m.contains("small-order")
        ));

        // y = 2^255 - 18, one past the field: a non-canonical encoding that
        // `from_bytes` would silently reduce to y = 1.
        let mut unreduced = [0xffu8; 32];
        unreduced[0] = 0xee;
        unreduced[31] = 0x7f;
        assert!(matches!(
            AccountLog::from_entries(vec![key(unreduced)]),
            Err(AccountLogError::Malformed(m)) if m.contains("canonical")
        ));

        // A removed key is not live, so it is never checked.
        assert!(
            AccountLog::from_entries(vec![key([0u8; 32]), AccountEntry::Remove { index: 0 }])
                .is_ok()
        );
    }
}
