use std::sync::LazyLock;

use account_log::{AccountEntry, AccountLog, Context, EntryData};
use thiserror::Error;

/// Profile data an owner may not publish.
///
/// Only the write side can fail. An entry already in a log is ignored where
/// it breaks a rule here, never refused — that is the AccountLog's call, and
/// nothing in this namespace makes a log invalid.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProfileError {
    #[error("a display name must not be empty")]
    EmptyDisplayName,
}

// Get namespace as a literal
macro_rules! namespace {
    () => {
        "profile"
    };
}
// Merge literals to create <namespace>.<label>
macro_rules! context {
    ($label:literal) => {
        concat!(namespace!(), ".", $label)
    };
}

// Context definitions

pub static DISPLAYNAME: LazyLock<Context> =
    LazyLock::new(|| Context::new(context!("displayname")).expect("valid context"));

/// Whether `value` is usable as a `profile.displayname`.
///
/// One definition serves both sides: an owner checks before publishing, and a
/// consumer applies the same rule when reading.
pub fn is_valid_display_name(value: &str) -> bool {
    !value.is_empty()
}

/// The entry endorsing `value` as the account's display name.
///
/// The rule is applied here so an owner cannot publish an entry that every
/// conforming reader will ignore for the life of the account.
pub fn endorse_display_name(value: &str) -> Result<AccountEntry, ProfileError> {
    if !is_valid_display_name(value) {
        return Err(ProfileError::EmptyDisplayName);
    }
    Ok(AccountEntry::add(
        DISPLAYNAME.clone(),
        EntryData::Text(value.into()),
    ))
}

/// A read-only view of the `profile` entries in a verified log.
///
/// Borrows rather than copying out: build one where it is needed, and cache
/// the `AccountRecord` instead.
pub struct Profile<'a>(&'a AccountLog);

impl<'a> Profile<'a> {
    pub fn of(log: &'a AccountLog) -> Self {
        Self(log)
    }

    /// The account's current display name, or `None` if not valid one exists.
    ///
    /// Highest index wins. Entries failing this spec are not considered at
    /// all, so an empty value published later does not shadow a good one.
    pub fn display_name(&self) -> Option<&'a str> {
        self.display_names().pop()
    }

    /// Names the account published and has since replaced, oldest first —
    /// usable as previous aliases.
    pub fn previous_display_names(&self) -> Vec<&'a str> {
        let mut names = self.display_names();
        names.pop();
        names
    }

    /// Live `profile.displayname` values that satisfy this spec, in log order.
    fn display_names(&self) -> Vec<&'a str> {
        self.0
            .text_for(&DISPLAYNAME)
            .into_iter()
            .filter(|value| is_valid_display_name(value))
            .collect()
    }
}

/// Reads a log's profile without naming [`Profile`]: `log.profile()`.
pub trait ProfileExt {
    fn profile(&self) -> Profile<'_>;
}

impl ProfileExt for AccountLog {
    fn profile(&self) -> Profile<'_> {
        Profile::of(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use account_log::{AccountLogDraft, Ed25519SigningKey, EntryData};

    /// A log holding `entries`, then revoking each index in `revoked`.
    fn log(entries: Vec<(&Context, EntryData)>, revoked: &[u32]) -> AccountLog {
        let mut draft = AccountLogDraft::new();
        for (context, data) in entries {
            draft.add(context.clone(), data).expect("valid entry");
        }
        for index in revoked {
            draft.revoke(*index).expect("valid revoke");
        }
        draft.into_log()
    }

    fn name(value: &str) -> EntryData {
        EntryData::Text(value.into())
    }

    fn key() -> EntryData {
        EntryData::Ed25519Key(Ed25519SigningKey::generate().verifying_key().to_bytes())
    }

    /// What the write side produces is what the read side finds.
    #[test]
    fn an_endorsed_name_reads_back() {
        let mut draft = AccountLogDraft::new();
        draft
            .push(endorse_display_name("alice").unwrap())
            .expect("valid entry");
        assert_eq!(draft.into_log().profile().display_name(), Some("alice"));
    }

    /// The emptiness rule binds the owner, not just the reader: an entry no
    /// consumer would use cannot be authored in the first place.
    #[test]
    fn an_empty_name_cannot_be_endorsed() {
        assert_eq!(
            endorse_display_name(""),
            Err(ProfileError::EmptyDisplayName)
        );
    }

    #[test]
    fn an_account_that_published_nothing_has_no_name() {
        let log = log(vec![], &[]);
        assert_eq!(log.profile().display_name(), None);
        assert!(log.profile().previous_display_names().is_empty());
    }

    /// Several entries may share the context; the latest is the current one,
    /// and the rest remain readable as previous aliases.
    #[test]
    fn the_latest_entry_is_the_current_name() {
        let log = log(
            vec![
                (&DISPLAYNAME, name("alice")),
                (&DISPLAYNAME, name("alice j")),
                (&DISPLAYNAME, name("alice jones")),
            ],
            &[],
        );
        assert_eq!(log.profile().display_name(), Some("alice jones"));
        assert_eq!(
            log.profile().previous_display_names(),
            vec!["alice", "alice j"]
        );
    }

    /// Replacing by revoking the old entry works too, and is not required.
    #[test]
    fn a_revoked_name_is_not_live() {
        let log = log(
            vec![(&DISPLAYNAME, name("alice")), (&DISPLAYNAME, name("bea"))],
            &[0],
        );
        assert_eq!(log.profile().display_name(), Some("bea"));
        assert!(log.profile().previous_display_names().is_empty());
    }

    /// An invalid entry is ignored rather than rejected — and is not
    /// considered for recency, so it cannot shadow the valid entry below it.
    #[test]
    fn invalid_entries_do_not_shadow_the_current_name() {
        // An empty value, published last.
        let empty = log(
            vec![(&DISPLAYNAME, name("alice")), (&DISPLAYNAME, name(""))],
            &[],
        );
        assert_eq!(empty.profile().display_name(), Some("alice"));

        // A key where the context calls for text.
        let wrong_type = log(
            vec![(&DISPLAYNAME, name("alice")), (&DISPLAYNAME, key())],
            &[],
        );
        assert_eq!(wrong_type.profile().display_name(), Some("alice"));
    }

    /// Selection is by context: text under another namespace is live, never
    /// read as profile data, and never a reason to reject anything.
    #[test]
    fn other_namespaces_are_not_profile_data() {
        let elsewhere = Context::new("chat.nickname").unwrap();
        let log = log(vec![(&elsewhere, name("not-a-profile"))], &[]);
        assert_eq!(log.profile().display_name(), None);
    }
}
