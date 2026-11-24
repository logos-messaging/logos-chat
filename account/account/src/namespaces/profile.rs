//! Information about the accounts owner, under the `profile.*` namespace.
//! This information helps applications display an account to other users such as profile
//! pictures, display names etc.
//!
//! Specification: <https://lip.logos.co/identity/raw/profile.html>

use account_log::{AccountLog, Context};

use crate::{AccountProvider, AccountPublisher, AccountUpdate};

/// The name an account presents itself under.
const PROFILE_DISPLAYNAME: Context = Context::literal("profile.displayname");

/// Reading an account's profile.
pub trait ProfileRead {
    /// The name the account currently presents itself under.
    fn display_name(&self) -> Option<&str>;

    /// What it called itself before, oldest first.
    fn previous_aliases(&self) -> Vec<&str>;
}

impl<T: AsRef<AccountLog>> ProfileRead for T {
    fn display_name(&self) -> Option<&str> {
        display_names(self.as_ref()).next_back()
    }

    fn previous_aliases(&self) -> Vec<&str> {
        let mut aliases: Vec<&str> = display_names(self.as_ref()).collect();
        aliases.pop();
        aliases
    }
}

/// The valid display names, oldest first. The spec has a consumer ignore an
/// empty one, recency included.
fn display_names(log: &AccountLog) -> impl DoubleEndedIterator<Item = &str> {
    log.text_for(&PROFILE_DISPLAYNAME)
        .into_iter()
        .filter(|name| !name.is_empty())
}

/// Writing your own profile.
pub trait ProfileWrite {
    /// The name that should be displayed for this account in applications.
    /// Readers ignore an empty one, so it does not clear an earlier name.
    fn set_display_name(self, name: impl Into<String>) -> Self;
}

impl<AP: AccountProvider + AccountPublisher> ProfileWrite for AccountUpdate<'_, AP> {
    fn set_display_name(self, name: impl Into<String>) -> Self {
        self.endorse_text(PROFILE_DISPLAYNAME, name)
    }
}

#[cfg(test)]
mod tests {
    use account_log::{AccountLogDraft, EntryData};

    use super::*;

    /// A log holding these display names, in order.
    fn names(names: &[&str]) -> AccountLog {
        let mut draft = AccountLogDraft::new();
        for name in names {
            draft
                .add(PROFILE_DISPLAYNAME, EntryData::Text((*name).into()))
                .unwrap();
        }
        draft.into_log()
    }

    /// The context string is a wire-format commitment: changing it orphans
    /// every entry already published under the old one.
    #[test]
    fn context_is_pinned() {
        assert_eq!(PROFILE_DISPLAYNAME.as_str(), "profile.displayname");
    }

    /// The spec has a consumer ignore an empty name, so it neither replaces
    /// the current name nor counts as an alias.
    #[test]
    fn empty_names_are_ignored() {
        let log = names(&["Saro", ""]);
        assert_eq!(log.display_name(), Some("Saro"));
        assert!(log.previous_aliases().is_empty());

        let log = names(&["Saro", "", "Saro K"]);
        assert_eq!(log.display_name(), Some("Saro K"));
        assert_eq!(log.previous_aliases(), vec!["Saro"]);

        assert_eq!(names(&[""]).display_name(), None);
    }
}
