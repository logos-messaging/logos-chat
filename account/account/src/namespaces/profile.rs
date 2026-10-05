//! Information about the accounts owner, under the `profile.*` namespace.
//! This information helps applications display an account to other users such as profile
//! pictures, display names etc.
//!
//! Specification: <https://lip.logos.co/identity/raw/profile.html>

use account_log::{AccountRecord, Context};

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

impl ProfileRead for AccountRecord {
    fn display_name(&self) -> Option<&str> {
        self.log()
            .text_for(&PROFILE_DISPLAYNAME)
            .into_iter()
            .next_back()
    }

    fn previous_aliases(&self) -> Vec<&str> {
        let mut aliases = self.log().text_for(&PROFILE_DISPLAYNAME);
        aliases.pop();
        aliases
    }
}

/// Writing your own profile.
pub trait ProfileWrite {
    /// The name that should be displayed for this account in applications.
    fn set_display_name(self, name: impl Into<String>) -> Self;
}

impl<AP: AccountProvider + AccountPublisher> ProfileWrite for AccountUpdate<'_, AP> {
    fn set_display_name(self, name: impl Into<String>) -> Self {
        self.endorse_text(PROFILE_DISPLAYNAME, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The context string is a wire-format commitment: changing it orphans
    /// every entry already published under the old one.
    #[test]
    fn context_is_pinned() {
        assert_eq!(PROFILE_DISPLAYNAME.as_str(), "profile.displayname");
    }
}
