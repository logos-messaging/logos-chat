//! Contexts: the label an [`Add`](crate::AccountEntry::Add) carries saying
//! what the endorsement is *for*.
//!
//! A consumer selects the entries bearing its own context and ignores the
//! rest, so a key endorsed for one purpose is never used for another. This
//! module defines only what a context is and how it is encoded; which
//! contexts exist is allocated by the protocols above the log.

use std::sync::LazyLock;

use crate::error::AccountLogError;

/// The context libchat endorses device (LocalIdentity) signing keys under.
///
/// Allocated by libchat, not by the account-log format: the format defines
/// only that every endorsement carries a context.
pub static SIGNER_CONTEXT: LazyLock<Context> =
    LazyLock::new(|| Context::new("chat.signer").expect("valid context"));

/// A validated context label. Comparison is a raw byte compare — permitting
/// general UTF-8 would admit normalization forms and case folding as sources
/// of disagreement over whether two entries share a context.
///
/// The first segment (before the first `.`) names the specification that
/// defines the context.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Context(Box<str>);

impl Context {
    /// Validate `label` as a context: 1-255 bytes of `a`-`z`, `0`-`9`, `.`,
    /// `-`, `_`, beginning with a letter and containing at least one `.`.
    pub fn new(label: &str) -> Result<Self, AccountLogError> {
        Self::from_bytes(label.as_bytes())
    }

    /// [`new`](Self::new) over raw bytes — what the decoder holds. The
    /// charset is a subset of ASCII, so a passing byte string is valid UTF-8.
    pub(crate) fn from_bytes(label: &[u8]) -> Result<Self, AccountLogError> {
        let invalid = |detail: &str| {
            Err(AccountLogError::InvalidContext(format!(
                "context {}: {detail}",
                String::from_utf8_lossy(label)
            )))
        };
        if label.is_empty() || label.len() > 255 {
            return invalid("must be 1-255 bytes");
        }
        if !label[0].is_ascii_lowercase() {
            return invalid("must begin with a-z");
        }
        if !label.contains(&b'.') {
            return invalid("must contain a '.'");
        }
        if !label.iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        }) {
            return invalid("must be a-z 0-9 . - _ only");
        }
        Ok(Self(
            String::from_utf8(label.to_vec())
                .expect("charset is ASCII")
                .into_boxed_str(),
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The encoded form. At most 255 bytes, so its length fits `ctx_len`.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Display for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_allowed_charset() {
        for label in ["chat.signer", "a.b", "profile.display-name_2", "a.9-_."] {
            assert_eq!(Context::new(label).unwrap().as_str(), label);
        }
    }

    /// Every rejection rule: empty, over-length, leading non-letter, no dot,
    /// and a byte outside the charset (including uppercase).
    #[test]
    fn rejects_malformed_labels() {
        let long = format!("a.{}", "x".repeat(254));
        for label in [
            "",
            &long,
            "1chat.signer",
            ".chat.signer",
            "signer",
            "chat.sign@r",
            "Chat.signer",
            "chat.signer\u{e9}",
        ] {
            assert!(
                matches!(Context::new(label), Err(AccountLogError::InvalidContext(_))),
                "accepted {label:?}"
            );
        }
    }

    /// The pinned context is valid, so its LazyLock cannot panic at first use.
    #[test]
    fn signer_context_is_valid() {
        assert_eq!(SIGNER_CONTEXT.as_str(), "chat.signer");
    }
}
