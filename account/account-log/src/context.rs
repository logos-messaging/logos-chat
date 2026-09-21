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

/// Longest namespace and label, in octets.
const MAX_NAMESPACE: usize = 16;
const MAX_LABEL: usize = 64;

/// A validated context, `<namespace>.<label>`. Comparison is a raw byte
/// compare — permitting general UTF-8 would admit normalization forms and case
/// folding as sources of disagreement over whether two entries share a context.
///
/// The namespace names the specification that defines the context; the label
/// names one use within it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Context(Box<str>);

impl Context {
    /// Validate `context` as `<namespace>.<label>`: a namespace of 1-16
    /// octets from `a`-`z` `0`-`9` `-`, then a label of 1-64 octets from
    /// `a`-`z` `0`-`9` `-` `.`, each beginning with a letter.
    pub fn new(context: &str) -> Result<Self, AccountLogError> {
        Self::from_bytes(context.as_bytes())
    }

    /// [`new`](Self::new) over raw bytes — what the decoder holds. The
    /// charset is a subset of ASCII, so a passing byte string is valid UTF-8.
    pub(crate) fn from_bytes(context: &[u8]) -> Result<Self, AccountLogError> {
        let invalid = |detail: &str| {
            Err(AccountLogError::InvalidContext(format!(
                "context {}: {detail}",
                String::from_utf8_lossy(context)
            )))
        };
        // Split at the *first* full stop: the rest belongs to the label,
        // which may contain further stops.
        let Some(dot) = context.iter().position(|&b| b == b'.') else {
            return invalid("must contain a '.' separating namespace from label");
        };
        let (namespace, label) = (&context[..dot], &context[dot + 1..]);

        if namespace.is_empty() || namespace.len() > MAX_NAMESPACE {
            return invalid("namespace must be 1-16 octets");
        }
        if label.is_empty() || label.len() > MAX_LABEL {
            return invalid("label must be 1-64 octets");
        }
        if !namespace[0].is_ascii_lowercase() {
            return invalid("namespace must begin with a-z");
        }
        if !label[0].is_ascii_lowercase() {
            return invalid("label must begin with a-z");
        }
        if !namespace
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        {
            return invalid("namespace must be a-z 0-9 - only");
        }
        if !label
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
        {
            return invalid("label must be a-z 0-9 - . only");
        }
        Ok(Self(
            String::from_utf8(context.to_vec())
                .expect("charset is ASCII")
                .into_boxed_str(),
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The encoded form. At most 81 bytes, so its length fits `ctx_len`.
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
        let longest = format!("{}.{}", "n".repeat(MAX_NAMESPACE), "l".repeat(MAX_LABEL));
        for context in [
            "chat.signer",
            "a.b",
            "profile.display-name",
            "my-ns.a.b.c",
            "a9.z0",
            longest.as_str(),
        ] {
            assert_eq!(Context::new(context).unwrap().as_str(), context);
        }
    }

    /// Every rejection rule, on both halves: empty, over-length, a leading
    /// non-letter, a missing separator, and a byte outside the charset —
    /// which no longer includes `_`.
    #[test]
    fn rejects_malformed_contexts() {
        let long_namespace = format!("{}.signer", "n".repeat(MAX_NAMESPACE + 1));
        let long_label = format!("chat.{}", "l".repeat(MAX_LABEL + 1));
        for context in [
            "",
            "signer",
            ".signer",
            "chat.",
            long_namespace.as_str(),
            long_label.as_str(),
            "1chat.signer",
            "chat.9signer",
            "chat.-signer",
            "chat.sign@r",
            "Chat.signer",
            "chat.signer\u{e9}",
            "chat.my_key",
            "my_ns.signer",
        ] {
            assert!(
                matches!(
                    Context::new(context),
                    Err(AccountLogError::InvalidContext(_))
                ),
                "accepted {context:?}"
            );
        }
    }

    /// The pinned context is valid, so its LazyLock cannot panic at first use.
    #[test]
    fn signer_context_is_valid() {
        assert_eq!(SIGNER_CONTEXT.as_str(), "chat.signer");
    }
}
