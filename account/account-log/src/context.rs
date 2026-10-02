//! Contexts: the label an [`Add`](crate::AccountEntry::Add) carries saying
//! what the endorsement is *for*.
//!
//! A consumer selects the entries bearing its own context and ignores the
//! rest, so a key endorsed for one purpose is never used for another. This
//! module defines only what a context is and how it is encoded; which
//! contexts exist is allocated by the protocols above the log.

use crate::error::AccountLogError;

/// The context libchat endorses device (LocalIdentity) signing keys under.
///
/// Allocated by libchat, not by the account-log format: the format defines
/// only that every endorsement carries a context.
pub const CHATSIGNER_CONTEXT: Context = Context::from_static("chat.signer");

/// Longest namespace and label, in octets.
const MAX_NAMESPACE: usize = 16;
const MAX_LABEL: usize = 64;
/// `<namespace>.<label>`, so the separator too. Its length fits `ctx_len`.
const MAX_CONTEXT: usize = MAX_NAMESPACE + 1 + MAX_LABEL;

/// A validated context, `<namespace>.<label>`. Comparison is a raw byte
/// compare — permitting general UTF-8 would admit normalization forms and case
/// folding as sources of disagreement over whether two entries share a context.
///
/// The namespace names the specification that defines the context; the label
/// names one use within it.
///
/// Stored inline rather than boxed so [`from_static`](Self::from_static) can
/// run in a `const`. Unused bytes are zero, and `0x00` is outside the charset,
/// so the derived `Ord` matches ordering the strings themselves.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Context {
    buf: [u8; MAX_CONTEXT],
    len: u8,
}

impl Context {
    /// Validate `context` as `<namespace>.<label>`: a namespace of 1-16
    /// octets from `a`-`z` `0`-`9` `-`, then a label of 1-64 octets from
    /// `a`-`z` `0`-`9` `-` `.`, each beginning with a letter.
    pub fn new(context: &str) -> Result<Self, AccountLogError> {
        Self::from_bytes(context.as_bytes())
    }

    /// [`new`](Self::new) for a literal, checked while compiling: an invalid
    /// one fails the build rather than the first use.
    pub const fn from_static(context: &'static str) -> Self {
        match Self::checked(context.as_bytes()) {
            Ok(context) => context,
            Err(detail) => panic!("{}", detail),
        }
    }

    /// [`new`](Self::new) over raw bytes — what the decoder holds. The
    /// charset is a subset of ASCII, so a passing byte string is valid UTF-8.
    pub(crate) fn from_bytes(context: &[u8]) -> Result<Self, AccountLogError> {
        Self::checked(context).map_err(|detail| {
            AccountLogError::InvalidContext(format!(
                "context {}: {detail}",
                String::from_utf8_lossy(context)
            ))
        })
    }

    /// The one implementation of the rule, so the `const` and runtime paths
    /// cannot drift apart. `Err` carries the detail each reports.
    const fn checked(context: &[u8]) -> Result<Self, &'static str> {
        // Split at the *first* full stop: the rest belongs to the label,
        // which may contain further stops.
        let mut dot = usize::MAX;
        let mut i = 0;
        while i < context.len() {
            if context[i] == b'.' {
                dot = i;
                break;
            }
            i += 1;
        }
        if dot == usize::MAX {
            return Err("must contain a '.' separating namespace from label");
        }
        let (namespace, label) = (context.split_at(dot).0, context.split_at(dot + 1).1);

        if namespace.is_empty() || namespace.len() > MAX_NAMESPACE {
            return Err("namespace must be 1-16 octets");
        }
        if label.is_empty() || label.len() > MAX_LABEL {
            return Err("label must be 1-64 octets");
        }
        if !namespace[0].is_ascii_lowercase() {
            return Err("namespace must begin with a-z");
        }
        if !label[0].is_ascii_lowercase() {
            return Err("label must begin with a-z");
        }
        let mut i = 0;
        while i < namespace.len() {
            let b = namespace[i];
            if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
                return Err("namespace must be a-z 0-9 - only");
            }
            i += 1;
        }
        let mut i = 0;
        while i < label.len() {
            let b = label[i];
            if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.') {
                return Err("label must be a-z 0-9 - . only");
            }
            i += 1;
        }

        let mut buf = [0u8; MAX_CONTEXT];
        let mut i = 0;
        while i < context.len() {
            buf[i] = context[i];
            i += 1;
        }
        Ok(Self {
            buf,
            len: context.len() as u8,
        })
    }

    pub const fn as_str(&self) -> &str {
        match std::str::from_utf8(self.as_bytes()) {
            Ok(context) => context,
            Err(_) => panic!("charset is ASCII"),
        }
    }

    /// The encoded form. At most 81 bytes, so its length fits `ctx_len`.
    pub const fn as_bytes(&self) -> &[u8] {
        self.buf.split_at(self.len as usize).0
    }
}

impl std::fmt::Display for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The 81-byte buffer is noise; the context is the string in it.
impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Context").field(&self.as_str()).finish()
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

    /// Invalid would now be a build failure, so this only pins the value.
    #[test]
    fn signer_context_is_valid() {
        assert_eq!(CHATSIGNER_CONTEXT.as_str(), "chat.signer");
    }
}
