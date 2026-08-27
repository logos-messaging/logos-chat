use thiserror::Error;

/// Failures parsing an [`AccountAddr`](crate::AccountAddr).
///
/// Kept separate from [`AccountLogError`]: an unparseable address is a caller
/// input problem, not a statement about any log's contents.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AccountAddrError {
    #[error("not a valid account address")]
    InvalidAddress,
}

/// Failures building, decoding, or verifying an [`AccountLog`](crate::AccountLog).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AccountLogError {
    /// The entries do not form a valid log, or the bytes do not decode to one.
    #[error("malformed account log: {0}")]
    Malformed(String),

    /// The context label is not in the accepted form — see [`Context`](crate::Context).
    #[error("invalid context: {0}")]
    InvalidContext(String),

    /// The payload exceeds the accepted size. Bounded so a decoder can reject a
    /// hostile length before allocating.
    #[error("payload exceeds the {0} byte limit")]
    TooLarge(usize),

    /// The payload carries a domain version this build does not implement.
    #[error("unsupported account log version {0}")]
    Version(String),

    /// The account signature does not verify over the payload bytes.
    #[error("account signature verification failed")]
    SignatureInvalid,

    /// The candidate log is not newer than the one already held.
    #[error("account log is not newer than the log already held")]
    Stale,

    /// The candidate log is longer but does not extend the held one: history has
    /// been rewritten. Either the signer is showing different histories to
    /// different readers, or the account key is compromised.
    #[error("account log forks from the log already held")]
    Forked,
}
