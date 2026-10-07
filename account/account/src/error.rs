use account_log::AccountLogError;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AccountError {
    /// Transparent: the inner message already names the log.
    #[error(transparent)]
    Log(#[from] AccountLogError),

    /// The provider's own error, stringified.
    #[error("account provider: {0}")]
    Provider(String),

    /// The fetched log does not extend the one already held: the account has
    /// shown two histories. The held record stands.
    #[error("account log forks from the log already held")]
    Forked,
}

/// Routed through [`AccountLogError`] rather than added as a variant of its
/// own: to a caller, bytes that are not a key are the same class of failure as
/// a log that does not decode. `?` will not chain two conversions, so the hop
/// `AccountLogError` already implements is not enough on its own.
impl From<account_log::Ed25519Error> for AccountError {
    fn from(error: account_log::Ed25519Error) -> Self {
        Self::Log(error.into())
    }
}
