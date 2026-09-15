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
