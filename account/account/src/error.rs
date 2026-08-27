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
}
