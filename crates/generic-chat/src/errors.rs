use libchat::{ChatError, StorageError};
use logos_account::AccountError;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Chat(#[from] ChatError),
    #[error(transparent)]
    Account(#[from] AccountError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("failed to start the transport: {0}")]
    Transport(String),
    #[error("not an account address: {0}")]
    InvalidAccountAddress(String),
    #[error("installation is not endorsed by its account: {0}")]
    NotEndorsed(String),
    /// The store holds a record this build cannot read. Never treated as "no installation":
    /// registering a fresh one over conversations belonging to the stored one would orphan them.
    #[error("the stored installation cannot be read: {0}")]
    MalformedInstallationRecord(String),
}
