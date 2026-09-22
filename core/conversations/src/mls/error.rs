use crate::storage::StorageError;
use thiserror::Error;

/// What the MLS storage provider can fail with.
#[derive(Debug, Error)]
pub(crate) enum MlsStorageError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("codec error: {0}")]
    Codec(#[from] serde_json::Error),
    /// State addressed through a provider that carries no scope holding it.
    #[error("no scope bound for {0}")]
    Unscoped(&'static str),
}
