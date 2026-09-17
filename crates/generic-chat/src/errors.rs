use libchat::ChatError;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Chat(#[from] ChatError),
    #[error("external id is not an account address")]
    InvalidExternalId,
    #[error("failed to start the transport: {0}")]
    Transport(String),
    #[error("account resolution failed: {0}")]
    AccountResolution(String),
    #[error("device bundle publish failed: {0}")]
    BundlePublish(String),
}
