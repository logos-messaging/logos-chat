use libchat::ChatError;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Chat(#[from] ChatError),
    #[error("received credential could not be parsed")]
    BadlyFormedCredential,
    #[error("failed to start the transport: {0}")]
    Transport(String),
    #[error("account resolution failed: {0}")]
    AccountResolution(String),
    #[error("device bundle publish failed: {0}")]
    BundlePublish(String),
    #[error("failed to encode message content: {0}")]
    ContentEncode(#[from] message_types::Error),
}
