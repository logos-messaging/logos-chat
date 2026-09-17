use libchat::ChatError;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Chat(#[from] ChatError),
    #[error("participant id is not an account address")]
    InvalidAccount,
    #[error("failed to start the transport: {0}")]
    Transport(String),
    #[error("not an account address: {0}")]
    InvalidAccountAddress(String),
    #[error("installation is not endorsed by its account: {0}")]
    NotEndorsed(String),
    #[error("device bundle publish failed: {0}")]
    BundlePublish(String),
}
