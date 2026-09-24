use libchat::ChatError;
use logos_account::AccountError;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Chat(#[from] ChatError),
    #[error(transparent)]
    Account(#[from] AccountError),
    #[error("failed to start the transport: {0}")]
    Transport(String),
    #[error("not an account address: {0}")]
    InvalidAccountAddress(String),
    #[error("installation is not endorsed by its account: {0}")]
    NotEndorsed(String),
}
