use de_mls::{ConversationError, mls_crypto::MlsError};
use openmls::ciphersuite::signature::SignaturePublicKey;
use openmls::group::{CreateMessageError, MergePendingCommitError};
use openmls::{framing::errors::MlsMessageError, prelude::tls_codec};
use openmls_memory_storage::MemoryStorageError;
pub use thiserror::Error;

use crate::identity::AuthStatus;
use crate::storage::StorageError;

use crate::{ConversationId, Signer, SignerKey};

#[derive(Error, Debug)]
pub enum ChatError {
    #[error("protocol error: {0:?}")]
    Protocol(String),
    #[error("protocol error: Got {0:?} expected {1:?}")]
    ProtocolExpectation(&'static str, String),
    #[error("Failed to decode payload: {0}")]
    DecodeError(#[from] prost::DecodeError),
    #[error("incorrect bundle value: {0:?}")]
    UnexpectedPayload(String),
    #[error("unexpected payload contents: {0}")]
    BadBundleValue(String),
    #[error("handshake initiated with a unknown ephemeral key")]
    UnknownEphemeralKey(),
    #[error("expected a different key length")]
    InvalidKeyLength,
    #[error("bytes provided to {0} failed")]
    BadParsing(&'static str),
    #[error("convo with id: {0} was not found")]
    NoConvo(String),
    #[error("unsupported conversation type: {0}")]
    UnsupportedConvoType(String),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("mls error: {0}")]
    MlsMessageError(#[from] MlsMessageError),
    #[error("TlsCodec: {0}")]
    TlsCodec(#[from] tls_codec::Error),
    #[error("generic: {0}")]
    Generic(String),
    #[error("KeyPackage: {0}")]
    KeyPackageVerify(#[from] openmls::prelude::KeyPackageVerifyError),
    #[error("Delivery: {0}")]
    Delivery(String),
    #[error("mls error: {0}")]
    MlsError(#[from] MlsError),
    #[error("demls error: {0}")]
    DeMlsError(#[from] ConversationError),
    // Used when a core function is called with a convo_id which is unsupported
    #[error("convo:{0} does not support {1}")]
    UnsupportedFunction(ConversationId, String),
    // Removal outcomes, surfaced to the UI as-is.
    #[error("you can't remove yourself from a group")]
    CannotRemoveSelf,
    // Also covers a pending invite: it holds no seat either.
    #[error("no one named is a member of this group")]
    NotAGroupMember,
    #[error("you can't start a direct conversation with yourself")]
    CannotMessageSelf,
    #[error("authentication failed: SignerKey({0}) is not valid for participant_id({1})")]
    Auth(String, String),
    #[error("participant resolution failed: {0}")]
    ParticipantResolution(String),

    #[error("KeyPackage: {0}")]
    KeyPackage(#[from] KeyPackageError),

    #[error("creating group: {0}")]
    GroupCreate(String),

    #[error("SendError: {0}")]
    SendError(#[from] SendError),

    #[error("type conversion: {0}")]
    ConversionError(#[from] TypeConversionError),
}

impl ChatError {
    // This is a stopgap until there is a proper error system in place
    pub fn generic(e: impl ToString) -> Self {
        Self::Generic(e.to_string())
    }
}

#[derive(Error, Debug)]
pub enum KeyPackageError {
    #[error("mls verify failed: {0}")]
    MlsVerify(#[from] openmls::prelude::KeyPackageVerifyError),
    #[error("{0}")]
    TypeConvert(#[from] TypeConversionError),
    #[error("reported signer {signer:?} failed auth with {auth_status}")]
    AuthFailed {
        signer: Signer,
        auth_status: AuthStatus,
    },
    #[error("expected signer {expected} got {}", hex::encode(got.as_slice()))]
    WrongPackage {
        expected: SignerKey,
        got: SignaturePublicKey,
    },
    #[error("key package decode failed: {0}")]
    Decode(#[from] tls_codec::Error),
}

#[derive(Error, Debug)]
pub enum TypeConversionError {
    #[error("could not convert BasicCredential to ParticipantId({0})")]
    ParticipantId(#[from] openmls::credentials::errors::BasicCredentialError),
}

#[derive(Error, Debug)]
pub enum SendError {
    #[error("mls failed creating message: {0}")]
    MlsCreate(#[from] CreateMessageError),
    #[error("delivery: {0}")]
    Delivery(String),
    #[error("mls message: {0}")]
    MlsMessageError(#[from] MlsMessageError),
    #[error("mls merge commit: {0}")]
    MlsMergeCommit(#[from] MergePendingCommitError<MemoryStorageError>),
}
