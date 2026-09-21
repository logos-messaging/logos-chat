mod builder;
mod client;
mod delivery_in_process;
mod errors;
mod event;
mod installation;
mod members;

pub use builder::{ChatClientBuilder, Unset};
pub use client::{ChatClient, GroupMetadata, Transport};
pub use delivery_in_process::{InProcessDelivery, MessageBus};
pub use errors::ClientError;
pub use event::Event;
pub use installation::{Installation, PendingInstallation};
pub use members::{AuthenticatedMember, Member};

// Re-export types callers need to interact with ChatClient.
pub use chat_sqlite::{SqliteStore, StorageConfig};
pub use libchat::{
    AddressedEnvelope, AuthService, ConversationClass, ConversationId, ConversationStore,
    ConvoMetadata, DeliveryService, GroupV2Config, IdentityProvider, MessageId,
    RegistrationService,
};
// The directory trait bounds ChatClient's registry parameter, so callers
// writing code generic over ChatClient need it too.
pub use logos_account::AccountAddr;

// Re-export bundled registry implementations so callers can pick one without
// pulling in `components` directly.
pub use components::{
    ContactRegistry, ContactRegistryError, EphemeralRegistry, RegistryPublishMode,
};
