mod causal_history;
mod conversation;
mod core;
mod errors;
mod inbox_v2;
mod kv;
mod outcomes;
mod proto;
mod protocol;
mod service_context;
mod service_traits;
mod storage;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
mod types;
mod utils;

pub use causal_history::{DeliveryAck, Frontier, MissingMessage};
pub use conversation::{GroupV2Clock, MessageId};
pub use core::{ConversationId, Core};
/// Timing/policy for GroupV2 conversations (de-mls's per-conversation config).
/// Defaults to the de-mls library defaults; inject via
/// [`Core::set_group_v2_config`]. The creator's phase durations (commit
/// inactivity, freeze, recovery, voting inactivity, proposal expiration,
/// consensus timeout) travel to joiners with the welcome and overwrite
/// theirs; vote delays and the policy fields stay local to each member.
pub use de_mls::ConversationConfig as GroupV2Config;
pub use de_mls::MockClock;
pub use errors::ChatError;
pub use kv::{KvTransaction, ScopedKvStore};
pub use outcomes::{
    Content, ConversationClass, ConvoOutcome, InboxOutcome, NewConversation, PayloadOutcome,
};
pub use protocol::Protocol;
pub use service_context::ExternalServices;
pub use service_traits::{DeliveryService, RegistrationService, WakeupService};
pub use shared_traits::{IdentId, IdentIdRef, IdentityProvider};
pub use storage::{
    ConversationMeta, ConversationStore, KvPair, KvStore, KvTx, Namespace, Scope, StorageError,
};
pub use types::{AddressedEnvelope, ConvoMetadata};
pub use utils::{hex_trunc, trunc};
