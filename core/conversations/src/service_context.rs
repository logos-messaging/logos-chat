//! Bundles the services a conversation operation needs into one [`ServiceContext`].

use openmls_libcrux_crypto::CryptoProvider as LibcruxCryptoProvider;

use crate::IdentityProvider;
use crate::causal_history::CausalHistoryStore;
use crate::conversation::GroupV2Clock;
use crate::inbox_v2::MlsIdentityProvider;
use crate::service_traits::WakeupService;
use crate::staged_delivery::StagedDelivery;
use crate::{ConversationStore, KvStore};
use crate::{DeliveryService, RegistrationService};

/// Bundles the external service types (`DS`, `RS`, `CS`) behind one `S`. The
/// `(DS, RS, CS)` tuple impl lets them still be supplied separately.
pub trait ExternalServices {
    type IP: IdentityProvider;
    type DS: DeliveryService;
    type RS: RegistrationService;
    type WS: WakeupService;
    type CS: KvStore + ConversationStore;
}

impl<IP, DS, RS, WS, CS> ExternalServices for (IP, DS, RS, WS, CS)
where
    IP: IdentityProvider,
    DS: DeliveryService,
    RS: RegistrationService,
    WS: WakeupService,
    CS: KvStore + ConversationStore,
{
    type IP = IP;
    type DS = DS;
    type RS = RS;
    type WS = WS;
    type CS = CS;
}

/// Bundles every service a conversation operation may need.
pub(crate) struct ServiceContext<S: ExternalServices> {
    pub(crate) ds: StagedDelivery<S::DS>,
    pub(crate) registry: S::RS,
    pub(crate) mls_identity: MlsIdentityProvider<S::IP>,
    pub(crate) crypto: LibcruxCryptoProvider,
    pub(crate) causal: CausalHistoryStore,
    pub(crate) wakeup_service: S::WS,
    /// Time source for GroupV2 (de-mls) conversations.
    pub(crate) demls_clock: GroupV2Clock,
    /// Timing/policy for GroupV2 (de-mls) conversations, applied at
    /// create/join. The creator's phase durations reach joiners inside the
    /// welcome's `ConversationSync`.
    pub(crate) demls_config: de_mls::ConversationConfig,
}
