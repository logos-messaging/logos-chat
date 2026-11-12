//! Bundles the services a conversation operation needs into one [`ServiceContext`].

use std::collections::HashMap;

use crate::IdentityProvider;
use crate::causal_history::CausalHistoryStore;
use crate::clock::Clock;
use crate::inbox_v2::{MlsEphemeralPqProvider, MlsIdentityProvider};
use crate::service_traits::AuthService;
use crate::service_traits::WakeupService;
use crate::{ConversationStore, DeliveryService, RegistrationService};

/// Bundles the external service types (`DS`, `RS`, `CS`) behind one `S`. The
/// `(DS, RS, CS)` tuple impl lets them still be supplied separately.
pub trait ExternalServices {
    type IP: IdentityProvider;
    type AS: AuthService;
    type DS: DeliveryService;
    type RS: RegistrationService;
    type WS: WakeupService;
    type CS: ConversationStore;
}

impl<IP, AS, DS, RS, WS, CS> ExternalServices for (IP, AS, DS, RS, WS, CS)
where
    IP: IdentityProvider,
    AS: AuthService,
    DS: DeliveryService,
    RS: RegistrationService,
    WS: WakeupService,
    CS: ConversationStore,
{
    type IP = IP;
    type AS = AS;
    type DS = DS;
    type RS = RS;
    type WS = WS;
    type CS = CS;
}

/// Bundles every service a conversation operation may need.
pub(crate) struct ServiceContext<S: ExternalServices> {
    pub(crate) ds: S::DS,
    pub(crate) registry: S::RS,
    pub(crate) store: S::CS,
    pub(crate) mls_identity: MlsIdentityProvider<S::IP>,
    pub(crate) auth: S::AS,
    pub(crate) mls_provider: MlsEphemeralPqProvider,
    pub(crate) causal: CausalHistoryStore,
    pub(crate) wakeup_service: S::WS,
    /// Time source for conversation timers.
    pub(crate) clock: Clock,
    /// Timing/policy for GroupV2 (de-mls) conversations, applied at
    /// create/join. The creator's phase durations reach joiners inside the
    /// welcome's `ConversationSync`.
    pub(crate) demls_config: de_mls::ConversationConfig,
    /// GroupV3 conversations that asked to be re-added, by convo id; only
    /// these accept a replacing Welcome.
    pub(crate) readd_pending: HashMap<String, ReAddTarget>,
}

/// The branch a re-add request was sealed to.
#[derive(Debug)]
pub(crate) struct ReAddTarget {
    pub epoch: u64,
    /// Leaf signature keys of the members who vouched for it.
    pub vouchers: Vec<Vec<u8>>,
}
