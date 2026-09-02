use components::{EphemeralRegistry, LocalBroadcaster};
use libchat::Core;
use libchat::test_support::MemStore;

use crate::test_ident::TestIdent;
use crate::wakeup::NoopWakeupService;

/// A core over an in-memory store whose test drives no timers.
pub type PeerCore = Core<(
    TestIdent,
    LocalBroadcaster,
    EphemeralRegistry,
    NoopWakeupService,
    MemStore,
)>;

/// A peer that registers a key package others can invite, and reads what they publish.
pub fn open_peer(name: &str, ds: LocalBroadcaster, rs: EphemeralRegistry) -> PeerCore {
    Core::new_from_store(
        TestIdent::new(name),
        ds,
        rs,
        NoopWakeupService,
        MemStore::new(),
    )
    .unwrap()
}
