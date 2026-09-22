use components::{EphemeralRegistry, LocalBroadcaster};
use libchat::test_support::{KvTransaction, MemStore};
use libchat::{
    ConversationKind, ConversationStore, ConvoOutcome, Core, KvPair, KvStore, PayloadOutcome,
};

use crate::test_ident::TestIdent;
use crate::wakeup::NoopWakeupService;

/// A core whose test drives no timers, over whichever store the case needs.
pub type PeerCore<CS = MemStore> = Core<(
    TestIdent,
    LocalBroadcaster,
    EphemeralRegistry,
    NoopWakeupService,
    CS,
)>;

/// Opens a core over `store`. The identity is passed in rather than built here, since a restart
/// case turns on reopening the same installation over a store on the same file.
pub fn open_core<CS: KvStore + ConversationStore + 'static>(
    ident: TestIdent,
    ds: LocalBroadcaster,
    rs: EphemeralRegistry,
    store: CS,
) -> PeerCore<CS> {
    Core::new_from_store(ident, ds, rs, NoopWakeupService, store).unwrap()
}

/// A peer that registers a key package others can invite, and reads what they publish.
pub fn open_peer(name: &str, ds: LocalBroadcaster, rs: EphemeralRegistry) -> PeerCore {
    open_core(TestIdent::new(name), ds, rs, MemStore::new())
}

/// Hands `core` every payload published since the last call.
pub fn drain<CS: KvStore + ConversationStore + 'static>(
    core: &mut PeerCore<CS>,
) -> Vec<PayloadOutcome> {
    let payloads: Vec<_> = {
        let ds = core.ds();
        std::iter::from_fn(|| ds.poll()).collect()
    };

    payloads
        .iter()
        .map(|payload| core.handle_payload(payload).unwrap())
        .collect()
}

/// The conversation content `outcomes` carry, in the order they arrived.
pub fn content(outcomes: &[PayloadOutcome]) -> Vec<Vec<u8>> {
    outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            PayloadOutcome::Convo(ConvoOutcome {
                content: Some(content),
                ..
            }) => Some(content.bytes.clone()),
            _ => None,
        })
        .collect()
}

/// Everything a conversation's own scope holds.
pub fn scope_entries<S: KvStore>(store: &S, kind: ConversationKind, convo_id: &str) -> Vec<KvPair> {
    let tx = KvTransaction::begin(store).unwrap();
    tx.scope(kind, convo_id).scan_prefix(b"").unwrap()
}
