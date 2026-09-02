//! Nothing is announced before the state behind it is stored, and nothing that was stored is
//! forgotten because the announcement failed.
//!
//! Saro's key package commits private init and encryption keys to storage, so the registry must
//! not serve one whose unit was rolled back: a peer fetching it would send a welcome Saro cannot
//! open. In the other direction, a conversation whose unit landed is real, so a publish that
//! fails afterwards costs a message, never the conversation.

use std::cell::Cell;
use std::rc::Rc;

use components::{EphemeralRegistry, LocalBroadcaster};
use integration_tests_core::{Faults, NoopWakeupService, TestIdent, open_peer};
use libchat::test_support::MemStore;
use libchat::{AddressedEnvelope, Core, DeliveryService, RegistrationService};

/// A transport that refuses to publish while the switch is set, so an operation fails with its
/// state already stored.
#[derive(Debug)]
struct FaultDelivery {
    inner: LocalBroadcaster,
    fail_publish: Rc<Cell<bool>>,
}

impl DeliveryService for FaultDelivery {
    type Error = String;

    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), String> {
        if self.fail_publish.get() {
            return Err("publish refused".into());
        }
        self.inner.publish(envelope)
    }

    fn subscribe(&mut self, delivery_address: &str) -> Result<(), String> {
        self.inner.subscribe(delivery_address)
    }
}

#[test]
fn a_key_package_is_not_registered_when_its_unit_does_not_land() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();
    let faults = Faults::new();

    let mut saro = Core::new_from_store(
        TestIdent::new("saro"),
        ds.new_consumer(),
        rs.clone(),
        NoopWakeupService,
        faults.store(),
    )
    .unwrap();
    let device_id = saro.ident_id().to_string();
    let published = rs.retrieve(&device_id).unwrap();
    assert!(published.is_some());

    faults.fail_commit(true);
    assert!(saro.register_keypackage().is_err());
    faults.fail_commit(false);

    // The rolled-back package's private keys are gone, so the registry must still hold the one
    // whose keys Saro kept.
    assert_eq!(rs.retrieve(&device_id).unwrap(), published);
}

#[test]
fn a_conversation_survives_a_publish_that_fails_after_its_unit_landed() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();
    let fail_publish = Rc::new(Cell::new(false));

    let raya = open_peer("raya", ds.new_consumer(), rs.clone());
    let raya_id = raya.ident_id().clone();

    let mut saro = Core::new_from_store(
        TestIdent::new("saro"),
        FaultDelivery {
            inner: ds.new_consumer(),
            fail_publish: fail_publish.clone(),
        },
        rs.clone(),
        NoopWakeupService,
        MemStore::new(),
    )
    .unwrap();

    fail_publish.set(true);
    assert!(
        saro.create_group_convo_v2(&[&raya_id], "book club", "")
            .is_err()
    );
    fail_publish.set(false);

    // GroupV2 has no load path, so the conversation exists only where the create left it.
    let convos = saro.list_conversations().unwrap();
    assert_eq!(convos.len(), 1);
    assert_eq!(saro.convo_metadata(&convos[0]).unwrap().name, "book club");
}
