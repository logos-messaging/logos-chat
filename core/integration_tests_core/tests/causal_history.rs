//! End-to-end test for causal-history gap detection in group conversation.
//!
//! Saro and Raya share a group. Saro sends three messages; Raya never
//! receives the second one. The third message's causal history references
//! the missing second message, so Raya must detect and report the gap.

use std::ops::{Deref, DerefMut};

use components::{EphemeralRegistry, LocalBroadcaster};
use integration_tests_core::TestIdent;
use libchat::test_support::MemStore;
use libchat::{Core, MissingMessage, WakeupService};

#[derive(Debug)]
struct NoopWakeupService {}
impl WakeupService for NoopWakeupService {
    fn wakeup_in(&mut self, _: std::time::Duration, _: libchat::ConversationId) {}
}

struct Client {
    inner: Core<(
        TestIdent,
        LocalBroadcaster,
        EphemeralRegistry,
        NoopWakeupService,
        MemStore,
    )>,
}

impl Client {
    fn init(
        core: Core<(
            TestIdent,
            LocalBroadcaster,
            EphemeralRegistry,
            NoopWakeupService,
            MemStore,
        )>,
    ) -> Self {
        Client { inner: core }
    }

    /// Poll every pending payload and feed it to the protocol.
    fn process_messages(&mut self) {
        let messages: Vec<_> = {
            let ds = self.inner.ds();
            std::iter::from_fn(|| ds.poll()).collect()
        };
        for data in messages {
            self.inner.handle_payload(&data).unwrap();
        }
    }

    /// Poll every pending payload and discard it — simulates messages that
    /// never reach this client.
    fn drop_pending_messages(&mut self) {
        let ds = self.inner.ds();
        while ds.poll().is_some() {}
    }
}

impl Deref for Client {
    type Target = Core<(
        TestIdent,
        LocalBroadcaster,
        EphemeralRegistry,
        NoopWakeupService,
        MemStore,
    )>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Client {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[test]
fn missing_group_message_is_detected() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let saro_ident = TestIdent::new("saro");
    let saro_ctx = Core::new_with_name(
        saro_ident,
        ds.new_consumer(),
        rs.clone(),
        NoopWakeupService {},
        MemStore::new(),
    )
    .unwrap();

    let raya_ident = TestIdent::new("raya");
    let raya_ctx = Core::new_with_name(
        raya_ident,
        ds.clone(),
        rs.clone(),
        NoopWakeupService {},
        MemStore::new(),
    )
    .unwrap();

    let mut saro = Client::init(saro_ctx);
    let mut raya = Client::init(raya_ctx);

    // Saro creates a group with Raya.
    let raya_id = raya.ident_id().clone();
    let convo_id = saro.create_group_convo_v1(&[&raya_id]).unwrap().to_string();

    // Raya joins (processes the Welcome + commit).
    raya.process_messages();

    // Message 1 is delivered normally.
    saro.send_content(convo_id.as_str(), b"first").unwrap();
    raya.process_messages();
    assert!(
        raya.take_missing_messages().is_empty(),
        "no gap expected while every message is delivered"
    );

    // Message 2 is published but never reaches Raya.
    saro.send_content(convo_id.as_str(), b"second").unwrap();
    raya.drop_pending_messages();

    // Message 3 is delivered; its causal history references the missing M2.
    saro.send_content(convo_id.as_str(), b"third").unwrap();
    raya.process_messages();

    let missing: Vec<MissingMessage> = raya.take_missing_messages();
    assert_eq!(missing.len(), 1, "exactly one message should be missing");
    assert_eq!(missing[0].conversation_id, convo_id);
    assert!(
        !missing[0].frontier.message_id().is_empty(),
        "the missing message must be identified"
    );
    // The causal sender hint carries the sender's identity id ("saro"), not
    // the signer id the inbox and registry key on.
    assert_eq!(
        missing[0].frontier.sender_id(),
        "saro",
        "missing-message sender hint should attribute to Saro"
    );

    // Draining clears the report; a resolved gap is not surfaced again.
    assert!(raya.take_missing_messages().is_empty());
}
