use std::{
    cell::RefCell,
    collections::{HashSet, VecDeque},
    hash::{DefaultHasher, Hash, Hasher},
    rc::Rc,
};

use libchat::{AddressedEnvelope, DeliveryService};
use tracing::info;

#[derive(Debug)]
struct BroadcasterShared<T> {
    /// Per-address message queue; all published messages are appended here.
    messages: VecDeque<T>,
    base_index: usize,
}

impl<T> BroadcasterShared<T> {
    pub fn read(&self, cursor: usize) -> Option<&T> {
        self.messages.get(cursor + self.base_index)
    }

    pub fn tail(&self) -> usize {
        self.messages.len() + self.base_index
    }
}

#[derive(Clone, Debug)]
pub struct LocalBroadcaster {
    shared: Rc<RefCell<BroadcasterShared<AddressedEnvelope>>>,
    cursor: usize,
    subscriptions: HashSet<String>,
    outbound_msgs: Vec<u64>,
}

/// This is Lightweight DeliveryService which can be used for tests
/// and local examples. Messages are not delivered until `poll` is called
/// which allows for more fine grain test cases.
impl LocalBroadcaster {
    pub fn new() -> Self {
        let shared = Rc::new(RefCell::new(BroadcasterShared {
            messages: VecDeque::new(),
            base_index: 0,
        }));

        let cursor = shared.borrow().tail();
        Self {
            shared,
            cursor,
            subscriptions: HashSet::new(),
            outbound_msgs: Vec::new(),
        }
    }

    /// Returns a new consumer that shares the same message store but has its
    /// own independent cursor — it starts from the beginning of each address
    /// queue regardless of what any other consumer has already processed.
    pub fn new_consumer(&self) -> Self {
        let inner = self.shared.clone();
        let cursor = inner.borrow().tail();
        Self {
            shared: inner,
            cursor,
            subscriptions: HashSet::new(),
            outbound_msgs: Vec::new(),
        }
    }

    /// Pulls all messages this consumer has not yet seen on `address`,
    /// applying any registered filter.  Advances the cursor so the same
    /// messages are not returned again.
    pub fn poll(&mut self) -> Option<Vec<u8>> {
        self.poll_envelope().map(|envelope| envelope.data)
    }

    /// [`Self::poll`], returning the whole envelope rather than its data.
    // clippy's question_mark (1.97+) wants `self.shared.borrow().read(next)?`, but
    // `read` returns a reference into the RefCell `Ref`; the `?` form drops that
    // guard at the `;` and `ae` would dangle. Keep the explicit match.
    #[allow(clippy::question_mark)]
    pub fn poll_envelope(&mut self) -> Option<AddressedEnvelope> {
        loop {
            let next = self.cursor;
            match self.shared.borrow().read(next) {
                None => return None,
                Some(ae) => {
                    self.cursor = next + 1;
                    if self.subscriptions.contains(ae.delivery_address.as_str())
                        && self.is_inbound(ae)
                    {
                        return Some(ae.clone());
                    }
                }
            }
        }
    }

    fn msg_id(msg: &AddressedEnvelope) -> u64 {
        let mut hasher = DefaultHasher::new();
        msg.data.as_slice().hash(&mut hasher);
        hasher.finish()
    }

    fn is_inbound(&self, msg: &AddressedEnvelope) -> bool {
        let mid = Self::msg_id(msg);
        !self.outbound_msgs.contains(&mid)
    }
}

impl Default for LocalBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

impl DeliveryService for LocalBroadcaster {
    type Error = String;

    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), Self::Error> {
        info!(?envelope.delivery_address, len=envelope.data.len(), "DS:Publish");
        self.outbound_msgs.push(Self::msg_id(&envelope));
        self.shared.borrow_mut().messages.push_back(envelope);

        Ok(())
    }

    fn subscribe(&mut self, delivery_address: &str) -> Result<(), Self::Error> {
        info!(delivery_address, "DS:Subscribe");
        // Strict temporal ordering of subscriptions is not enforced.
        // Subscriptions are evaluated on polling, not when the message is published
        self.subscriptions.insert(delivery_address.to_string());
        Ok(())
    }
}
