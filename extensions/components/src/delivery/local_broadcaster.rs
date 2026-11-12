use std::{
    cell::RefCell,
    collections::{HashSet, VecDeque},
    hash::{DefaultHasher, Hash, Hasher},
    rc::Rc,
};

use libchat::{AddressedEnvelope, DeliveryInfo, DeliveryMsgId, DeliveryService, DeliveryTag};
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
    fetched: VecDeque<(Vec<u8>, DeliveryInfo)>,
    /// Set by [`Self::report_ids_late`]: the ids `publish` no longer returns.
    reports: Option<VecDeque<(DeliveryTag, DeliveryInfo)>>,
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
            fetched: VecDeque::new(),
            reports: None,
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
            fetched: VecDeque::new(),
            reports: None,
        }
    }

    /// Pulls all messages this consumer has not yet seen on `address`,
    /// applying any registered filter.  Advances the cursor so the same
    /// messages are not returned again.
    /// Fetched messages come first, and each comes with its delivery info.
    // clippy's question_mark (1.97+) wants `self.shared.borrow().read(next)?`, but
    // `read` returns a reference into the RefCell `Ref`; the `?` form drops that
    // guard at the `;` and `ae` would dangle. Keep the explicit match.
    #[allow(clippy::question_mark)]
    pub fn poll(&mut self) -> Option<(Vec<u8>, DeliveryInfo)> {
        if let Some(fetched) = self.fetched.pop_front() {
            return Some(fetched);
        }
        loop {
            let next = self.cursor;
            match self.shared.borrow().read(next) {
                None => return None,
                Some(ae) => {
                    self.cursor = next + 1;
                    if self.subscriptions.contains(ae.delivery_address.as_str())
                        && self.is_inbound(ae)
                    {
                        return Some((ae.data.clone(), Self::info_for(next)));
                    }
                }
            }
        }
    }

    /// From the call on, `publish` returns no id, as a delivery node that learns it from a later
    /// event does; [`Self::poll_report`] hands out a tagged envelope's id instead.
    pub fn report_ids_late(&mut self) {
        self.reports.get_or_insert_default();
    }

    /// The next id learned after `publish` returned, with the tag of the envelope it names.
    pub fn poll_report(&mut self) -> Option<(DeliveryTag, DeliveryInfo)> {
        self.reports.as_mut()?.pop_front()
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

    /// A message's delivery message id is the cursor that reads it.
    fn id_for(cursor: usize) -> DeliveryMsgId {
        DeliveryMsgId::from((cursor as u64).to_be_bytes().to_vec())
    }

    fn info_for(cursor: usize) -> DeliveryInfo {
        DeliveryInfo {
            delivery_msg_id: Self::id_for(cursor),
        }
    }

    fn cursor_from(id: &DeliveryMsgId) -> Option<usize> {
        let bytes = <[u8; 8]>::try_from(id.as_bytes()).ok()?;
        Some(u64::from_be_bytes(bytes) as usize)
    }
}

impl Default for LocalBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

impl DeliveryService for LocalBroadcaster {
    type Error = String;

    fn publish(
        &mut self,
        envelope: AddressedEnvelope,
    ) -> Result<Option<DeliveryMsgId>, Self::Error> {
        info!(?envelope.delivery_address, len=envelope.data.len(), "DS:Publish");
        self.outbound_msgs.push(Self::msg_id(&envelope));
        let tag = envelope.tag.clone();
        let mut shared = self.shared.borrow_mut();
        let cursor = shared.tail();
        shared.messages.push_back(envelope);

        let Some(reports) = &mut self.reports else {
            return Ok(Some(Self::id_for(cursor)));
        };
        if let Some(tag) = tag {
            reports.push_back((tag, Self::info_for(cursor)));
        }
        Ok(None)
    }

    fn subscribe(&mut self, delivery_address: &str) -> Result<(), Self::Error> {
        info!(delivery_address, "DS:Subscribe");
        // Strict temporal ordering of subscriptions is not enforced.
        // Subscriptions are evaluated on polling, not when the message is published
        self.subscriptions.insert(delivery_address.to_string());
        Ok(())
    }

    fn fetch_messages(
        &mut self,
        delivery_address: &str,
        delivery_msg_ids: &[DeliveryMsgId],
    ) -> Result<(), Self::Error> {
        info!(
            delivery_address,
            count = delivery_msg_ids.len(),
            "DS:FetchMessages"
        );
        let shared = self.shared.borrow();
        for id in delivery_msg_ids {
            // An id naming nothing on the address finds nothing.
            if let Some(cursor) = Self::cursor_from(id)
                && let Some(ae) = shared
                    .read(cursor)
                    .filter(|ae| ae.delivery_address == delivery_address)
            {
                self.fetched
                    .push_back((ae.data.clone(), Self::info_for(cursor)));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(delivery_address: &str, data: &[u8]) -> AddressedEnvelope {
        AddressedEnvelope {
            delivery_address: delivery_address.into(),
            data: data.to_vec(),
            tag: None,
        }
    }

    #[test]
    fn fetch_delivers_what_the_ids_name_on_the_address() {
        let mut saro = LocalBroadcaster::new();
        let mut raya = saro.new_consumer();
        raya.subscribe("group").unwrap();
        let m1 = saro
            .publish(envelope("group", b"m1"))
            .unwrap()
            .expect("delivery message id");
        let x1 = saro
            .publish(envelope("elsewhere", b"x1"))
            .unwrap()
            .expect("delivery message id");
        // Raya was there: m1 reaches it live, with the id its publish returned.
        assert_eq!(raya.poll().unwrap().1.delivery_msg_id, m1);

        // Pax arrives after both went out, so neither reaches it live; x1 is on another address.
        let mut pax = saro.new_consumer();
        pax.subscribe("group").unwrap();
        pax.fetch_messages("group", &[m1.clone(), x1]).unwrap();
        let (data, info) = pax.poll().expect("m1");
        assert_eq!(data, b"m1");
        assert_eq!(info.delivery_msg_id, m1);
        assert!(pax.poll().is_none());
    }
}
