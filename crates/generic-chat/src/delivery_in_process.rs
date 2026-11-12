use crate::{
    AddressedEnvelope, DeliveryInfo, DeliveryMsgId, DeliveryService, InboundPayload, Transport,
};
use crossbeam_channel::{Receiver, Sender, unbounded};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

type Message = InboundPayload;

/// Shared in-process message bus. Cheap to clone — all clones share one routing
/// table. On `publish`, a message is fanned out to every endpoint subscribed to
/// its delivery address.
/// The bus keeps each message, for fetching by the id `publish` returns.
#[derive(Clone, Default, Debug)]
pub struct MessageBus {
    routes: Arc<Mutex<HashMap<String, Vec<Sender<Message>>>>>,
    published: Arc<Mutex<Vec<AddressedEnvelope>>>,
}

impl MessageBus {
    fn register(&self, address: &str, sender: Sender<Message>) {
        let mut routes = self.routes.lock().unwrap();
        let senders = routes.entry(address.to_string()).or_default();
        // Idempotent per endpoint: the core re-subscribes an address whenever it
        // rebuilds a conversation, so skip senders already registered for it —
        // otherwise each payload reaches that endpoint more than once.
        if senders.iter().any(|s| s.same_channel(&sender)) {
            return;
        }
        senders.push(sender);
    }

    /// A message's delivery message id is its index among all the bus carried.
    fn publish(&self, address: &str, data: Vec<u8>) -> DeliveryMsgId {
        let mut published = self.published.lock().unwrap();
        let id = DeliveryMsgId::from((published.len() as u64).to_be_bytes().to_vec());
        published.push(AddressedEnvelope {
            delivery_address: address.to_string(),
            data: data.clone(),
        });
        let message = Message {
            data,
            delivery_info: Some(DeliveryInfo {
                delivery_msg_id: id.clone(),
            }),
        };
        if let Some(senders) = self.routes.lock().unwrap().get_mut(address) {
            // Prune endpoints whose receiver was dropped: a disconnected endpoint
            // is harmless, but keeping its sender would leak it in `routes`.
            senders.retain(|tx| tx.send(message.clone()).is_ok());
        }
        id
    }

    fn fetch(&self, address: &str, delivery_msg_ids: &[DeliveryMsgId], sender: &Sender<Message>) {
        let published = self.published.lock().unwrap();
        for id in delivery_msg_ids {
            // An id naming nothing on the address finds nothing.
            let Some(envelope) = <[u8; 8]>::try_from(id.as_bytes())
                .ok()
                .and_then(|index| published.get(u64::from_be_bytes(index) as usize))
                .filter(|envelope| envelope.delivery_address == address)
            else {
                continue;
            };
            let message = Message {
                data: envelope.data.clone(),
                delivery_info: Some(DeliveryInfo {
                    delivery_msg_id: id.clone(),
                }),
            };
            if sender.send(message).is_err() {
                break;
            }
        }
    }
}

/// One client's endpoint onto a shared [`MessageBus`].
///
/// `publish` fans the message out through the bus; `subscribe` registers this
/// endpoint's inbound sender for an address, so subsequent publishes to it are
/// delivered. The client obtains the inbound stream via [`Transport::inbound`].
/// `fetch_messages` delivers again, on that stream, the messages its ids name.
#[derive(Debug)]
pub struct InProcessDelivery {
    bus: MessageBus,
    inbound_tx: Sender<Message>,
    inbound_rx: Option<Receiver<Message>>,
}

impl InProcessDelivery {
    /// Create an endpoint on `bus`.
    pub fn new(bus: MessageBus) -> Self {
        let (tx, rx) = unbounded();
        Self {
            bus,
            inbound_tx: tx,
            inbound_rx: Some(rx),
        }
    }
}

impl DeliveryService for InProcessDelivery {
    type Error = Infallible;

    fn publish(
        &mut self,
        envelope: AddressedEnvelope,
    ) -> Result<Option<DeliveryMsgId>, Infallible> {
        let id = self.bus.publish(&envelope.delivery_address, envelope.data);
        Ok(Some(id))
    }

    fn subscribe(&mut self, delivery_address: &str) -> Result<(), Self::Error> {
        self.bus.register(delivery_address, self.inbound_tx.clone());
        Ok(())
    }

    fn fetch_messages(
        &mut self,
        delivery_address: &str,
        delivery_msg_ids: &[DeliveryMsgId],
    ) -> Result<(), Self::Error> {
        self.bus
            .fetch(delivery_address, delivery_msg_ids, &self.inbound_tx);
        Ok(())
    }
}

impl Transport for InProcessDelivery {
    fn inbound(&mut self) -> Receiver<InboundPayload> {
        self.inbound_rx
            .take()
            .expect("InProcessDelivery::inbound called more than once")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(delivery_address: &str, data: &[u8]) -> AddressedEnvelope {
        AddressedEnvelope {
            delivery_address: delivery_address.into(),
            data: data.to_vec(),
        }
    }

    #[test]
    fn fetch_delivers_what_the_ids_name_on_the_address() {
        let bus = MessageBus::default();
        let mut saro = InProcessDelivery::new(bus.clone());
        let mut raya = InProcessDelivery::new(bus.clone());
        let raya_inbound = raya.inbound();
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
        let live = raya_inbound.try_recv().expect("m1");
        assert_eq!(
            live.delivery_info.map(|info| info.delivery_msg_id),
            Some(m1.clone())
        );

        // Pax arrives after both went out, so neither reaches it live; x1 is on another address.
        let mut pax = InProcessDelivery::new(bus);
        let pax_inbound = pax.inbound();
        pax.subscribe("group").unwrap();
        pax.fetch_messages("group", &[m1.clone(), x1]).unwrap();
        let fetched = pax_inbound.try_recv().expect("m1");
        assert_eq!(fetched.data, b"m1");
        assert_eq!(
            fetched.delivery_info.map(|info| info.delivery_msg_id),
            Some(m1)
        );
        assert!(pax_inbound.try_recv().is_err());
    }
}
