use std::collections::HashMap;

use crate::DeliveryService;
use crate::types::{AddressedEnvelope, DeliveryMsgId, PublishReceipt, PublishedId};

/// A Wrapper for a DeliveryService which keeps the delivery tracking state
///
/// A service that learns a payload's id only after `publish` returns names the payload by its own
/// receipt. This type keeps the message each receipt names, so implementations need not.
#[derive(Debug)]
pub struct TrackedDelivery<T: DeliveryService> {
    inner: T,
    pending: HashMap<PublishReceipt, TrackedMessage>,
}

/// The message a payload carries, kept until the service reports the payload's id.
#[derive(Debug)]
pub struct TrackedMessage {
    pub convo_id: String,
    pub message_id: String,
}

impl<T: DeliveryService> TrackedDelivery<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            pending: HashMap::new(),
        }
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Publishes `envelope`, which carries `message_id` in `convo_id`, and returns the payload's
    /// id if the service knows it. A receipt keeps the message for [`Self::take_tracked`].
    pub fn publish_tracked(
        &mut self,
        envelope: AddressedEnvelope,
        convo_id: &str,
        message_id: &str,
    ) -> Result<Option<DeliveryMsgId>, T::Error> {
        Ok(match self.inner.publish(envelope)? {
            PublishedId::Known(delivery_msg_id) => Some(delivery_msg_id),
            PublishedId::Pending(receipt) => {
                let message = TrackedMessage {
                    convo_id: convo_id.into(),
                    message_id: message_id.into(),
                };
                self.pending.insert(receipt, message);
                None
            }
            PublishedId::Unknown => None,
        })
    }

    /// The message published under `receipt`, for the service's first report under it only.
    pub fn take_tracked(&mut self, receipt: &PublishReceipt) -> Option<TrackedMessage> {
        self.pending.remove(receipt)
    }
}

impl<T: DeliveryService> DeliveryService for TrackedDelivery<T> {
    type Error = T::Error;

    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<PublishedId, Self::Error> {
        self.inner.publish(envelope)
    }

    fn subscribe(&mut self, delivery_address: &str) -> Result<(), Self::Error> {
        self.inner.subscribe(delivery_address)
    }

    fn fetch_messages(
        &mut self,
        delivery_address: &str,
        delivery_msg_ids: &[DeliveryMsgId],
    ) -> Result<(), Self::Error> {
        self.inner
            .fetch_messages(delivery_address, delivery_msg_ids)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;

    /// A service whose `publish` returns `next`.
    #[derive(Debug)]
    struct Returns {
        next: PublishedId,
    }

    impl DeliveryService for Returns {
        type Error = Infallible;

        fn publish(&mut self, _: AddressedEnvelope) -> Result<PublishedId, Infallible> {
            Ok(self.next.clone())
        }

        fn subscribe(&mut self, _: &str) -> Result<(), Infallible> {
            Ok(())
        }

        fn fetch_messages(&mut self, _: &str, _: &[DeliveryMsgId]) -> Result<(), Infallible> {
            Ok(())
        }
    }

    fn envelope() -> AddressedEnvelope {
        AddressedEnvelope {
            delivery_address: "group".into(),
            data: b"m1".to_vec(),
        }
    }

    #[test]
    fn a_receipt_names_its_message_for_one_report() {
        let receipt = PublishReceipt::from(b"r1".to_vec());
        let mut delivery = TrackedDelivery::new(Returns {
            next: PublishedId::Pending(receipt.clone()),
        });

        let id = delivery.publish_tracked(envelope(), "convo", "m1").unwrap();

        assert_eq!(id, None);
        let message = delivery
            .take_tracked(&receipt)
            .expect("m1 under its receipt");
        assert_eq!(
            (message.convo_id.as_str(), message.message_id.as_str()),
            ("convo", "m1")
        );
        assert!(
            delivery.take_tracked(&receipt).is_none(),
            "a repeated report"
        );
    }

    #[test]
    fn a_known_id_keeps_nothing() {
        let id = DeliveryMsgId::from(b"h1".to_vec());
        let mut delivery = TrackedDelivery::new(Returns {
            next: PublishedId::Known(id.clone()),
        });

        assert_eq!(
            delivery.publish_tracked(envelope(), "convo", "m1").unwrap(),
            Some(id)
        );
        assert!(delivery.pending.is_empty());
    }
}
