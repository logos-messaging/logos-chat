use crate::service_traits::DeliveryService;
use crate::types::AddressedEnvelope;

/// A delivery service that holds every publish until it is flushed, so what an operation produces
/// for the wire can wait for the state behind it. Subscriptions pass straight through.
#[derive(Debug)]
pub(crate) struct StagedDelivery<DS> {
    inner: DS,
    staged: Vec<AddressedEnvelope>,
}

impl<DS: DeliveryService> StagedDelivery<DS> {
    pub(crate) fn new(inner: DS) -> Self {
        Self {
            inner,
            staged: Vec::new(),
        }
    }

    pub(crate) fn inner_mut(&mut self) -> &mut DS {
        &mut self.inner
    }

    /// Publishes what is held, in the order it was published.
    pub(crate) fn flush(&mut self) -> Result<(), DS::Error> {
        for envelope in self.staged.drain(..) {
            self.inner.publish(envelope)?;
        }
        Ok(())
    }

    /// Drops what is held, unsent.
    pub(crate) fn discard(&mut self) {
        self.staged.clear();
    }
}

impl<DS: DeliveryService> DeliveryService for StagedDelivery<DS> {
    type Error = DS::Error;

    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), Self::Error> {
        self.staged.push(envelope);
        Ok(())
    }

    fn subscribe(&mut self, delivery_address: &str) -> Result<(), Self::Error> {
        self.inner.subscribe(delivery_address)
    }
}
