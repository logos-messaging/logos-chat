use libchat::{ConversationId, MockClock, WakeupService};
use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fmt::Debug;
use std::rc::Rc;
use std::time::Duration;
use tracing::{info, trace};

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct WakeupRecord {
    pub expiry: Duration,
    pub client_index: usize,
    pub convo_id: String,
}

pub struct TestWakeupProvider {
    service: Rc<RefCell<InnerWakeupService>>,
    client_index: usize,
}

impl Debug for TestWakeupProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestWakeupProvider")
            .field("client_index", &self.client_index)
            .finish()
    }
}

impl TestWakeupProvider {
    pub fn new(service: Rc<RefCell<InnerWakeupService>>, id: usize) -> Self {
        Self {
            service,
            client_index: id,
        }
    }
}

impl WakeupService for TestWakeupProvider {
    fn wakeup_in(&mut self, duration: Duration, convo_id: ConversationId) {
        info!(?duration, convo_id, "Wakeup In");
        self.service
            .borrow_mut()
            .register_wakeup(duration, self.client_index, convo_id);
    }
}

pub struct InnerWakeupService {
    now: Duration,
    pending: BinaryHeap<Reverse<WakeupRecord>>,
}

impl InnerWakeupService {
    pub fn new() -> Self {
        Self {
            now: Duration::new(0, 0),
            pending: BinaryHeap::new(),
        }
    }

    pub fn register_wakeup(&mut self, wake_in: Duration, client_index: usize, convo_id: String) {
        info!(%client_index, ?wake_in, "ask for wake up");
        self.pending.push(Reverse(WakeupRecord {
            expiry: self.now + wake_in,
            client_index,
            convo_id,
        }));
    }

    fn get_expired(&mut self) -> Vec<WakeupRecord> {
        trace!("Get Expired");
        let mut fired = vec![];

        while self
            .pending
            .peek()
            .is_some_and(|Reverse(w)| w.expiry <= self.now)
        {
            let Reverse(w) = self.pending.pop().unwrap();
            info!(now = self.now.as_secs(), w.convo_id, "Popping");
            fired.push(w);
        }

        fired
    }
}

pub struct TestWakeupService {
    inner: Rc<RefCell<InnerWakeupService>>,
    clock: MockClock,
}

impl Debug for TestWakeupService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let srv = self.inner.borrow_mut();

        f.debug_struct("TestWakeupService")
            .field("heap", &srv.pending)
            .finish()
    }
}

impl TestWakeupService {
    pub fn new() -> Self {
        Self {
            inner: Rc::new(RefCell::new(InnerWakeupService::new())),
            clock: MockClock::new(),
        }
    }

    pub fn clock(&self) -> MockClock {
        self.clock.clone()
    }

    pub fn new_provider(&self, id: usize) -> TestWakeupProvider {
        TestWakeupProvider {
            service: self.inner.clone(),
            client_index: id,
        }
    }

    // Returns the ConvoIDs that triggered in order
    pub fn advance_time(&mut self, duration: Duration) -> Vec<WakeupRecord> {
        let mut srv = self.inner.borrow_mut();
        trace!(?duration, "Advanced");
        self.clock.advance(duration);
        srv.now = srv.now.checked_add(duration).unwrap();
        srv.get_expired()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wakeup_service() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let mut ws = TestWakeupService::new();

        let mut p1 = ws.new_provider(1);
        let mut p2 = ws.new_provider(2);

        p1.wakeup_in(Duration::from_secs(2), "convo1".into());
        p1.wakeup_in(Duration::from_secs(4), "convo1".into());

        p2.wakeup_in(Duration::from_secs(5), "convo1".into());
        p2.wakeup_in(Duration::from_secs(4), "convo1".into());

        {
            let batch = ws.advance_time(Duration::from_secs(2));
            assert_eq!(batch.len(), 1, "too many records");
            assert_eq!(batch[0].client_index, 1, "client mismatch");
        }

        {
            let batch = ws.advance_time(Duration::from_secs(2));
            assert_eq!(batch.len(), 2, "too many records");
            assert_eq!(
                batch[0].client_index, 1,
                "client 1 shoudld be first, as it was entered first"
            );
            assert_eq!(batch[1].client_index, 2, "client 2 should be second");
        }

        {
            let batch = ws.advance_time(Duration::from_secs(1));
            assert_eq!(batch.len(), 1, "too many records");
            assert_eq!(batch[0].client_index, 2, "client mismatch");
        }

        {
            let batch = ws.advance_time(Duration::from_secs(1));
            assert_eq!(batch.len(), 0, "records should be completely drained");
        }
    }
}

/// A wakeup service that never fires, for a core whose test drives no timers.
#[derive(Debug)]
pub struct NoopWakeupService;

impl WakeupService for NoopWakeupService {
    fn wakeup_in(&mut self, _: Duration, _: ConversationId) {}
}
