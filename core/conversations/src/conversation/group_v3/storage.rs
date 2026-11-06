use std::collections::HashSet;

use sds::{InMemoryStorage, LogEntry, Storage};

use crate::MessageId;

/// An SDS log that also counts the ids an invite carried as delivered, without logging them.
pub(super) struct SeededStorage {
    log: InMemoryStorage,
    seeded: HashSet<MessageId>,
}

impl SeededStorage {
    pub(super) fn new(seeded_ids: &[MessageId]) -> Self {
        Self {
            log: InMemoryStorage::default(),
            seeded: seeded_ids.iter().cloned().collect(),
        }
    }
}

impl Storage for SeededStorage {
    fn insert(&mut self, entry: LogEntry) {
        self.log.insert(entry);
    }

    fn contains(&self, message_id: &str) -> bool {
        self.seeded.contains(message_id) || self.log.contains(message_id)
    }

    fn get(&self, message_id: &str) -> Option<LogEntry> {
        self.log.get(message_id)
    }

    fn latest(&self, count: usize) -> Vec<LogEntry> {
        self.log.latest(count)
    }

    fn message_count(&self) -> usize {
        self.log.message_count()
    }

    fn remove_oldest(&mut self) -> Option<LogEntry> {
        self.log.remove_oldest()
    }
}
