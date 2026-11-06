//! A time source: the system clock, or a clock moved by hand.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The system clock, or a [`MockClock`].
#[derive(Debug, Clone, Default)]
pub enum Clock {
    #[default]
    System,
    Mock(MockClock),
}

impl Clock {
    /// The time since the Unix epoch.
    pub fn now(&self) -> Duration {
        match self {
            Clock::System => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default(),
            Clock::Mock(clock) => clock.now(),
        }
    }
}

/// A clock moved by hand. Clones share one time.
#[derive(Debug, Clone, Default)]
pub struct MockClock {
    now_nanos: Arc<AtomicU64>,
}

impl MockClock {
    /// A clock at the Unix epoch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Moves time forward by `d`, saturating.
    pub fn advance(&self, d: Duration) {
        let nanos = d.as_nanos().min(u64::MAX as u128) as u64;
        self.now_nanos
            .update(Ordering::Relaxed, Ordering::Relaxed, |now| {
                now.saturating_add(nanos)
            });
    }

    /// The time since the Unix epoch.
    pub fn now(&self) -> Duration {
        Duration::from_nanos(self.now_nanos.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_clock_clones_share_time() {
        let clock = MockClock::new();
        let reader = Clock::Mock(clock.clone());
        clock.advance(Duration::from_secs(61));
        assert_eq!(reader.now(), Duration::from_secs(61));
    }
}
