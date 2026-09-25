//! Retries for the registry's HTTP API, which serves key packages and account
//! logs.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Retry budget for the registry's transient, load-induced 5xx/429 responses.
/// The service is reliable request-by-request but sheds concurrent bursts, so a
/// few backed-off retries let a request land once the burst clears. On that path
/// each retry returns fast, so the added cost is the ~3s worst-case backoff sum,
/// well inside chat_module's ~20s init IPC budget.
const MAX_RETRIES: u32 = 4;
const RETRY_BASE_MS: u64 = 200;
const RETRY_MAX_BACKOFF_MS: u64 = 2000;

/// Which failures [`send_retrying`] tries again.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Retry {
    /// 5xx and 429 responses only, so an unreachable registry costs one timeout.
    StatusOnly,
    /// Also network errors and timeouts. A fully unreachable registry then
    /// costs up to MAX_RETRIES times the reqwest timeout, which no retry
    /// budget can rescue.
    StatusAndNetwork,
}

/// Send a request built by `build`, retrying transient failures — 5xx/429
/// responses, and network errors as `retry` allows — with exponential backoff
/// and full jitter. The registry is reliable request-by-request but sheds
/// concurrent bursts with a 5xx, so a backed-off retry lands once the burst
/// clears; a 4xx (and any other final response) is returned to the caller
/// unchanged. `build` is re-invoked per attempt because sending consumes the
/// builder.
pub(crate) fn send_retrying(
    retry: Retry,
    build: impl Fn() -> reqwest::blocking::RequestBuilder,
) -> reqwest::Result<reqwest::blocking::Response> {
    let mut attempt = 0;
    loop {
        let outcome = build().send();
        let transient = match &outcome {
            Err(_) => matches!(retry, Retry::StatusAndNetwork), // network error / timeout
            Ok(resp) => is_transient_status(resp.status()),
        };
        if !transient || attempt >= MAX_RETRIES {
            return outcome;
        }
        std::thread::sleep(backoff_with_jitter(attempt));
        attempt += 1;
    }
}

/// Whether a response status is worth retrying: 5xx (the registry sheds
/// concurrent load with these) or 429 (explicit backpressure). A 4xx is the
/// caller's fault and won't change on retry.
fn is_transient_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS
}

/// Full-jitter exponential backoff: a random delay in
/// `[0, min(RETRY_MAX_BACKOFF_MS, RETRY_BASE_MS * 2^attempt)]`. The jitter
/// decorrelates concurrent publishers so their retries don't collide into the
/// same burst that failed them.
fn backoff_with_jitter(attempt: u32) -> Duration {
    let exp = RETRY_BASE_MS.saturating_mul(1u64 << attempt.min(16));
    Duration::from_millis(jitter_below(exp.min(RETRY_MAX_BACKOFF_MS)))
}

/// A value in `[0, max]`, seeded from the wall clock's sub-second nanos — enough
/// entropy to spread retries across processes without pulling in an RNG crate.
fn jitter_below(max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    nanos % (max + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only 5xx and 429 are retried; 2xx/4xx are returned to the caller as-is.
    #[test]
    fn only_5xx_and_429_are_transient() {
        use reqwest::StatusCode;
        for s in [500u16, 502, 503, 504, 429] {
            assert!(
                is_transient_status(StatusCode::from_u16(s).unwrap()),
                "{s} should be retried"
            );
        }
        for s in [200u16, 201, 400, 401, 404, 409] {
            assert!(
                !is_transient_status(StatusCode::from_u16(s).unwrap()),
                "{s} should not be retried"
            );
        }
    }

    /// Backoff never exceeds the exponential ceiling for its attempt, nor the
    /// absolute cap — and the exponent shift can't overflow at high attempts.
    #[test]
    fn backoff_stays_within_the_cap() {
        for attempt in 0..40u32 {
            let ceiling = RETRY_BASE_MS
                .saturating_mul(1u64 << attempt.min(16))
                .min(RETRY_MAX_BACKOFF_MS);
            let delay = backoff_with_jitter(attempt).as_millis() as u64;
            assert!(delay <= ceiling, "attempt {attempt}: {delay} > {ceiling}");
        }
    }

    #[test]
    fn jitter_is_bounded() {
        assert_eq!(jitter_below(0), 0);
        for _ in 0..200 {
            assert!(jitter_below(50) <= 50);
        }
    }
}
