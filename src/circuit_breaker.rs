//! Thread-safe, opt-in upstream circuit breaker.
//!
//! This module is intentionally not wired to the proxy until per-upstream routing,
//! status accounting, and probe ownership are configured. The implementation itself
//! is compile/test ready and grants at most one half-open probe at a time.

#![allow(dead_code)]

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::{interval, MissedTickBehavior};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug)]
struct Inner {
    state: CircuitState,
    failures: u32,
    successes: u32,
    last_failure: Instant,
    half_open_probe_in_flight: bool,
}

pub struct CircuitBreaker {
    inner: Mutex<Inner>,
    failure_threshold: u32,
    success_threshold: u32,
    timeout: Duration,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, success_threshold: u32, timeout: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner {
                state: CircuitState::Closed,
                failures: 0,
                successes: 0,
                last_failure: Instant::now(),
                half_open_probe_in_flight: false,
            }),
            failure_threshold: failure_threshold.max(1),
            success_threshold: success_threshold.max(1),
            timeout,
        }
    }

    pub fn state(&self) -> CircuitState {
        self.inner
            .lock()
            .map(|inner| inner.state)
            .unwrap_or(CircuitState::Open)
    }

    pub fn record_success(&self) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        match inner.state {
            CircuitState::Closed => {
                inner.failures = 0;
            }
            CircuitState::Open => {
                // Ignore stale successes from requests that began before the trip.
            }
            CircuitState::HalfOpen => {
                inner.half_open_probe_in_flight = false;
                inner.successes = inner.successes.saturating_add(1);
                if inner.successes >= self.success_threshold {
                    inner.state = CircuitState::Closed;
                    inner.failures = 0;
                    inner.successes = 0;
                }
            }
        }
    }

    pub fn record_failure(&self) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        inner.failures = inner.failures.saturating_add(1);
        inner.last_failure = Instant::now();
        inner.successes = 0;
        inner.half_open_probe_in_flight = false;
        if inner.state == CircuitState::HalfOpen || inner.failures >= self.failure_threshold {
            inner.state = CircuitState::Open;
        }
    }

    /// Decide whether to let a request through. A single caller receives the
    /// half-open probe permit after the recovery timeout; concurrent callers wait.
    pub fn check_access(&self) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        match inner.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if inner.last_failure.elapsed() < self.timeout {
                    return false;
                }
                inner.state = CircuitState::HalfOpen;
                inner.successes = 0;
                inner.half_open_probe_in_flight = true;
                true
            }
            CircuitState::HalfOpen => {
                if inner.half_open_probe_in_flight {
                    false
                } else {
                    inner.half_open_probe_in_flight = true;
                    true
                }
            }
        }
    }
}

/// Optional background health probe. The caller is responsible for attaching
/// this worker to a specific upstream and for calling it from a live Tokio runtime.
pub async fn health_probe_worker<F, Fut>(
    name: String,
    check: F,
    breaker: Arc<CircuitBreaker>,
    probe_interval: Duration,
) where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let mut ticker = interval(probe_interval.max(Duration::from_millis(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match check().await {
            Ok(()) => breaker.record_success(),
            Err(error) => {
                eprintln!("upstream health probe failed for {name}: {error}");
                breaker.record_failure();
            }
        }
    }
}

pub fn record_from_status(
    record_success: fn(),
    record_failure: fn(),
    success_status_codes: &[u16],
) -> impl FnOnce(u16) {
    // Own the status codes so the returned closure does not borrow the caller.
    let success_status_codes = success_status_codes.to_vec();
    move |status| {
        if success_status_codes.contains(&status) {
            record_success();
        } else {
            record_failure();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn closed_allows_access_until_threshold() {
        let breaker = CircuitBreaker::new(3, 2, Duration::from_secs(30));
        assert!(breaker.check_access());
        breaker.record_failure();
        breaker.record_failure();
        assert!(breaker.check_access());
        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitState::Open);
        assert!(!breaker.check_access());
    }

    #[test]
    fn only_one_half_open_probe_is_permitted() {
        let breaker = CircuitBreaker::new(1, 2, Duration::from_millis(1));
        breaker.record_failure();
        thread::sleep(Duration::from_millis(3));
        assert!(breaker.check_access());
        assert!(!breaker.check_access());
        breaker.record_success();
        assert!(breaker.check_access());
        breaker.record_success();
        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    #[test]
    fn failed_half_open_probe_reopens_the_circuit() {
        let breaker = CircuitBreaker::new(1, 1, Duration::from_millis(1));
        breaker.record_failure();
        thread::sleep(Duration::from_millis(3));
        assert!(breaker.check_access());
        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitState::Open);
        assert!(!breaker.check_access());
    }
}
