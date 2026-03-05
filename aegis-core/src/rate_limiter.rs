use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::config::RateLimitConfig;
use crate::error::AegisError;

/// Fixed-window rate limiter backed by a concurrent hash map.
pub struct RateLimiter {
    max_requests: u64,
    window: Duration,
    counters: DashMap<String, (u64, Instant)>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            max_requests: config.max_requests,
            window: Duration::from_secs(config.window_secs),
            counters: DashMap::new(),
        }
    }

    /// Check whether `key` (typically a client IP) is within the allowed rate.
    pub fn check(&self, key: &str) -> Result<(), AegisError> {
        let now = Instant::now();
        let mut entry = self.counters.entry(key.to_string()).or_insert((0, now));
        let (count, window_start) = entry.value_mut();

        if now.duration_since(*window_start) >= self.window {
            *count = 1;
            *window_start = now;
            return Ok(());
        }

        *count += 1;
        if *count > self.max_requests {
            return Err(AegisError::RateLimited);
        }

        Ok(())
    }
}
