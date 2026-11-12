//! Token-bucket bandwidth limiter for background shard egress and repair traffic.

/// Deterministic token-bucket bandwidth rate limiter for background shard egress and repair traffic.
#[derive(Debug, Clone)]
pub struct TokenBucketRateLimiter {
    capacity_bytes: u64,
    tokens_bytes: f64,
    refill_bytes_per_sec: f64,
    last_refill_ms: u64,
}

impl TokenBucketRateLimiter {
    pub fn new(rate_bytes_per_sec: u64, burst_bytes: u64, now_ms: u64) -> Self {
        let capacity_bytes = if burst_bytes > 0 {
            burst_bytes
        } else {
            rate_bytes_per_sec.max(1)
        };
        Self {
            capacity_bytes,
            tokens_bytes: capacity_bytes as f64,
            refill_bytes_per_sec: (rate_bytes_per_sec.max(1)) as f64,
            last_refill_ms: now_ms,
        }
    }

    pub fn refill(&mut self, now_ms: u64) {
        if now_ms > self.last_refill_ms {
            let elapsed_sec = (now_ms - self.last_refill_ms) as f64 / 1000.0;
            self.tokens_bytes = (self.tokens_bytes + elapsed_sec * self.refill_bytes_per_sec)
                .min(self.capacity_bytes as f64);
            self.last_refill_ms = now_ms;
        }
    }

    pub fn try_consume(&mut self, bytes: u64, now_ms: u64) -> bool {
        self.refill(now_ms);
        let needed = bytes as f64;
        if self.tokens_bytes >= needed {
            self.tokens_bytes -= needed;
            true
        } else {
            false
        }
    }

    pub fn available_tokens(&mut self, now_ms: u64) -> u64 {
        self.refill(now_ms);
        self.tokens_bytes.max(0.0) as u64
    }

    pub fn wait_time_ms(&mut self, bytes: u64, now_ms: u64) -> u64 {
        self.refill(now_ms);
        let needed = bytes as f64;
        if self.tokens_bytes >= needed {
            return 0;
        }
        let deficit = needed - self.tokens_bytes;
        ((deficit / self.refill_bytes_per_sec) * 1000.0).ceil() as u64
    }
}
