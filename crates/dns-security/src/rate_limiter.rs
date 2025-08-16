//! Atomic token bucket rate limiting per client IP
//! 
//! Implements high-performance rate limiting using atomic operations and lock-free data structures.
//! Each client IP gets its own token bucket that refills at a configurable rate.

use crate::{SecurityError, SecurityResult, current_timestamp_ms, hash_ip_address};
use lockfree::map::Map as LockFreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use serde::{Deserialize, Serialize};

/// Configuration for rate limiting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum tokens per bucket (burst capacity)
    pub max_tokens: u32,
    /// Tokens added per second (sustained rate)
    pub refill_rate: u32,
    /// Global rate limit (queries per second across all clients)
    pub global_rate_limit: Option<u32>,
    /// Cleanup interval for unused buckets (seconds)
    pub cleanup_interval: u64,
    /// Maximum number of client buckets to track
    pub max_clients: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_tokens: 100,        // 100 query burst
            refill_rate: 10,        // 10 queries per second sustained
            global_rate_limit: Some(10000), // 10k queries/sec global limit
            cleanup_interval: 300,  // Clean up every 5 minutes
            max_clients: 100000,    // Track up to 100k clients
        }
    }
}

/// Atomic token bucket for individual client rate limiting
pub struct AtomicTokenBucket {
    /// Current number of tokens (atomic)
    tokens: AtomicU32,
    /// Last refill timestamp in milliseconds (atomic)
    last_refill: AtomicU64,
    /// Maximum tokens this bucket can hold
    max_tokens: u32,
    /// Tokens added per second
    refill_rate: u32,
    /// Last access timestamp for cleanup (atomic)
    last_access: AtomicU64,
    /// Whether this bucket is marked for deletion (atomic)
    marked_for_deletion: AtomicBool,
}

impl AtomicTokenBucket {
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        let now = current_timestamp_ms();
        Self {
            tokens: AtomicU32::new(max_tokens),
            last_refill: AtomicU64::new(now),
            max_tokens,
            refill_rate,
            last_access: AtomicU64::new(now),
            marked_for_deletion: AtomicBool::new(false),
        }
    }

    /// Check if tokens are available and consume them atomically
    pub fn check_and_consume(&self, tokens_needed: u32) -> bool {
        let now = current_timestamp_ms();
        
        // Update last access time
        self.last_access.store(now, Ordering::Relaxed);
        
        // Refill tokens if needed
        self.refill_tokens(now);
        
        // Try to consume tokens atomically
        loop {
            let current_tokens = self.tokens.load(Ordering::Acquire);
            
            if current_tokens < tokens_needed {
                return false; // Not enough tokens
            }
            
            // Try to atomically subtract tokens
            match self.tokens.compare_exchange_weak(
                current_tokens,
                current_tokens - tokens_needed,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,  // Successfully consumed tokens
                Err(_) => continue,    // Retry due to concurrent modification
            }
        }
    }

    /// Refill tokens based on elapsed time
    fn refill_tokens(&self, now: u64) {
        let last_refill = self.last_refill.load(Ordering::Acquire);
        
        if now <= last_refill {
            return; // No time has passed or clock went backwards
        }
        
        let time_passed_ms = now - last_refill;
        let tokens_to_add = (time_passed_ms * self.refill_rate as u64) / 1000;
        
        if tokens_to_add == 0 {
            return; // Less than 1 second passed
        }
        
        // Try to update refill time and add tokens atomically
        if self.last_refill.compare_exchange_weak(
            last_refill,
            now,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ).is_ok() {
            // Successfully updated refill time, now add tokens
            loop {
                let current_tokens = self.tokens.load(Ordering::Acquire);
                let new_tokens = (current_tokens + tokens_to_add as u32).min(self.max_tokens);
                
                if self.tokens.compare_exchange_weak(
                    current_tokens,
                    new_tokens,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ).is_ok() {
                    break; // Successfully added tokens
                }
            }
        }
    }

    /// Get current token count (for monitoring)
    pub fn current_tokens(&self) -> u32 {
        self.tokens.load(Ordering::Relaxed)
    }

    /// Get last access time (for cleanup)
    pub fn last_access_time(&self) -> u64 {
        self.last_access.load(Ordering::Relaxed)
    }

    /// Mark bucket for deletion
    pub fn mark_for_deletion(&self) {
        self.marked_for_deletion.store(true, Ordering::Relaxed);
    }

    /// Check if bucket is marked for deletion
    pub fn is_marked_for_deletion(&self) -> bool {
        self.marked_for_deletion.load(Ordering::Relaxed)
    }
}

/// High-performance atomic rate limiter
pub struct AtomicRateLimiter {
    /// Per-client token buckets (lock-free map)
    client_buckets: Arc<LockFreeMap<u64, Arc<AtomicTokenBucket>>>,
    /// Global rate limiting bucket
    global_bucket: Option<Arc<AtomicTokenBucket>>,
    /// Configuration
    config: RateLimitConfig,
    /// Statistics
    stats: Arc<RateLimitStats>,
    /// Last cleanup timestamp
    last_cleanup: AtomicU64,
}

impl AtomicRateLimiter {
    pub fn new(config: RateLimitConfig) -> SecurityResult<Self> {
        let global_bucket = config.global_rate_limit.map(|rate| {
            Arc::new(AtomicTokenBucket::new(rate * 2, rate)) // 2 second burst capacity
        });

        Ok(Self {
            client_buckets: Arc::new(LockFreeMap::new()),
            global_bucket,
            config,
            stats: Arc::new(RateLimitStats::new()),
            last_cleanup: AtomicU64::new(current_timestamp_ms()),
        })
    }

    /// Check rate limit for a client IP
    pub async fn check_rate_limit(&self, client_ip: IpAddr) -> SecurityResult<bool> {
        // Check global rate limit first
        if let Some(global_bucket) = &self.global_bucket {
            if !global_bucket.check_and_consume(1) {
                self.stats.global_rate_limit_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(false);
            }
        }

        // Get or create client bucket
        let client_hash = hash_ip_address(client_ip);
        let bucket = self.get_or_create_bucket(client_hash).await?;

        // Check client-specific rate limit
        if bucket.check_and_consume(1) {
            self.stats.allowed_requests.fetch_add(1, Ordering::Relaxed);
            Ok(true)
        } else {
            self.stats.client_rate_limit_hits.fetch_add(1, Ordering::Relaxed);
            Ok(false)
        }
    }

    /// Get existing bucket or create new one
    async fn get_or_create_bucket(&self, client_hash: u64) -> SecurityResult<Arc<AtomicTokenBucket>> {
        // Try to get existing bucket
        if let Some(bucket) = self.client_buckets.get(&client_hash) {
            return Ok(bucket.val().clone());
        }

        // Create new bucket
        let bucket = Arc::new(AtomicTokenBucket::new(
            self.config.max_tokens,
            self.config.refill_rate,
        ));

        // Insert into map (may race with other threads)
        if let Some(_) = self.client_buckets.insert(client_hash, bucket.clone()) {
            // Key already existed, use the existing one
            Ok(self.client_buckets.get(&client_hash)
                .ok_or_else(|| SecurityError::internal_error("Bucket disappeared after insert"))?
                .val().clone())
        } else {
            // Successfully inserted new bucket
            self.stats.active_clients.fetch_add(1, Ordering::Relaxed);
            Ok(bucket)
        }
    }

    /// Clean up old unused buckets
    async fn cleanup_old_buckets(&self) -> SecurityResult<()> {
        let now = current_timestamp_ms();
        let last_cleanup = self.last_cleanup.load(Ordering::Relaxed);
        
        // Only cleanup if enough time has passed
        if now - last_cleanup < self.config.cleanup_interval * 1000 {
            return Ok(());
        }

        // Try to update cleanup timestamp
        if self.last_cleanup.compare_exchange_weak(
            last_cleanup,
            now,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ).is_err() {
            return Ok(()); // Another thread is doing cleanup
        }

        let cleanup_threshold = now - (self.config.cleanup_interval * 1000);
        let mut removed_count = 0;
        let mut keys_to_remove = Vec::new();

        // Iterate through buckets and collect old ones for removal
        for entry in self.client_buckets.iter() {
            let bucket = entry.val();
            if bucket.last_access_time() < cleanup_threshold {
                keys_to_remove.push(*entry.key());
            }
        }

        // Remove old buckets
        for key in keys_to_remove {
            if self.client_buckets.remove(&key).is_some() {
                removed_count += 1;
            }
        }

        if removed_count > 0 {
            self.stats.active_clients.fetch_sub(removed_count, Ordering::Relaxed);
        }
        self.stats.cleanup_operations.fetch_add(1, Ordering::Relaxed);

        tracing::debug!("Rate limiter cleanup removed {} old buckets", removed_count);
        Ok(())
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> SecurityResult<RateLimitStats> {
        Ok(self.stats.snapshot())
    }

    /// Reset statistics
    pub async fn reset_stats(&self) -> SecurityResult<()> {
        self.stats.reset();
        Ok(())
    }
}

/// Rate limiting statistics
#[derive(Debug)]
pub struct RateLimitStats {
    /// Total allowed requests
    pub allowed_requests: AtomicU64,
    /// Client rate limit hits
    pub client_rate_limit_hits: AtomicU64,
    /// Global rate limit hits
    pub global_rate_limit_hits: AtomicU64,
    /// Number of active client buckets
    pub active_clients: AtomicU64,
    /// Number of cleanup operations performed
    pub cleanup_operations: AtomicU64,
    /// Statistics creation timestamp
    pub created_at: AtomicU64,
}

impl RateLimitStats {
    pub fn new() -> Self {
        Self {
            allowed_requests: AtomicU64::new(0),
            client_rate_limit_hits: AtomicU64::new(0),
            global_rate_limit_hits: AtomicU64::new(0),
            active_clients: AtomicU64::new(0),
            cleanup_operations: AtomicU64::new(0),
            created_at: AtomicU64::new(current_timestamp_ms()),
        }
    }

    pub fn snapshot(&self) -> Self {
        Self {
            allowed_requests: AtomicU64::new(self.allowed_requests.load(Ordering::Relaxed)),
            client_rate_limit_hits: AtomicU64::new(self.client_rate_limit_hits.load(Ordering::Relaxed)),
            global_rate_limit_hits: AtomicU64::new(self.global_rate_limit_hits.load(Ordering::Relaxed)),
            active_clients: AtomicU64::new(self.active_clients.load(Ordering::Relaxed)),
            cleanup_operations: AtomicU64::new(self.cleanup_operations.load(Ordering::Relaxed)),
            created_at: AtomicU64::new(self.created_at.load(Ordering::Relaxed)),
        }
    }

    pub fn reset(&self) {
        self.allowed_requests.store(0, Ordering::Relaxed);
        self.client_rate_limit_hits.store(0, Ordering::Relaxed);
        self.global_rate_limit_hits.store(0, Ordering::Relaxed);
        // Don't reset active_clients and cleanup_operations as they represent current state
    }

    /// Calculate rate limit hit ratio
    pub fn hit_ratio(&self) -> f64 {
        let total_hits = self.client_rate_limit_hits.load(Ordering::Relaxed) +
                        self.global_rate_limit_hits.load(Ordering::Relaxed);
        let total_requests = self.allowed_requests.load(Ordering::Relaxed) + total_hits;
        
        if total_requests == 0 {
            0.0
        } else {
            total_hits as f64 / total_requests as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_token_bucket_basic() {
        let bucket = AtomicTokenBucket::new(10, 5);
        
        // Should allow initial burst
        assert!(bucket.check_and_consume(5));
        assert!(bucket.check_and_consume(5));
        
        // Should be empty now
        assert!(!bucket.check_and_consume(1));
    }

    #[tokio::test]
    async fn test_token_bucket_refill() {
        let bucket = AtomicTokenBucket::new(10, 10); // 10 tokens/sec
        
        // Consume all tokens
        assert!(bucket.check_and_consume(10));
        assert!(!bucket.check_and_consume(1));
        
        // Wait for refill (need to simulate time passing)
        sleep(Duration::from_millis(1100)).await;
        
        // Should have refilled
        assert!(bucket.check_and_consume(1));
    }

    #[tokio::test]
    async fn test_rate_limiter_per_client() {
        let config = RateLimitConfig {
            max_tokens: 5,
            refill_rate: 1,
            global_rate_limit: None,
            cleanup_interval: 60,
            max_clients: 1000,
        };
        
        let limiter = AtomicRateLimiter::new(config).unwrap();
        let client1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let client2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        
        // Each client should have independent limits
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(client1).await.unwrap());
            assert!(limiter.check_rate_limit(client2).await.unwrap());
        }
        
        // Both should be rate limited now
        assert!(!limiter.check_rate_limit(client1).await.unwrap());
        assert!(!limiter.check_rate_limit(client2).await.unwrap());
    }

    #[tokio::test]
    async fn test_global_rate_limit() {
        let config = RateLimitConfig {
            max_tokens: 100,
            refill_rate: 10,
            global_rate_limit: Some(5), // Very low global limit
            cleanup_interval: 60,
            max_clients: 1000,
        };
        
        let limiter = AtomicRateLimiter::new(config).unwrap();
        let client = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Should hit global limit before client limit
        let mut allowed = 0;
        for _ in 0..20 {
            if limiter.check_rate_limit(client).await.unwrap() {
                allowed += 1;
            }
        }
        
        // Should be limited by global rate (5*2 = 10 burst capacity)
        assert!(allowed <= 10);
    }
}