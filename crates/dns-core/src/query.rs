//! Hash-Based Query Processing Engine
//!
//! This module implements ultra-fast DNS query processing using hash-only operations,
//! binary search algorithms, and atomic data structures for maximum performance.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use bytes::Bytes;
use lockfree::map::Map as LockFreeMap;

use crate::types::{DnsQuery, RecordType, DnsClass, ResponseCode};
use crate::hash::{hash_domain_name, hash_query, hash_client_ip};
use crate::atomic::{AtomicCache, AtomicCacheEntry};
use crate::error::{DnsError, DnsResult};

/// Atomic query structure optimized for hash-based processing
#[derive(Debug, Clone)]
pub struct AtomicQuery {
    pub id: u16,
    pub name_hash: u64,              // Pre-computed hash for fast lookup
    pub record_type: u16,
    pub class: u16,
    pub query_hash: u64,             // Pre-computed query hash for cache
    pub client_hash: u64,            // Pre-computed client hash for rate limiting
    pub timestamp: u64,              // Unix timestamp
    pub flags: u16,                  // DNS flags
    pub recursion_desired: bool,
    pub dnssec_ok: bool,
}

impl AtomicQuery {
    /// Create atomic query from DNS query
    pub fn from_dns_query(query: &DnsQuery) -> Self {
        let query_hash = hash_query(
            query.name_hash,
            query.record_type.to_u16(),
            query.class.to_u16(),
        );
        let client_hash = hash_client_ip(&query.client_addr);
        
        Self {
            id: query.id,
            name_hash: query.name_hash,
            record_type: query.record_type.to_u16(),
            class: query.class.to_u16(),
            query_hash,
            client_hash,
            timestamp: query.timestamp,
            flags: 0, // TODO: Extract from DNS query
            recursion_desired: query.recursion_desired,
            dnssec_ok: query.dnssec_ok,
        }
    }
}

/// Pre-computed response cache for common queries
pub struct PreComputedResponseCache {
    /// Cache entries indexed by query hash
    responses: Arc<LockFreeMap<u64, Arc<PreComputedResponse>>>,
    /// Cache statistics
    hits: AtomicU64,
    misses: AtomicU64,
    size_bytes: AtomicU64,
    entry_count: AtomicUsize,
}

/// Pre-computed DNS response with metadata
#[derive(Debug)]
pub struct PreComputedResponse {
    /// Raw DNS response packet (ready to send)
    pub data: Arc<[u8]>,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Original TTL for response ID updates
    pub original_ttl: u32,
    /// Response size in bytes
    pub size: usize,
    /// Hit count for statistics
    pub hit_count: AtomicU64,
    /// Last access timestamp
    pub last_accessed: AtomicU64,
}

impl PreComputedResponse {
    /// Create new pre-computed response
    pub fn new(data: Arc<[u8]>, ttl: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Self {
            size: data.len(),
            data,
            expires_at: now + ttl as u64,
            original_ttl: ttl,
            hit_count: AtomicU64::new(0),
            last_accessed: AtomicU64::new(now),
        }
    }
    
    /// Check if response is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expires_at
    }
    
    /// Get response data with updated ID (zero-copy operation)
    pub fn get_with_id(&self, query_id: u16) -> Option<Arc<[u8]>> {
        if self.is_expired() {
            return None;
        }
        
        // Record access
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.hit_count.fetch_add(1, Ordering::Relaxed);
        self.last_accessed.store(now, Ordering::Release);
        
        // Update response ID in-place (only modify 2 bytes)
        let mut response_data = (*self.data).to_vec();
        response_data[0] = (query_id >> 8) as u8;
        response_data[1] = (query_id & 0xFF) as u8;
        
        Some(Arc::from(response_data))
    }
}

impl PreComputedResponseCache {
    /// Create new pre-computed response cache
    pub fn new() -> Self {
        Self {
            responses: Arc::new(LockFreeMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            size_bytes: AtomicU64::new(0),
            entry_count: AtomicUsize::new(0),
        }
    }
    
    /// Get pre-computed response by query hash
    pub fn get(&self, query_hash: u64, query_id: u16) -> Option<Arc<[u8]>> {
        if let Some(response_guard) = self.responses.get(&query_hash) {
            if let Some(data) = response_guard.val().get_with_id(query_id) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(data);
            } else {
                // Response expired, remove it
                self.responses.remove(&query_hash);
                self.entry_count.fetch_sub(1, Ordering::Relaxed);
                self.size_bytes.fetch_sub(response_guard.val().size as u64, Ordering::Relaxed);
            }
        }
        
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }
    
    /// Insert pre-computed response
    pub fn insert(&self, query_hash: u64, data: Arc<[u8]>, ttl: u32) -> bool {
        let response = Arc::new(PreComputedResponse::new(data, ttl));
        let response_size = response.size as u64;
        
        if self.responses.insert(query_hash, response).is_none() {
            self.entry_count.fetch_add(1, Ordering::Relaxed);
            self.size_bytes.fetch_add(response_size, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
    
    /// Get cache statistics
    pub fn stats(&self) -> PreComputedCacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        let hit_rate = if total > 0 { (hits * 10000) / total } else { 0 };
        
        PreComputedCacheStats {
            hits,
            misses,
            hit_rate,
            size_bytes: self.size_bytes.load(Ordering::Relaxed),
            entry_count: self.entry_count.load(Ordering::Relaxed),
        }
    }
}

/// Pre-computed cache statistics
#[derive(Debug, Clone)]
pub struct PreComputedCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: u64, // Percentage * 100 (0-10000)
    pub size_bytes: u64,
    pub entry_count: usize,
}

/// Atomic rate limiter using token bucket algorithm
pub struct AtomicRateLimiter {
    /// Token buckets per client using atomic operations
    client_buckets: Arc<LockFreeMap<u64, Arc<AtomicTokenBucket>>>,
    /// Global rate limiting
    global_bucket: Arc<AtomicTokenBucket>,
    /// Rate limiting statistics
    rate_limited_queries: AtomicU64,
    /// Active client count
    active_clients: AtomicUsize,
}

/// Atomic token bucket for rate limiting
pub struct AtomicTokenBucket {
    /// Current token count
    tokens: AtomicU64,
    /// Last refill timestamp
    last_refill: AtomicU64,
    /// Maximum tokens
    max_tokens: u64,
    /// Refill rate (tokens per second)
    refill_rate: u64,
}

impl AtomicTokenBucket {
    /// Create new atomic token bucket
    pub fn new(max_tokens: u64, refill_rate: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Self {
            tokens: AtomicU64::new(max_tokens),
            last_refill: AtomicU64::new(now),
            max_tokens,
            refill_rate,
        }
    }
    
    /// Check if tokens are available and consume them atomically
    pub fn check_atomic(&self, tokens_needed: u64) -> bool {
        // Refill tokens based on time elapsed
        self.refill_tokens();
        
        // Try to consume tokens atomically
        loop {
            let current_tokens = self.tokens.load(Ordering::Acquire);
            if current_tokens < tokens_needed {
                return false;
            }
            
            if self.tokens.compare_exchange_weak(
                current_tokens,
                current_tokens - tokens_needed,
                Ordering::AcqRel,
                Ordering::Relaxed
            ).is_ok() {
                return true;
            }
        }
    }
    
    /// Refill tokens based on elapsed time
    fn refill_tokens(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        let last_refill = self.last_refill.load(Ordering::Acquire);
        if now > last_refill {
            let time_elapsed = now - last_refill;
            let tokens_to_add = time_elapsed * self.refill_rate;
            
            if tokens_to_add > 0 {
                let current_tokens = self.tokens.load(Ordering::Acquire);
                let new_tokens = (current_tokens + tokens_to_add).min(self.max_tokens);
                
                // Atomic compare-and-swap for refill
                if self.tokens.compare_exchange_weak(
                    current_tokens,
                    new_tokens,
                    Ordering::AcqRel,
                    Ordering::Relaxed
                ).is_ok() {
                    self.last_refill.store(now, Ordering::Release);
                }
            }
        }
    }
}

impl AtomicRateLimiter {
    /// Create new atomic rate limiter
    pub fn new(global_max_qps: u64, per_client_max_qps: u64) -> Self {
        Self {
            client_buckets: Arc::new(LockFreeMap::new()),
            global_bucket: Arc::new(AtomicTokenBucket::new(global_max_qps, global_max_qps)),
            rate_limited_queries: AtomicU64::new(0),
            active_clients: AtomicUsize::new(0),
        }
    }
    
    /// Check rate limit for client
    pub fn check_rate_limit(&self, client_hash: u64, tokens_needed: u64) -> bool {
        // Check global rate limit first
        if !self.global_bucket.check_atomic(tokens_needed) {
            self.rate_limited_queries.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        
        // Get or create client bucket
        let client_bucket = if let Some(bucket_guard) = self.client_buckets.get(&client_hash) {
            bucket_guard.val().clone()
        } else {
            let new_bucket = Arc::new(AtomicTokenBucket::new(100, 10)); // 100 tokens, 10/sec refill
            if self.client_buckets.insert(client_hash, new_bucket.clone()).is_none() {
                self.active_clients.fetch_add(1, Ordering::Relaxed);
            }
            new_bucket
        };
        
        // Check client rate limit
        if !client_bucket.check_atomic(tokens_needed) {
            self.rate_limited_queries.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        
        true
    }
    
    /// Get rate limiting statistics
    pub fn stats(&self) -> RateLimitStats {
        RateLimitStats {
            rate_limited_queries: self.rate_limited_queries.load(Ordering::Relaxed),
            active_clients: self.active_clients.load(Ordering::Relaxed),
        }
    }
}

/// Rate limiting statistics
#[derive(Debug, Clone)]
pub struct RateLimitStats {
    pub rate_limited_queries: u64,
    pub active_clients: usize,
}