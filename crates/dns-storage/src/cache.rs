//! Zero-copy cache implementation with atomic operations
//!
//! This module provides a high-performance, lock-free cache for DNS responses
//! and zone data using atomic operations and zero-copy techniques.

use lockfree::map::Map as LockFreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};

/// Zero-copy cache with atomic operations
pub struct ZeroCopyCache {
    /// Lock-free cache entries
    entries: Arc<LockFreeMap<u64, Arc<AtomicCacheEntry>>>,
    
    /// Atomic statistics
    total_entries: AtomicUsize,
    memory_usage: AtomicU64,
    hit_count: AtomicU64,
    miss_count: AtomicU64,
    eviction_count: AtomicU64,
    
    /// Configuration
    max_entries: usize,
    max_memory_bytes: u64,
    default_ttl: u64,
}

/// Atomic cache entry for lock-free operations
pub struct AtomicCacheEntry {
    /// Immutable cache key
    pub key: u64,
    
    /// Cached data (immutable after creation)
    pub data: Arc<[u8]>,
    
    /// Atomic expiration timestamp
    pub expires_at: AtomicU64,
    
    /// Atomic access tracking
    pub hit_count: AtomicU64,
    pub last_accessed: AtomicU64,
    
    /// Atomic size tracking
    pub size: AtomicUsize,
    
    /// Atomic validity flag
    pub is_valid: AtomicBool,
    
    /// Atomic flags for cache management
    pub is_compressed: AtomicBool,
    pub needs_refresh: AtomicBool,
}

/// Cache statistics
#[derive(Debug)]
pub struct AtomicCacheStats {
    pub total_entries: usize,
    pub memory_usage: usize,
    pub hit_rate: u64,        // Stored as fixed-point percentage
    pub miss_rate: u64,
    pub eviction_count: u64,
    pub last_updated: u64,
}

/// Trait for atomic zero-copy cache operations
pub trait AtomicZeroCopyCache: Send + Sync {
    /// Async lock-free cache operations using atomic compare-and-swap
    async fn get_raw_atomic(&self, key: u64) -> Option<Arc<[u8]>>;
    async fn set_raw_atomic(&self, key: u64, data: Arc<[u8]>, expires_at: u64) -> bool;
    
    /// Async atomic pre-built response operations
    async fn get_prebuilt_atomic(&self, query_hash: u64) -> Option<Arc<[u8]>>;
    async fn set_prebuilt_atomic(&self, query_hash: u64, response: Arc<[u8]>, expires_at: u64) -> bool;
    
    /// Async atomic batch operations for better performance
    async fn get_batch_atomic(&self, keys: &[u64]) -> Vec<Option<Arc<[u8]>>>;
    async fn set_batch_atomic(&self, entries: &[(u64, Arc<[u8]>, u64)]) -> Vec<bool>;
    
    /// Async lock-free invalidation using atomic flags
    async fn invalidate_atomic(&self, key: u64) -> bool;
    async fn invalidate_pattern_atomic(&self, pattern_hash: u64) -> usize;
    
    /// Async atomic statistics without locks
    async fn stats_atomic(&self) -> AtomicCacheStats;
    
    /// Async atomic cache maintenance
    async fn evict_expired_atomic(&self) -> usize;
    async fn compact_atomic(&self) -> bool;
}

impl ZeroCopyCache {
    /// Create a new zero-copy cache
    pub fn new() -> Self {
        Self {
            entries: Arc::new(LockFreeMap::new()),
            total_entries: AtomicUsize::new(0),
            memory_usage: AtomicU64::new(0),
            hit_count: AtomicU64::new(0),
            miss_count: AtomicU64::new(0),
            eviction_count: AtomicU64::new(0),
            max_entries: 1_000_000, // 1M entries default
            max_memory_bytes: 1024 * 1024 * 1024, // 1GB default
            default_ttl: 300, // 5 minutes default
        }
    }

    /// Create cache with custom configuration
    pub fn with_config(max_entries: usize, max_memory_bytes: u64, default_ttl: u64) -> Self {
        Self {
            entries: Arc::new(LockFreeMap::new()),
            total_entries: AtomicUsize::new(0),
            memory_usage: AtomicU64::new(0),
            hit_count: AtomicU64::new(0),
            miss_count: AtomicU64::new(0),
            eviction_count: AtomicU64::new(0),
            max_entries,
            max_memory_bytes,
            default_ttl,
        }
    }

    /// Get cached data atomically
    pub async fn get_atomic(&self, key: u64) -> Option<Arc<[u8]>> {
        if let Some(entry) = self.entries.get(&key) {
            let entry = entry.val();
            
            // Check if entry is still valid
            if !entry.is_valid.load(Ordering::Acquire) {
                return None;
            }
            
            // Check expiration
            let now = Self::current_timestamp();
            let expires_at = entry.expires_at.load(Ordering::Acquire);
            if expires_at > 0 && now > expires_at {
                // Mark as invalid and return None
                entry.is_valid.store(false, Ordering::Release);
                return None;
            }
            
            // Update access statistics atomically
            entry.hit_count.fetch_add(1, Ordering::Relaxed);
            entry.last_accessed.store(now, Ordering::Relaxed);
            
            self.hit_count.fetch_add(1, Ordering::Relaxed);
            
            Some(entry.data.clone())
        } else {
            self.miss_count.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Set cached data atomically
    pub async fn set_atomic(&self, key: u64, data: Arc<[u8]>, ttl_seconds: u64) -> bool {
        let now = Self::current_timestamp();
        let expires_at = if ttl_seconds > 0 {
            now + ttl_seconds
        } else {
            now + self.default_ttl
        };
        
        let data_size = data.len();
        
        // Check memory limits
        let current_memory = self.memory_usage.load(Ordering::Acquire);
        if current_memory + data_size as u64 > self.max_memory_bytes {
            // Try to evict some entries first
            self.evict_lru_entries(data_size).await;
            
            // Check again
            let current_memory = self.memory_usage.load(Ordering::Acquire);
            if current_memory + data_size as u64 > self.max_memory_bytes {
                return false; // Still not enough space
            }
        }
        
        // Check entry count limits
        let current_entries = self.total_entries.load(Ordering::Acquire);
        if current_entries >= self.max_entries {
            // Try to evict some entries
            self.evict_lru_entries(0).await;
            
            let current_entries = self.total_entries.load(Ordering::Acquire);
            if current_entries >= self.max_entries {
                return false; // Still too many entries
            }
        }
        
        let entry = Arc::new(AtomicCacheEntry {
            key,
            data,
            expires_at: AtomicU64::new(expires_at),
            hit_count: AtomicU64::new(0),
            last_accessed: AtomicU64::new(now),
            size: AtomicUsize::new(data_size),
            is_valid: AtomicBool::new(true),
            is_compressed: AtomicBool::new(false),
            needs_refresh: AtomicBool::new(false),
        });
        
        // Check if key already exists
        if let Some(existing) = self.entries.get(&key) {
            let old_size = existing.val().size.load(Ordering::Acquire);
            self.memory_usage.fetch_sub(old_size as u64, Ordering::AcqRel);
        } else {
            self.total_entries.fetch_add(1, Ordering::AcqRel);
        }
        
        // Insert new entry
        self.entries.insert(key, entry);
        self.memory_usage.fetch_add(data_size as u64, Ordering::AcqRel);
        
        true
    }

    /// Invalidate cache entry atomically
    pub async fn invalidate_atomic(&self, key: u64) -> bool {
        if let Some(entry) = self.entries.get(&key) {
            let entry = entry.val();
            let was_valid = entry.is_valid.swap(false, Ordering::AcqRel);
            
            if was_valid {
                // Update memory usage
                let size = entry.size.load(Ordering::Acquire);
                self.memory_usage.fetch_sub(size as u64, Ordering::AcqRel);
            }
            
            was_valid
        } else {
            false
        }
    }

    /// Get cache statistics atomically
    pub async fn get_statistics_atomic(&self) -> AtomicCacheStats {
        let hit_count = self.hit_count.load(Ordering::Relaxed);
        let miss_count = self.miss_count.load(Ordering::Relaxed);
        let total_requests = hit_count + miss_count;
        
        let hit_rate = if total_requests > 0 {
            hit_count * 10000 / total_requests // Fixed-point percentage (0.01% precision)
        } else {
            0
        };
        
        let miss_rate = if total_requests > 0 {
            miss_count * 10000 / total_requests
        } else {
            0
        };
        
        AtomicCacheStats {
            total_entries: self.total_entries.load(Ordering::Relaxed),
            memory_usage: self.memory_usage.load(Ordering::Relaxed) as usize,
            hit_rate,
            miss_rate,
            eviction_count: self.eviction_count.load(Ordering::Relaxed),
            last_updated: Self::current_timestamp(),
        }
    }

    /// Evict expired entries atomically
    pub async fn evict_expired_atomic(&self) -> usize {
        let now = Self::current_timestamp();
        let mut evicted_count = 0;
        
        // Collect expired entries
        let mut expired_keys = Vec::new();
        
        for entry in self.entries.iter() {
            let key = *entry.key();
            let cache_entry = entry.val();
            
            let expires_at = cache_entry.expires_at.load(Ordering::Acquire);
            if expires_at > 0 && now > expires_at {
                expired_keys.push(key);
            }
        }
        
        // Remove expired entries
        for key in expired_keys {
            if let Some(entry) = self.entries.remove(&key) {
                let size = entry.val().size.load(Ordering::Acquire);
                self.memory_usage.fetch_sub(size as u64, Ordering::AcqRel);
                self.total_entries.fetch_sub(1, Ordering::AcqRel);
                evicted_count += 1;
            }
        }
        
        if evicted_count > 0 {
            self.eviction_count.fetch_add(evicted_count, Ordering::Relaxed);
            tracing::debug!("Evicted {} expired cache entries", evicted_count);
        }
        
        evicted_count.try_into().unwrap()
    }

    /// Compact cache by removing invalid entries
    pub async fn compact_atomic(&self) -> bool {
        let mut removed_count = 0;
        
        // Collect invalid entries
        let mut invalid_keys = Vec::new();
        
        for entry in self.entries.iter() {
            let key = *entry.key();
            let cache_entry = entry.val();
            
            if !cache_entry.is_valid.load(Ordering::Acquire) {
                invalid_keys.push(key);
            }
        }
        
        // Remove invalid entries
        for key in invalid_keys {
            if let Some(entry) = self.entries.remove(&key) {
                let size = entry.val().size.load(Ordering::Acquire);
                self.memory_usage.fetch_sub(size as u64, Ordering::AcqRel);
                self.total_entries.fetch_sub(1, Ordering::AcqRel);
                removed_count += 1;
            }
        }
        
        if removed_count > 0 {
            tracing::debug!("Compacted cache: removed {} invalid entries", removed_count);
            true
        } else {
            false
        }
    }

    // Private helper methods

    async fn evict_lru_entries(&self, needed_space: usize) {
        let mut candidates = Vec::new();
        
        // Collect LRU candidates
        for entry in self.entries.iter() {
            let key = *entry.key();
            let cache_entry = entry.val();
            
            let last_accessed = cache_entry.last_accessed.load(Ordering::Acquire);
            let hit_count = cache_entry.hit_count.load(Ordering::Acquire);
            
            candidates.push((key, last_accessed, hit_count));
        }
        
        // Sort by access time (oldest first) and hit count (least accessed first)
        candidates.sort_by(|a, b| {
            a.1.cmp(&b.1).then(a.2.cmp(&b.2))
        });
        
        // Evict entries until we have enough space or entries
        let mut freed_space = 0;
        let mut evicted_count = 0;
        
        for (key, _, _) in candidates {
            if needed_space > 0 && freed_space >= needed_space {
                break;
            }
            
            if let Some(entry) = self.entries.remove(&key) {
                let size = entry.val().size.load(Ordering::Acquire);
                freed_space += size;
                evicted_count += 1;
                
                self.memory_usage.fetch_sub(size as u64, Ordering::AcqRel);
                self.total_entries.fetch_sub(1, Ordering::AcqRel);
            }
            
            // Don't evict too many at once
            if evicted_count >= 1000 {
                break;
            }
        }
        
        if evicted_count > 0 {
            self.eviction_count.fetch_add(evicted_count, Ordering::Relaxed);
            tracing::debug!("Evicted {} LRU cache entries (freed {} bytes)", evicted_count, freed_space);
        }
    }

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

impl AtomicZeroCopyCache for ZeroCopyCache {
    async fn get_raw_atomic(&self, key: u64) -> Option<Arc<[u8]>> {
        self.get_atomic(key).await
    }

    async fn set_raw_atomic(&self, key: u64, data: Arc<[u8]>, expires_at: u64) -> bool {
        let ttl = if expires_at > 0 {
            let now = Self::current_timestamp();
            expires_at.saturating_sub(now)
        } else {
            self.default_ttl
        };
        
        self.set_atomic(key, data, ttl).await
    }

    async fn get_prebuilt_atomic(&self, query_hash: u64) -> Option<Arc<[u8]>> {
        self.get_atomic(query_hash).await
    }

    async fn set_prebuilt_atomic(&self, query_hash: u64, response: Arc<[u8]>, expires_at: u64) -> bool {
        self.set_raw_atomic(query_hash, response, expires_at).await
    }

    async fn get_batch_atomic(&self, keys: &[u64]) -> Vec<Option<Arc<[u8]>>> {
        let mut results = Vec::with_capacity(keys.len());
        
        for &key in keys {
            results.push(self.get_atomic(key).await);
        }
        
        results
    }

    async fn set_batch_atomic(&self, entries: &[(u64, Arc<[u8]>, u64)]) -> Vec<bool> {
        let mut results = Vec::with_capacity(entries.len());
        
        for (key, data, expires_at) in entries {
            results.push(self.set_raw_atomic(*key, data.clone(), *expires_at).await);
        }
        
        results
    }

    async fn invalidate_atomic(&self, key: u64) -> bool {
        self.invalidate_atomic(key).await
    }

    async fn invalidate_pattern_atomic(&self, _pattern_hash: u64) -> usize {
        // TODO: Implement pattern-based invalidation
        // This would require storing pattern information with cache entries
        0
    }

    async fn stats_atomic(&self) -> AtomicCacheStats {
        self.get_statistics_atomic().await
    }

    async fn evict_expired_atomic(&self) -> usize {
        self.evict_expired_atomic().await
    }

    async fn compact_atomic(&self) -> bool {
        self.compact_atomic().await
    }
}

impl Default for ZeroCopyCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_basic_operations() {
        let cache = ZeroCopyCache::new();
        
        let key = 12345u64;
        let data: Arc<[u8]> = Arc::from(b"test data".as_slice());
        
        // Set data
        assert!(cache.set_atomic(key, data.clone(), 60).await);
        
        // Get data
        let retrieved = cache.get_atomic(key).await.unwrap();
        assert_eq!(&retrieved[..], b"test data");
        
        // Check statistics
        let stats = cache.get_statistics_atomic().await;
        assert_eq!(stats.total_entries, 1);
        assert!(stats.hit_rate > 0);
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = ZeroCopyCache::new();
        
        let key = 12345u64;
        let data: Arc<[u8]> = Arc::from(b"test data".as_slice());
        
        // Set data with very short TTL
        assert!(cache.set_atomic(key, data, 1).await);
        
        // Should be available immediately
        assert!(cache.get_atomic(key).await.is_some());
        
        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        
        // Should be expired now
        assert!(cache.get_atomic(key).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_invalidation() {
        let cache = ZeroCopyCache::new();
        
        let key = 12345u64;
        let data: Arc<[u8]> = Arc::from(b"test data".as_slice());
        
        // Set and verify data
        assert!(cache.set_atomic(key, data, 60).await);
        assert!(cache.get_atomic(key).await.is_some());
        
        // Invalidate
        assert!(cache.invalidate_atomic(key).await);
        
        // Should be gone now
        assert!(cache.get_atomic(key).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_eviction() {
        let cache = ZeroCopyCache::with_config(2, 1024, 60); // Very small cache
        
        let data: Arc<[u8]> = Arc::from(vec![0u8; 100].as_slice()); // 100 bytes each
        
        // Fill cache
        assert!(cache.set_atomic(1, data.clone(), 60).await);
        assert!(cache.set_atomic(2, data.clone(), 60).await);
        
        // This should trigger eviction
        assert!(cache.set_atomic(3, data.clone(), 60).await);
        
        // Check that we still have 2 entries (one was evicted)
        let stats = cache.get_statistics_atomic().await;
        assert!(stats.total_entries <= 2);
    }

    #[tokio::test]
    async fn test_atomic_cache_trait() {
        let cache = ZeroCopyCache::new();
        
        let key = 12345u64;
        let data: Arc<[u8]> = Arc::from(b"test data".as_slice());
        
        // Test trait methods directly
        assert!(cache.set_raw_atomic(key, data.clone(), 0).await);
        
        let retrieved = cache.get_raw_atomic(key).await.unwrap();
        assert_eq!(&retrieved[..], b"test data");
        
        let stats = cache.stats_atomic().await;
        assert_eq!(stats.total_entries, 1);
    }
}