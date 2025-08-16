//! Multi-Level Atomic Caching System
//!
//! This module implements a three-tier caching system:
//! - L1: Hot cache using atomic operations for fastest access
//! - L2: Memory cache with LRU eviction using atomic reference counting
//! - L3: SSD cache with memory-mapped access for warm data
//!
//! All operations are lock-free and use atomic operations for maximum performance.

use crate::{AtomicCacheEntry, AtomicCacheStats, AtomicZeroCopyCache};
use lockfree::map::Map as LockFreeMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use memmap2::{Mmap, MmapMut, MmapOptions};
use std::fs::{File, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use tokio::sync::RwLock;
use tracing::{debug, warn, error};

/// Multi-level atomic caching system with L1, L2, and L3 tiers
pub struct MultiLevelAtomicCache {
    /// L1 Cache: Hot cache for most frequently accessed items
    l1_cache: Arc<L1HotCache>,
    
    /// L2 Cache: Memory cache with LRU eviction
    l2_cache: Arc<L2MemoryCache>,
    
    /// L3 Cache: SSD cache with memory-mapped access
    l3_cache: Arc<L3SsdCache>,
    
    /// Cache warming and predictive caching
    cache_warmer: Arc<CacheWarmer>,
    
    /// Global statistics across all cache levels
    global_stats: Arc<GlobalCacheStats>,
    
    /// Configuration
    config: MultiLevelCacheConfig,
}

/// Configuration for multi-level cache
#[derive(Debug, Clone)]
pub struct MultiLevelCacheConfig {
    /// L1 cache configuration
    pub l1_max_entries: usize,
    pub l1_max_memory_mb: usize,
    
    /// L2 cache configuration  
    pub l2_max_entries: usize,
    pub l2_max_memory_mb: usize,
    
    /// L3 cache configuration
    pub l3_cache_dir: PathBuf,
    pub l3_max_files: usize,
    pub l3_max_size_gb: usize,
    
    /// Cache warming configuration
    pub enable_cache_warming: bool,
    pub warming_batch_size: usize,
    pub predictive_cache_size: usize,
}

/// L1 Hot Cache - Atomic operations for fastest access
pub struct L1HotCache {
    /// Lock-free hot entries map
    entries: Arc<LockFreeMap<u64, Arc<AtomicCacheEntry>>>,
    
    /// Atomic counters
    total_entries: AtomicUsize,
    memory_usage: AtomicU64,
    hit_count: AtomicU64,
    miss_count: AtomicU64,
    
    /// Configuration
    max_entries: usize,
    max_memory_bytes: u64,
}

/// L2 Memory Cache - LRU eviction with atomic reference counting
pub struct L2MemoryCache {
    /// Lock-free entries map
    entries: Arc<LockFreeMap<u64, Arc<L2CacheEntry>>>,
    
    /// LRU tracking with atomic operations
    lru_tracker: Arc<AtomicLruTracker>,
    
    /// Atomic counters
    total_entries: AtomicUsize,
    memory_usage: AtomicU64,
    hit_count: AtomicU64,
    miss_count: AtomicU64,
    eviction_count: AtomicU64,
    
    /// Configuration
    max_entries: usize,
    max_memory_bytes: u64,
}

/// L2 Cache entry with atomic LRU tracking
pub struct L2CacheEntry {
    /// Cache key
    pub key: u64,
    
    /// Cached data
    pub data: Arc<[u8]>,
    
    /// Atomic expiration
    pub expires_at: AtomicU64,
    
    /// Atomic LRU tracking
    pub access_count: AtomicU64,
    pub last_accessed: AtomicU64,
    pub lru_position: AtomicU64,
    
    /// Size tracking
    pub size: AtomicUsize,
    
    /// Validity flag
    pub is_valid: AtomicBool,
}

/// Atomic LRU tracker for L2 cache
pub struct AtomicLruTracker {
    /// Global LRU counter
    global_counter: AtomicU64,
    
    /// LRU position map (position -> key)
    position_map: Arc<LockFreeMap<u64, u64>>,
    
    /// Eviction candidates queue
    eviction_queue: Arc<lockfree::queue::Queue<u64>>,
}

/// L3 SSD Cache - Memory-mapped files for warm data
pub struct L3SsdCache {
    /// Cache directory
    cache_dir: PathBuf,
    
    /// Memory-mapped cache files
    mmap_files: Arc<RwLock<HashMap<u64, Arc<MmapCacheFile>>>>,
    
    /// File allocation tracker
    file_allocator: Arc<AtomicFileAllocator>,
    
    /// Atomic counters
    total_files: AtomicUsize,
    total_size: AtomicU64,
    hit_count: AtomicU64,
    miss_count: AtomicU64,
    
    /// Configuration
    max_files: usize,
    max_size_bytes: u64,
}

/// Memory-mapped cache file
pub struct MmapCacheFile {
    /// File path
    pub path: PathBuf,
    
    /// Memory mapping
    pub mmap: Mmap,
    
    /// File metadata
    pub key: u64,
    pub size: usize,
    pub created_at: u64,
    pub last_accessed: AtomicU64,
    pub access_count: AtomicU64,
}

/// Atomic file allocator for L3 cache
pub struct AtomicFileAllocator {
    /// Next file ID
    next_file_id: AtomicU64,
    
    /// File size tracker
    allocated_size: AtomicU64,
    
    /// Free file slots
    free_slots: Arc<lockfree::queue::Queue<u64>>,
}

/// Cache warming and predictive caching
pub struct CacheWarmer {
    /// Query pattern tracker
    pattern_tracker: Arc<QueryPatternTracker>,
    
    /// Predictive cache entries
    predictive_cache: Arc<LockFreeMap<u64, Arc<PredictiveCacheEntry>>>,
    
    /// Warming statistics
    warming_stats: Arc<WarmingStats>,
    
    /// Configuration
    enabled: AtomicBool,
    batch_size: usize,
    max_predictive_entries: usize,
}

/// Query pattern tracker for predictive caching
pub struct QueryPatternTracker {
    /// Query frequency map
    query_frequency: Arc<LockFreeMap<u64, Arc<QueryFrequency>>>,
    
    /// Query sequence patterns
    sequence_patterns: Arc<LockFreeMap<u64, Arc<SequencePattern>>>,
    
    /// Time-based patterns
    time_patterns: Arc<LockFreeMap<u64, Arc<TimePattern>>>,
}

/// Query frequency tracking
pub struct QueryFrequency {
    pub query_hash: u64,
    pub count: AtomicU64,
    pub last_seen: AtomicU64,
    pub frequency_score: AtomicU64, // Calculated score for caching priority
}

/// Query sequence pattern
pub struct SequencePattern {
    pub pattern_hash: u64,
    pub sequence: Vec<u64>, // Sequence of query hashes
    pub frequency: AtomicU64,
    pub confidence: AtomicU64, // Confidence in pattern (0-10000)
}

/// Time-based query pattern
pub struct TimePattern {
    pub query_hash: u64,
    pub hour_frequency: [AtomicU64; 24], // Frequency by hour of day
    pub day_frequency: [AtomicU64; 7],   // Frequency by day of week
    pub peak_hours: AtomicU64, // Bit mask of peak hours
}

/// Predictive cache entry
pub struct PredictiveCacheEntry {
    pub query_hash: u64,
    pub predicted_data: Arc<[u8]>,
    pub confidence: AtomicU64,
    pub created_at: AtomicU64,
    pub expires_at: AtomicU64,
    pub hit_count: AtomicU64,
}

/// Cache warming statistics
pub struct WarmingStats {
    pub predictions_made: AtomicU64,
    pub predictions_hit: AtomicU64,
    pub patterns_detected: AtomicU64,
    pub cache_warmed_entries: AtomicU64,
}

/// Global cache statistics across all levels
pub struct GlobalCacheStats {
    /// Per-level statistics
    pub l1_stats: AtomicCacheStats,
    pub l2_stats: AtomicCacheStats,
    pub l3_stats: AtomicCacheStats,
    
    /// Global counters
    pub total_requests: AtomicU64,
    pub total_hits: AtomicU64,
    pub total_misses: AtomicU64,
    
    /// Cache efficiency metrics
    pub l1_hit_ratio: AtomicU64, // Fixed-point percentage
    pub l2_hit_ratio: AtomicU64,
    pub l3_hit_ratio: AtomicU64,
    pub overall_hit_ratio: AtomicU64,
    
    /// Performance metrics
    pub avg_l1_latency_ns: AtomicU64,
    pub avg_l2_latency_ns: AtomicU64,
    pub avg_l3_latency_ns: AtomicU64,
}

impl MultiLevelAtomicCache {
    /// Create new multi-level cache with configuration
    pub fn new(config: MultiLevelCacheConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Create cache directory if it doesn't exist
        std::fs::create_dir_all(&config.l3_cache_dir)?;
        
        let l1_cache = Arc::new(L1HotCache::new(
            config.l1_max_entries,
            (config.l1_max_memory_mb * 1024 * 1024) as u64,
        ));
        
        let l2_cache = Arc::new(L2MemoryCache::new(
            config.l2_max_entries,
            (config.l2_max_memory_mb * 1024 * 1024) as u64,
        ));
        
        let l3_cache = Arc::new(L3SsdCache::new(
            config.l3_cache_dir.clone(),
            config.l3_max_files,
            (config.l3_max_size_gb * 1024 * 1024 * 1024) as u64,
        )?);
        
        let cache_warmer = Arc::new(CacheWarmer::new(
            config.enable_cache_warming,
            config.warming_batch_size,
            config.predictive_cache_size,
        ));
        
        let global_stats = Arc::new(GlobalCacheStats::new());
        
        Ok(Self {
            l1_cache,
            l2_cache,
            l3_cache,
            cache_warmer,
            global_stats,
            config,
        })
    }
    
    /// Get data from cache (tries L1 -> L2 -> L3)
    pub async fn get_atomic(&self, key: u64) -> Option<Arc<[u8]>> {
        let start_time = Self::current_timestamp_ns();
        
        // Update total requests counter
        self.global_stats.total_requests.fetch_add(1, Ordering::Relaxed);
        
        // Try L1 cache first (fastest)
        if let Some(data) = self.l1_cache.get_atomic(key).await {
            let latency = Self::current_timestamp_ns() - start_time;
            self.global_stats.avg_l1_latency_ns.store(latency, Ordering::Relaxed);
            self.global_stats.total_hits.fetch_add(1, Ordering::Relaxed);
            
            // Update cache warmer with successful hit
            self.cache_warmer.record_hit(key).await;
            
            return Some(data);
        }
        
        // Try L2 cache
        if let Some(data) = self.l2_cache.get_atomic(key).await {
            let latency = Self::current_timestamp_ns() - start_time;
            self.global_stats.avg_l2_latency_ns.store(latency, Ordering::Relaxed);
            self.global_stats.total_hits.fetch_add(1, Ordering::Relaxed);
            
            // Promote to L1 cache
            let _ = self.l1_cache.set_atomic(key, data.clone(), 300).await;
            
            // Update cache warmer
            self.cache_warmer.record_hit(key).await;
            
            return Some(data);
        }
        
        // Try L3 cache
        if let Some(data) = self.l3_cache.get_atomic(key).await {
            let latency = Self::current_timestamp_ns() - start_time;
            self.global_stats.avg_l3_latency_ns.store(latency, Ordering::Relaxed);
            self.global_stats.total_hits.fetch_add(1, Ordering::Relaxed);
            
            // Promote to L2 and L1 caches
            let _ = self.l2_cache.set_atomic(key, data.clone(), 600).await;
            let _ = self.l1_cache.set_atomic(key, data.clone(), 300).await;
            
            // Update cache warmer
            self.cache_warmer.record_hit(key).await;
            
            return Some(data);
        }
        
        // Cache miss across all levels
        self.global_stats.total_misses.fetch_add(1, Ordering::Relaxed);
        self.cache_warmer.record_miss(key).await;
        
        None
    }
    
    /// Set data in cache (stores in all levels)
    pub async fn set_atomic(&self, key: u64, data: Arc<[u8]>, ttl_seconds: u64) -> bool {
        let mut success = true;
        
        // Store in L1 cache
        if !self.l1_cache.set_atomic(key, data.clone(), ttl_seconds).await {
            success = false;
        }
        
        // Store in L2 cache with longer TTL
        if !self.l2_cache.set_atomic(key, data.clone(), ttl_seconds * 2).await {
            success = false;
        }
        
        // Store in L3 cache with even longer TTL
        if !self.l3_cache.set_atomic(key, data.clone(), ttl_seconds * 4).await {
            success = false;
        }
        
        // Update cache warmer with new data
        self.cache_warmer.record_set(key, &data).await;
        
        success
    }
    
    /// Invalidate data across all cache levels
    pub async fn invalidate_atomic(&self, key: u64) -> bool {
        let l1_result = self.l1_cache.invalidate_atomic(key).await;
        let l2_result = self.l2_cache.invalidate_atomic(key).await;
        let l3_result = self.l3_cache.invalidate_atomic(key).await;
        
        l1_result || l2_result || l3_result
    }
    
    /// Get comprehensive cache statistics
    pub async fn get_statistics_atomic(&self) -> MultiLevelCacheStats {
        let l1_stats = self.l1_cache.get_statistics_atomic().await;
        let l2_stats = self.l2_cache.get_statistics_atomic().await;
        let l3_stats = self.l3_cache.get_statistics_atomic().await;
        let warming_stats = self.cache_warmer.get_statistics().await;
        
        // Calculate global hit ratios
        let total_requests = self.global_stats.total_requests.load(Ordering::Relaxed);
        let total_hits = self.global_stats.total_hits.load(Ordering::Relaxed);
        
        let overall_hit_ratio = if total_requests > 0 {
            total_hits * 10000 / total_requests
        } else {
            0
        };
        
        MultiLevelCacheStats {
            l1_stats,
            l2_stats,
            l3_stats,
            warming_stats,
            overall_hit_ratio,
            total_requests,
            total_hits,
            avg_l1_latency_ns: self.global_stats.avg_l1_latency_ns.load(Ordering::Relaxed),
            avg_l2_latency_ns: self.global_stats.avg_l2_latency_ns.load(Ordering::Relaxed),
            avg_l3_latency_ns: self.global_stats.avg_l3_latency_ns.load(Ordering::Relaxed),
        }
    }
    
    /// Perform cache maintenance across all levels
    pub async fn maintenance_atomic(&self) -> MaintenanceResult {
        let l1_evicted = self.l1_cache.evict_expired_atomic().await;
        let l2_evicted = self.l2_cache.evict_expired_atomic().await;
        let l3_evicted = self.l3_cache.evict_expired_atomic().await;
        
        // Perform cache warming
        let warmed = if self.config.enable_cache_warming {
            self.cache_warmer.warm_cache(&*self.l1_cache, &*self.l2_cache).await
        } else {
            0
        };
        
        MaintenanceResult {
            l1_evicted,
            l2_evicted,
            l3_evicted,
            entries_warmed: warmed,
        }
    }
    
    fn current_timestamp_ns() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }
}

/// Multi-level cache statistics
#[derive(Debug)]
pub struct MultiLevelCacheStats {
    pub l1_stats: AtomicCacheStats,
    pub l2_stats: AtomicCacheStats,
    pub l3_stats: AtomicCacheStats,
    pub warming_stats: WarmingStatistics,
    pub overall_hit_ratio: u64,
    pub total_requests: u64,
    pub total_hits: u64,
    pub avg_l1_latency_ns: u64,
    pub avg_l2_latency_ns: u64,
    pub avg_l3_latency_ns: u64,
}

/// Cache warming statistics
#[derive(Debug)]
pub struct WarmingStatistics {
    pub predictions_made: u64,
    pub predictions_hit: u64,
    pub patterns_detected: u64,
    pub cache_warmed_entries: u64,
    pub prediction_accuracy: u64, // Percentage
}

/// Maintenance operation result
#[derive(Debug)]
pub struct MaintenanceResult {
    pub l1_evicted: usize,
    pub l2_evicted: usize,
    pub l3_evicted: usize,
    pub entries_warmed: usize,
}

impl Default for MultiLevelCacheConfig {
    fn default() -> Self {
        Self {
            l1_max_entries: 10_000,
            l1_max_memory_mb: 64,
            l2_max_entries: 100_000,
            l2_max_memory_mb: 512,
            l3_cache_dir: PathBuf::from("/tmp/dns_cache"),
            l3_max_files: 1000,
            l3_max_size_gb: 4,
            enable_cache_warming: true,
            warming_batch_size: 100,
            predictive_cache_size: 1000,
        }
    }
}

impl GlobalCacheStats {
    fn new() -> Self {
        Self {
            l1_stats: AtomicCacheStats {
                total_entries: 0,
                memory_usage: 0,
                hit_rate: 0,
                miss_rate: 0,
                eviction_count: 0,
                last_updated: 0,
            },
            l2_stats: AtomicCacheStats {
                total_entries: 0,
                memory_usage: 0,
                hit_rate: 0,
                miss_rate: 0,
                eviction_count: 0,
                last_updated: 0,
            },
            l3_stats: AtomicCacheStats {
                total_entries: 0,
                memory_usage: 0,
                hit_rate: 0,
                miss_rate: 0,
                eviction_count: 0,
                last_updated: 0,
            },
            total_requests: AtomicU64::new(0),
            total_hits: AtomicU64::new(0),
            total_misses: AtomicU64::new(0),
            l1_hit_ratio: AtomicU64::new(0),
            l2_hit_ratio: AtomicU64::new(0),
            l3_hit_ratio: AtomicU64::new(0),
            overall_hit_ratio: AtomicU64::new(0),
            avg_l1_latency_ns: AtomicU64::new(0),
            avg_l2_latency_ns: AtomicU64::new(0),
            avg_l3_latency_ns: AtomicU64::new(0),
        }
    }
}

// L1 Hot Cache Implementation
impl L1HotCache {
    /// Create new L1 hot cache
    pub fn new(max_entries: usize, max_memory_bytes: u64) -> Self {
        Self {
            entries: Arc::new(LockFreeMap::new()),
            total_entries: AtomicUsize::new(0),
            memory_usage: AtomicU64::new(0),
            hit_count: AtomicU64::new(0),
            miss_count: AtomicU64::new(0),
            max_entries,
            max_memory_bytes,
        }
    }
    
    /// Get data from L1 cache atomically
    pub async fn get_atomic(&self, key: u64) -> Option<Arc<[u8]>> {
        if let Some(entry) = self.entries.get(&key) {
            let entry = entry.val();
            
            // Check validity
            if !entry.is_valid.load(Ordering::Acquire) {
                return None;
            }
            
            // Check expiration
            let now = Self::current_timestamp();
            let expires_at = entry.expires_at.load(Ordering::Acquire);
            if expires_at > 0 && now > expires_at {
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
    
    /// Set data in L1 cache atomically
    pub async fn set_atomic(&self, key: u64, data: Arc<[u8]>, ttl_seconds: u64) -> bool {
        let now = Self::current_timestamp();
        let expires_at = now + ttl_seconds;
        let data_size = data.len();
        
        // Check memory limits
        let current_memory = self.memory_usage.load(Ordering::Acquire);
        if current_memory + data_size as u64 > self.max_memory_bytes {
            // Try to evict some entries
            self.evict_lru_entries(data_size).await;
            
            // Check again
            let current_memory = self.memory_usage.load(Ordering::Acquire);
            if current_memory + data_size as u64 > self.max_memory_bytes {
                return false;
            }
        }
        
        // Check entry count limits
        let current_entries = self.total_entries.load(Ordering::Acquire);
        if current_entries >= self.max_entries {
            self.evict_lru_entries(0).await;
            
            let current_entries = self.total_entries.load(Ordering::Acquire);
            if current_entries >= self.max_entries {
                return false;
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
        
        // Handle existing entry
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
    
    /// Invalidate entry atomically
    pub async fn invalidate_atomic(&self, key: u64) -> bool {
        if let Some(entry) = self.entries.get(&key) {
            let entry = entry.val();
            let was_valid = entry.is_valid.swap(false, Ordering::AcqRel);
            
            if was_valid {
                let size = entry.size.load(Ordering::Acquire);
                self.memory_usage.fetch_sub(size as u64, Ordering::AcqRel);
            }
            
            was_valid
        } else {
            false
        }
    }
    
    /// Get L1 cache statistics
    pub async fn get_statistics_atomic(&self) -> AtomicCacheStats {
        let hit_count = self.hit_count.load(Ordering::Relaxed);
        let miss_count = self.miss_count.load(Ordering::Relaxed);
        let total_requests = hit_count + miss_count;
        
        let hit_rate = if total_requests > 0 {
            hit_count * 10000 / total_requests
        } else {
            0
        };
        
        AtomicCacheStats {
            total_entries: self.total_entries.load(Ordering::Relaxed),
            memory_usage: self.memory_usage.load(Ordering::Relaxed) as usize,
            hit_rate,
            miss_rate: 10000 - hit_rate,
            eviction_count: 0, // TODO: Track evictions
            last_updated: Self::current_timestamp(),
        }
    }
    
    /// Evict expired entries
    pub async fn evict_expired_atomic(&self) -> usize {
        let now = Self::current_timestamp();
        let mut evicted_count = 0;
        
        let mut expired_keys = Vec::new();
        
        for entry in self.entries.iter() {
            let key = *entry.key();
            let cache_entry = entry.val();
            
            let expires_at = cache_entry.expires_at.load(Ordering::Acquire);
            if expires_at > 0 && now > expires_at {
                expired_keys.push(key);
            }
        }
        
        for key in expired_keys {
            if let Some(entry) = self.entries.remove(&key) {
                let size = entry.val().size.load(Ordering::Acquire);
                self.memory_usage.fetch_sub(size as u64, Ordering::AcqRel);
                self.total_entries.fetch_sub(1, Ordering::AcqRel);
                evicted_count += 1;
            }
        }
        
        evicted_count
    }
    
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
        
        // Sort by access time and hit count
        candidates.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
        
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
            
            if evicted_count >= 100 {
                break;
            }
        }
        
        if evicted_count > 0 {
            debug!("L1 cache evicted {} entries (freed {} bytes)", evicted_count, freed_space);
        }
    }
    
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

// L2 Memory Cache Implementation
impl L2MemoryCache {
    /// Create new L2 memory cache
    pub fn new(max_entries: usize, max_memory_bytes: u64) -> Self {
        Self {
            entries: Arc::new(LockFreeMap::new()),
            lru_tracker: Arc::new(AtomicLruTracker::new()),
            total_entries: AtomicUsize::new(0),
            memory_usage: AtomicU64::new(0),
            hit_count: AtomicU64::new(0),
            miss_count: AtomicU64::new(0),
            eviction_count: AtomicU64::new(0),
            max_entries,
            max_memory_bytes,
        }
    }
    
    /// Get data from L2 cache atomically
    pub async fn get_atomic(&self, key: u64) -> Option<Arc<[u8]>> {
        if let Some(entry) = self.entries.get(&key) {
            let entry = entry.val();
            
            // Check validity
            if !entry.is_valid.load(Ordering::Acquire) {
                return None;
            }
            
            // Check expiration
            let now = Self::current_timestamp();
            let expires_at = entry.expires_at.load(Ordering::Acquire);
            if expires_at > 0 && now > expires_at {
                entry.is_valid.store(false, Ordering::Release);
                return None;
            }
            
            // Update LRU tracking atomically
            let new_position = self.lru_tracker.update_access(key);
            entry.lru_position.store(new_position, Ordering::Relaxed);
            entry.access_count.fetch_add(1, Ordering::Relaxed);
            entry.last_accessed.store(now, Ordering::Relaxed);
            
            self.hit_count.fetch_add(1, Ordering::Relaxed);
            
            Some(entry.data.clone())
        } else {
            self.miss_count.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
    
    /// Set data in L2 cache atomically
    pub async fn set_atomic(&self, key: u64, data: Arc<[u8]>, ttl_seconds: u64) -> bool {
        let now = Self::current_timestamp();
        let expires_at = now + ttl_seconds;
        let data_size = data.len();
        
        // Check memory limits
        let current_memory = self.memory_usage.load(Ordering::Acquire);
        if current_memory + data_size as u64 > self.max_memory_bytes {
            self.evict_lru_entries(data_size).await;
            
            let current_memory = self.memory_usage.load(Ordering::Acquire);
            if current_memory + data_size as u64 > self.max_memory_bytes {
                return false;
            }
        }
        
        // Check entry count limits
        let current_entries = self.total_entries.load(Ordering::Acquire);
        if current_entries >= self.max_entries {
            self.evict_lru_entries(0).await;
            
            let current_entries = self.total_entries.load(Ordering::Acquire);
            if current_entries >= self.max_entries {
                return false;
            }
        }
        
        let lru_position = self.lru_tracker.get_next_position();
        
        let entry = Arc::new(L2CacheEntry {
            key,
            data,
            expires_at: AtomicU64::new(expires_at),
            access_count: AtomicU64::new(0),
            last_accessed: AtomicU64::new(now),
            lru_position: AtomicU64::new(lru_position),
            size: AtomicUsize::new(data_size),
            is_valid: AtomicBool::new(true),
        });
        
        // Handle existing entry
        if let Some(existing) = self.entries.get(&key) {
            let old_size = existing.val().size.load(Ordering::Acquire);
            self.memory_usage.fetch_sub(old_size as u64, Ordering::AcqRel);
        } else {
            self.total_entries.fetch_add(1, Ordering::AcqRel);
        }
        
        // Insert new entry and update LRU tracker
        self.entries.insert(key, entry);
        self.lru_tracker.add_entry(key, lru_position);
        self.memory_usage.fetch_add(data_size as u64, Ordering::AcqRel);
        
        true
    }
    
    /// Invalidate entry atomically
    pub async fn invalidate_atomic(&self, key: u64) -> bool {
        if let Some(entry) = self.entries.get(&key) {
            let entry = entry.val();
            let was_valid = entry.is_valid.swap(false, Ordering::AcqRel);
            
            if was_valid {
                let size = entry.size.load(Ordering::Acquire);
                self.memory_usage.fetch_sub(size as u64, Ordering::AcqRel);
                
                // Remove from LRU tracker
                self.lru_tracker.remove_entry(key);
            }
            
            was_valid
        } else {
            false
        }
    }
    
    /// Get L2 cache statistics
    pub async fn get_statistics_atomic(&self) -> AtomicCacheStats {
        let hit_count = self.hit_count.load(Ordering::Relaxed);
        let miss_count = self.miss_count.load(Ordering::Relaxed);
        let total_requests = hit_count + miss_count;
        
        let hit_rate = if total_requests > 0 {
            hit_count * 10000 / total_requests
        } else {
            0
        };
        
        AtomicCacheStats {
            total_entries: self.total_entries.load(Ordering::Relaxed),
            memory_usage: self.memory_usage.load(Ordering::Relaxed) as usize,
            hit_rate,
            miss_rate: 10000 - hit_rate,
            eviction_count: self.eviction_count.load(Ordering::Relaxed),
            last_updated: Self::current_timestamp(),
        }
    }
    
    /// Evict expired entries
    pub async fn evict_expired_atomic(&self) -> usize {
        let now = Self::current_timestamp();
        let mut evicted_count = 0;
        
        let mut expired_keys = Vec::new();
        
        for entry in self.entries.iter() {
            let key = *entry.key();
            let cache_entry = entry.val();
            
            let expires_at = cache_entry.expires_at.load(Ordering::Acquire);
            if expires_at > 0 && now > expires_at {
                expired_keys.push(key);
            }
        }
        
        for key in expired_keys {
            if let Some(entry) = self.entries.remove(&key) {
                let size = entry.val().size.load(Ordering::Acquire);
                self.memory_usage.fetch_sub(size as u64, Ordering::AcqRel);
                self.total_entries.fetch_sub(1, Ordering::AcqRel);
                self.lru_tracker.remove_entry(key);
                evicted_count += 1;
            }
        }
        
        if evicted_count > 0 {
            self.eviction_count.fetch_add(evicted_count as u64, Ordering::Relaxed);
        }
        
        evicted_count
    }
    
    async fn evict_lru_entries(&self, needed_space: usize) {
        let lru_candidates = self.lru_tracker.get_lru_candidates(100);
        
        let mut freed_space = 0;
        let mut evicted_count = 0;
        
        for key in lru_candidates {
            if needed_space > 0 && freed_space >= needed_space {
                break;
            }
            
            if let Some(entry) = self.entries.remove(&key) {
                let size = entry.val().size.load(Ordering::Acquire);
                freed_space += size;
                evicted_count += 1;
                
                self.memory_usage.fetch_sub(size as u64, Ordering::AcqRel);
                self.total_entries.fetch_sub(1, Ordering::AcqRel);
                self.lru_tracker.remove_entry(key);
            }
        }
        
        if evicted_count > 0 {
            self.eviction_count.fetch_add(evicted_count, Ordering::Relaxed);
            debug!("L2 cache evicted {} LRU entries (freed {} bytes)", evicted_count, freed_space);
        }
    }
    
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

// Atomic LRU Tracker Implementation
impl AtomicLruTracker {
    /// Create new atomic LRU tracker
    pub fn new() -> Self {
        Self {
            global_counter: AtomicU64::new(0),
            position_map: Arc::new(LockFreeMap::new()),
            eviction_queue: Arc::new(lockfree::queue::Queue::new()),
        }
    }
    
    /// Update access for a key and return new position
    pub fn update_access(&self, key: u64) -> u64 {
        let new_position = self.global_counter.fetch_add(1, Ordering::AcqRel);
        self.position_map.insert(key, new_position);
        new_position
    }
    
    /// Get next position for new entry
    pub fn get_next_position(&self) -> u64 {
        self.global_counter.fetch_add(1, Ordering::AcqRel)
    }
    
    /// Add new entry to tracker
    pub fn add_entry(&self, key: u64, position: u64) {
        self.position_map.insert(key, position);
    }
    
    /// Remove entry from tracker
    pub fn remove_entry(&self, key: u64) {
        self.position_map.remove(&key);
    }
    
    /// Get LRU candidates for eviction
    pub fn get_lru_candidates(&self, max_count: usize) -> Vec<u64> {
        let mut candidates = Vec::new();
        
        // Collect all entries with their positions
        for entry in self.position_map.iter() {
            let key = *entry.key();
            let position = *entry.val();
            candidates.push((key, position));
        }
        
        // Sort by position (oldest first)
        candidates.sort_by_key(|&(_, position)| position);
        
        // Return up to max_count oldest entries
        candidates.into_iter()
            .take(max_count)
            .map(|(key, _)| key)
            .collect()
    }
}

// L3 SSD Cache Implementation
impl L3SsdCache {
    /// Create new L3 SSD cache
    pub fn new(cache_dir: PathBuf, max_files: usize, max_size_bytes: u64) -> Result<Self, Box<dyn std::error::Error>> {
        std::fs::create_dir_all(&cache_dir)?;
        
        Ok(Self {
            cache_dir,
            mmap_files: Arc::new(RwLock::new(HashMap::new())),
            file_allocator: Arc::new(AtomicFileAllocator::new()),
            total_files: AtomicUsize::new(0),
            total_size: AtomicU64::new(0),
            hit_count: AtomicU64::new(0),
            miss_count: AtomicU64::new(0),
            max_files,
            max_size_bytes,
        })
    }
    
    /// Get data from L3 cache atomically
    pub async fn get_atomic(&self, key: u64) -> Option<Arc<[u8]>> {
        let mmap_files = self.mmap_files.read().await;
        
        if let Some(mmap_file) = mmap_files.get(&key) {
            // Update access statistics
            let now = Self::current_timestamp();
            mmap_file.last_accessed.store(now, Ordering::Relaxed);
            mmap_file.access_count.fetch_add(1, Ordering::Relaxed);
            
            self.hit_count.fetch_add(1, Ordering::Relaxed);
            
            // Return data from memory-mapped file
            Some(Arc::from(&mmap_file.mmap[..]))
        } else {
            self.miss_count.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
    
    /// Set data in L3 cache atomically
    pub async fn set_atomic(&self, key: u64, data: Arc<[u8]>, _ttl_seconds: u64) -> bool {
        let data_size = data.len();
        
        // Check size limits
        let current_size = self.total_size.load(Ordering::Acquire);
        if current_size + data_size as u64 > self.max_size_bytes {
            self.evict_lru_files(data_size).await;
            
            let current_size = self.total_size.load(Ordering::Acquire);
            if current_size + data_size as u64 > self.max_size_bytes {
                return false;
            }
        }
        
        // Check file count limits
        let current_files = self.total_files.load(Ordering::Acquire);
        if current_files >= self.max_files {
            self.evict_lru_files(0).await;
            
            let current_files = self.total_files.load(Ordering::Acquire);
            if current_files >= self.max_files {
                return false;
            }
        }
        
        // Create memory-mapped file
        match self.create_mmap_file(key, &data).await {
            Ok(mmap_file) => {
                let mut mmap_files = self.mmap_files.write().await;
                
                // Remove existing file if present
                if let Some(existing) = mmap_files.remove(&key) {
                    self.total_size.fetch_sub(existing.size as u64, Ordering::AcqRel);
                    let _ = std::fs::remove_file(&existing.path);
                } else {
                    self.total_files.fetch_add(1, Ordering::AcqRel);
                }
                
                // Insert new file
                mmap_files.insert(key, Arc::new(mmap_file));
                self.total_size.fetch_add(data_size as u64, Ordering::AcqRel);
                
                true
            }
            Err(e) => {
                error!("Failed to create memory-mapped cache file: {}", e);
                false
            }
        }
    }
    
    /// Invalidate entry atomically
    pub async fn invalidate_atomic(&self, key: u64) -> bool {
        let mut mmap_files = self.mmap_files.write().await;
        
        if let Some(mmap_file) = mmap_files.remove(&key) {
            self.total_size.fetch_sub(mmap_file.size as u64, Ordering::AcqRel);
            self.total_files.fetch_sub(1, Ordering::AcqRel);
            
            // Remove file from disk
            let _ = std::fs::remove_file(&mmap_file.path);
            
            true
        } else {
            false
        }
    }
    
    /// Get L3 cache statistics
    pub async fn get_statistics_atomic(&self) -> AtomicCacheStats {
        let hit_count = self.hit_count.load(Ordering::Relaxed);
        let miss_count = self.miss_count.load(Ordering::Relaxed);
        let total_requests = hit_count + miss_count;
        
        let hit_rate = if total_requests > 0 {
            hit_count * 10000 / total_requests
        } else {
            0
        };
        
        AtomicCacheStats {
            total_entries: self.total_files.load(Ordering::Relaxed),
            memory_usage: self.total_size.load(Ordering::Relaxed) as usize,
            hit_rate,
            miss_rate: 10000 - hit_rate,
            eviction_count: 0, // TODO: Track evictions
            last_updated: Self::current_timestamp(),
        }
    }
    
    /// Evict expired entries
    pub async fn evict_expired_atomic(&self) -> usize {
        // L3 cache doesn't use TTL-based expiration, only LRU
        0
    }
    
    async fn create_mmap_file(&self, key: u64, data: &[u8]) -> Result<MmapCacheFile, Box<dyn std::error::Error>> {
        let file_id = self.file_allocator.allocate_file_id();
        let file_path = self.cache_dir.join(format!("cache_{:016x}_{}.dat", key, file_id));
        
        // Create and write file
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(true)
            .open(&file_path)?;
        
        file.write_all(data)?;
        file.flush()?;
        
        // Create memory mapping
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        
        let now = Self::current_timestamp();
        
        Ok(MmapCacheFile {
            path: file_path,
            mmap,
            key,
            size: data.len(),
            created_at: now,
            last_accessed: AtomicU64::new(now),
            access_count: AtomicU64::new(0),
        })
    }
    
    async fn evict_lru_files(&self, needed_space: usize) {
        let mut candidates = Vec::new();
        
        // Collect LRU candidates
        {
            let mmap_files = self.mmap_files.read().await;
            for (key, mmap_file) in mmap_files.iter() {
                let last_accessed = mmap_file.last_accessed.load(Ordering::Acquire);
                let access_count = mmap_file.access_count.load(Ordering::Acquire);
                candidates.push((*key, last_accessed, access_count, mmap_file.size));
            }
        }
        
        // Sort by access time and access count
        candidates.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
        
        let mut freed_space = 0;
        let mut evicted_count = 0;
        
        for (key, _, _, size) in candidates {
            if needed_space > 0 && freed_space >= needed_space {
                break;
            }
            
            if self.invalidate_atomic(key).await {
                freed_space += size;
                evicted_count += 1;
            }
            
            if evicted_count >= 10 {
                break;
            }
        }
        
        if evicted_count > 0 {
            debug!("L3 cache evicted {} files (freed {} bytes)", evicted_count, freed_space);
        }
    }
    
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

// Atomic File Allocator Implementation
impl AtomicFileAllocator {
    /// Create new atomic file allocator
    pub fn new() -> Self {
        Self {
            next_file_id: AtomicU64::new(1),
            allocated_size: AtomicU64::new(0),
            free_slots: Arc::new(lockfree::queue::Queue::new()),
        }
    }
    
    /// Allocate new file ID
    pub fn allocate_file_id(&self) -> u64 {
        // Try to reuse a free slot first
        if let Some(free_id) = self.free_slots.pop() {
            free_id
        } else {
            self.next_file_id.fetch_add(1, Ordering::AcqRel)
        }
    }
    
    /// Free a file ID for reuse
    pub fn free_file_id(&self, file_id: u64) {
        self.free_slots.push(file_id);
    }
    
    /// Update allocated size
    pub fn add_allocated_size(&self, size: u64) {
        self.allocated_size.fetch_add(size, Ordering::AcqRel);
    }
    
    /// Update allocated size
    pub fn sub_allocated_size(&self, size: u64) {
        self.allocated_size.fetch_sub(size, Ordering::AcqRel);
    }
    
    /// Get current allocated size
    pub fn get_allocated_size(&self) -> u64 {
        self.allocated_size.load(Ordering::Acquire)
    }
}

// Cache Warmer Implementation
impl CacheWarmer {
    /// Create new cache warmer
    pub fn new(enabled: bool, batch_size: usize, max_predictive_entries: usize) -> Self {
        Self {
            pattern_tracker: Arc::new(QueryPatternTracker::new()),
            predictive_cache: Arc::new(LockFreeMap::new()),
            warming_stats: Arc::new(WarmingStats::new()),
            enabled: AtomicBool::new(enabled),
            batch_size,
            max_predictive_entries,
        }
    }
    
    /// Record cache hit for pattern analysis
    pub async fn record_hit(&self, query_hash: u64) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        
        self.pattern_tracker.record_query(query_hash).await;
        
        // Check if we have a predictive entry that was hit
        if let Some(predictive_entry) = self.predictive_cache.get(&query_hash) {
            predictive_entry.val().hit_count.fetch_add(1, Ordering::Relaxed);
            self.warming_stats.predictions_hit.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    /// Record cache miss for pattern analysis
    pub async fn record_miss(&self, query_hash: u64) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        
        self.pattern_tracker.record_query(query_hash).await;
    }
    
    /// Record cache set operation
    pub async fn record_set(&self, query_hash: u64, data: &[u8]) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        
        self.pattern_tracker.record_query(query_hash).await;
        
        // Create predictive cache entry if patterns suggest it
        if self.should_create_predictive_entry(query_hash).await {
            self.create_predictive_entry(query_hash, data).await;
        }
    }
    
    /// Warm cache based on detected patterns
    pub async fn warm_cache(&self, l1_cache: &L1HotCache, l2_cache: &L2MemoryCache) -> usize {
        if !self.enabled.load(Ordering::Acquire) {
            return 0;
        }
        
        let predictions = self.generate_predictions().await;
        let mut warmed_count = 0;
        
        for prediction in predictions.into_iter().take(self.batch_size) {
            if let Some(predictive_entry) = self.predictive_cache.get(&prediction.query_hash) {
                let entry = predictive_entry.val();
                
                // Warm L1 cache
                if l1_cache.set_atomic(
                    prediction.query_hash,
                    entry.predicted_data.clone(),
                    300, // 5 minutes TTL
                ).await {
                    warmed_count += 1;
                }
                
                // Warm L2 cache
                let _ = l2_cache.set_atomic(
                    prediction.query_hash,
                    entry.predicted_data.clone(),
                    600, // 10 minutes TTL
                ).await;
            }
        }
        
        if warmed_count > 0 {
            self.warming_stats.cache_warmed_entries.fetch_add(warmed_count as u64, Ordering::Relaxed);
            debug!("Cache warmer preloaded {} entries", warmed_count);
        }
        
        warmed_count
    }
    
    /// Get warming statistics
    pub async fn get_statistics(&self) -> WarmingStatistics {
        let predictions_made = self.warming_stats.predictions_made.load(Ordering::Relaxed);
        let predictions_hit = self.warming_stats.predictions_hit.load(Ordering::Relaxed);
        
        let prediction_accuracy = if predictions_made > 0 {
            predictions_hit * 100 / predictions_made
        } else {
            0
        };
        
        WarmingStatistics {
            predictions_made,
            predictions_hit,
            patterns_detected: self.warming_stats.patterns_detected.load(Ordering::Relaxed),
            cache_warmed_entries: self.warming_stats.cache_warmed_entries.load(Ordering::Relaxed),
            prediction_accuracy,
        }
    }
    
    async fn should_create_predictive_entry(&self, query_hash: u64) -> bool {
        // Check if query frequency suggests caching
        if let Some(frequency) = self.pattern_tracker.query_frequency.get(&query_hash) {
            let freq = frequency.val();
            let count = freq.count.load(Ordering::Relaxed);
            let score = freq.frequency_score.load(Ordering::Relaxed);
            
            // Cache if query has been seen multiple times with high score
            count >= 3 && score >= 7000 // 70% confidence threshold
        } else {
            false
        }
    }
    
    async fn create_predictive_entry(&self, query_hash: u64, data: &[u8]) {
        let now = Self::current_timestamp();
        
        let predictive_entry = Arc::new(PredictiveCacheEntry {
            query_hash,
            predicted_data: Arc::from(data),
            confidence: AtomicU64::new(8000), // 80% initial confidence
            created_at: AtomicU64::new(now),
            expires_at: AtomicU64::new(now + 3600), // 1 hour expiry
            hit_count: AtomicU64::new(0),
        });
        
        // Check if we have space for more predictive entries
        let current_entries = self.predictive_cache.iter().count();
        if current_entries >= self.max_predictive_entries {
            // Remove oldest entries
            self.evict_old_predictive_entries().await;
        }
        
        self.predictive_cache.insert(query_hash, predictive_entry);
        self.warming_stats.predictions_made.fetch_add(1, Ordering::Relaxed);
    }
    
    async fn generate_predictions(&self) -> Vec<CachePrediction> {
        let mut predictions = Vec::new();
        
        // Generate predictions based on query frequency
        for entry in self.pattern_tracker.query_frequency.iter() {
            let query_hash = *entry.key();
            let frequency = entry.val();
            
            let score = frequency.frequency_score.load(Ordering::Relaxed);
            let last_seen = frequency.last_seen.load(Ordering::Relaxed);
            let now = Self::current_timestamp();
            
            // Predict queries that are frequently accessed and recently seen
            if score >= 6000 && (now - last_seen) < 3600 {
                predictions.push(CachePrediction {
                    query_hash,
                    confidence: score,
                    predicted_time: now + 300, // Predict access in 5 minutes
                });
            }
        }
        
        // Sort by confidence
        predictions.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        
        predictions
    }
    
    async fn evict_old_predictive_entries(&self) {
        let now = Self::current_timestamp();
        let mut expired_keys = Vec::new();
        
        // Collect expired entries
        for entry in self.predictive_cache.iter() {
            let key = *entry.key();
            let predictive_entry = entry.val();
            
            let expires_at = predictive_entry.expires_at.load(Ordering::Acquire);
            if now > expires_at {
                expired_keys.push(key);
            }
        }
        
        // Remove expired entries
        for key in expired_keys {
            self.predictive_cache.remove(&key);
        }
    }
    
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

/// Cache prediction for warming
#[derive(Debug)]
struct CachePrediction {
    query_hash: u64,
    confidence: u64,
    predicted_time: u64,
}

// Query Pattern Tracker Implementation
impl QueryPatternTracker {
    /// Create new query pattern tracker
    pub fn new() -> Self {
        Self {
            query_frequency: Arc::new(LockFreeMap::new()),
            sequence_patterns: Arc::new(LockFreeMap::new()),
            time_patterns: Arc::new(LockFreeMap::new()),
        }
    }
    
    /// Record a query for pattern analysis
    pub async fn record_query(&self, query_hash: u64) {
        let now = Self::current_timestamp();
        
        // Update query frequency
        if let Some(frequency) = self.query_frequency.get(&query_hash) {
            let freq = frequency.val();
            freq.count.fetch_add(1, Ordering::Relaxed);
            freq.last_seen.store(now, Ordering::Relaxed);
            
            // Update frequency score based on recency and count
            let count = freq.count.load(Ordering::Relaxed);
            let time_since_last = now - freq.last_seen.load(Ordering::Relaxed);
            
            // Calculate score: higher for frequent recent queries
            let recency_factor = if time_since_last < 300 { 10000 } else { 5000 };
            let frequency_factor = (count * 1000).min(5000);
            let score = (recency_factor + frequency_factor) / 2;
            
            freq.frequency_score.store(score, Ordering::Relaxed);
        } else {
            let frequency = Arc::new(QueryFrequency {
                query_hash,
                count: AtomicU64::new(1),
                last_seen: AtomicU64::new(now),
                frequency_score: AtomicU64::new(5000), // Initial score
            });
            
            self.query_frequency.insert(query_hash, frequency);
        }
        
        // Update time-based patterns
        self.update_time_patterns(query_hash, now).await;
    }
    
    async fn update_time_patterns(&self, query_hash: u64, timestamp: u64) {
        let datetime = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);
        let datetime = datetime.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        
        // Calculate hour and day of week
        let total_hours = datetime.as_secs() / 3600;
        let hour_of_day = (total_hours % 24) as usize;
        let day_of_week = ((total_hours / 24) % 7) as usize;
        
        if let Some(time_pattern) = self.time_patterns.get(&query_hash) {
            let pattern = time_pattern.val();
            pattern.hour_frequency[hour_of_day].fetch_add(1, Ordering::Relaxed);
            pattern.day_frequency[day_of_week].fetch_add(1, Ordering::Relaxed);
            
            // Update peak hours bit mask
            let hour_freq = pattern.hour_frequency[hour_of_day].load(Ordering::Relaxed);
            if hour_freq >= 5 { // Consider peak if >= 5 queries in this hour
                let current_peaks = pattern.peak_hours.load(Ordering::Relaxed);
                let new_peaks = current_peaks | (1u64 << hour_of_day);
                pattern.peak_hours.store(new_peaks, Ordering::Relaxed);
            }
        } else {
            let mut hour_frequency = [const { AtomicU64::new(0) }; 24];
            let mut day_frequency = [const { AtomicU64::new(0) }; 7];
            
            hour_frequency[hour_of_day] = AtomicU64::new(1);
            day_frequency[day_of_week] = AtomicU64::new(1);
            
            let time_pattern = Arc::new(TimePattern {
                query_hash,
                hour_frequency,
                day_frequency,
                peak_hours: AtomicU64::new(0),
            });
            
            self.time_patterns.insert(query_hash, time_pattern);
        }
    }
    
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

// Warming Stats Implementation
impl WarmingStats {
    fn new() -> Self {
        Self {
            predictions_made: AtomicU64::new(0),
            predictions_hit: AtomicU64::new(0),
            patterns_detected: AtomicU64::new(0),
            cache_warmed_entries: AtomicU64::new(0),
        }
    }
}

// Implement AtomicZeroCopyCache trait for MultiLevelAtomicCache
impl AtomicZeroCopyCache for MultiLevelAtomicCache {
    async fn get_raw_atomic(&self, key: u64) -> Option<Arc<[u8]>> {
        self.get_atomic(key).await
    }

    async fn set_raw_atomic(&self, key: u64, data: Arc<[u8]>, expires_at: u64) -> bool {
        let ttl = if expires_at > 0 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            expires_at.saturating_sub(now)
        } else {
            300 // Default 5 minutes
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
        
        // Process batch requests concurrently
        let futures = keys.iter().map(|&key| self.get_atomic(key));
        let batch_results = futures::future::join_all(futures).await;
        
        results.extend(batch_results);
        results
    }

    async fn set_batch_atomic(&self, entries: &[(u64, Arc<[u8]>, u64)]) -> Vec<bool> {
        let mut results = Vec::with_capacity(entries.len());
        
        // Process batch sets concurrently
        let futures = entries.iter().map(|(key, data, expires_at)| {
            self.set_raw_atomic(*key, data.clone(), *expires_at)
        });
        let batch_results = futures::future::join_all(futures).await;
        
        results.extend(batch_results);
        results
    }

    async fn invalidate_atomic(&self, key: u64) -> bool {
        self.invalidate_atomic(key).await
    }

    async fn invalidate_pattern_atomic(&self, pattern_hash: u64) -> usize {
        // TODO: Implement pattern-based invalidation
        // This would require storing pattern information with cache entries
        let _ = pattern_hash;
        0
    }

    async fn stats_atomic(&self) -> AtomicCacheStats {
        let multi_stats = self.get_statistics_atomic().await;
        
        // Return combined statistics from all levels
        AtomicCacheStats {
            total_entries: multi_stats.l1_stats.total_entries + 
                          multi_stats.l2_stats.total_entries + 
                          multi_stats.l3_stats.total_entries,
            memory_usage: multi_stats.l1_stats.memory_usage + 
                         multi_stats.l2_stats.memory_usage + 
                         multi_stats.l3_stats.memory_usage,
            hit_rate: multi_stats.overall_hit_ratio,
            miss_rate: 10000 - multi_stats.overall_hit_ratio,
            eviction_count: multi_stats.l1_stats.eviction_count + 
                           multi_stats.l2_stats.eviction_count + 
                           multi_stats.l3_stats.eviction_count,
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    async fn evict_expired_atomic(&self) -> usize {
        let maintenance_result = self.maintenance_atomic().await;
        maintenance_result.l1_evicted + maintenance_result.l2_evicted + maintenance_result.l3_evicted
    }

    async fn compact_atomic(&self) -> bool {
        // Perform compaction across all cache levels
        let l1_compacted = self.l1_cache.evict_expired_atomic().await > 0;
        let l2_compacted = self.l2_cache.evict_expired_atomic().await > 0;
        let l3_compacted = self.l3_cache.evict_expired_atomic().await > 0;
        
        l1_compacted || l2_compacted || l3_compacted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_multi_level_cache_basic_operations() {
        let temp_dir = TempDir::new().unwrap();
        let config = MultiLevelCacheConfig {
            l1_max_entries: 10,
            l1_max_memory_mb: 1,
            l2_max_entries: 20,
            l2_max_memory_mb: 2,
            l3_cache_dir: temp_dir.path().to_path_buf(),
            l3_max_files: 5,
            l3_max_size_gb: 1,
            enable_cache_warming: true,
            warming_batch_size: 5,
            predictive_cache_size: 10,
        };
        
        let cache = MultiLevelAtomicCache::new(config).unwrap();
        
        let key = 12345u64;
        let data: Arc<[u8]> = Arc::from(b"test data".as_slice());
        
        // Set data
        assert!(cache.set_atomic(key, data.clone(), 60).await);
        
        // Get data (should hit L1)
        let retrieved = cache.get_atomic(key).await.unwrap();
        assert_eq!(&retrieved[..], b"test data");
        
        // Check statistics
        let stats = cache.get_statistics_atomic().await;
        assert!(stats.l1_stats.total_entries > 0);
        assert!(stats.overall_hit_ratio > 0);
    }

    #[tokio::test]
    async fn test_cache_promotion() {
        let temp_dir = TempDir::new().unwrap();
        let config = MultiLevelCacheConfig {
            l1_max_entries: 1, // Very small L1 to force eviction
            l1_max_memory_mb: 1,
            l2_max_entries: 10,
            l2_max_memory_mb: 2,
            l3_cache_dir: temp_dir.path().to_path_buf(),
            l3_max_files: 5,
            l3_max_size_gb: 1,
            enable_cache_warming: false,
            warming_batch_size: 5,
            predictive_cache_size: 10,
        };
        
        let cache = MultiLevelAtomicCache::new(config).unwrap();
        
        let data1: Arc<[u8]> = Arc::from(b"test data 1".as_slice());
        let data2: Arc<[u8]> = Arc::from(b"test data 2".as_slice());
        
        // Set first item
        assert!(cache.set_atomic(1, data1.clone(), 60).await);
        
        // Set second item (should evict first from L1)
        assert!(cache.set_atomic(2, data2.clone(), 60).await);
        
        // Get first item (should promote from L2 to L1)
        let retrieved = cache.get_atomic(1).await.unwrap();
        assert_eq!(&retrieved[..], b"test data 1");
        
        // Verify it's now in L1
        let l1_data = cache.l1_cache.get_atomic(1).await;
        assert!(l1_data.is_some());
    }

    #[tokio::test]
    async fn test_cache_warming() {
        let temp_dir = TempDir::new().unwrap();
        let config = MultiLevelCacheConfig {
            l1_max_entries: 10,
            l1_max_memory_mb: 1,
            l2_max_entries: 20,
            l2_max_memory_mb: 2,
            l3_cache_dir: temp_dir.path().to_path_buf(),
            l3_max_files: 5,
            l3_max_size_gb: 1,
            enable_cache_warming: true,
            warming_batch_size: 5,
            predictive_cache_size: 10,
        };
        
        let cache = MultiLevelAtomicCache::new(config).unwrap();
        
        let key = 12345u64;
        let data: Arc<[u8]> = Arc::from(b"test data".as_slice());
        
        // Simulate multiple accesses to build pattern
        for _ in 0..5 {
            cache.cache_warmer.record_hit(key).await;
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
        
        // Set data to trigger predictive caching
        assert!(cache.set_atomic(key, data.clone(), 60).await);
        
        // Check warming statistics
        let warming_stats = cache.cache_warmer.get_statistics().await;
        assert!(warming_stats.predictions_made > 0);
    }

    #[tokio::test]
    async fn test_l3_memory_mapped_cache() {
        let temp_dir = TempDir::new().unwrap();
        let l3_cache = L3SsdCache::new(
            temp_dir.path().to_path_buf(),
            10,
            1024 * 1024, // 1MB
        ).unwrap();
        
        let key = 12345u64;
        let data: Arc<[u8]> = Arc::from(b"test data for memory mapping".as_slice());
        
        // Set data in L3 cache
        assert!(l3_cache.set_atomic(key, data.clone(), 60).await);
        
        // Get data from L3 cache
        let retrieved = l3_cache.get_atomic(key).await.unwrap();
        assert_eq!(&retrieved[..], b"test data for memory mapping");
        
        // Verify file was created
        let stats = l3_cache.get_statistics_atomic().await;
        assert_eq!(stats.total_entries, 1);
        assert!(stats.memory_usage > 0);
    }

    #[tokio::test]
    async fn test_atomic_lru_tracker() {
        let lru_tracker = AtomicLruTracker::new();
        
        // Add entries
        lru_tracker.add_entry(1, lru_tracker.get_next_position());
        lru_tracker.add_entry(2, lru_tracker.get_next_position());
        lru_tracker.add_entry(3, lru_tracker.get_next_position());
        
        // Update access for entry 1 (should move it to end)
        lru_tracker.update_access(1);
        
        // Get LRU candidates (should return 2, 3 first)
        let candidates = lru_tracker.get_lru_candidates(2);
        assert_eq!(candidates.len(), 2);
        assert!(candidates.contains(&2));
        assert!(candidates.contains(&3));
        assert!(!candidates.contains(&1)); // Should not be in LRU list
    }
}