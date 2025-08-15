//! Atomic data structures and lock-free collections for high-performance DNS operations
//!
//! This module provides lock-free data structures optimized for concurrent DNS query processing,
//! zone management, and clustering operations. All structures use atomic operations and
//! compare-and-swap for thread-safe access without locks.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use lockfree::map::Map as LockFreeMap;
use crate::types::{NodeInfo, ZoneMetadata};
use crate::error::DnsResult;

/// Atomic zone metadata with compare-and-swap operations
#[derive(Debug)]
pub struct AtomicZoneMetadata {
    /// Zone name hash (immutable after creation)
    pub name_hash: u64,
    /// Zone name (immutable after creation)
    pub name: Arc<str>,
    /// Current version number (atomic updates)
    pub version: AtomicU64,
    /// Serial number for SOA record (atomic updates)
    pub serial: AtomicU32,
    /// Last modification timestamp (atomic updates)
    pub last_modified: AtomicU64,
    /// Number of records in zone (atomic updates)
    pub record_count: AtomicU32,
    /// Zone size in bytes (atomic updates)
    pub size_bytes: AtomicU64,
    /// Access counter for LRU eviction (atomic updates)
    pub access_count: AtomicU64,
    /// Loading state flag (atomic updates)
    pub is_loading: AtomicBool,
    /// Authoritative flag (atomic updates)
    pub is_authoritative: AtomicBool,
    /// DNSSEC enabled flag (atomic updates)
    pub dnssec_enabled: AtomicBool,
}

impl AtomicZoneMetadata {
    /// Create new atomic zone metadata
    pub fn new(name: String, name_hash: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Self {
            name_hash,
            name: Arc::from(name),
            version: AtomicU64::new(1),
            serial: AtomicU32::new(1),
            last_modified: AtomicU64::new(now),
            record_count: AtomicU32::new(0),
            size_bytes: AtomicU64::new(0),
            access_count: AtomicU64::new(0),
            is_loading: AtomicBool::new(false),
            is_authoritative: AtomicBool::new(false),
            dnssec_enabled: AtomicBool::new(false),
        }
    }
    
    /// Atomically increment version and update timestamp
    pub fn increment_version(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        self.last_modified.store(now, Ordering::Release);
        self.version.fetch_add(1, Ordering::AcqRel)
    }
    
    /// Atomically update record count
    pub fn update_record_count(&self, count: u32) {
        self.record_count.store(count, Ordering::Release);
    }
    
    /// Atomically update size
    pub fn update_size(&self, size: u64) {
        self.size_bytes.store(size, Ordering::Release);
    }
    
    /// Atomically increment access count
    pub fn record_access(&self) -> u64 {
        self.access_count.fetch_add(1, Ordering::Relaxed)
    }
    
    /// Compare and swap version (for optimistic concurrency control)
    pub fn compare_and_swap_version(&self, expected: u64, new: u64) -> Result<u64, u64> {
        match self.version.compare_exchange_weak(
            expected,
            new,
            Ordering::AcqRel,
            Ordering::Acquire
        ) {
            Ok(old) => Ok(old),
            Err(actual) => Err(actual),
        }
    }
    
    /// Get current version
    pub fn current_version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }
    
    /// Check if zone is currently loading
    pub fn is_loading(&self) -> bool {
        self.is_loading.load(Ordering::Acquire)
    }
    
    /// Set loading state atomically
    pub fn set_loading(&self, loading: bool) -> bool {
        self.is_loading.swap(loading, Ordering::AcqRel)
    }
    
    /// Convert to regular ZoneMetadata for API responses
    pub fn to_zone_metadata(&self) -> ZoneMetadata {
        ZoneMetadata {
            name: self.name.to_string(),
            name_hash: self.name_hash,
            serial: self.serial.load(Ordering::Acquire),
            version: self.version.load(Ordering::Acquire),
            last_modified: self.last_modified.load(Ordering::Acquire),
            record_count: self.record_count.load(Ordering::Acquire),
            size_bytes: self.size_bytes.load(Ordering::Acquire),
            is_authoritative: self.is_authoritative.load(Ordering::Acquire),
            dnssec_enabled: self.dnssec_enabled.load(Ordering::Acquire),
        }
    }
}

/// Lock-free hash map for zone storage
pub struct AtomicZoneStorage {
    /// Zone metadata indexed by zone hash
    zones: Arc<LockFreeMap<u64, Arc<AtomicZoneMetadata>>>,
    /// Zone data indexed by zone hash (atomic pointers to memory-mapped data)
    zone_data: Arc<LockFreeMap<u64, Arc<AtomicPtr<u8>>>>,
    /// Total number of zones (atomic counter)
    zone_count: AtomicUsize,
    /// Total storage size (atomic counter)
    total_size: AtomicU64,
}

impl AtomicZoneStorage {
    /// Create new atomic zone storage
    pub fn new() -> Self {
        Self {
            zones: Arc::new(LockFreeMap::new()),
            zone_data: Arc::new(LockFreeMap::new()),
            zone_count: AtomicUsize::new(0),
            total_size: AtomicU64::new(0),
        }
    }
    
    /// Insert zone metadata atomically
    pub fn insert_zone(&self, zone_hash: u64, metadata: Arc<AtomicZoneMetadata>) -> Option<Arc<AtomicZoneMetadata>> {
        let result = self.zones.insert(zone_hash, metadata.clone());
        if result.is_none() {
            self.zone_count.fetch_add(1, Ordering::Relaxed);
            self.total_size.fetch_add(metadata.size_bytes.load(Ordering::Acquire), Ordering::Relaxed);
        }
        result.map(|removed| removed.val().clone())
    }
    
    /// Get zone metadata by hash
    pub fn get_zone(&self, zone_hash: u64) -> Option<Arc<AtomicZoneMetadata>> {
        if let Some(zone_guard) = self.zones.get(&zone_hash) {
            let zone = zone_guard.val().clone();
            zone.record_access();
            Some(zone)
        } else {
            None
        }
    }
    
    /// Remove zone atomically
    pub fn remove_zone(&self, zone_hash: u64) -> Option<Arc<AtomicZoneMetadata>> {
        if let Some(removed) = self.zones.remove(&zone_hash) {
            self.zone_data.remove(&zone_hash);
            self.zone_count.fetch_sub(1, Ordering::Relaxed);
            self.total_size.fetch_sub(removed.val().size_bytes.load(Ordering::Acquire), Ordering::Relaxed);
            Some(removed.val().clone())
        } else {
            None
        }
    }
    
    /// List all zone hashes
    pub fn list_zones(&self) -> Vec<u64> {
        self.zones.iter().map(|guard| *guard.key()).collect()
    }
    
    /// Get zone count
    pub fn zone_count(&self) -> usize {
        self.zone_count.load(Ordering::Relaxed)
    }
    
    /// Get total storage size
    pub fn total_size(&self) -> u64 {
        self.total_size.load(Ordering::Relaxed)
    }
    
    /// Update zone data pointer atomically
    pub fn update_zone_data(&self, zone_hash: u64, data_ptr: *mut u8) -> bool {
        if let Some(atomic_ptr_guard) = self.zone_data.get(&zone_hash) {
            atomic_ptr_guard.val().store(data_ptr, Ordering::Release);
            true
        } else {
            // Insert new atomic pointer
            let atomic_ptr = Arc::new(AtomicPtr::new(data_ptr));
            self.zone_data.insert(zone_hash, atomic_ptr);
            true
        }
    }
    
    /// Get zone data pointer atomically
    pub fn get_zone_data(&self, zone_hash: u64) -> Option<*mut u8> {
        self.zone_data.get(&zone_hash)
            .map(|atomic_ptr_guard| atomic_ptr_guard.val().load(Ordering::Acquire))
    }
}

impl Default for AtomicZoneStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Lock-free cache with atomic operations
pub struct AtomicCache {
    /// Cache entries indexed by query hash
    entries: Arc<LockFreeMap<u64, Arc<AtomicCacheEntry>>>,
    /// Cache size in bytes (atomic counter)
    size_bytes: AtomicU64,
    /// Cache entry count (atomic counter)
    entry_count: AtomicUsize,
    /// Cache hit counter (atomic)
    hits: AtomicU64,
    /// Cache miss counter (atomic)
    misses: AtomicU64,
    /// Eviction counter (atomic)
    evictions: AtomicU64,
    /// Maximum cache size
    max_size_bytes: u64,
    /// Maximum number of entries
    max_entries: usize,
}

/// Atomic cache entry
#[derive(Debug)]
pub struct AtomicCacheEntry {
    /// Response data (immutable after creation)
    pub data: Arc<[u8]>,
    /// Expiration timestamp (atomic)
    pub expires_at: AtomicU64,
    /// Hit count for LRU eviction (atomic)
    pub hit_count: AtomicU64,
    /// Last access timestamp (atomic)
    pub last_accessed: AtomicU64,
    /// Entry size in bytes (immutable)
    pub size: usize,
    /// Valid flag (atomic)
    pub is_valid: AtomicBool,
}

impl AtomicCacheEntry {
    /// Create new cache entry
    pub fn new(data: Arc<[u8]>, ttl_seconds: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Self {
            size: data.len(),
            data,
            expires_at: AtomicU64::new(now + ttl_seconds as u64),
            hit_count: AtomicU64::new(0),
            last_accessed: AtomicU64::new(now),
            is_valid: AtomicBool::new(true),
        }
    }
    
    /// Check if entry is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expires_at.load(Ordering::Acquire)
    }
    
    /// Record access and return data if valid
    pub fn access(&self) -> Option<Arc<[u8]>> {
        if !self.is_valid.load(Ordering::Acquire) || self.is_expired() {
            return None;
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        self.hit_count.fetch_add(1, Ordering::Relaxed);
        self.last_accessed.store(now, Ordering::Release);
        
        Some(self.data.clone())
    }
    
    /// Invalidate entry atomically
    pub fn invalidate(&self) {
        self.is_valid.store(false, Ordering::Release);
    }
}

impl AtomicCache {
    /// Create new atomic cache
    pub fn new(max_size_bytes: u64, max_entries: usize) -> Self {
        Self {
            entries: Arc::new(LockFreeMap::new()),
            size_bytes: AtomicU64::new(0),
            entry_count: AtomicUsize::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            max_size_bytes,
            max_entries,
        }
    }
    
    /// Get entry from cache
    pub fn get(&self, key: u64) -> Option<Arc<[u8]>> {
        if let Some(entry_guard) = self.entries.get(&key) {
            if let Some(data) = entry_guard.val().access() {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(data);
            } else {
                // Entry expired or invalid, remove it
                self.remove_entry(key, entry_guard.val());
            }
        }
        
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }
    
    /// Insert entry into cache
    pub fn insert(&self, key: u64, data: Arc<[u8]>, ttl_seconds: u32) -> bool {
        let entry = Arc::new(AtomicCacheEntry::new(data, ttl_seconds));
        let entry_size = entry.size as u64;
        
        // Check if we need to evict entries
        self.maybe_evict(entry_size);
        
        // Insert the entry
        if self.entries.insert(key, entry).is_none() {
            self.size_bytes.fetch_add(entry_size, Ordering::Relaxed);
            self.entry_count.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
    
    /// Remove entry from cache
    pub fn remove(&self, key: u64) -> bool {
        if let Some(removed) = self.entries.remove(&key) {
            self.remove_entry(key, removed.val());
            true
        } else {
            false
        }
    }
    
    /// Remove entry and update counters
    fn remove_entry(&self, _key: u64, entry: &Arc<AtomicCacheEntry>) {
        self.size_bytes.fetch_sub(entry.size as u64, Ordering::Relaxed);
        self.entry_count.fetch_sub(1, Ordering::Relaxed);
    }
    
    /// Maybe evict entries if cache is full
    fn maybe_evict(&self, new_entry_size: u64) {
        let current_size = self.size_bytes.load(Ordering::Relaxed);
        let current_count = self.entry_count.load(Ordering::Relaxed);
        
        // Check if we need to evict based on size or count
        if current_size + new_entry_size > self.max_size_bytes || current_count >= self.max_entries {
            self.evict_lru_entries();
        }
    }
    
    /// Evict least recently used entries
    fn evict_lru_entries(&self) {
        let mut entries_to_evict = Vec::new();
        
        // Collect entries sorted by last access time
        for entry_guard in self.entries.iter() {
            if entry_guard.val().is_expired() || !entry_guard.val().is_valid.load(Ordering::Acquire) {
                entries_to_evict.push(*entry_guard.key());
            }
        }
        
        // Remove expired/invalid entries first
        for key in entries_to_evict {
            self.entries.remove(&key);
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
        
        // If still over limit, remove LRU entries
        let current_count = self.entry_count.load(Ordering::Relaxed);
        if current_count >= self.max_entries {
            let mut lru_entries: Vec<_> = self.entries.iter()
                .map(|entry_guard| (*entry_guard.key(), entry_guard.val().last_accessed.load(Ordering::Acquire)))
                .collect();
                
            lru_entries.sort_by_key(|(_, last_accessed)| *last_accessed);
            
            let to_remove = current_count - (self.max_entries * 3 / 4); // Remove 25% of entries
            for (key, _) in lru_entries.into_iter().take(to_remove) {
                self.entries.remove(&key);
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    
    /// Get cache statistics
    pub fn stats(&self) -> AtomicCacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        let hit_rate = if total > 0 { (hits * 10000) / total } else { 0 };
        
        AtomicCacheStats {
            size_bytes: self.size_bytes.load(Ordering::Relaxed),
            entry_count: self.entry_count.load(Ordering::Relaxed),
            hits,
            misses,
            hit_rate,
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }
    
    /// Clear all entries
    pub fn clear(&self) {
        // Remove all entries one by one since lockfree map doesn't have clear()
        let keys: Vec<u64> = self.entries.iter().map(|guard| *guard.key()).collect();
        for key in keys {
            self.entries.remove(&key);
        }
        self.size_bytes.store(0, Ordering::Release);
        self.entry_count.store(0, Ordering::Release);
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct AtomicCacheStats {
    pub size_bytes: u64,
    pub entry_count: usize,
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: u64, // Percentage * 100 (0-10000)
    pub evictions: u64,
}

impl Default for AtomicCache {
    fn default() -> Self {
        Self::new(1024 * 1024 * 1024, 1000000) // 1GB, 1M entries
    }
}

/// Atomic consistent hash ring for unlimited cluster scaling
pub struct AtomicConsistentHashRing {
    /// Lock-free hash ring with atomic updates
    ring: Arc<LockFreeMap<u64, Arc<AtomicNodeInfo>>>,
    /// Virtual nodes per physical node (atomic configuration)
    virtual_nodes_per_node: AtomicU32,
    /// Total nodes in ring (atomic counter)
    total_nodes: AtomicUsize,
    /// Ring version for atomic updates
    ring_version: AtomicU64,
    /// Node health status
    node_health: Arc<LockFreeMap<u64, Arc<AtomicBool>>>,
}

/// Atomic node information for cluster management
#[derive(Debug)]
pub struct AtomicNodeInfo {
    /// Node ID (immutable after creation)
    pub node_id: u64,
    /// Node address (immutable after creation)
    pub address: Arc<str>,
    /// Region (immutable after creation)
    pub region: Arc<str>,
    /// Datacenter (immutable after creation)
    pub datacenter: Arc<str>,
    /// Load factor (atomic updates, fixed-point * 1000)
    pub load_factor: AtomicU32,
    /// Last seen timestamp (atomic updates)
    pub last_seen: AtomicU64,
    /// Health status (atomic updates)
    pub is_healthy: AtomicBool,
    /// Query count (atomic counter)
    pub query_count: AtomicU64,
    /// Response time sum for average calculation (atomic)
    pub response_time_sum_ns: AtomicU64,
    /// Connection count (atomic counter)
    pub connection_count: AtomicUsize,
}

impl AtomicNodeInfo {
    /// Create new atomic node info
    pub fn new(node_info: NodeInfo) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Self {
            node_id: node_info.node_id,
            address: Arc::from(node_info.address),
            region: Arc::from(node_info.region),
            datacenter: Arc::from(node_info.datacenter),
            load_factor: AtomicU32::new((node_info.load_factor * 1000.0) as u32),
            last_seen: AtomicU64::new(now),
            is_healthy: AtomicBool::new(node_info.is_healthy),
            query_count: AtomicU64::new(0),
            response_time_sum_ns: AtomicU64::new(0),
            connection_count: AtomicUsize::new(0),
        }
    }
    
    /// Update health status atomically
    pub fn set_healthy(&self, healthy: bool) {
        self.is_healthy.store(healthy, Ordering::Release);
        if healthy {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            self.last_seen.store(now, Ordering::Release);
        }
    }
    
    /// Record query with response time
    pub fn record_query(&self, response_time_ns: u64) {
        self.query_count.fetch_add(1, Ordering::Relaxed);
        self.response_time_sum_ns.fetch_add(response_time_ns, Ordering::Relaxed);
    }
    
    /// Update load factor atomically
    pub fn update_load_factor(&self, load_factor: f32) {
        self.load_factor.store((load_factor * 1000.0) as u32, Ordering::Release);
    }
    
    /// Get current load factor
    pub fn current_load_factor(&self) -> f32 {
        self.load_factor.load(Ordering::Acquire) as f32 / 1000.0
    }
    
    /// Get average response time
    pub fn average_response_time_ns(&self) -> u64 {
        let total_time = self.response_time_sum_ns.load(Ordering::Relaxed);
        let query_count = self.query_count.load(Ordering::Relaxed);
        if query_count > 0 {
            total_time / query_count
        } else {
            0
        }
    }
    
    /// Convert to regular NodeInfo for API responses
    pub fn to_node_info(&self) -> NodeInfo {
        NodeInfo {
            node_id: self.node_id,
            address: self.address.to_string(),
            region: self.region.to_string(),
            datacenter: self.datacenter.to_string(),
            capabilities: vec![], // Not stored in atomic version
            load_factor: self.current_load_factor(),
            last_seen: self.last_seen.load(Ordering::Acquire),
            is_healthy: self.is_healthy.load(Ordering::Acquire),
        }
    }
}

impl AtomicConsistentHashRing {
    /// Create new atomic consistent hash ring
    pub fn new(virtual_nodes_per_node: u32) -> Self {
        Self {
            ring: Arc::new(LockFreeMap::new()),
            virtual_nodes_per_node: AtomicU32::new(virtual_nodes_per_node),
            total_nodes: AtomicUsize::new(0),
            ring_version: AtomicU64::new(1),
            node_health: Arc::new(LockFreeMap::new()),
        }
    }
    
    /// Add node to ring atomically
    pub fn add_node(&self, node_info: NodeInfo) -> DnsResult<()> {
        let atomic_node = Arc::new(AtomicNodeInfo::new(node_info));
        let virtual_nodes = self.virtual_nodes_per_node.load(Ordering::Acquire);
        
        // Add virtual nodes to ring
        for i in 0..virtual_nodes {
            let virtual_hash = self.calculate_virtual_node_hash(atomic_node.node_id, i);
            self.ring.insert(virtual_hash, atomic_node.clone());
        }
        
        // Add health tracking
        let health = Arc::new(AtomicBool::new(atomic_node.is_healthy.load(Ordering::Acquire)));
        self.node_health.insert(atomic_node.node_id, health);
        
        self.total_nodes.fetch_add(1, Ordering::AcqRel);
        self.ring_version.fetch_add(1, Ordering::AcqRel);
        
        Ok(())
    }
    
    /// Remove node from ring atomically
    pub fn remove_node(&self, node_id: u64) -> DnsResult<()> {
        let virtual_nodes = self.virtual_nodes_per_node.load(Ordering::Acquire);
        
        // Remove all virtual nodes
        for i in 0..virtual_nodes {
            let virtual_hash = self.calculate_virtual_node_hash(node_id, i);
            self.ring.remove(&virtual_hash);
        }
        
        // Remove health tracking
        self.node_health.remove(&node_id);
        
        self.total_nodes.fetch_sub(1, Ordering::AcqRel);
        self.ring_version.fetch_add(1, Ordering::AcqRel);
        
        Ok(())
    }
    
    /// Find nodes responsible for a zone hash (O(log N) lookup)
    pub fn find_nodes_for_zone(&self, zone_hash: u64, replica_count: usize) -> Vec<u64> {
        let mut nodes = Vec::with_capacity(replica_count);
        let mut seen_nodes = std::collections::HashSet::new();
        let mut current_hash = zone_hash;
        let mut attempts = 0;
        let max_attempts = self.total_nodes.load(Ordering::Acquire) * 2; // Prevent infinite loops
        
        // Find unique nodes by walking the ring
        while nodes.len() < replica_count && attempts < max_attempts {
            if let Some(node) = self.find_next_node(current_hash) {
                if seen_nodes.insert(node.node_id) {
                    // Only add healthy nodes
                    if node.is_healthy.load(Ordering::Acquire) {
                        nodes.push(node.node_id);
                    }
                }
                // Move to next position in ring
                current_hash = current_hash.wrapping_add(1);
                attempts += 1;
            } else {
                break;
            }
        }
        
        nodes
    }
    
    /// Find next node in ring for given hash
    fn find_next_node(&self, hash: u64) -> Option<Arc<AtomicNodeInfo>> {
        // Find the first node with hash >= target hash
        let mut best_hash = u64::MAX;
        let mut best_node = None;
        
        for entry_guard in self.ring.iter() {
            if *entry_guard.key() >= hash && *entry_guard.key() < best_hash {
                best_hash = *entry_guard.key();
                best_node = Some(entry_guard.val().clone());
            }
        }
        
        // If no node found, wrap around to smallest hash
        if best_node.is_none() {
            let mut smallest_hash = u64::MAX;
            for entry_guard in self.ring.iter() {
                if *entry_guard.key() < smallest_hash {
                    smallest_hash = *entry_guard.key();
                    best_node = Some(entry_guard.val().clone());
                }
            }
        }
        
        best_node
    }
    
    /// Calculate virtual node hash
    fn calculate_virtual_node_hash(&self, node_id: u64, virtual_index: u32) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        node_id.hash(&mut hasher);
        virtual_index.hash(&mut hasher);
        hasher.finish()
    }
    
    /// Get next hash value
    fn next_hash(&self, hash: u64) -> u64 {
        hash.wrapping_add(1)
    }
    
    /// Update node health atomically
    pub fn update_node_health(&self, node_id: u64, healthy: bool) -> bool {
        if let Some(health_guard) = self.node_health.get(&node_id) {
            health_guard.val().store(healthy, Ordering::Release);
            
            // Also update the node info if it exists in ring
            let virtual_nodes = self.virtual_nodes_per_node.load(Ordering::Acquire);
            for i in 0..virtual_nodes {
                let virtual_hash = self.calculate_virtual_node_hash(node_id, i);
                if let Some(node_guard) = self.ring.get(&virtual_hash) {
                    node_guard.val().set_healthy(healthy);
                    break; // All virtual nodes point to same AtomicNodeInfo
                }
            }
            true
        } else {
            false
        }
    }
    
    /// Get node by ID
    pub fn get_node(&self, node_id: u64) -> Option<Arc<AtomicNodeInfo>> {
        let virtual_hash = self.calculate_virtual_node_hash(node_id, 0);
        self.ring.get(&virtual_hash).map(|guard| guard.val().clone())
    }
    
    /// List all nodes
    pub fn list_nodes(&self) -> Vec<Arc<AtomicNodeInfo>> {
        let mut nodes = Vec::new();
        let mut seen_nodes = std::collections::HashSet::new();
        
        for entry_guard in self.ring.iter() {
            if seen_nodes.insert(entry_guard.val().node_id) {
                nodes.push(entry_guard.val().clone());
            }
        }
        
        nodes
    }
    
    /// Get ring statistics
    pub fn stats(&self) -> ConsistentHashRingStats {
        let healthy_nodes = self.node_health.iter()
            .filter(|health_guard| health_guard.val().load(Ordering::Acquire))
            .count();
            
        ConsistentHashRingStats {
            total_nodes: self.total_nodes.load(Ordering::Relaxed),
            healthy_nodes,
            virtual_nodes_per_node: self.virtual_nodes_per_node.load(Ordering::Acquire),
            ring_version: self.ring_version.load(Ordering::Acquire),
            total_virtual_nodes: self.ring.iter().count(),
        }
    }
    
    /// Get current ring version
    pub fn ring_version(&self) -> u64 {
        self.ring_version.load(Ordering::Acquire)
    }
}

/// Consistent hash ring statistics
#[derive(Debug, Clone)]
pub struct ConsistentHashRingStats {
    pub total_nodes: usize,
    pub healthy_nodes: usize,
    pub virtual_nodes_per_node: u32,
    pub ring_version: u64,
    pub total_virtual_nodes: usize,
}

impl Default for AtomicConsistentHashRing {
    fn default() -> Self {
        Self::new(1000) // Default 1000 virtual nodes per physical node
    }
}

/// Atomic statistics collector for performance metrics
#[derive(Debug)]
pub struct AtomicStatsCollector {
    /// Query processing statistics
    pub queries_processed: AtomicU64,
    pub queries_per_second: AtomicU64,
    pub average_response_time_ns: AtomicU64,
    pub peak_qps: AtomicU64,
    
    /// Cache statistics
    pub cache_operations: AtomicU64,
    pub cache_hit_rate: AtomicU64, // Fixed-point percentage * 100
    pub cache_memory_usage: AtomicU64,
    pub cache_eviction_rate: AtomicU64,
    
    /// Zone statistics
    pub zones_loaded: AtomicUsize,
    pub zone_updates: AtomicU64,
    pub zone_transfers: AtomicU64,
    pub zone_memory_usage: AtomicU64,
    
    /// Cluster statistics
    pub cluster_nodes: AtomicUsize,
    pub cluster_health_score: AtomicU64, // Fixed-point percentage * 100
    pub replication_lag_ms: AtomicU64,
    pub node_failures: AtomicU64,
    
    /// Error statistics
    pub total_errors: AtomicU64,
    pub error_rate: AtomicU64, // Errors per second
    pub timeout_errors: AtomicU64,
    pub network_errors: AtomicU64,
    
    /// Resource usage statistics
    pub memory_usage_bytes: AtomicU64,
    pub cpu_usage_percent: AtomicU64, // Fixed-point percentage * 100
    pub disk_usage_bytes: AtomicU64,
    pub network_bytes_sent: AtomicU64,
    pub network_bytes_received: AtomicU64,
    
    /// Last update timestamp
    pub last_updated: AtomicU64,
}

impl AtomicStatsCollector {
    /// Create new atomic statistics collector
    pub fn new() -> Self {
        Self {
            queries_processed: AtomicU64::new(0),
            queries_per_second: AtomicU64::new(0),
            average_response_time_ns: AtomicU64::new(0),
            peak_qps: AtomicU64::new(0),
            
            cache_operations: AtomicU64::new(0),
            cache_hit_rate: AtomicU64::new(0),
            cache_memory_usage: AtomicU64::new(0),
            cache_eviction_rate: AtomicU64::new(0),
            
            zones_loaded: AtomicUsize::new(0),
            zone_updates: AtomicU64::new(0),
            zone_transfers: AtomicU64::new(0),
            zone_memory_usage: AtomicU64::new(0),
            
            cluster_nodes: AtomicUsize::new(1),
            cluster_health_score: AtomicU64::new(10000), // 100.00%
            replication_lag_ms: AtomicU64::new(0),
            node_failures: AtomicU64::new(0),
            
            total_errors: AtomicU64::new(0),
            error_rate: AtomicU64::new(0),
            timeout_errors: AtomicU64::new(0),
            network_errors: AtomicU64::new(0),
            
            memory_usage_bytes: AtomicU64::new(0),
            cpu_usage_percent: AtomicU64::new(0),
            disk_usage_bytes: AtomicU64::new(0),
            network_bytes_sent: AtomicU64::new(0),
            network_bytes_received: AtomicU64::new(0),
            
            last_updated: AtomicU64::new(0),
        }
    }
    
    /// Record query processing
    pub fn record_query(&self, response_time_ns: u64) {
        self.queries_processed.fetch_add(1, Ordering::Relaxed);
        
        // Update average response time using exponential moving average
        let current_avg = self.average_response_time_ns.load(Ordering::Acquire);
        let new_avg = if current_avg == 0 {
            response_time_ns
        } else {
            // EMA with alpha = 0.1 (90% old, 10% new)
            (current_avg * 9 + response_time_ns) / 10
        };
        self.average_response_time_ns.store(new_avg, Ordering::Release);
        
        self.update_timestamp();
    }
    
    /// Update queries per second
    pub fn update_qps(&self, qps: u64) {
        self.queries_per_second.store(qps, Ordering::Release);
        
        // Update peak QPS if necessary
        let current_peak = self.peak_qps.load(Ordering::Acquire);
        if qps > current_peak {
            self.peak_qps.compare_exchange_weak(
                current_peak,
                qps,
                Ordering::AcqRel,
                Ordering::Relaxed
            ).ok(); // Ignore failure, another thread may have updated it
        }
    }
    
    /// Update cache statistics
    pub fn update_cache_stats(&self, hit_rate: u64, memory_usage: u64, operations: u64) {
        self.cache_hit_rate.store(hit_rate, Ordering::Release);
        self.cache_memory_usage.store(memory_usage, Ordering::Release);
        self.cache_operations.fetch_add(operations, Ordering::Relaxed);
    }
    
    /// Update zone statistics
    pub fn update_zone_stats(&self, zones_loaded: usize, memory_usage: u64) {
        self.zones_loaded.store(zones_loaded, Ordering::Release);
        self.zone_memory_usage.store(memory_usage, Ordering::Release);
    }
    
    /// Record zone update
    pub fn record_zone_update(&self) {
        self.zone_updates.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record zone transfer
    pub fn record_zone_transfer(&self) {
        self.zone_transfers.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Update cluster statistics
    pub fn update_cluster_stats(&self, nodes: usize, health_score: u64, replication_lag_ms: u64) {
        self.cluster_nodes.store(nodes, Ordering::Release);
        self.cluster_health_score.store(health_score, Ordering::Release);
        self.replication_lag_ms.store(replication_lag_ms, Ordering::Release);
    }
    
    /// Record node failure
    pub fn record_node_failure(&self) {
        self.node_failures.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record error
    pub fn record_error(&self, error_type: &str) {
        self.total_errors.fetch_add(1, Ordering::Relaxed);
        
        match error_type {
            "timeout" => self.timeout_errors.fetch_add(1, Ordering::Relaxed),
            "network" => self.network_errors.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }
    
    /// Update resource usage
    pub fn update_resource_usage(&self, memory_bytes: u64, cpu_percent: u64, disk_bytes: u64) {
        self.memory_usage_bytes.store(memory_bytes, Ordering::Release);
        self.cpu_usage_percent.store(cpu_percent, Ordering::Release);
        self.disk_usage_bytes.store(disk_bytes, Ordering::Release);
    }
    
    /// Record network traffic
    pub fn record_network_traffic(&self, bytes_sent: u64, bytes_received: u64) {
        self.network_bytes_sent.fetch_add(bytes_sent, Ordering::Relaxed);
        self.network_bytes_received.fetch_add(bytes_received, Ordering::Relaxed);
    }
    
    /// Update timestamp
    fn update_timestamp(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_updated.store(now, Ordering::Release);
    }
    
    /// Get statistics snapshot
    pub fn snapshot(&self) -> AtomicStatsSnapshot {
        AtomicStatsSnapshot {
            queries_processed: self.queries_processed.load(Ordering::Relaxed),
            queries_per_second: self.queries_per_second.load(Ordering::Acquire),
            average_response_time_ns: self.average_response_time_ns.load(Ordering::Acquire),
            peak_qps: self.peak_qps.load(Ordering::Acquire),
            
            cache_operations: self.cache_operations.load(Ordering::Relaxed),
            cache_hit_rate: self.cache_hit_rate.load(Ordering::Acquire),
            cache_memory_usage: self.cache_memory_usage.load(Ordering::Acquire),
            
            zones_loaded: self.zones_loaded.load(Ordering::Acquire),
            zone_updates: self.zone_updates.load(Ordering::Relaxed),
            zone_transfers: self.zone_transfers.load(Ordering::Relaxed),
            zone_memory_usage: self.zone_memory_usage.load(Ordering::Acquire),
            
            cluster_nodes: self.cluster_nodes.load(Ordering::Acquire),
            cluster_health_score: self.cluster_health_score.load(Ordering::Acquire),
            replication_lag_ms: self.replication_lag_ms.load(Ordering::Acquire),
            node_failures: self.node_failures.load(Ordering::Relaxed),
            
            total_errors: self.total_errors.load(Ordering::Relaxed),
            timeout_errors: self.timeout_errors.load(Ordering::Relaxed),
            network_errors: self.network_errors.load(Ordering::Relaxed),
            
            memory_usage_bytes: self.memory_usage_bytes.load(Ordering::Acquire),
            cpu_usage_percent: self.cpu_usage_percent.load(Ordering::Acquire),
            disk_usage_bytes: self.disk_usage_bytes.load(Ordering::Acquire),
            network_bytes_sent: self.network_bytes_sent.load(Ordering::Relaxed),
            network_bytes_received: self.network_bytes_received.load(Ordering::Relaxed),
            
            last_updated: self.last_updated.load(Ordering::Acquire),
        }
    }
    
    /// Reset all statistics
    pub fn reset(&self) {
        self.queries_processed.store(0, Ordering::Release);
        self.queries_per_second.store(0, Ordering::Release);
        self.average_response_time_ns.store(0, Ordering::Release);
        self.peak_qps.store(0, Ordering::Release);
        
        self.cache_operations.store(0, Ordering::Release);
        self.cache_hit_rate.store(0, Ordering::Release);
        self.cache_memory_usage.store(0, Ordering::Release);
        
        self.zone_updates.store(0, Ordering::Release);
        self.zone_transfers.store(0, Ordering::Release);
        
        self.node_failures.store(0, Ordering::Release);
        self.total_errors.store(0, Ordering::Release);
        self.timeout_errors.store(0, Ordering::Release);
        self.network_errors.store(0, Ordering::Release);
        
        self.network_bytes_sent.store(0, Ordering::Release);
        self.network_bytes_received.store(0, Ordering::Release);
        
        self.update_timestamp();
    }
}

/// Statistics snapshot
#[derive(Debug, Clone)]
pub struct AtomicStatsSnapshot {
    pub queries_processed: u64,
    pub queries_per_second: u64,
    pub average_response_time_ns: u64,
    pub peak_qps: u64,
    
    pub cache_operations: u64,
    pub cache_hit_rate: u64,
    pub cache_memory_usage: u64,
    
    pub zones_loaded: usize,
    pub zone_updates: u64,
    pub zone_transfers: u64,
    pub zone_memory_usage: u64,
    
    pub cluster_nodes: usize,
    pub cluster_health_score: u64,
    pub replication_lag_ms: u64,
    pub node_failures: u64,
    
    pub total_errors: u64,
    pub timeout_errors: u64,
    pub network_errors: u64,
    
    pub memory_usage_bytes: u64,
    pub cpu_usage_percent: u64,
    pub disk_usage_bytes: u64,
    pub network_bytes_sent: u64,
    pub network_bytes_received: u64,
    
    pub last_updated: u64,
}

impl Default for AtomicStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Global atomic statistics instance
static GLOBAL_ATOMIC_STATS: std::sync::OnceLock<AtomicStatsCollector> = std::sync::OnceLock::new();

/// Get the global atomic statistics instance
pub fn global_atomic_stats() -> &'static AtomicStatsCollector {
    GLOBAL_ATOMIC_STATS.get_or_init(AtomicStatsCollector::new)
}

#[cfg(test)]
mod tests;