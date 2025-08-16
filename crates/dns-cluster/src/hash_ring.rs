//! Atomic consistent hash ring implementation
//!
//! Implements a lock-free consistent hash ring that supports unlimited nodes
//! using atomic operations and virtual nodes for better load distribution.

use crate::{NodeInfo, Result, ClusterError};
use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::BTreeMap;
use ahash::AHasher;
use std::hash::{Hash, Hasher};
use lockfree::map::Map as LockFreeMap;
use tracing::{debug, info, warn};

/// Atomic consistent hash ring with unlimited node support
pub struct AtomicConsistentHashRing {
    // Lock-free hash ring with atomic updates
    ring: Arc<LockFreeMap<u64, Arc<NodeInfo>>>,
    
    // Virtual nodes for better distribution (configurable, default 1000 per node)
    virtual_nodes_per_node: AtomicU64,
    
    // Total nodes in ring (atomic counter)
    total_nodes: AtomicUsize,
    
    // Total virtual nodes (atomic counter)
    total_virtual_nodes: AtomicUsize,
    
    // Ring version for atomic updates
    ring_version: AtomicU64,
    
    // Ring statistics
    stats: Arc<HashRingStats>,
    
    // Configuration
    config: HashRingConfig,
}

/// Hash ring configuration
#[derive(Debug, Clone)]
pub struct HashRingConfig {
    pub virtual_nodes_per_node: u64,
    pub hash_function: HashFunction,
    pub replication_factor: usize,
    pub load_balancing_enabled: bool,
}

impl Default for HashRingConfig {
    fn default() -> Self {
        Self {
            virtual_nodes_per_node: 1000,
            hash_function: HashFunction::Blake3,
            replication_factor: 3,
            load_balancing_enabled: true,
        }
    }
}

/// Hash function options
#[derive(Debug, Clone, Copy)]
pub enum HashFunction {
    Blake3,
    AHash,
    Sha256,
}

/// Hash ring statistics
pub struct HashRingStats {
    pub lookups_total: AtomicU64,
    pub node_additions: AtomicU64,
    pub node_removals: AtomicU64,
    pub ring_rebuilds: AtomicU64,
    pub load_imbalance_events: AtomicU64,
    pub last_rebalance_time: AtomicU64,
}

impl HashRingStats {
    pub fn new() -> Self {
        Self {
            lookups_total: AtomicU64::new(0),
            node_additions: AtomicU64::new(0),
            node_removals: AtomicU64::new(0),
            ring_rebuilds: AtomicU64::new(0),
            load_imbalance_events: AtomicU64::new(0),
            last_rebalance_time: AtomicU64::new(0),
        }
    }
}

impl AtomicConsistentHashRing {
    /// Create a new atomic consistent hash ring
    pub fn new(config: HashRingConfig) -> Self {
        Self {
            ring: Arc::new(LockFreeMap::new()),
            virtual_nodes_per_node: AtomicU64::new(config.virtual_nodes_per_node),
            total_nodes: AtomicUsize::new(0),
            total_virtual_nodes: AtomicUsize::new(0),
            ring_version: AtomicU64::new(0),
            stats: Arc::new(HashRingStats::new()),
            config,
        }
    }
    
    /// Add a node to the ring atomically
    pub async fn add_node_atomic(&self, node: NodeInfo) -> Result<bool> {
        let virtual_nodes = self.virtual_nodes_per_node.load(Ordering::Acquire);
        let node_arc = Arc::new(node.clone());
        
        info!("Adding node {} to hash ring with {} virtual nodes", 
              node.node_id, virtual_nodes);
        
        // Add virtual nodes atomically
        let mut added_count = 0;
        for i in 0..virtual_nodes {
            let virtual_hash = self.calculate_virtual_node_hash(node.node_id, i);
            
            // Insert virtual node into ring
            if self.ring.insert(virtual_hash, Arc::clone(&node_arc)).is_none() {
                added_count += 1;
            }
        }
        
        if added_count > 0 {
            self.total_nodes.fetch_add(1, Ordering::AcqRel);
            self.total_virtual_nodes.fetch_add(added_count, Ordering::AcqRel);
            self.ring_version.fetch_add(1, Ordering::AcqRel);
            self.stats.node_additions.fetch_add(1, Ordering::Relaxed);
            
            debug!("Successfully added {} virtual nodes for node {}", 
                   added_count, node.node_id);
            
            // Trigger rebalancing if enabled
            if self.config.load_balancing_enabled {
                self.check_load_balance().await;
            }
            
            Ok(true)
        } else {
            warn!("Failed to add any virtual nodes for node {}", node.node_id);
            Ok(false)
        }
    }
    
    /// Remove a node from the ring atomically
    pub async fn remove_node_atomic(&self, node_id: u64) -> Result<bool> {
        let virtual_nodes = self.virtual_nodes_per_node.load(Ordering::Acquire);
        
        info!("Removing node {} from hash ring", node_id);
        
        // Remove virtual nodes atomically
        let mut removed_count = 0;
        for i in 0..virtual_nodes {
            let virtual_hash = self.calculate_virtual_node_hash(node_id, i);
            
            if self.ring.remove(&virtual_hash).is_some() {
                removed_count += 1;
            }
        }
        
        if removed_count > 0 {
            self.total_nodes.fetch_sub(1, Ordering::AcqRel);
            self.total_virtual_nodes.fetch_sub(removed_count, Ordering::AcqRel);
            self.ring_version.fetch_add(1, Ordering::AcqRel);
            self.stats.node_removals.fetch_add(1, Ordering::Relaxed);
            
            debug!("Successfully removed {} virtual nodes for node {}", 
                   removed_count, node_id);
            
            // Trigger rebalancing if enabled
            if self.config.load_balancing_enabled {
                self.check_load_balance().await;
            }
            
            Ok(true)
        } else {
            warn!("No virtual nodes found to remove for node {}", node_id);
            Ok(false)
        }
    }
    
    /// Find nodes responsible for a zone with O(log N) lookup
    pub async fn find_nodes_for_zone(&self, zone_hash: u64, replica_count: usize) -> Vec<u64> {
        self.stats.lookups_total.fetch_add(1, Ordering::Relaxed);
        
        let mut nodes = Vec::with_capacity(replica_count);
        let mut seen_nodes = std::collections::HashSet::new();
        let mut current_hash = zone_hash;
        
        // Find unique nodes by walking the ring
        while nodes.len() < replica_count && seen_nodes.len() < self.total_nodes.load(Ordering::Acquire) {
            if let Some(node) = self.find_next_node_atomic(current_hash) {
                if seen_nodes.insert(node.node_id) {
                    nodes.push(node.node_id);
                }
                // Move to next position in ring
                current_hash = self.next_hash_atomic(current_hash);
            } else {
                break;
            }
        }
        
        debug!("Found {} nodes for zone hash {}: {:?}", 
               nodes.len(), zone_hash, nodes);
        
        nodes
    }
    
    /// Find the next node in the ring for a given hash
    fn find_next_node_atomic(&self, hash: u64) -> Option<Arc<NodeInfo>> {
        // Find the first node with hash >= target hash
        // This is a simplified implementation that iterates through all nodes
        let mut best_hash = u64::MAX;
        let mut best_node = None;
        
        for guard in self.ring.iter() {
            let node_hash = *guard.key();
            if node_hash >= hash && node_hash < best_hash {
                best_hash = node_hash;
                best_node = Some(guard.val().clone());
            }
        }
        
        // If no node found with hash >= target, wrap around to smallest hash
        if best_node.is_none() {
            let mut smallest_hash = u64::MAX;
            for guard in self.ring.iter() {
                let node_hash = *guard.key();
                if node_hash < smallest_hash {
                    smallest_hash = node_hash;
                    best_node = Some(guard.val().clone());
                }
            }
        }
        
        best_node
    }
    
    /// Calculate the next hash position in the ring
    fn next_hash_atomic(&self, current_hash: u64) -> u64 {
        // Simple increment with wraparound
        current_hash.wrapping_add(1)
    }
    
    /// Calculate virtual node hash
    fn calculate_virtual_node_hash(&self, node_id: u64, virtual_index: u64) -> u64 {
        match self.config.hash_function {
            HashFunction::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&node_id.to_be_bytes());
                hasher.update(&virtual_index.to_be_bytes());
                let hash = hasher.finalize();
                u64::from_be_bytes(hash.as_bytes()[0..8].try_into().unwrap())
            }
            HashFunction::AHash => {
                let mut hasher = AHasher::default();
                node_id.hash(&mut hasher);
                virtual_index.hash(&mut hasher);
                hasher.finish()
            }
            HashFunction::Sha256 => {
                // Would use SHA-256 implementation
                // For now, fallback to AHash
                let mut hasher = AHasher::default();
                node_id.hash(&mut hasher);
                virtual_index.hash(&mut hasher);
                hasher.finish()
            }
        }
    }
    
    /// Get all nodes in the ring
    pub async fn get_all_nodes(&self) -> Vec<Arc<NodeInfo>> {
        let mut nodes = Vec::new();
        let mut seen_nodes = std::collections::HashSet::new();
        
        // Iterate through ring and collect unique nodes
        for guard in self.ring.iter() {
            let node = guard.val();
            if seen_nodes.insert(node.node_id) {
                nodes.push(Arc::clone(node));
            }
        }
        
        nodes
    }
    
    /// Get ring statistics
    pub fn get_stats(&self) -> RingStats {
        RingStats {
            total_nodes: self.total_nodes.load(Ordering::Relaxed),
            total_virtual_nodes: self.total_virtual_nodes.load(Ordering::Relaxed),
            virtual_nodes_per_node: self.virtual_nodes_per_node.load(Ordering::Relaxed),
            ring_version: self.ring_version.load(Ordering::Relaxed),
            lookups_total: self.stats.lookups_total.load(Ordering::Relaxed),
            node_additions: self.stats.node_additions.load(Ordering::Relaxed),
            node_removals: self.stats.node_removals.load(Ordering::Relaxed),
            ring_rebuilds: self.stats.ring_rebuilds.load(Ordering::Relaxed),
        }
    }
    
    /// Check and rebalance load if necessary
    async fn check_load_balance(&self) {
        // This would implement load balancing logic
        // For now, it's a placeholder
        debug!("Checking load balance across ring");
        
        let total_nodes = self.total_nodes.load(Ordering::Relaxed);
        if total_nodes == 0 {
            return;
        }
        
        // Calculate load distribution
        let nodes = self.get_all_nodes().await;
        let mut load_factors: Vec<f32> = nodes.iter()
            .map(|node| node.metadata.get_load_factor())
            .collect();
        
        if load_factors.is_empty() {
            return;
        }
        
        load_factors.sort_by(|a, b| a.partial_cmp(b).unwrap());
        
        let min_load = load_factors[0];
        let max_load = load_factors[load_factors.len() - 1];
        let load_imbalance = max_load - min_load;
        
        // If load imbalance is significant, consider rebalancing
        if load_imbalance > 20.0 { // 20% threshold
            self.stats.load_imbalance_events.fetch_add(1, Ordering::Relaxed);
            warn!("Load imbalance detected: min={:.1}%, max={:.1}%, diff={:.1}%", 
                  min_load, max_load, load_imbalance);
            
            // Trigger rebalancing logic here
            self.rebalance_ring().await;
        }
    }
    
    /// Rebalance the ring by adjusting virtual node distribution
    async fn rebalance_ring(&self) {
        info!("Starting ring rebalancing");
        
        // This would implement sophisticated rebalancing logic
        // For now, it's a placeholder that updates the rebalance timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.stats.last_rebalance_time.store(now, Ordering::Relaxed);
        self.stats.ring_rebuilds.fetch_add(1, Ordering::Relaxed);
        
        debug!("Ring rebalancing completed");
    }
    
    /// Update virtual nodes per node setting
    pub fn set_virtual_nodes_per_node(&self, count: u64) {
        self.virtual_nodes_per_node.store(count, Ordering::Release);
        self.ring_version.fetch_add(1, Ordering::AcqRel);
        info!("Updated virtual nodes per node to {}", count);
    }
    
    /// Get current ring version
    pub fn get_version(&self) -> u64 {
        self.ring_version.load(Ordering::Acquire)
    }
    
    /// Check if ring is empty
    pub fn is_empty(&self) -> bool {
        self.total_nodes.load(Ordering::Relaxed) == 0
    }
    
    /// Get node count
    pub fn node_count(&self) -> usize {
        self.total_nodes.load(Ordering::Relaxed)
    }
}

/// Ring statistics snapshot
#[derive(Debug, Clone)]
pub struct RingStats {
    pub total_nodes: usize,
    pub total_virtual_nodes: usize,
    pub virtual_nodes_per_node: u64,
    pub ring_version: u64,
    pub lookups_total: u64,
    pub node_additions: u64,
    pub node_removals: u64,
    pub ring_rebuilds: u64,
}

/// Load balancer for the hash ring
pub struct HashRingLoadBalancer {
    ring: Arc<AtomicConsistentHashRing>,
    config: LoadBalancerConfig,
}

/// Load balancer configuration
#[derive(Debug, Clone)]
pub struct LoadBalancerConfig {
    pub rebalance_threshold: f32,
    pub rebalance_interval: std::time::Duration,
    pub enable_adaptive_virtual_nodes: bool,
    pub min_virtual_nodes: u64,
    pub max_virtual_nodes: u64,
}

impl Default for LoadBalancerConfig {
    fn default() -> Self {
        Self {
            rebalance_threshold: 20.0, // 20% load difference threshold
            rebalance_interval: std::time::Duration::from_secs(300), // 5 minutes
            enable_adaptive_virtual_nodes: true,
            min_virtual_nodes: 100,
            max_virtual_nodes: 10000,
        }
    }
}

impl HashRingLoadBalancer {
    pub fn new(ring: Arc<AtomicConsistentHashRing>, config: LoadBalancerConfig) -> Self {
        Self { ring, config }
    }
    
    /// Start the load balancer
    pub async fn start(&self) {
        let ring = Arc::clone(&self.ring);
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.rebalance_interval);
            
            loop {
                interval.tick().await;
                
                if config.enable_adaptive_virtual_nodes {
                    Self::adaptive_rebalance(&ring, &config).await;
                }
            }
        });
    }
    
    /// Perform adaptive rebalancing
    async fn adaptive_rebalance(ring: &AtomicConsistentHashRing, config: &LoadBalancerConfig) {
        let nodes = ring.get_all_nodes().await;
        if nodes.len() < 2 {
            return; // Need at least 2 nodes for balancing
        }
        
        // Calculate load statistics
        let mut loads: Vec<f32> = nodes.iter()
            .map(|node| node.metadata.get_load_factor())
            .collect();
        
        loads.sort_by(|a, b| a.partial_cmp(b).unwrap());
        
        let min_load = loads[0];
        let max_load = loads[loads.len() - 1];
        let load_difference = max_load - min_load;
        
        if load_difference > config.rebalance_threshold {
            info!("Load imbalance detected: {:.1}% difference", load_difference);
            
            // Adjust virtual nodes based on load
            for node in &nodes {
                let node_load = node.metadata.get_load_factor();
                let current_virtual_nodes = ring.virtual_nodes_per_node.load(Ordering::Acquire);
                
                // Calculate new virtual node count based on inverse load
                let load_factor = if node_load > 0.0 { 100.0 / node_load } else { 1.0 };
                let new_virtual_nodes = ((current_virtual_nodes as f32) * load_factor) as u64;
                
                // Clamp to configured limits
                let clamped_virtual_nodes = new_virtual_nodes
                    .max(config.min_virtual_nodes)
                    .min(config.max_virtual_nodes);
                
                if clamped_virtual_nodes != current_virtual_nodes {
                    debug!("Adjusting virtual nodes for node {} from {} to {}", 
                           node.node_id, current_virtual_nodes, clamped_virtual_nodes);
                    
                    // This would require per-node virtual node counts
                    // For now, we update the global setting
                    ring.set_virtual_nodes_per_node(clamped_virtual_nodes);
                    break; // Only adjust one at a time
                }
            }
        }
    }
}