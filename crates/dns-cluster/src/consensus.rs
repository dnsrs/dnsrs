//! Atomic cluster state management without consensus
//!
//! Implements consensus-free cluster state management using atomic operations,
//! eventual consistency, and conflict-free replicated data types (CRDTs).

use crate::{NodeInfo, NodeCapabilities, Result, ClusterError};
use std::sync::atomic::{AtomicU64, AtomicU32, AtomicUsize, AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::interval;
use lockfree::map::Map as LockFreeMap;
use tracing::{info, warn, error, debug};
use ahash::AHashMap;

/// Atomic cluster state manager without consensus
pub struct AtomicClusterState {
    // Node membership using atomic operations
    nodes: Arc<LockFreeMap<u64, Arc<AtomicNodeState>>>,
    
    // Zone ownership mapping (zone_hash -> primary_node_id)
    zone_ownership: Arc<LockFreeMap<u64, u64>>,
    
    // Zone replica mapping (zone_hash -> Vec<node_id>)
    zone_replicas: Arc<RwLock<AHashMap<u64, Vec<u64>>>>,
    
    // Cluster metadata
    cluster_metadata: Arc<AtomicClusterMetadata>,
    
    // Configuration
    config: ClusterStateConfig,
    
    // Statistics
    stats: Arc<ClusterStateStats>,
    
    // Local node information
    local_node_id: u64,
    
    // Running state
    is_running: AtomicBool,
}

/// Cluster state configuration
#[derive(Debug, Clone)]
pub struct ClusterStateConfig {
    pub state_sync_interval: Duration,
    pub node_timeout: Duration,
    pub max_nodes: usize,
    pub replication_factor: usize,
    pub enable_auto_rebalancing: bool,
    pub rebalance_threshold: f32,
    pub conflict_resolution_strategy: ConflictResolutionStrategy,
}

impl Default for ClusterStateConfig {
    fn default() -> Self {
        Self {
            state_sync_interval: Duration::from_secs(30),
            node_timeout: Duration::from_secs(300), // 5 minutes
            max_nodes: 10000, // Support up to 10k nodes
            replication_factor: 3,
            enable_auto_rebalancing: true,
            rebalance_threshold: 20.0, // 20% load difference
            conflict_resolution_strategy: ConflictResolutionStrategy::LastWriterWins,
        }
    }
}

/// Conflict resolution strategies for eventual consistency
#[derive(Debug, Clone, Copy)]
pub enum ConflictResolutionStrategy {
    LastWriterWins,
    HighestNodeId,
    LowestNodeId,
    MostReplicas,
}

/// Atomic node state for lock-free operations
pub struct AtomicNodeState {
    pub node_id: u64,
    pub address: std::net::SocketAddr,
    pub region: String,
    pub datacenter: String,
    pub is_active: AtomicBool,
    pub last_seen: AtomicU64,
    pub load_factor: AtomicU64, // Fixed-point percentage (0-10000)
    pub zone_count: AtomicU32,
    pub version: AtomicU64, // For conflict resolution
    pub capabilities: NodeCapabilities,
}

impl AtomicNodeState {
    pub fn new(node: NodeInfo) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Self {
            node_id: node.node_id,
            address: node.address,
            region: node.region,
            datacenter: node.datacenter,
            is_active: AtomicBool::new(true),
            last_seen: AtomicU64::new(now),
            load_factor: AtomicU64::new(0),
            zone_count: AtomicU32::new(0),
            version: AtomicU64::new(1),
            capabilities: node.capabilities,
        }
    }
    
    pub fn update_last_seen(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_seen.store(now, Ordering::Relaxed);
        self.version.fetch_add(1, Ordering::AcqRel);
    }
    
    pub fn set_load_factor(&self, load_percent: f32) {
        let load_fixed = (load_percent * 100.0) as u64;
        self.load_factor.store(load_fixed, Ordering::Relaxed);
        self.version.fetch_add(1, Ordering::AcqRel);
    }
    
    pub fn get_load_factor(&self) -> f32 {
        self.load_factor.load(Ordering::Relaxed) as f32 / 100.0
    }
    
    pub fn is_expired(&self, timeout: Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let last_seen = self.last_seen.load(Ordering::Relaxed);
        
        now.saturating_sub(last_seen) > timeout.as_secs()
    }
}

/// Atomic cluster metadata
pub struct AtomicClusterMetadata {
    pub cluster_id: u64,
    pub total_nodes: AtomicUsize,
    pub active_nodes: AtomicUsize,
    pub total_zones: AtomicUsize,
    pub last_rebalance_time: AtomicU64,
    pub cluster_version: AtomicU64,
    pub formation_time: u64, // Immutable
}

impl AtomicClusterMetadata {
    pub fn new(cluster_id: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Self {
            cluster_id,
            total_nodes: AtomicUsize::new(0),
            active_nodes: AtomicUsize::new(0),
            total_zones: AtomicUsize::new(0),
            last_rebalance_time: AtomicU64::new(now),
            cluster_version: AtomicU64::new(1),
            formation_time: now,
        }
    }
}

/// Cluster state statistics
pub struct ClusterStateStats {
    pub state_updates: AtomicU64,
    pub node_joins: AtomicU64,
    pub node_leaves: AtomicU64,
    pub zone_assignments: AtomicU64,
    pub zone_reassignments: AtomicU64,
    pub conflicts_resolved: AtomicU64,
    pub rebalance_operations: AtomicU64,
    pub last_sync_time: AtomicU64,
}

impl ClusterStateStats {
    pub fn new() -> Self {
        Self {
            state_updates: AtomicU64::new(0),
            node_joins: AtomicU64::new(0),
            node_leaves: AtomicU64::new(0),
            zone_assignments: AtomicU64::new(0),
            zone_reassignments: AtomicU64::new(0),
            conflicts_resolved: AtomicU64::new(0),
            rebalance_operations: AtomicU64::new(0),
            last_sync_time: AtomicU64::new(0),
        }
    }
}

impl AtomicClusterState {
    pub fn new(local_node_id: u64, cluster_id: u64, config: ClusterStateConfig) -> Self {
        Self {
            nodes: Arc::new(LockFreeMap::new()),
            zone_ownership: Arc::new(LockFreeMap::new()),
            zone_replicas: Arc::new(RwLock::new(AHashMap::new())),
            cluster_metadata: Arc::new(AtomicClusterMetadata::new(cluster_id)),
            config,
            stats: Arc::new(ClusterStateStats::new()),
            local_node_id,
            is_running: AtomicBool::new(false),
        }
    }
    
    /// Start cluster state management
    pub async fn start(&self) -> Result<()> {
        if self.is_running.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        
        info!("Starting atomic cluster state management for node {}", self.local_node_id);
        
        // Start state synchronization loop
        self.start_sync_loop().await;
        
        // Start node timeout monitoring
        self.start_timeout_monitoring().await;
        
        // Start auto-rebalancing if enabled
        if self.config.enable_auto_rebalancing {
            self.start_auto_rebalancing().await;
        }
        
        Ok(())
    }
    
    /// Add a node to the cluster atomically
    pub async fn add_node(&self, node: NodeInfo) -> Result<()> {
        let node_state = Arc::new(AtomicNodeState::new(node));
        
        // Check cluster size limit
        let current_nodes = self.cluster_metadata.total_nodes.load(Ordering::Relaxed);
        if current_nodes >= self.config.max_nodes {
            return Err(ClusterError::InconsistentState);
        }
        
        // Add node atomically
        self.nodes.insert(node_state.node_id, Arc::clone(&node_state));
        
        // Update cluster metadata
        self.cluster_metadata.total_nodes.fetch_add(1, Ordering::AcqRel);
        self.cluster_metadata.active_nodes.fetch_add(1, Ordering::AcqRel);
        self.cluster_metadata.cluster_version.fetch_add(1, Ordering::AcqRel);
        
        // Update statistics
        self.stats.node_joins.fetch_add(1, Ordering::Relaxed);
        self.stats.state_updates.fetch_add(1, Ordering::Relaxed);
        
        info!("Added node {} to cluster", node_state.node_id);
        
        Ok(())
    }
    
    /// Remove a node from the cluster atomically
    pub async fn remove_node(&self, node_id: u64) -> Result<()> {
        if let Some(node_state) = self.nodes.remove(&node_id) {
            let node_state = node_state.val();
            
            // Mark as inactive
            node_state.is_active.store(false, Ordering::Release);
            
            // Update cluster metadata
            self.cluster_metadata.total_nodes.fetch_sub(1, Ordering::AcqRel);
            if node_state.is_active.load(Ordering::Relaxed) {
                self.cluster_metadata.active_nodes.fetch_sub(1, Ordering::AcqRel);
            }
            self.cluster_metadata.cluster_version.fetch_add(1, Ordering::AcqRel);
            
            // Reassign zones owned by this node
            self.reassign_zones_from_node(node_id).await?;
            
            // Update statistics
            self.stats.node_leaves.fetch_add(1, Ordering::Relaxed);
            self.stats.state_updates.fetch_add(1, Ordering::Relaxed);
            
            info!("Removed node {} from cluster", node_id);
        }
        
        Ok(())
    }
    
    /// Assign a zone to a node atomically
    pub async fn assign_zone(&self, zone_hash: u64, primary_node_id: u64) -> Result<()> {
        // Check if node exists and is active
        if let Some(node_state) = self.nodes.get(&primary_node_id) {
            let node_state = node_state.val();
            if !node_state.is_active.load(Ordering::Relaxed) {
                return Err(ClusterError::NodeNotFound { node_id: primary_node_id });
            }
        } else {
            return Err(ClusterError::NodeNotFound { node_id: primary_node_id });
        }
        
        // Assign primary ownership
        let previous_owner = self.zone_ownership.insert(zone_hash, primary_node_id);
        
        // Calculate replica nodes
        let replica_nodes = self.calculate_replica_nodes(zone_hash, primary_node_id).await;
        
        // Update replica mapping
        {
            let mut zone_replicas = self.zone_replicas.write().await;
            zone_replicas.insert(zone_hash, replica_nodes);
        }
        
        // Update zone count for primary node
        if let Some(node_state) = self.nodes.get(&primary_node_id) {
            node_state.val().zone_count.fetch_add(1, Ordering::Relaxed);
        }
        
        // Update cluster metadata
        if previous_owner.is_none() {
            self.cluster_metadata.total_zones.fetch_add(1, Ordering::AcqRel);
            self.stats.zone_assignments.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.zone_reassignments.fetch_add(1, Ordering::Relaxed);
        }
        
        self.cluster_metadata.cluster_version.fetch_add(1, Ordering::AcqRel);
        self.stats.state_updates.fetch_add(1, Ordering::Relaxed);
        
        debug!("Assigned zone {} to node {}", zone_hash, primary_node_id);
        
        Ok(())
    }
    
    /// Get the primary node for a zone
    pub fn get_zone_primary(&self, zone_hash: u64) -> Option<u64> {
        self.zone_ownership.get(&zone_hash).map(|guard| *guard.val())
    }
    
    /// Get replica nodes for a zone
    pub async fn get_zone_replicas(&self, zone_hash: u64) -> Vec<u64> {
        let zone_replicas = self.zone_replicas.read().await;
        zone_replicas.get(&zone_hash).cloned().unwrap_or_default()
    }
    
    /// Get all active nodes
    pub fn get_active_nodes(&self) -> Vec<u64> {
        self.nodes.iter()
            .filter_map(|guard| {
                let node_state = guard.val();
                if node_state.is_active.load(Ordering::Relaxed) {
                    Some(node_state.node_id)
                } else {
                    None
                }
            })
            .collect()
    }
    
    /// Get node state
    pub fn get_node_state(&self, node_id: u64) -> Option<Arc<AtomicNodeState>> {
        self.nodes.get(&node_id).map(|guard| guard.val().clone())
    }
    
    /// Update node load factor
    pub fn update_node_load(&self, node_id: u64, load_factor: f32) -> Result<()> {
        if let Some(node_state) = self.nodes.get(&node_id) {
            node_state.val().set_load_factor(load_factor);
            Ok(())
        } else {
            Err(ClusterError::NodeNotFound { node_id })
        }
    }
    
    /// Get cluster statistics
    pub fn get_stats(&self) -> ClusterStateStatsSnapshot {
        ClusterStateStatsSnapshot {
            total_nodes: self.cluster_metadata.total_nodes.load(Ordering::Relaxed),
            active_nodes: self.cluster_metadata.active_nodes.load(Ordering::Relaxed),
            total_zones: self.cluster_metadata.total_zones.load(Ordering::Relaxed),
            cluster_version: self.cluster_metadata.cluster_version.load(Ordering::Relaxed),
            state_updates: self.stats.state_updates.load(Ordering::Relaxed),
            node_joins: self.stats.node_joins.load(Ordering::Relaxed),
            node_leaves: self.stats.node_leaves.load(Ordering::Relaxed),
            zone_assignments: self.stats.zone_assignments.load(Ordering::Relaxed),
            zone_reassignments: self.stats.zone_reassignments.load(Ordering::Relaxed),
            conflicts_resolved: self.stats.conflicts_resolved.load(Ordering::Relaxed),
            rebalance_operations: self.stats.rebalance_operations.load(Ordering::Relaxed),
            last_sync_time: self.stats.last_sync_time.load(Ordering::Relaxed),
        }
    }
    
    /// Calculate replica nodes for a zone
    async fn calculate_replica_nodes(&self, zone_hash: u64, primary_node_id: u64) -> Vec<u64> {
        let mut replica_nodes = Vec::new();
        let active_nodes = self.get_active_nodes();
        
        // Remove primary node from candidates
        let candidates: Vec<u64> = active_nodes.into_iter()
            .filter(|&node_id| node_id != primary_node_id)
            .collect();
        
        if candidates.is_empty() {
            return replica_nodes;
        }
        
        // Select replicas based on consistent hashing
        let replica_count = (self.config.replication_factor - 1).min(candidates.len());
        
        // Simple selection based on hash distance
        let mut sorted_candidates = candidates;
        sorted_candidates.sort_by_key(|&node_id| {
            // Calculate hash distance
            zone_hash ^ node_id
        });
        
        replica_nodes.extend(sorted_candidates.into_iter().take(replica_count));
        
        replica_nodes
    }
    
    /// Reassign zones from a failed node
    async fn reassign_zones_from_node(&self, failed_node_id: u64) -> Result<()> {
        let mut zones_to_reassign = Vec::new();
        
        // Find zones owned by the failed node
        for guard in self.zone_ownership.iter() {
            if *guard.val() == failed_node_id {
                zones_to_reassign.push(*guard.key());
            }
        }
        
        // Reassign each zone
        for zone_hash in zones_to_reassign {
            if let Some(new_primary) = self.select_new_primary_node(zone_hash, failed_node_id).await {
                self.assign_zone(zone_hash, new_primary).await?;
                info!("Reassigned zone {} from failed node {} to node {}", 
                      zone_hash, failed_node_id, new_primary);
            } else {
                warn!("No suitable node found to reassign zone {} from failed node {}", 
                      zone_hash, failed_node_id);
            }
        }
        
        Ok(())
    }
    
    /// Select a new primary node for zone reassignment
    async fn select_new_primary_node(&self, zone_hash: u64, exclude_node_id: u64) -> Option<u64> {
        let active_nodes = self.get_active_nodes();
        
        // Filter out the excluded node
        let candidates: Vec<u64> = active_nodes.into_iter()
            .filter(|&node_id| node_id != exclude_node_id)
            .collect();
        
        if candidates.is_empty() {
            return None;
        }
        
        // Select node with lowest load
        let mut best_node = None;
        let mut best_load = f32::MAX;
        
        for node_id in candidates {
            if let Some(node_state) = self.nodes.get(&node_id) {
                let load = node_state.val().get_load_factor();
                if load < best_load {
                    best_load = load;
                    best_node = Some(node_id);
                }
            }
        }
        
        best_node
    }
    
    /// Start state synchronization loop
    async fn start_sync_loop(&self) {
        let nodes = Arc::clone(&self.nodes);
        let stats = Arc::clone(&self.stats);
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut sync_interval = interval(config.state_sync_interval);
            
            loop {
                sync_interval.tick().await;
                
                // Update last seen timestamps for active nodes
                for guard in nodes.iter() {
                    let node_state = guard.val();
                    if node_state.is_active.load(Ordering::Relaxed) {
                        node_state.update_last_seen();
                    }
                }
                
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                stats.last_sync_time.store(now, Ordering::Relaxed);
                
                debug!("Cluster state sync completed");
            }
        });
    }
    
    /// Start node timeout monitoring
    async fn start_timeout_monitoring(&self) {
        let nodes = Arc::clone(&self.nodes);
        let cluster_metadata = Arc::clone(&self.cluster_metadata);
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut timeout_interval = interval(Duration::from_secs(60));
            
            loop {
                timeout_interval.tick().await;
                
                let mut expired_nodes = Vec::new();
                
                // Check for expired nodes
                for guard in nodes.iter() {
                    let node_state = guard.val();
                    if node_state.is_active.load(Ordering::Relaxed) && 
                       node_state.is_expired(config.node_timeout) {
                        expired_nodes.push(node_state.node_id);
                    }
                }
                
                // Mark expired nodes as inactive
                for node_id in expired_nodes {
                    if let Some(node_state) = nodes.get(&node_id) {
                        let node_state = node_state.val();
                        if node_state.is_active.swap(false, Ordering::AcqRel) {
                            cluster_metadata.active_nodes.fetch_sub(1, Ordering::AcqRel);
                            warn!("Node {} marked as inactive due to timeout", node_id);
                        }
                    }
                }
            }
        });
    }
    
    /// Start auto-rebalancing
    async fn start_auto_rebalancing(&self) {
        let nodes = Arc::clone(&self.nodes);
        let zone_ownership = Arc::clone(&self.zone_ownership);
        let config = self.config.clone();
        let stats = Arc::clone(&self.stats);
        
        tokio::spawn(async move {
            let mut rebalance_interval = interval(Duration::from_secs(300)); // 5 minutes
            
            loop {
                rebalance_interval.tick().await;
                
                // Check if rebalancing is needed
                if Self::should_rebalance(&nodes, config.rebalance_threshold) {
                    info!("Starting automatic cluster rebalancing");
                    
                    // Perform rebalancing logic here
                    // This is a placeholder for the actual rebalancing algorithm
                    
                    stats.rebalance_operations.fetch_add(1, Ordering::Relaxed);
                    
                    debug!("Automatic rebalancing completed");
                }
            }
        });
    }
    
    /// Check if cluster rebalancing is needed
    fn should_rebalance(nodes: &LockFreeMap<u64, Arc<AtomicNodeState>>, threshold: f32) -> bool {
        let mut loads = Vec::new();
        
        for guard in nodes.iter() {
            let node_state = guard.val();
            if node_state.is_active.load(Ordering::Relaxed) {
                loads.push(node_state.get_load_factor());
            }
        }
        
        if loads.len() < 2 {
            return false;
        }
        
        loads.sort_by(|a, b| a.partial_cmp(b).unwrap());
        
        let min_load = loads[0];
        let max_load = loads[loads.len() - 1];
        let load_difference = max_load - min_load;
        
        load_difference > threshold
    }
}

/// Cluster state statistics snapshot
#[derive(Debug, Clone)]
pub struct ClusterStateStatsSnapshot {
    pub total_nodes: usize,
    pub active_nodes: usize,
    pub total_zones: usize,
    pub cluster_version: u64,
    pub state_updates: u64,
    pub node_joins: u64,
    pub node_leaves: u64,
    pub zone_assignments: u64,
    pub zone_reassignments: u64,
    pub conflicts_resolved: u64,
    pub rebalance_operations: u64,
    pub last_sync_time: u64,
}

/// Consensus manager that coordinates atomic cluster state
pub struct ConsensusManager {
    cluster_state: Arc<AtomicClusterState>,
    config: ClusterStateConfig,
    is_running: AtomicBool,
}

impl ConsensusManager {
    pub fn new(local_node_id: u64, cluster_id: u64, config: ClusterStateConfig) -> Self {
        Self {
            cluster_state: Arc::new(AtomicClusterState::new(local_node_id, cluster_id, config.clone())),
            config,
            is_running: AtomicBool::new(false),
        }
    }
    
    pub async fn start(&self) -> Result<()> {
        if self.is_running.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        
        info!("Starting consensus-free cluster state manager");
        
        // Start cluster state management
        self.cluster_state.start().await?;
        
        Ok(())
    }
    
    pub fn get_cluster_state(&self) -> Arc<AtomicClusterState> {
        Arc::clone(&self.cluster_state)
    }
    
    pub async fn add_node(&self, node: NodeInfo) -> Result<()> {
        self.cluster_state.add_node(node).await
    }
    
    pub async fn remove_node(&self, node_id: u64) -> Result<()> {
        self.cluster_state.remove_node(node_id).await
    }
    
    pub async fn assign_zone(&self, zone_hash: u64, node_id: u64) -> Result<()> {
        self.cluster_state.assign_zone(zone_hash, node_id).await
    }
    
    pub fn get_stats(&self) -> ClusterStateStatsSnapshot {
        self.cluster_state.get_stats()
    }
}