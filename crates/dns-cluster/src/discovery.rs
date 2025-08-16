//! Hierarchical node discovery implementation
//!
//! Implements multi-tier discovery system for unlimited cluster scaling:
//! - Local discovery: Same datacenter/region
//! - Regional discovery: Cross-region within same continent
//! - Global discovery: Planet-wide discovery

use crate::{NodeInfo, NodeMetadata, NodeCapabilities, Result, ClusterError};
use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::{interval, timeout};
use tracing::{info, warn, error, debug};
use ahash::AHashMap;

/// Hierarchical node discovery manager
pub struct HierarchicalNodeDiscovery {
    local_discovery: Arc<LocalNodeDiscovery>,
    regional_discovery: Arc<RegionalNodeDiscovery>,
    global_discovery: Arc<GlobalNodeDiscovery>,
    
    // Current node information
    local_node: NodeInfo,
    
    // Discovery configuration
    config: DiscoveryConfig,
    
    // Atomic statistics
    total_discovered_nodes: AtomicUsize,
    last_discovery_time: AtomicU64,
    discovery_failures: AtomicU64,
}

/// Configuration for node discovery
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub local_discovery_interval: Duration,
    pub regional_discovery_interval: Duration,
    pub global_discovery_interval: Duration,
    pub node_timeout: Duration,
    pub max_nodes_per_tier: usize,
    pub enable_multicast: bool,
    pub multicast_address: IpAddr,
    pub multicast_port: u16,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            local_discovery_interval: Duration::from_secs(30),
            regional_discovery_interval: Duration::from_secs(120),
            global_discovery_interval: Duration::from_secs(300),
            node_timeout: Duration::from_secs(10),
            max_nodes_per_tier: 1000,
            enable_multicast: true,
            multicast_address: "224.0.0.251".parse().unwrap(), // mDNS multicast
            multicast_port: 5353,
        }
    }
}

impl HierarchicalNodeDiscovery {
    pub fn new(local_node: NodeInfo, config: DiscoveryConfig) -> Self {
        let local_discovery = Arc::new(LocalNodeDiscovery::new(
            local_node.clone(),
            config.clone(),
        ));
        
        let regional_discovery = Arc::new(RegionalNodeDiscovery::new(
            local_node.clone(),
            config.clone(),
        ));
        
        let global_discovery = Arc::new(GlobalNodeDiscovery::new(
            local_node.clone(),
            config.clone(),
        ));
        
        Self {
            local_discovery,
            regional_discovery,
            global_discovery,
            local_node,
            config,
            total_discovered_nodes: AtomicUsize::new(0),
            last_discovery_time: AtomicU64::new(0),
            discovery_failures: AtomicU64::new(0),
        }
    }
    
    /// Start all discovery services
    pub async fn start(&self) -> Result<()> {
        info!("Starting hierarchical node discovery for node {}", self.local_node.node_id);
        
        // Start local discovery
        self.local_discovery.start().await?;
        
        // Start regional discovery
        self.regional_discovery.start().await?;
        
        // Start global discovery
        self.global_discovery.start().await?;
        
        // Start discovery coordination task
        self.start_coordination_task().await;
        
        Ok(())
    }
    
    /// Get all discovered nodes across all tiers
    pub async fn get_all_nodes(&self) -> Vec<NodeInfo> {
        let mut all_nodes = Vec::new();
        
        // Get local nodes (highest priority)
        all_nodes.extend(self.local_discovery.get_nodes().await);
        
        // Get regional nodes
        all_nodes.extend(self.regional_discovery.get_nodes().await);
        
        // Get global nodes (lowest priority)
        all_nodes.extend(self.global_discovery.get_nodes().await);
        
        // Deduplicate by node_id
        let mut seen = std::collections::HashSet::new();
        all_nodes.retain(|node| seen.insert(node.node_id));
        
        self.total_discovered_nodes.store(all_nodes.len(), Ordering::Relaxed);
        
        all_nodes
    }
    
    /// Get nodes by region
    pub async fn get_nodes_by_region(&self, region: &str) -> Vec<NodeInfo> {
        let all_nodes = self.get_all_nodes().await;
        all_nodes.into_iter()
            .filter(|node| node.region == region)
            .collect()
    }
    
    /// Get nodes by datacenter
    pub async fn get_nodes_by_datacenter(&self, datacenter: &str) -> Vec<NodeInfo> {
        let all_nodes = self.get_all_nodes().await;
        all_nodes.into_iter()
            .filter(|node| node.datacenter == datacenter)
            .collect()
    }
    
    /// Get closest nodes based on network topology
    pub async fn get_closest_nodes(&self, count: usize) -> Vec<NodeInfo> {
        let mut all_nodes = self.get_all_nodes().await;
        
        // Sort by proximity: local > regional > global
        all_nodes.sort_by(|a, b| {
            // Same datacenter (highest priority)
            if a.datacenter == self.local_node.datacenter && b.datacenter != self.local_node.datacenter {
                return std::cmp::Ordering::Less;
            }
            if b.datacenter == self.local_node.datacenter && a.datacenter != self.local_node.datacenter {
                return std::cmp::Ordering::Greater;
            }
            
            // Same region (medium priority)
            if a.region == self.local_node.region && b.region != self.local_node.region {
                return std::cmp::Ordering::Less;
            }
            if b.region == self.local_node.region && a.region != self.local_node.region {
                return std::cmp::Ordering::Greater;
            }
            
            // Compare by load factor (lower is better)
            let a_load = a.metadata.get_load_factor();
            let b_load = b.metadata.get_load_factor();
            a_load.partial_cmp(&b_load).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        all_nodes.into_iter().take(count).collect()
    }
    
    /// Register a new node manually
    pub async fn register_node(&self, node: NodeInfo) -> Result<()> {
        // Determine which tier to register with based on location
        if node.datacenter == self.local_node.datacenter {
            self.local_discovery.register_node(node).await
        } else if node.region == self.local_node.region {
            self.regional_discovery.register_node(node).await
        } else {
            self.global_discovery.register_node(node).await
        }
    }
    
    /// Remove a node from discovery
    pub async fn remove_node(&self, node_id: u64) -> Result<()> {
        // Try to remove from all tiers
        let _ = self.local_discovery.remove_node(node_id).await;
        let _ = self.regional_discovery.remove_node(node_id).await;
        let _ = self.global_discovery.remove_node(node_id).await;
        Ok(())
    }
    
    /// Get discovery statistics
    pub fn get_stats(&self) -> DiscoveryStats {
        DiscoveryStats {
            total_nodes: self.total_discovered_nodes.load(Ordering::Relaxed),
            local_nodes: self.local_discovery.node_count(),
            regional_nodes: self.regional_discovery.node_count(),
            global_nodes: self.global_discovery.node_count(),
            last_discovery_time: self.last_discovery_time.load(Ordering::Relaxed),
            discovery_failures: self.discovery_failures.load(Ordering::Relaxed),
        }
    }
    
    /// Start coordination task for cross-tier communication
    async fn start_coordination_task(&self) {
        let local_discovery = Arc::clone(&self.local_discovery);
        let regional_discovery = Arc::clone(&self.regional_discovery);
        let global_discovery = Arc::clone(&self.global_discovery);
        
        tokio::spawn(async move {
            let mut coordination_interval = interval(Duration::from_secs(60));
            
            loop {
                coordination_interval.tick().await;
                
                // Share local nodes with regional tier
                if let Ok(local_nodes) = local_discovery.get_healthy_nodes().await {
                    for node in local_nodes {
                        if let Err(e) = regional_discovery.share_node_info(node).await {
                            warn!("Failed to share local node with regional tier: {}", e);
                        }
                    }
                }
                
                // Share regional nodes with global tier
                if let Ok(regional_nodes) = regional_discovery.get_healthy_nodes().await {
                    for node in regional_nodes {
                        if let Err(e) = global_discovery.share_node_info(node).await {
                            warn!("Failed to share regional node with global tier: {}", e);
                        }
                    }
                }
                
                debug!("Coordination cycle completed");
            }
        });
    }
}

/// Local node discovery (same datacenter/region)
pub struct LocalNodeDiscovery {
    nodes: Arc<RwLock<AHashMap<u64, NodeInfo>>>,
    local_node: NodeInfo,
    config: DiscoveryConfig,
    node_count: AtomicUsize,
    is_running: AtomicBool,
}

impl LocalNodeDiscovery {
    pub fn new(local_node: NodeInfo, config: DiscoveryConfig) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(AHashMap::new())),
            local_node,
            config,
            node_count: AtomicUsize::new(0),
            is_running: AtomicBool::new(false),
        }
    }
    
    pub async fn start(&self) -> Result<()> {
        if self.is_running.swap(true, Ordering::AcqRel) {
            return Ok(()); // Already running
        }
        
        info!("Starting local node discovery");
        
        // Start multicast discovery if enabled
        if self.config.enable_multicast {
            self.start_multicast_discovery().await?;
        }
        
        // Start periodic discovery
        self.start_periodic_discovery().await;
        
        Ok(())
    }
    
    pub async fn get_nodes(&self) -> Vec<NodeInfo> {
        self.nodes.read().await.values().cloned().collect()
    }
    
    pub async fn get_healthy_nodes(&self) -> Result<Vec<NodeInfo>> {
        let nodes = self.nodes.read().await;
        let healthy_nodes = nodes.values()
            .filter(|node| node.metadata.is_healthy.load(Ordering::Relaxed))
            .cloned()
            .collect();
        Ok(healthy_nodes)
    }
    
    pub async fn register_node(&self, node: NodeInfo) -> Result<()> {
        let mut nodes = self.nodes.write().await;
        if nodes.len() >= self.config.max_nodes_per_tier {
            return Err(ClusterError::InconsistentState);
        }
        
        nodes.insert(node.node_id, node);
        self.node_count.store(nodes.len(), Ordering::Relaxed);
        Ok(())
    }
    
    pub async fn remove_node(&self, node_id: u64) -> Result<()> {
        let mut nodes = self.nodes.write().await;
        nodes.remove(&node_id);
        self.node_count.store(nodes.len(), Ordering::Relaxed);
        Ok(())
    }
    
    pub fn node_count(&self) -> usize {
        self.node_count.load(Ordering::Relaxed)
    }
    
    async fn start_multicast_discovery(&self) -> Result<()> {
        // Implementation for multicast discovery using mDNS-like protocol
        debug!("Starting multicast discovery on {}:{}", 
               self.config.multicast_address, self.config.multicast_port);
        
        // This would implement actual multicast socket handling
        // For now, we'll simulate it with a placeholder
        Ok(())
    }
    
    async fn start_periodic_discovery(&self) {
        let nodes = Arc::clone(&self.nodes);
        let config = self.config.clone();
        let local_node = self.local_node.clone();
        
        tokio::spawn(async move {
            let mut discovery_interval = interval(config.local_discovery_interval);
            
            loop {
                discovery_interval.tick().await;
                
                // Perform health checks on known nodes
                let current_nodes: Vec<NodeInfo> = {
                    nodes.read().await.values().cloned().collect()
                };
                
                for node in current_nodes {
                    if let Err(_) = Self::health_check(&node, config.node_timeout).await {
                        // Mark node as unhealthy
                        node.metadata.is_healthy.store(false, Ordering::Relaxed);
                        warn!("Node {} failed health check", node.node_id);
                    } else {
                        node.metadata.is_healthy.store(true, Ordering::Relaxed);
                        node.metadata.update_last_seen();
                    }
                }
                
                // Clean up unhealthy nodes
                let mut nodes_write = nodes.write().await;
                let initial_count = nodes_write.len();
                nodes_write.retain(|_, node| {
                    let is_healthy = node.metadata.is_healthy.load(Ordering::Relaxed);
                    let last_seen = node.metadata.last_seen.load(Ordering::Relaxed);
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    
                    // Keep node if healthy or seen recently
                    is_healthy || (now - last_seen) < config.node_timeout.as_secs() * 3
                });
                
                if nodes_write.len() != initial_count {
                    info!("Cleaned up {} unhealthy nodes", initial_count - nodes_write.len());
                }
            }
        });
    }
    
    async fn health_check(node: &NodeInfo, timeout_duration: Duration) -> Result<()> {
        // Simple TCP connection test
        match timeout(timeout_duration, tokio::net::TcpStream::connect(node.address)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(ClusterError::Network(e)),
            Err(_) => Err(ClusterError::Timeout),
        }
    }
}

/// Regional node discovery (cross-region within continent)
pub struct RegionalNodeDiscovery {
    nodes: Arc<RwLock<AHashMap<u64, NodeInfo>>>,
    local_node: NodeInfo,
    config: DiscoveryConfig,
    node_count: AtomicUsize,
    is_running: AtomicBool,
}

impl RegionalNodeDiscovery {
    pub fn new(local_node: NodeInfo, config: DiscoveryConfig) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(AHashMap::new())),
            local_node,
            config,
            node_count: AtomicUsize::new(0),
            is_running: AtomicBool::new(false),
        }
    }
    
    pub async fn start(&self) -> Result<()> {
        if self.is_running.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        
        info!("Starting regional node discovery");
        self.start_regional_discovery().await;
        Ok(())
    }
    
    pub async fn get_nodes(&self) -> Vec<NodeInfo> {
        self.nodes.read().await.values().cloned().collect()
    }
    
    pub async fn get_healthy_nodes(&self) -> Result<Vec<NodeInfo>> {
        let nodes = self.nodes.read().await;
        let healthy_nodes = nodes.values()
            .filter(|node| node.metadata.is_healthy.load(Ordering::Relaxed))
            .cloned()
            .collect();
        Ok(healthy_nodes)
    }
    
    pub async fn register_node(&self, node: NodeInfo) -> Result<()> {
        let mut nodes = self.nodes.write().await;
        if nodes.len() >= self.config.max_nodes_per_tier {
            return Err(ClusterError::InconsistentState);
        }
        
        nodes.insert(node.node_id, node);
        self.node_count.store(nodes.len(), Ordering::Relaxed);
        Ok(())
    }
    
    pub async fn remove_node(&self, node_id: u64) -> Result<()> {
        let mut nodes = self.nodes.write().await;
        nodes.remove(&node_id);
        self.node_count.store(nodes.len(), Ordering::Relaxed);
        Ok(())
    }
    
    pub async fn share_node_info(&self, node: NodeInfo) -> Result<()> {
        // Share node information with other regional nodes
        self.register_node(node).await
    }
    
    pub fn node_count(&self) -> usize {
        self.node_count.load(Ordering::Relaxed)
    }
    
    async fn start_regional_discovery(&self) {
        let _nodes = Arc::clone(&self.nodes);
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut discovery_interval = interval(config.regional_discovery_interval);
            
            loop {
                discovery_interval.tick().await;
                
                // Regional discovery logic would go here
                // This could involve DNS-SD, consul, etcd, or custom protocols
                debug!("Performing regional node discovery");
            }
        });
    }
}

/// Global node discovery (planet-wide)
pub struct GlobalNodeDiscovery {
    nodes: Arc<RwLock<AHashMap<u64, NodeInfo>>>,
    local_node: NodeInfo,
    config: DiscoveryConfig,
    node_count: AtomicUsize,
    is_running: AtomicBool,
}

impl GlobalNodeDiscovery {
    pub fn new(local_node: NodeInfo, config: DiscoveryConfig) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(AHashMap::new())),
            local_node,
            config,
            node_count: AtomicUsize::new(0),
            is_running: AtomicBool::new(false),
        }
    }
    
    pub async fn start(&self) -> Result<()> {
        if self.is_running.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        
        info!("Starting global node discovery");
        self.start_global_discovery().await;
        Ok(())
    }
    
    pub async fn get_nodes(&self) -> Vec<NodeInfo> {
        self.nodes.read().await.values().cloned().collect()
    }
    
    pub async fn get_healthy_nodes(&self) -> Result<Vec<NodeInfo>> {
        let nodes = self.nodes.read().await;
        let healthy_nodes = nodes.values()
            .filter(|node| node.metadata.is_healthy.load(Ordering::Relaxed))
            .cloned()
            .collect();
        Ok(healthy_nodes)
    }
    
    pub async fn register_node(&self, node: NodeInfo) -> Result<()> {
        let mut nodes = self.nodes.write().await;
        if nodes.len() >= self.config.max_nodes_per_tier {
            return Err(ClusterError::InconsistentState);
        }
        
        nodes.insert(node.node_id, node);
        self.node_count.store(nodes.len(), Ordering::Relaxed);
        Ok(())
    }
    
    pub async fn remove_node(&self, node_id: u64) -> Result<()> {
        let mut nodes = self.nodes.write().await;
        nodes.remove(&node_id);
        self.node_count.store(nodes.len(), Ordering::Relaxed);
        Ok(())
    }
    
    pub async fn share_node_info(&self, node: NodeInfo) -> Result<()> {
        // Share node information globally
        self.register_node(node).await
    }
    
    pub fn node_count(&self) -> usize {
        self.node_count.load(Ordering::Relaxed)
    }
    
    async fn start_global_discovery(&self) {
        let _nodes = Arc::clone(&self.nodes);
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut discovery_interval = interval(config.global_discovery_interval);
            
            loop {
                discovery_interval.tick().await;
                
                // Global discovery logic would go here
                // This could involve cloud provider APIs, global registries, etc.
                debug!("Performing global node discovery");
            }
        });
    }
}

/// Discovery statistics
#[derive(Debug, Clone)]
pub struct DiscoveryStats {
    pub total_nodes: usize,
    pub local_nodes: usize,
    pub regional_nodes: usize,
    pub global_nodes: usize,
    pub last_discovery_time: u64,
    pub discovery_failures: u64,
}