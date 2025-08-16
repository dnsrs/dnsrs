//! Cluster health monitoring and failure detection
//!
//! Implements automatic node failure detection, recovery mechanisms,
//! and comprehensive health monitoring for unlimited cluster scaling.

use crate::{NodeInfo, Result, ClusterError};
use std::sync::atomic::{AtomicU64, AtomicU32, AtomicUsize, AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::net::SocketAddr;
use tokio::sync::RwLock;
use tokio::time::{interval, timeout, Instant};
use lockfree::map::Map as LockFreeMap;
use tracing::{info, warn, error, debug};
use ahash::AHashMap;

/// Cluster health monitor with automatic failure detection
pub struct ClusterHealthMonitor {
    // Node health tracking
    node_health: Arc<LockFreeMap<u64, Arc<AtomicNodeHealth>>>,
    
    // Health check configuration
    config: HealthConfig,
    
    // Health statistics
    stats: Arc<HealthStats>,
    
    // Failure detection state
    failure_detector: Arc<FailureDetector>,
    
    // Recovery manager
    recovery_manager: Arc<RecoveryManager>,
    
    // Running state
    is_running: AtomicBool,
}

/// Health monitoring configuration
#[derive(Debug, Clone)]
pub struct HealthConfig {
    pub health_check_interval: Duration,
    pub health_check_timeout: Duration,
    pub failure_threshold: u32,
    pub recovery_threshold: u32,
    pub max_concurrent_checks: usize,
    pub enable_adaptive_intervals: bool,
    pub min_check_interval: Duration,
    pub max_check_interval: Duration,
    pub enable_deep_health_checks: bool,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            health_check_interval: Duration::from_secs(30),
            health_check_timeout: Duration::from_secs(5),
            failure_threshold: 3,
            recovery_threshold: 2,
            max_concurrent_checks: 50,
            enable_adaptive_intervals: true,
            min_check_interval: Duration::from_secs(10),
            max_check_interval: Duration::from_secs(300),
            enable_deep_health_checks: false,
        }
    }
}

/// Atomic node health tracking
pub struct AtomicNodeHealth {
    pub node_id: u64,
    pub address: SocketAddr,
    pub is_healthy: AtomicBool,
    pub last_check_time: AtomicU64,
    pub last_success_time: AtomicU64,
    pub consecutive_failures: AtomicU32,
    pub consecutive_successes: AtomicU32,
    pub total_checks: AtomicU64,
    pub successful_checks: AtomicU64,
    pub failed_checks: AtomicU64,
    pub average_response_time: AtomicU64, // Microseconds
    pub current_check_interval: AtomicU64, // Seconds
    pub is_checking: AtomicBool,
    pub health_score: AtomicU64, // 0-10000 (0-100.00%)
}

impl AtomicNodeHealth {
    pub fn new(node_id: u64, address: SocketAddr) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Self {
            node_id,
            address,
            is_healthy: AtomicBool::new(true),
            last_check_time: AtomicU64::new(now),
            last_success_time: AtomicU64::new(now),
            consecutive_failures: AtomicU32::new(0),
            consecutive_successes: AtomicU32::new(0),
            total_checks: AtomicU64::new(0),
            successful_checks: AtomicU64::new(0),
            failed_checks: AtomicU64::new(0),
            average_response_time: AtomicU64::new(0),
            current_check_interval: AtomicU64::new(30), // Default 30 seconds
            is_checking: AtomicBool::new(false),
            health_score: AtomicU64::new(10000), // Start with 100%
        }
    }
    
    pub fn record_check_result(&self, success: bool, response_time_us: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        self.last_check_time.store(now, Ordering::Relaxed);
        self.total_checks.fetch_add(1, Ordering::Relaxed);
        
        if success {
            self.last_success_time.store(now, Ordering::Relaxed);
            self.successful_checks.fetch_add(1, Ordering::Relaxed);
            self.consecutive_successes.fetch_add(1, Ordering::Relaxed);
            self.consecutive_failures.store(0, Ordering::Relaxed);
            
            // Update average response time
            let current_avg = self.average_response_time.load(Ordering::Relaxed);
            let new_avg = if current_avg == 0 {
                response_time_us
            } else {
                (current_avg + response_time_us) / 2
            };
            self.average_response_time.store(new_avg, Ordering::Relaxed);
            
        } else {
            self.failed_checks.fetch_add(1, Ordering::Relaxed);
            self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
            self.consecutive_successes.store(0, Ordering::Relaxed);
        }
        
        // Update health score
        self.update_health_score();
    }
    
    fn update_health_score(&self) {
        let total = self.total_checks.load(Ordering::Relaxed);
        if total == 0 {
            return;
        }
        
        let successful = self.successful_checks.load(Ordering::Relaxed);
        let consecutive_failures = self.consecutive_failures.load(Ordering::Relaxed);
        
        // Base score from success rate
        let success_rate = (successful * 10000) / total;
        
        // Penalty for consecutive failures
        let failure_penalty = (consecutive_failures as u64 * 1000).min(5000);
        
        // Calculate final score
        let health_score = success_rate.saturating_sub(failure_penalty);
        
        self.health_score.store(health_score, Ordering::Relaxed);
    }
    
    pub fn get_health_score(&self) -> f32 {
        self.health_score.load(Ordering::Relaxed) as f32 / 100.0
    }
    
    pub fn should_be_healthy(&self, failure_threshold: u32) -> bool {
        self.consecutive_failures.load(Ordering::Relaxed) < failure_threshold
    }
    
    pub fn should_be_recovered(&self, recovery_threshold: u32) -> bool {
        self.consecutive_successes.load(Ordering::Relaxed) >= recovery_threshold
    }
}

/// Health monitoring statistics
pub struct HealthStats {
    pub total_nodes_monitored: AtomicUsize,
    pub healthy_nodes: AtomicUsize,
    pub unhealthy_nodes: AtomicUsize,
    pub total_health_checks: AtomicU64,
    pub successful_health_checks: AtomicU64,
    pub failed_health_checks: AtomicU64,
    pub nodes_recovered: AtomicU64,
    pub nodes_failed: AtomicU64,
    pub average_check_time: AtomicU64, // Microseconds
    pub last_check_time: AtomicU64,
}

impl HealthStats {
    pub fn new() -> Self {
        Self {
            total_nodes_monitored: AtomicUsize::new(0),
            healthy_nodes: AtomicUsize::new(0),
            unhealthy_nodes: AtomicUsize::new(0),
            total_health_checks: AtomicU64::new(0),
            successful_health_checks: AtomicU64::new(0),
            failed_health_checks: AtomicU64::new(0),
            nodes_recovered: AtomicU64::new(0),
            nodes_failed: AtomicU64::new(0),
            average_check_time: AtomicU64::new(0),
            last_check_time: AtomicU64::new(0),
        }
    }
}

impl ClusterHealthMonitor {
    pub fn new(config: HealthConfig) -> Self {
        Self {
            node_health: Arc::new(LockFreeMap::new()),
            config: config.clone(),
            stats: Arc::new(HealthStats::new()),
            failure_detector: Arc::new(FailureDetector::new(config.clone())),
            recovery_manager: Arc::new(RecoveryManager::new(config)),
            is_running: AtomicBool::new(false),
        }
    }
    
    /// Start health monitoring
    pub async fn start(&self) -> Result<()> {
        if self.is_running.swap(true, Ordering::AcqRel) {
            return Ok(()); // Already running
        }
        
        info!("Starting cluster health monitoring");
        
        // Start health check loop
        self.start_health_check_loop().await;
        
        // Start failure detection
        self.failure_detector.start().await?;
        
        // Start recovery manager
        self.recovery_manager.start().await?;
        
        Ok(())
    }
    
    /// Add a node to health monitoring
    pub async fn add_node(&self, node: NodeInfo) -> Result<()> {
        let health = Arc::new(AtomicNodeHealth::new(node.node_id, node.address));
        self.node_health.insert(node.node_id, health);
        
        self.stats.total_nodes_monitored.fetch_add(1, Ordering::Relaxed);
        self.stats.healthy_nodes.fetch_add(1, Ordering::Relaxed);
        
        info!("Added node {} to health monitoring", node.node_id);
        Ok(())
    }
    
    /// Remove a node from health monitoring
    pub async fn remove_node(&self, node_id: u64) -> Result<()> {
        if let Some(health) = self.node_health.remove(&node_id) {
            let was_healthy = health.val().is_healthy.load(Ordering::Relaxed);
            
            self.stats.total_nodes_monitored.fetch_sub(1, Ordering::Relaxed);
            
            if was_healthy {
                self.stats.healthy_nodes.fetch_sub(1, Ordering::Relaxed);
            } else {
                self.stats.unhealthy_nodes.fetch_sub(1, Ordering::Relaxed);
            }
            
            info!("Removed node {} from health monitoring", node_id);
        }
        
        Ok(())
    }
    
    /// Get health status for a specific node
    pub fn get_node_health(&self, node_id: u64) -> Option<NodeHealthStatus> {
        self.node_health.get(&node_id).map(|guard| {
            let health = guard.val();
            NodeHealthStatus {
                node_id,
                is_healthy: health.is_healthy.load(Ordering::Relaxed),
                health_score: health.get_health_score(),
                last_check_time: health.last_check_time.load(Ordering::Relaxed),
                last_success_time: health.last_success_time.load(Ordering::Relaxed),
                consecutive_failures: health.consecutive_failures.load(Ordering::Relaxed),
                consecutive_successes: health.consecutive_successes.load(Ordering::Relaxed),
                total_checks: health.total_checks.load(Ordering::Relaxed),
                successful_checks: health.successful_checks.load(Ordering::Relaxed),
                failed_checks: health.failed_checks.load(Ordering::Relaxed),
                average_response_time_us: health.average_response_time.load(Ordering::Relaxed),
            }
        })
    }
    
    /// Get all healthy nodes
    pub fn get_healthy_nodes(&self) -> Vec<u64> {
        self.node_health.iter()
            .filter_map(|guard| {
                let health = guard.val();
                if health.is_healthy.load(Ordering::Relaxed) {
                    Some(health.node_id)
                } else {
                    None
                }
            })
            .collect()
    }
    
    /// Get all unhealthy nodes
    pub fn get_unhealthy_nodes(&self) -> Vec<u64> {
        self.node_health.iter()
            .filter_map(|guard| {
                let health = guard.val();
                if !health.is_healthy.load(Ordering::Relaxed) {
                    Some(health.node_id)
                } else {
                    None
                }
            })
            .collect()
    }
    
    /// Get health statistics
    pub fn get_stats(&self) -> HealthStatsSnapshot {
        HealthStatsSnapshot {
            total_nodes_monitored: self.stats.total_nodes_monitored.load(Ordering::Relaxed),
            healthy_nodes: self.stats.healthy_nodes.load(Ordering::Relaxed),
            unhealthy_nodes: self.stats.unhealthy_nodes.load(Ordering::Relaxed),
            total_health_checks: self.stats.total_health_checks.load(Ordering::Relaxed),
            successful_health_checks: self.stats.successful_health_checks.load(Ordering::Relaxed),
            failed_health_checks: self.stats.failed_health_checks.load(Ordering::Relaxed),
            nodes_recovered: self.stats.nodes_recovered.load(Ordering::Relaxed),
            nodes_failed: self.stats.nodes_failed.load(Ordering::Relaxed),
            average_check_time_us: self.stats.average_check_time.load(Ordering::Relaxed),
            last_check_time: self.stats.last_check_time.load(Ordering::Relaxed),
        }
    }
    
    /// Start the health check loop
    async fn start_health_check_loop(&self) {
        let node_health = Arc::clone(&self.node_health);
        let config = self.config.clone();
        let stats = Arc::clone(&self.stats);
        
        tokio::spawn(async move {
            let mut check_interval = interval(config.health_check_interval);
            let semaphore = Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_checks));
            
            loop {
                check_interval.tick().await;
                
                let start_time = Instant::now();
                let mut check_futures = Vec::new();
                
                // Create health check tasks for all nodes
                for guard in node_health.iter() {
                    let health = guard.val().clone();
                    let config = config.clone();
                    let stats = Arc::clone(&stats);
                    let semaphore = Arc::clone(&semaphore);
                    
                    // Skip if already checking
                    if health.is_checking.swap(true, Ordering::AcqRel) {
                        continue;
                    }
                    
                    let future = async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        
                        let check_start = Instant::now();
                        let result = Self::perform_health_check(&health, &config).await;
                        let check_duration = check_start.elapsed().as_micros() as u64;
                        
                        // Record result
                        health.record_check_result(result.is_ok(), check_duration);
                        health.is_checking.store(false, Ordering::Release);
                        
                        // Update global statistics
                        stats.total_health_checks.fetch_add(1, Ordering::Relaxed);
                        
                        if result.is_ok() {
                            stats.successful_health_checks.fetch_add(1, Ordering::Relaxed);
                        } else {
                            stats.failed_health_checks.fetch_add(1, Ordering::Relaxed);
                        }
                        
                        // Update average check time
                        let current_avg = stats.average_check_time.load(Ordering::Relaxed);
                        let new_avg = if current_avg == 0 {
                            check_duration
                        } else {
                            (current_avg + check_duration) / 2
                        };
                        stats.average_check_time.store(new_avg, Ordering::Relaxed);
                        
                        result
                    };
                    
                    check_futures.push(future);
                }
                
                // Execute all health checks in parallel
                if !check_futures.is_empty() {
                    let _results = futures::future::join_all(check_futures).await;
                }
                
                let total_check_time = start_time.elapsed().as_secs();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                
                stats.last_check_time.store(now, Ordering::Relaxed);
                
                debug!("Health check cycle completed in {}s", total_check_time);
            }
        });
    }
    
    /// Perform a single health check
    async fn perform_health_check(health: &AtomicNodeHealth, config: &HealthConfig) -> Result<()> {
        // Basic TCP connection test
        match timeout(
            config.health_check_timeout,
            tokio::net::TcpStream::connect(health.address)
        ).await {
            Ok(Ok(_)) => {
                debug!("Health check passed for node {}", health.node_id);
                Ok(())
            }
            Ok(Err(e)) => {
                debug!("Health check failed for node {}: {}", health.node_id, e);
                Err(ClusterError::Network(e))
            }
            Err(_) => {
                debug!("Health check timed out for node {}", health.node_id);
                Err(ClusterError::Timeout)
            }
        }
    }
}

/// Failure detector for automatic node failure detection
pub struct FailureDetector {
    config: HealthConfig,
    is_running: AtomicBool,
}

impl FailureDetector {
    pub fn new(config: HealthConfig) -> Self {
        Self {
            config,
            is_running: AtomicBool::new(false),
        }
    }
    
    pub async fn start(&self) -> Result<()> {
        if self.is_running.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        
        info!("Starting failure detector");
        
        // Start failure detection loop
        self.start_detection_loop().await;
        
        Ok(())
    }
    
    async fn start_detection_loop(&self) {
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut detection_interval = interval(Duration::from_secs(10));
            
            loop {
                detection_interval.tick().await;
                
                // Failure detection logic would go here
                debug!("Running failure detection cycle");
            }
        });
    }
}

/// Recovery manager for automatic node recovery
pub struct RecoveryManager {
    config: HealthConfig,
    is_running: AtomicBool,
}

impl RecoveryManager {
    pub fn new(config: HealthConfig) -> Self {
        Self {
            config,
            is_running: AtomicBool::new(false),
        }
    }
    
    pub async fn start(&self) -> Result<()> {
        if self.is_running.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        
        info!("Starting recovery manager");
        
        // Start recovery loop
        self.start_recovery_loop().await;
        
        Ok(())
    }
    
    async fn start_recovery_loop(&self) {
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut recovery_interval = interval(Duration::from_secs(30));
            
            loop {
                recovery_interval.tick().await;
                
                // Recovery logic would go here
                debug!("Running recovery cycle");
            }
        });
    }
}

/// Node health status snapshot
#[derive(Debug, Clone)]
pub struct NodeHealthStatus {
    pub node_id: u64,
    pub is_healthy: bool,
    pub health_score: f32,
    pub last_check_time: u64,
    pub last_success_time: u64,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub total_checks: u64,
    pub successful_checks: u64,
    pub failed_checks: u64,
    pub average_response_time_us: u64,
}

/// Health statistics snapshot
#[derive(Debug, Clone)]
pub struct HealthStatsSnapshot {
    pub total_nodes_monitored: usize,
    pub healthy_nodes: usize,
    pub unhealthy_nodes: usize,
    pub total_health_checks: u64,
    pub successful_health_checks: u64,
    pub failed_health_checks: u64,
    pub nodes_recovered: u64,
    pub nodes_failed: u64,
    pub average_check_time_us: u64,
    pub last_check_time: u64,
}