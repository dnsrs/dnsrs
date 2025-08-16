//! Health check endpoints for Kubernetes readiness/liveness probes
//!
//! Provides comprehensive health checking for all DNS server components
//! with detailed status reporting and configurable check intervals.

use dns_core::{DnsResult, DnsError, global_metrics};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::interval;

/// Configuration for health checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    /// Enable health checks
    pub enabled: bool,
    /// Health check interval in seconds
    pub check_interval_secs: u64,
    /// Timeout for individual health checks in seconds
    pub check_timeout_secs: u64,
    /// Maximum allowed memory usage percentage (0-100)
    pub max_memory_usage_percent: f64,
    /// Maximum allowed CPU usage percentage (0-100)
    pub max_cpu_usage_percent: f64,
    /// Maximum allowed response time in milliseconds
    pub max_response_time_ms: u64,
    /// Minimum cache hit rate percentage (0-100)
    pub min_cache_hit_rate_percent: f64,
    /// Maximum allowed error rate percentage (0-100)
    pub max_error_rate_percent: f64,
    /// Enable detailed component checks
    pub detailed_checks: bool,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_secs: 30,
            check_timeout_secs: 5,
            max_memory_usage_percent: 90.0,
            max_cpu_usage_percent: 95.0,
            max_response_time_ms: 100,
            min_cache_hit_rate_percent: 80.0,
            max_error_rate_percent: 5.0,
            detailed_checks: true,
        }
    }
}

/// Overall health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    /// All systems operational
    Healthy,
    /// Some non-critical issues detected
    Degraded,
    /// Critical issues detected
    Unhealthy,
    /// Health check system not initialized
    Unknown,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Degraded => write!(f, "degraded"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
            HealthStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// Individual component health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name
    pub name: String,
    /// Health status
    pub status: HealthStatus,
    /// Status message
    pub message: String,
    /// Last check timestamp
    pub last_check: u64,
    /// Check duration in milliseconds
    pub check_duration_ms: u64,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Complete health check report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    /// Overall status
    pub status: HealthStatus,
    /// Timestamp of the report
    pub timestamp: u64,
    /// Server uptime in seconds
    pub uptime_seconds: u64,
    /// Individual component health
    pub components: HashMap<String, ComponentHealth>,
    /// Summary statistics
    pub summary: HealthSummary,
}

/// Health summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSummary {
    /// Total components checked
    pub total_components: usize,
    /// Number of healthy components
    pub healthy_components: usize,
    /// Number of degraded components
    pub degraded_components: usize,
    /// Number of unhealthy components
    pub unhealthy_components: usize,
    /// Overall health score (0-100)
    pub health_score: f64,
}

/// Health checker implementation
pub struct HealthChecker {
    config: HealthConfig,
    start_time: Instant,
    last_report: Arc<RwLock<Option<HealthReport>>>,
    system_info: Arc<RwLock<SystemInfo>>,
}

/// System information for health checks
#[derive(Debug, Clone)]
struct SystemInfo {
    memory_usage_percent: f64,
    cpu_usage_percent: f64,
    disk_usage_percent: f64,
    network_connections: usize,
    last_updated: Instant,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(config: HealthConfig) -> Self {
        Self {
            config,
            start_time: Instant::now(),
            last_report: Arc::new(RwLock::new(None)),
            system_info: Arc::new(RwLock::new(SystemInfo {
                memory_usage_percent: 0.0,
                cpu_usage_percent: 0.0,
                disk_usage_percent: 0.0,
                network_connections: 0,
                last_updated: Instant::now(),
            })),
        }
    }
    
    /// Start the health check loop
    pub async fn start(&self) -> DnsResult<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        let mut interval = interval(Duration::from_secs(self.config.check_interval_secs));
        let system_info = self.system_info.clone();
        let last_report = self.last_report.clone();
        let config = self.config.clone();
        let start_time = self.start_time;
        
        tokio::spawn(async move {
            loop {
                interval.tick().await;
                
                // Update system information
                if let Ok(mut info) = system_info.write().await {
                    Self::update_system_info(&mut info).await;
                }
                
                // Perform health checks
                let report = Self::perform_health_checks(&config, start_time, &system_info).await;
                
                // Update last report
                if let Ok(mut last) = last_report.write().await {
                    *last = Some(report);
                }
            }
        });
        
        Ok(())
    }
    
    /// Get the current health status
    pub async fn get_health_status(&self) -> HealthStatus {
        if let Ok(report) = self.last_report.read().await {
            if let Some(ref report) = *report {
                return report.status.clone();
            }
        }
        HealthStatus::Unknown
    }
    
    /// Get the full health report
    pub async fn get_health_report(&self) -> Option<HealthReport> {
        if let Ok(report) = self.last_report.read().await {
            return report.clone();
        }
        None
    }
    
    /// Check if the server is ready (Kubernetes readiness probe)
    pub async fn is_ready(&self) -> bool {
        match self.get_health_status().await {
            HealthStatus::Healthy | HealthStatus::Degraded => true,
            _ => false,
        }
    }
    
    /// Check if the server is alive (Kubernetes liveness probe)
    pub async fn is_alive(&self) -> bool {
        // More lenient check - only fail if completely unhealthy
        match self.get_health_status().await {
            HealthStatus::Unhealthy => false,
            _ => true,
        }
    }
    
    /// Perform all health checks
    async fn perform_health_checks(
        config: &HealthConfig,
        start_time: Instant,
        system_info: &Arc<RwLock<SystemInfo>>,
    ) -> HealthReport {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let uptime_seconds = start_time.elapsed().as_secs();
        
        let mut components = HashMap::new();
        
        // DNS Core Health Check
        components.insert(
            "dns_core".to_string(),
            Self::check_dns_core(config).await,
        );
        
        // Cache Health Check
        components.insert(
            "cache".to_string(),
            Self::check_cache(config).await,
        );
        
        // Storage Health Check
        components.insert(
            "storage".to_string(),
            Self::check_storage(config).await,
        );
        
        // Network Health Check
        components.insert(
            "network".to_string(),
            Self::check_network(config).await,
        );
        
        // System Resources Health Check
        components.insert(
            "system_resources".to_string(),
            Self::check_system_resources(config, system_info).await,
        );
        
        // Cluster Health Check (if applicable)
        if config.detailed_checks {
            components.insert(
                "cluster".to_string(),
                Self::check_cluster(config).await,
            );
            
            // Security Health Check
            components.insert(
                "security".to_string(),
                Self::check_security(config).await,
            );
        }
        
        // Calculate overall status and summary
        let summary = Self::calculate_summary(&components);
        let status = Self::determine_overall_status(&summary);
        
        HealthReport {
            status,
            timestamp,
            uptime_seconds,
            components,
            summary,
        }
    }
    
    /// Check DNS core functionality
    async fn check_dns_core(config: &HealthConfig) -> ComponentHealth {
        let start = Instant::now();
        let metrics = global_metrics().snapshot();
        
        let mut metadata = HashMap::new();
        metadata.insert("queries_total".to_string(), serde_json::Value::Number(metrics.queries_total.into()));
        metadata.insert("queries_per_second".to_string(), serde_json::Value::Number(metrics.queries_per_second.into()));
        metadata.insert("average_response_time_ns".to_string(), serde_json::Value::Number(metrics.average_response_time_ns.into()));
        
        let avg_response_time_ms = metrics.average_response_time_ns / 1_000_000;
        let total_queries = metrics.queries_total;
        let total_errors = metrics.protocol_errors + metrics.storage_errors + metrics.network_errors + metrics.timeout_errors;
        let error_rate = if total_queries > 0 {
            (total_errors as f64 / total_queries as f64) * 100.0
        } else {
            0.0
        };
        
        let (status, message) = if avg_response_time_ms > config.max_response_time_ms {
            (HealthStatus::Degraded, format!("High response time: {}ms", avg_response_time_ms))
        } else if error_rate > config.max_error_rate_percent {
            (HealthStatus::Unhealthy, format!("High error rate: {:.2}%", error_rate))
        } else if total_queries == 0 {
            (HealthStatus::Degraded, "No queries processed yet".to_string())
        } else {
            (HealthStatus::Healthy, "DNS core functioning normally".to_string())
        };
        
        ComponentHealth {
            name: "dns_core".to_string(),
            status,
            message,
            last_check: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            check_duration_ms: start.elapsed().as_millis() as u64,
            metadata,
        }
    }
    
    /// Check cache health
    async fn check_cache(config: &HealthConfig) -> ComponentHealth {
        let start = Instant::now();
        let metrics = global_metrics().snapshot();
        
        let mut metadata = HashMap::new();
        metadata.insert("cache_hits".to_string(), serde_json::Value::Number(metrics.cache_hits.into()));
        metadata.insert("cache_misses".to_string(), serde_json::Value::Number(metrics.cache_misses.into()));
        metadata.insert("cache_size".to_string(), serde_json::Value::Number(metrics.cache_size.into()));
        metadata.insert("cache_evictions".to_string(), serde_json::Value::Number(metrics.cache_evictions.into()));
        
        let cache_hit_rate = metrics.cache_hit_rate as f64 / 100.0; // Convert from basis points to percentage
        
        let (status, message) = if cache_hit_rate < config.min_cache_hit_rate_percent {
            (HealthStatus::Degraded, format!("Low cache hit rate: {:.2}%", cache_hit_rate))
        } else if metrics.cache_size == 0 {
            (HealthStatus::Degraded, "Cache is empty".to_string())
        } else {
            (HealthStatus::Healthy, format!("Cache hit rate: {:.2}%", cache_hit_rate))
        };
        
        ComponentHealth {
            name: "cache".to_string(),
            status,
            message,
            last_check: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            check_duration_ms: start.elapsed().as_millis() as u64,
            metadata,
        }
    }
    
    /// Check storage health
    async fn check_storage(_config: &HealthConfig) -> ComponentHealth {
        let start = Instant::now();
        let metrics = global_metrics().snapshot();
        
        let mut metadata = HashMap::new();
        metadata.insert("storage_errors".to_string(), serde_json::Value::Number(metrics.storage_errors.into()));
        
        let (status, message) = if metrics.storage_errors > 0 {
            (HealthStatus::Degraded, format!("Storage errors detected: {}", metrics.storage_errors))
        } else {
            (HealthStatus::Healthy, "Storage functioning normally".to_string())
        };
        
        ComponentHealth {
            name: "storage".to_string(),
            status,
            message,
            last_check: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            check_duration_ms: start.elapsed().as_millis() as u64,
            metadata,
        }
    }
    
    /// Check network health
    async fn check_network(_config: &HealthConfig) -> ComponentHealth {
        let start = Instant::now();
        let metrics = global_metrics().snapshot();
        
        let mut metadata = HashMap::new();
        metadata.insert("network_errors".to_string(), serde_json::Value::Number(metrics.network_errors.into()));
        metadata.insert("active_connections".to_string(), serde_json::Value::Number(metrics.active_connections.into()));
        
        let (status, message) = if metrics.network_errors > 0 {
            (HealthStatus::Degraded, format!("Network errors detected: {}", metrics.network_errors))
        } else {
            (HealthStatus::Healthy, "Network functioning normally".to_string())
        };
        
        ComponentHealth {
            name: "network".to_string(),
            status,
            message,
            last_check: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            check_duration_ms: start.elapsed().as_millis() as u64,
            metadata,
        }
    }
    
    /// Check system resources
    async fn check_system_resources(
        config: &HealthConfig,
        system_info: &Arc<RwLock<SystemInfo>>,
    ) -> ComponentHealth {
        let start = Instant::now();
        
        let info = if let Ok(info) = system_info.read().await {
            info.clone()
        } else {
            SystemInfo {
                memory_usage_percent: 0.0,
                cpu_usage_percent: 0.0,
                disk_usage_percent: 0.0,
                network_connections: 0,
                last_updated: Instant::now(),
            }
        };
        
        let mut metadata = HashMap::new();
        metadata.insert("memory_usage_percent".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(info.memory_usage_percent).unwrap()));
        metadata.insert("cpu_usage_percent".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(info.cpu_usage_percent).unwrap()));
        metadata.insert("disk_usage_percent".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(info.disk_usage_percent).unwrap()));
        
        let (status, message) = if info.memory_usage_percent > config.max_memory_usage_percent {
            (HealthStatus::Unhealthy, format!("High memory usage: {:.1}%", info.memory_usage_percent))
        } else if info.cpu_usage_percent > config.max_cpu_usage_percent {
            (HealthStatus::Unhealthy, format!("High CPU usage: {:.1}%", info.cpu_usage_percent))
        } else if info.memory_usage_percent > config.max_memory_usage_percent * 0.8 {
            (HealthStatus::Degraded, format!("Elevated memory usage: {:.1}%", info.memory_usage_percent))
        } else if info.cpu_usage_percent > config.max_cpu_usage_percent * 0.8 {
            (HealthStatus::Degraded, format!("Elevated CPU usage: {:.1}%", info.cpu_usage_percent))
        } else {
            (HealthStatus::Healthy, "System resources normal".to_string())
        };
        
        ComponentHealth {
            name: "system_resources".to_string(),
            status,
            message,
            last_check: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            check_duration_ms: start.elapsed().as_millis() as u64,
            metadata,
        }
    }
    
    /// Check cluster health
    async fn check_cluster(_config: &HealthConfig) -> ComponentHealth {
        let start = Instant::now();
        let metrics = global_metrics().snapshot();
        
        let mut metadata = HashMap::new();
        metadata.insert("cluster_nodes".to_string(), serde_json::Value::Number(metrics.cluster_nodes.into()));
        metadata.insert("replication_lag_ms".to_string(), serde_json::Value::Number(metrics.replication_lag_ms.into()));
        
        let (status, message) = if metrics.cluster_nodes == 0 {
            (HealthStatus::Unhealthy, "No cluster nodes available".to_string())
        } else if metrics.replication_lag_ms > 5000 {
            (HealthStatus::Degraded, format!("High replication lag: {}ms", metrics.replication_lag_ms))
        } else {
            (HealthStatus::Healthy, format!("Cluster healthy with {} nodes", metrics.cluster_nodes))
        };
        
        ComponentHealth {
            name: "cluster".to_string(),
            status,
            message,
            last_check: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            check_duration_ms: start.elapsed().as_millis() as u64,
            metadata,
        }
    }
    
    /// Check security health
    async fn check_security(_config: &HealthConfig) -> ComponentHealth {
        let start = Instant::now();
        let metrics = global_metrics().snapshot();
        
        let mut metadata = HashMap::new();
        metadata.insert("blocked_queries".to_string(), serde_json::Value::Number(metrics.blocked_queries.into()));
        metadata.insert("dnssec_queries".to_string(), serde_json::Value::Number(metrics.dnssec_queries.into()));
        metadata.insert("dnssec_failures".to_string(), serde_json::Value::Number(metrics.dnssec_failures.into()));
        
        let dnssec_failure_rate = if metrics.dnssec_queries > 0 {
            (metrics.dnssec_failures as f64 / metrics.dnssec_queries as f64) * 100.0
        } else {
            0.0
        };
        
        let (status, message) = if dnssec_failure_rate > 10.0 {
            (HealthStatus::Degraded, format!("High DNSSEC failure rate: {:.2}%", dnssec_failure_rate))
        } else {
            (HealthStatus::Healthy, "Security systems functioning normally".to_string())
        };
        
        ComponentHealth {
            name: "security".to_string(),
            status,
            message,
            last_check: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            check_duration_ms: start.elapsed().as_millis() as u64,
            metadata,
        }
    }
    
    /// Update system information
    async fn update_system_info(info: &mut SystemInfo) {
        // This would typically use a system monitoring library like sysinfo
        // For now, we'll use placeholder values
        info.memory_usage_percent = 45.0; // Placeholder
        info.cpu_usage_percent = 25.0;    // Placeholder
        info.disk_usage_percent = 60.0;   // Placeholder
        info.network_connections = 150;   // Placeholder
        info.last_updated = Instant::now();
    }
    
    /// Calculate health summary
    fn calculate_summary(components: &HashMap<String, ComponentHealth>) -> HealthSummary {
        let total_components = components.len();
        let mut healthy_components = 0;
        let mut degraded_components = 0;
        let mut unhealthy_components = 0;
        
        for component in components.values() {
            match component.status {
                HealthStatus::Healthy => healthy_components += 1,
                HealthStatus::Degraded => degraded_components += 1,
                HealthStatus::Unhealthy => unhealthy_components += 1,
                HealthStatus::Unknown => {} // Don't count unknown
            }
        }
        
        // Calculate health score (0-100)
        let health_score = if total_components > 0 {
            ((healthy_components as f64 * 100.0) + (degraded_components as f64 * 50.0)) / total_components as f64
        } else {
            0.0
        };
        
        HealthSummary {
            total_components,
            healthy_components,
            degraded_components,
            unhealthy_components,
            health_score,
        }
    }
    
    /// Determine overall status from summary
    fn determine_overall_status(summary: &HealthSummary) -> HealthStatus {
        if summary.unhealthy_components > 0 {
            HealthStatus::Unhealthy
        } else if summary.degraded_components > 0 {
            HealthStatus::Degraded
        } else if summary.healthy_components > 0 {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unknown
        }
    }
}