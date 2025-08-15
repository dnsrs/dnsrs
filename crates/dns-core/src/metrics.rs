//! Atomic metrics collection for high-performance monitoring
//!
//! This module provides lock-free metrics collection using atomic operations
//! for minimal performance impact during DNS query processing.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Global metrics collector for the DNS server
pub struct AtomicMetrics {
    // Query metrics
    pub queries_total: AtomicU64,
    pub queries_per_second: AtomicU64,
    pub response_time_total_ns: AtomicU64,
    pub last_query_time: AtomicU64,
    
    // Response type metrics
    pub noerror_responses: AtomicU64,
    pub nxdomain_responses: AtomicU64,
    pub servfail_responses: AtomicU64,
    pub refused_responses: AtomicU64,
    
    // Cache metrics
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub cache_size: AtomicUsize,
    pub cache_evictions: AtomicU64,
    
    // Blocklist metrics
    pub blocked_queries: AtomicU64,
    pub blocklist_size: AtomicUsize,
    pub blocklist_hits: AtomicU64,
    
    // Protocol metrics
    pub udp_queries: AtomicU64,
    pub tcp_queries: AtomicU64,
    pub doh_queries: AtomicU64,
    pub dot_queries: AtomicU64,
    pub doq_queries: AtomicU64,
    
    // Error metrics
    pub protocol_errors: AtomicU64,
    pub storage_errors: AtomicU64,
    pub network_errors: AtomicU64,
    pub timeout_errors: AtomicU64,
    
    // Performance metrics
    pub memory_usage_bytes: AtomicUsize,
    pub cpu_usage_percent: AtomicU64, // Fixed-point percentage * 100
    pub active_connections: AtomicUsize,
    
    // Cluster metrics
    pub cluster_nodes: AtomicUsize,
    pub replication_lag_ms: AtomicU64,
    pub zone_transfers: AtomicU64,
    
    // DNSSEC metrics
    pub dnssec_queries: AtomicU64,
    pub dnssec_validations: AtomicU64,
    pub dnssec_failures: AtomicU64,
}

impl AtomicMetrics {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            queries_total: AtomicU64::new(0),
            queries_per_second: AtomicU64::new(0),
            response_time_total_ns: AtomicU64::new(0),
            last_query_time: AtomicU64::new(0),
            
            noerror_responses: AtomicU64::new(0),
            nxdomain_responses: AtomicU64::new(0),
            servfail_responses: AtomicU64::new(0),
            refused_responses: AtomicU64::new(0),
            
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            cache_size: AtomicUsize::new(0),
            cache_evictions: AtomicU64::new(0),
            
            blocked_queries: AtomicU64::new(0),
            blocklist_size: AtomicUsize::new(0),
            blocklist_hits: AtomicU64::new(0),
            
            udp_queries: AtomicU64::new(0),
            tcp_queries: AtomicU64::new(0),
            doh_queries: AtomicU64::new(0),
            dot_queries: AtomicU64::new(0),
            doq_queries: AtomicU64::new(0),
            
            protocol_errors: AtomicU64::new(0),
            storage_errors: AtomicU64::new(0),
            network_errors: AtomicU64::new(0),
            timeout_errors: AtomicU64::new(0),
            
            memory_usage_bytes: AtomicUsize::new(0),
            cpu_usage_percent: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
            
            cluster_nodes: AtomicUsize::new(1),
            replication_lag_ms: AtomicU64::new(0),
            zone_transfers: AtomicU64::new(0),
            
            dnssec_queries: AtomicU64::new(0),
            dnssec_validations: AtomicU64::new(0),
            dnssec_failures: AtomicU64::new(0),
        }
    }
    
    /// Record a DNS query with response time
    pub fn record_query(&self, response_time_ns: u64, protocol: crate::types::ProtocolType) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        self.queries_total.fetch_add(1, Ordering::Relaxed);
        self.response_time_total_ns.fetch_add(response_time_ns, Ordering::Relaxed);
        self.last_query_time.store(now, Ordering::Relaxed);
        
        // Update protocol-specific counters
        match protocol {
            crate::types::ProtocolType::Udp => {
                self.udp_queries.fetch_add(1, Ordering::Relaxed);
            }
            crate::types::ProtocolType::Tcp => {
                self.tcp_queries.fetch_add(1, Ordering::Relaxed);
            }
            crate::types::ProtocolType::DoH => {
                self.doh_queries.fetch_add(1, Ordering::Relaxed);
            }
            crate::types::ProtocolType::DoT => {
                self.dot_queries.fetch_add(1, Ordering::Relaxed);
            }
            crate::types::ProtocolType::DoQ => {
                self.doq_queries.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    
    /// Record a response by type
    pub fn record_response(&self, response_code: crate::types::ResponseCode) {
        match response_code {
            crate::types::ResponseCode::NoError => {
                self.noerror_responses.fetch_add(1, Ordering::Relaxed);
            }
            crate::types::ResponseCode::NXDomain => {
                self.nxdomain_responses.fetch_add(1, Ordering::Relaxed);
            }
            crate::types::ResponseCode::ServFail => {
                self.servfail_responses.fetch_add(1, Ordering::Relaxed);
            }
            crate::types::ResponseCode::Refused => {
                self.refused_responses.fetch_add(1, Ordering::Relaxed);
            }
            _ => {} // Other response codes not tracked separately
        }
    }
    
    /// Record cache hit
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record cache miss
    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record blocked query
    pub fn record_blocked_query(&self) {
        self.blocked_queries.fetch_add(1, Ordering::Relaxed);
        self.blocklist_hits.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record error by category
    pub fn record_error(&self, category: &str) {
        match category {
            "protocol" => self.protocol_errors.fetch_add(1, Ordering::Relaxed),
            "storage" => self.storage_errors.fetch_add(1, Ordering::Relaxed),
            "network" => self.network_errors.fetch_add(1, Ordering::Relaxed),
            "timeout" => self.timeout_errors.fetch_add(1, Ordering::Relaxed),
            _ => 0, // Unknown category
        };
    }
    
    /// Update cache size
    pub fn update_cache_size(&self, size: usize) {
        self.cache_size.store(size, Ordering::Relaxed);
    }
    
    /// Record cache eviction
    pub fn record_cache_eviction(&self) {
        self.cache_evictions.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Update memory usage
    pub fn update_memory_usage(&self, bytes: usize) {
        self.memory_usage_bytes.store(bytes, Ordering::Relaxed);
    }
    
    /// Update active connections
    pub fn update_active_connections(&self, count: usize) {
        self.active_connections.store(count, Ordering::Relaxed);
    }
    
    /// Calculate cache hit rate as percentage (0-10000 for 0.00% to 100.00%)
    pub fn cache_hit_rate(&self) -> u64 {
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let total = hits + misses;
        
        if total == 0 {
            0
        } else {
            (hits * 10000) / total
        }
    }
    
    /// Calculate average response time in nanoseconds
    pub fn average_response_time_ns(&self) -> u64 {
        let total_time = self.response_time_total_ns.load(Ordering::Relaxed);
        let total_queries = self.queries_total.load(Ordering::Relaxed);
        
        if total_queries == 0 {
            0
        } else {
            total_time / total_queries
        }
    }
    
    /// Get current queries per second (approximate)
    pub fn current_qps(&self) -> u64 {
        self.queries_per_second.load(Ordering::Relaxed)
    }
    
    /// Update queries per second (called periodically)
    pub fn update_qps(&self, qps: u64) {
        self.queries_per_second.store(qps, Ordering::Relaxed);
    }
    
    /// Get snapshot of all metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            queries_total: self.queries_total.load(Ordering::Relaxed),
            queries_per_second: self.queries_per_second.load(Ordering::Relaxed),
            average_response_time_ns: self.average_response_time_ns(),
            
            noerror_responses: self.noerror_responses.load(Ordering::Relaxed),
            nxdomain_responses: self.nxdomain_responses.load(Ordering::Relaxed),
            servfail_responses: self.servfail_responses.load(Ordering::Relaxed),
            refused_responses: self.refused_responses.load(Ordering::Relaxed),
            
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            cache_hit_rate: self.cache_hit_rate(),
            cache_size: self.cache_size.load(Ordering::Relaxed),
            cache_evictions: self.cache_evictions.load(Ordering::Relaxed),
            
            blocked_queries: self.blocked_queries.load(Ordering::Relaxed),
            blocklist_size: self.blocklist_size.load(Ordering::Relaxed),
            
            udp_queries: self.udp_queries.load(Ordering::Relaxed),
            tcp_queries: self.tcp_queries.load(Ordering::Relaxed),
            doh_queries: self.doh_queries.load(Ordering::Relaxed),
            dot_queries: self.dot_queries.load(Ordering::Relaxed),
            doq_queries: self.doq_queries.load(Ordering::Relaxed),
            
            protocol_errors: self.protocol_errors.load(Ordering::Relaxed),
            storage_errors: self.storage_errors.load(Ordering::Relaxed),
            network_errors: self.network_errors.load(Ordering::Relaxed),
            timeout_errors: self.timeout_errors.load(Ordering::Relaxed),
            
            memory_usage_bytes: self.memory_usage_bytes.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            
            cluster_nodes: self.cluster_nodes.load(Ordering::Relaxed),
            replication_lag_ms: self.replication_lag_ms.load(Ordering::Relaxed),
            zone_transfers: self.zone_transfers.load(Ordering::Relaxed),
            
            dnssec_queries: self.dnssec_queries.load(Ordering::Relaxed),
            dnssec_validations: self.dnssec_validations.load(Ordering::Relaxed),
            dnssec_failures: self.dnssec_failures.load(Ordering::Relaxed),
        }
    }
}

impl Default for AtomicMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of metrics at a point in time
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub queries_total: u64,
    pub queries_per_second: u64,
    pub average_response_time_ns: u64,
    
    pub noerror_responses: u64,
    pub nxdomain_responses: u64,
    pub servfail_responses: u64,
    pub refused_responses: u64,
    
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_rate: u64, // Percentage * 100 (0-10000)
    pub cache_size: usize,
    pub cache_evictions: u64,
    
    pub blocked_queries: u64,
    pub blocklist_size: usize,
    
    pub udp_queries: u64,
    pub tcp_queries: u64,
    pub doh_queries: u64,
    pub dot_queries: u64,
    pub doq_queries: u64,
    
    pub protocol_errors: u64,
    pub storage_errors: u64,
    pub network_errors: u64,
    pub timeout_errors: u64,
    
    pub memory_usage_bytes: usize,
    pub active_connections: usize,
    
    pub cluster_nodes: usize,
    pub replication_lag_ms: u64,
    pub zone_transfers: u64,
    
    pub dnssec_queries: u64,
    pub dnssec_validations: u64,
    pub dnssec_failures: u64,
}

/// Global metrics instance
static GLOBAL_METRICS: std::sync::OnceLock<AtomicMetrics> = std::sync::OnceLock::new();

/// Get the global metrics instance
pub fn global_metrics() -> &'static AtomicMetrics {
    GLOBAL_METRICS.get_or_init(AtomicMetrics::new)
}