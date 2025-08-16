//! Prometheus metrics collection and exposition

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use prometheus::{
    Counter, Encoder, Gauge, Histogram, IntCounter, IntGauge, Registry, TextEncoder,
};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Metrics collector for DNS server operations
#[derive(Clone)]
pub struct MetricsCollector {
    registry: Arc<Registry>,
    
    // DNS query metrics
    pub queries_total: IntCounter,
    pub queries_per_second: Gauge,
    pub query_duration: Histogram,
    
    // Cache metrics
    pub cache_hits_total: IntCounter,
    pub cache_misses_total: IntCounter,
    pub cache_size: IntGauge,
    pub cache_hit_ratio: Gauge,
    
    // Blocklist metrics
    pub blocked_queries_total: IntCounter,
    pub blocklist_size: IntGauge,
    
    // Zone metrics
    pub zones_total: IntGauge,
    pub records_total: IntGauge,
    pub zone_transfers_total: IntCounter,
    
    // Cluster metrics
    pub cluster_nodes_total: IntGauge,
    pub cluster_nodes_healthy: IntGauge,
    
    // System metrics
    pub memory_usage_bytes: IntGauge,
    pub cpu_usage_percent: Gauge,
    pub uptime_seconds: IntGauge,
    
    // Error metrics
    pub errors_total: IntCounter,
    pub nxdomain_responses_total: IntCounter,
    
    // Network metrics
    pub network_bytes_sent: IntCounter,
    pub network_bytes_received: IntCounter,
    pub active_connections: IntGauge,
}

impl MetricsCollector {
    /// Create new metrics collector
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Arc::new(Registry::new());
        
        // DNS query metrics
        let queries_total = IntCounter::new(
            "dns_queries_total",
            "Total number of DNS queries processed"
        )?;
        
        let queries_per_second = Gauge::new(
            "dns_queries_per_second",
            "Current DNS queries per second"
        )?;
        
        let query_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "dns_query_duration_seconds",
                "DNS query processing duration in seconds"
            ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0])
        )?;
        
        // Cache metrics
        let cache_hits_total = IntCounter::new(
            "dns_cache_hits_total",
            "Total number of cache hits"
        )?;
        
        let cache_misses_total = IntCounter::new(
            "dns_cache_misses_total",
            "Total number of cache misses"
        )?;
        
        let cache_size = IntGauge::new(
            "dns_cache_size_bytes",
            "Current cache size in bytes"
        )?;
        
        let cache_hit_ratio = Gauge::new(
            "dns_cache_hit_ratio",
            "Cache hit ratio (0.0 to 1.0)"
        )?;
        
        // Blocklist metrics
        let blocked_queries_total = IntCounter::new(
            "dns_blocked_queries_total",
            "Total number of blocked queries"
        )?;
        
        let blocklist_size = IntGauge::new(
            "dns_blocklist_size",
            "Number of entries in blocklist"
        )?;
        
        // Zone metrics
        let zones_total = IntGauge::new(
            "dns_zones_total",
            "Total number of DNS zones"
        )?;
        
        let records_total = IntGauge::new(
            "dns_records_total",
            "Total number of DNS records"
        )?;
        
        let zone_transfers_total = IntCounter::new(
            "dns_zone_transfers_total",
            "Total number of zone transfers"
        )?;
        
        // Cluster metrics
        let cluster_nodes_total = IntGauge::new(
            "dns_cluster_nodes_total",
            "Total number of cluster nodes"
        )?;
        
        let cluster_nodes_healthy = IntGauge::new(
            "dns_cluster_nodes_healthy",
            "Number of healthy cluster nodes"
        )?;
        
        // System metrics
        let memory_usage_bytes = IntGauge::new(
            "dns_memory_usage_bytes",
            "Memory usage in bytes"
        )?;
        
        let cpu_usage_percent = Gauge::new(
            "dns_cpu_usage_percent",
            "CPU usage percentage"
        )?;
        
        let uptime_seconds = IntGauge::new(
            "dns_uptime_seconds",
            "Server uptime in seconds"
        )?;
        
        // Error metrics
        let errors_total = IntCounter::new(
            "dns_errors_total",
            "Total number of errors"
        )?;
        
        let nxdomain_responses_total = IntCounter::new(
            "dns_nxdomain_responses_total",
            "Total number of NXDOMAIN responses"
        )?;
        
        // Network metrics
        let network_bytes_sent = IntCounter::new(
            "dns_network_bytes_sent_total",
            "Total bytes sent over network"
        )?;
        
        let network_bytes_received = IntCounter::new(
            "dns_network_bytes_received_total",
            "Total bytes received over network"
        )?;
        
        let active_connections = IntGauge::new(
            "dns_active_connections",
            "Number of active connections"
        )?;
        
        // Register all metrics
        registry.register(Box::new(queries_total.clone()))?;
        registry.register(Box::new(queries_per_second.clone()))?;
        registry.register(Box::new(query_duration.clone()))?;
        registry.register(Box::new(cache_hits_total.clone()))?;
        registry.register(Box::new(cache_misses_total.clone()))?;
        registry.register(Box::new(cache_size.clone()))?;
        registry.register(Box::new(cache_hit_ratio.clone()))?;
        registry.register(Box::new(blocked_queries_total.clone()))?;
        registry.register(Box::new(blocklist_size.clone()))?;
        registry.register(Box::new(zones_total.clone()))?;
        registry.register(Box::new(records_total.clone()))?;
        registry.register(Box::new(zone_transfers_total.clone()))?;
        registry.register(Box::new(cluster_nodes_total.clone()))?;
        registry.register(Box::new(cluster_nodes_healthy.clone()))?;
        registry.register(Box::new(memory_usage_bytes.clone()))?;
        registry.register(Box::new(cpu_usage_percent.clone()))?;
        registry.register(Box::new(uptime_seconds.clone()))?;
        registry.register(Box::new(errors_total.clone()))?;
        registry.register(Box::new(nxdomain_responses_total.clone()))?;
        registry.register(Box::new(network_bytes_sent.clone()))?;
        registry.register(Box::new(network_bytes_received.clone()))?;
        registry.register(Box::new(active_connections.clone()))?;
        
        Ok(Self {
            registry,
            queries_total,
            queries_per_second,
            query_duration,
            cache_hits_total,
            cache_misses_total,
            cache_size,
            cache_hit_ratio,
            blocked_queries_total,
            blocklist_size,
            zones_total,
            records_total,
            zone_transfers_total,
            cluster_nodes_total,
            cluster_nodes_healthy,
            memory_usage_bytes,
            cpu_usage_percent,
            uptime_seconds,
            errors_total,
            nxdomain_responses_total,
            network_bytes_sent,
            network_bytes_received,
            active_connections,
        })
    }
    
    /// Update cache hit ratio
    pub fn update_cache_hit_ratio(&self) {
        let hits = self.cache_hits_total.get();
        let misses = self.cache_misses_total.get();
        let total = hits + misses;
        
        if total > 0 {
            let ratio = hits as f64 / total as f64;
            self.cache_hit_ratio.set(ratio);
        }
    }
    
    /// Record a DNS query
    pub fn record_query(&self, duration_seconds: f64) {
        self.queries_total.inc();
        self.query_duration.observe(duration_seconds);
    }
    
    /// Record a cache hit
    pub fn record_cache_hit(&self) {
        self.cache_hits_total.inc();
        self.update_cache_hit_ratio();
    }
    
    /// Record a cache miss
    pub fn record_cache_miss(&self) {
        self.cache_misses_total.inc();
        self.update_cache_hit_ratio();
    }
    
    /// Record a blocked query
    pub fn record_blocked_query(&self) {
        self.blocked_queries_total.inc();
    }
    
    /// Record an error
    pub fn record_error(&self) {
        self.errors_total.inc();
    }
    
    /// Record NXDOMAIN response
    pub fn record_nxdomain(&self) {
        self.nxdomain_responses_total.inc();
    }
    
    /// Update system metrics
    pub fn update_system_metrics(&self, memory_bytes: i64, cpu_percent: f64, uptime_secs: i64) {
        self.memory_usage_bytes.set(memory_bytes);
        self.cpu_usage_percent.set(cpu_percent);
        self.uptime_seconds.set(uptime_secs);
    }
    
    /// Update cluster metrics
    pub fn update_cluster_metrics(&self, total_nodes: i64, healthy_nodes: i64) {
        self.cluster_nodes_total.set(total_nodes);
        self.cluster_nodes_healthy.set(healthy_nodes);
    }
    
    /// Get registry for custom metrics
    pub fn registry(&self) -> Arc<Registry> {
        self.registry.clone()
    }
}

/// Metrics state for the API server
#[derive(Clone)]
pub struct MetricsState {
    pub collector: Arc<MetricsCollector>,
    pub start_time: Arc<RwLock<std::time::Instant>>,
}

impl MetricsState {
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            collector: Arc::new(MetricsCollector::new()?),
            start_time: Arc::new(RwLock::new(std::time::Instant::now())),
        })
    }
}

/// Prometheus metrics endpoint handler
#[utoipa::path(
    get,
    path = "/metrics",
    responses(
        (status = 200, description = "Prometheus metrics", content_type = "text/plain")
    )
)]
pub async fn metrics_handler(
    State(metrics_state): State<MetricsState>,
) -> Result<Response, StatusCode> {
    // Update uptime metric
    let start_time = metrics_state.start_time.read().await;
    let uptime = start_time.elapsed().as_secs() as i64;
    metrics_state.collector.uptime_seconds.set(uptime);
    drop(start_time);
    
    // Gather metrics
    let metric_families = metrics_state.collector.registry.gather();
    
    // Encode to Prometheus text format
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    
    encoder.encode(&metric_families, &mut buffer)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, encoder.format_type())
        .body(buffer.into())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new().unwrap();
        
        // Test that metrics start at zero
        assert_eq!(collector.queries_total.get(), 0);
        assert_eq!(collector.cache_hits_total.get(), 0);
        assert_eq!(collector.blocked_queries_total.get(), 0);
    }

    #[test]
    fn test_record_query() {
        let collector = MetricsCollector::new().unwrap();
        
        collector.record_query(0.001);
        assert_eq!(collector.queries_total.get(), 1);
    }

    #[test]
    fn test_cache_hit_ratio_calculation() {
        let collector = MetricsCollector::new().unwrap();
        
        // Record some hits and misses
        collector.record_cache_hit();
        collector.record_cache_hit();
        collector.record_cache_miss();
        
        // Should be 2/3 = 0.666...
        let ratio = collector.cache_hit_ratio.get();
        assert!((ratio - 0.6666666666666666).abs() < f64::EPSILON);
    }

    #[test]
    fn test_system_metrics_update() {
        let collector = MetricsCollector::new().unwrap();
        
        collector.update_system_metrics(1024 * 1024 * 512, 75.5, 3600);
        
        assert_eq!(collector.memory_usage_bytes.get(), 1024 * 1024 * 512);
        assert_eq!(collector.cpu_usage_percent.get(), 75.5);
        assert_eq!(collector.uptime_seconds.get(), 3600);
    }
}