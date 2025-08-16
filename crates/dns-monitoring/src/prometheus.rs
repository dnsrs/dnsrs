//! Prometheus metrics exporter with atomic counters
//!
//! Provides comprehensive DNS server metrics in Prometheus format with
//! zero-overhead atomic operations for high-performance collection.

use dns_core::{DnsResult, DnsError, global_metrics, MetricsSnapshot};
use prometheus::{
    Counter, Gauge, Histogram, IntCounter, IntGauge, Registry, Encoder, TextEncoder,
    HistogramOpts, Opts, CounterVec, GaugeVec, HistogramVec,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::interval;
use serde::{Deserialize, Serialize};

/// Configuration for Prometheus metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrometheusConfig {
    /// Enable Prometheus metrics collection
    pub enabled: bool,
    /// Metrics collection interval in seconds
    pub collection_interval_secs: u64,
    /// Namespace for all metrics
    pub namespace: String,
    /// Additional labels to add to all metrics
    pub labels: std::collections::HashMap<String, String>,
    /// Enable detailed query histograms
    pub detailed_histograms: bool,
    /// Enable per-protocol metrics
    pub per_protocol_metrics: bool,
    /// Enable DNSSEC-specific metrics
    pub dnssec_metrics: bool,
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            collection_interval_secs: 5,
            namespace: "dns_server".to_string(),
            labels: std::collections::HashMap::new(),
            detailed_histograms: true,
            per_protocol_metrics: true,
            dnssec_metrics: true,
        }
    }
}

/// Prometheus metrics exporter
pub struct PrometheusExporter {
    config: PrometheusConfig,
    registry: Registry,
    
    // Query metrics
    queries_total: IntCounter,
    queries_per_second: IntGauge,
    query_duration: Histogram,
    
    // Response metrics
    responses_by_code: CounterVec,
    
    // Cache metrics
    cache_hits_total: IntCounter,
    cache_misses_total: IntCounter,
    cache_size: IntGauge,
    cache_evictions_total: IntCounter,
    cache_hit_ratio: Gauge,
    
    // Blocklist metrics
    blocked_queries_total: IntCounter,
    blocklist_size: IntGauge,
    
    // Protocol metrics
    protocol_queries: CounterVec,
    
    // Error metrics
    errors_by_category: CounterVec,
    
    // Performance metrics
    memory_usage_bytes: IntGauge,
    cpu_usage_percent: Gauge,
    active_connections: IntGauge,
    
    // Cluster metrics
    cluster_nodes: IntGauge,
    replication_lag_ms: IntGauge,
    zone_transfers_total: IntCounter,
    
    // DNSSEC metrics (optional)
    dnssec_queries_total: Option<IntCounter>,
    dnssec_validations_total: Option<IntCounter>,
    dnssec_failures_total: Option<IntCounter>,
    
    // Detailed histograms (optional)
    query_size_histogram: Option<Histogram>,
    response_size_histogram: Option<Histogram>,
    
    // System metrics
    uptime_seconds: IntGauge,
    start_time: Instant,
}

impl PrometheusExporter {
    /// Create a new Prometheus exporter
    pub fn new(config: PrometheusConfig) -> DnsResult<Self> {
        let registry = Registry::new();
        let namespace = &config.namespace;
        
        // Create base labels
        let mut base_labels = config.labels.clone();
        base_labels.insert("instance".to_string(), 
                          std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string()));
        
        // Query metrics
        let queries_total = IntCounter::with_opts(
            Opts::new("queries_total", "Total number of DNS queries processed")
                .namespace(namespace)
                .const_labels(base_labels.clone())
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create queries_total metric: {}", e)))?;
        registry.register(Box::new(queries_total.clone()))?;
        
        let queries_per_second = IntGauge::with_opts(
            Opts::new("queries_per_second", "Current queries per second")
                .namespace(namespace)
                .const_labels(base_labels.clone())
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create queries_per_second metric: {}", e)))?;
        registry.register(Box::new(queries_per_second.clone()))?;
        
        let query_duration = Histogram::with_opts(
            HistogramOpts::new("query_duration_seconds", "DNS query processing duration")
                .namespace(namespace)
                .const_labels(base_labels.clone())
                .buckets(vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0])
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create query_duration metric: {}", e)))?;
        registry.register(Box::new(query_duration.clone()))?;
        
        // Response metrics
        let responses_by_code = CounterVec::new(
            Opts::new("responses_total", "Total DNS responses by response code")
                .namespace(namespace)
                .const_labels(base_labels.clone()),
            &["code"]
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create responses_by_code metric: {}", e)))?;
        registry.register(Box::new(responses_by_code.clone()))?;
        
        // Cache metrics
        let cache_hits_total = IntCounter::with_opts(
            Opts::new("cache_hits_total", "Total cache hits")
                .namespace(namespace)
                .const_labels(base_labels.clone())
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create cache_hits_total metric: {}", e)))?;
        registry.register(Box::new(cache_hits_total.clone()))?;
        
        let cache_misses_total = IntCounter::with_opts(
            Opts::new("cache_misses_total", "Total cache misses")
                .namespace(namespace)
                .const_labels(base_labels.clone())
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create cache_misses_total metric: {}", e)))?;
        registry.register(Box::new(cache_misses_total.clone()))?;
        
        let cache_size = IntGauge::with_opts(
            Opts::new("cache_size_entries", "Current number of entries in cache")
                .namespace(namespace)
                .const_labels(base_labels.clone())
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create cache_size metric: {}", e)))?;
        registry.register(Box::new(cache_size.clone()))?;
        
        let cache_evictions_total = IntCounter::with_opts(
            Opts::new("cache_evictions_total", "Total cache evictions")
                .namespace(namespace)
                .const_labels(base_labels.clone())
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create cache_evictions_total metric: {}", e)))?;
        registry.register(Box::new(cache_evictions_total.clone()))?;
        
        let cache_hit_ratio = Gauge::with_opts(
            Opts::new("cache_hit_ratio", "Cache hit ratio (0.0 to 1.0)")
                .namespace(namespace)
                .const_labels(base_labels.clone())
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create cache_hit_ratio metric: {}", e)))?;
        registry.register(Box::new(cache_hit_ratio.clone()))?;
        
        // Blocklist metrics
        let blocked_queries_total = IntCounter::with_opts(
            Opts::new("blocked_queries_total", "Total blocked queries")
                .namespace(namespace)
                .const_labels(base_labels.clone())
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create blocked_queries_total metric: {}", e)))?;
        registry.register(Box::new(blocked_queries_total.clone()))?;
        
        let blocklist_size = IntGauge::with_opts(
            Opts::new("blocklist_size_entries", "Current number of entries in blocklist")
                .namespace(namespace)
                .const_labels(base_labels.clone())
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create blocklist_size metric: {}", e)))?;
        registry.register(Box::new(blocklist_size.clone()))?;
        
        // Protocol metrics
        let protocol_queries = if config.per_protocol_metrics {
            let metric = CounterVec::new(
                Opts::new("protocol_queries_total", "Total queries by protocol")
                    .namespace(namespace)
                    .const_labels(base_labels.clone()),
                &["protocol"]
            ).map_err(|e| DnsError::ConfigError(format!("Failed to create protocol_queries metric: {}", e)))?;
            registry.register(Box::new(metric.clone()))?;
            metric
        } else {
            CounterVec::new(
                Opts::new("protocol_queries_total", "Total queries by protocol")
                    .namespace(namespace),
                &["protocol"]
            ).unwrap()
        };
        
        // Error metrics
        let errors_by_category = CounterVec::new(
            Opts::new("errors_total", "Total errors by category")
                .namespace(namespace)
                .const_labels(base_labels.clone()),
            &["category"]
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create errors_by_category metric: {}", e)))?;
        registry.register(Box::new(errors_by_category.clone()))?;
        
        // Performance metrics
        let memory_usage_bytes = IntGauge::with_opts(
            Opts::new("memory_usage_bytes", "Current memory usage in bytes")
                .namespace(namespace)
                .const_labels(base_labels.clone())
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create memory_usage_bytes metric: {}", e)))?;
        registry.register(Box::new(memory_usage_bytes.clone()))?;
        
        let cpu_usage_percent = Gauge::with_opts(
            Opts::new("cpu_usage_percent", "Current CPU usage percentage")
                .namespace(namespace)
                .const_labels(base_labels.clone())
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create cpu_usage_percent metric: {}", e)))?;
        registry.register(Box::new(cpu_usage_percent.clone()))?;
        
        let active_connections = IntGauge::with_opts(
            Opts::new("active_connections", "Current number of active connections")
                .namespace(namespace)
                .const_labels(base_labels.clone())
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create active_connections metric: {}", e)))?;
        registry.register(Box::new(active_connections.clone()))?;
        
        // Cluster metrics
        let cluster_nodes = IntGauge::with_opts(
            Opts::new("cluster_nodes", "Current number of nodes in cluster")
                .namespace(namespace)
                .const_labels(base_labels.clone())
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create cluster_nodes metric: {}", e)))?;
        registry.register(Box::new(cluster_nodes.clone()))?;
        
        let replication_lag_ms = IntGauge::with_opts(
            Opts::new("replication_lag_milliseconds", "Current replication lag in milliseconds")
                .namespace(namespace)
                .const_labels(base_labels.clone())
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create replication_lag_ms metric: {}", e)))?;
        registry.register(Box::new(replication_lag_ms.clone()))?;
        
        let zone_transfers_total = IntCounter::with_opts(
            Opts::new("zone_transfers_total", "Total zone transfers")
                .namespace(namespace)
                .const_labels(base_labels.clone())
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create zone_transfers_total metric: {}", e)))?;
        registry.register(Box::new(zone_transfers_total.clone()))?;
        
        // DNSSEC metrics (optional)
        let (dnssec_queries_total, dnssec_validations_total, dnssec_failures_total) = if config.dnssec_metrics {
            let queries = IntCounter::with_opts(
                Opts::new("dnssec_queries_total", "Total DNSSEC queries")
                    .namespace(namespace)
                    .const_labels(base_labels.clone())
            ).map_err(|e| DnsError::ConfigError(format!("Failed to create dnssec_queries_total metric: {}", e)))?;
            registry.register(Box::new(queries.clone()))?;
            
            let validations = IntCounter::with_opts(
                Opts::new("dnssec_validations_total", "Total DNSSEC validations")
                    .namespace(namespace)
                    .const_labels(base_labels.clone())
            ).map_err(|e| DnsError::ConfigError(format!("Failed to create dnssec_validations_total metric: {}", e)))?;
            registry.register(Box::new(validations.clone()))?;
            
            let failures = IntCounter::with_opts(
                Opts::new("dnssec_failures_total", "Total DNSSEC validation failures")
                    .namespace(namespace)
                    .const_labels(base_labels.clone())
            ).map_err(|e| DnsError::ConfigError(format!("Failed to create dnssec_failures_total metric: {}", e)))?;
            registry.register(Box::new(failures.clone()))?;
            
            (Some(queries), Some(validations), Some(failures))
        } else {
            (None, None, None)
        };
        
        // Detailed histograms (optional)
        let (query_size_histogram, response_size_histogram) = if config.detailed_histograms {
            let query_hist = Histogram::with_opts(
                HistogramOpts::new("query_size_bytes", "DNS query size in bytes")
                    .namespace(namespace)
                    .const_labels(base_labels.clone())
                    .buckets(vec![64.0, 128.0, 256.0, 512.0, 1024.0, 2048.0, 4096.0])
            ).map_err(|e| DnsError::ConfigError(format!("Failed to create query_size_histogram metric: {}", e)))?;
            registry.register(Box::new(query_hist.clone()))?;
            
            let response_hist = Histogram::with_opts(
                HistogramOpts::new("response_size_bytes", "DNS response size in bytes")
                    .namespace(namespace)
                    .const_labels(base_labels.clone())
                    .buckets(vec![64.0, 128.0, 256.0, 512.0, 1024.0, 2048.0, 4096.0, 8192.0])
            ).map_err(|e| DnsError::ConfigError(format!("Failed to create response_size_histogram metric: {}", e)))?;
            registry.register(Box::new(response_hist.clone()))?;
            
            (Some(query_hist), Some(response_hist))
        } else {
            (None, None)
        };
        
        // System metrics
        let uptime_seconds = IntGauge::with_opts(
            Opts::new("uptime_seconds", "Server uptime in seconds")
                .namespace(namespace)
                .const_labels(base_labels.clone())
        ).map_err(|e| DnsError::ConfigError(format!("Failed to create uptime_seconds metric: {}", e)))?;
        registry.register(Box::new(uptime_seconds.clone()))?;
        
        Ok(Self {
            config,
            registry,
            queries_total,
            queries_per_second,
            query_duration,
            responses_by_code,
            cache_hits_total,
            cache_misses_total,
            cache_size,
            cache_evictions_total,
            cache_hit_ratio,
            blocked_queries_total,
            blocklist_size,
            protocol_queries,
            errors_by_category,
            memory_usage_bytes,
            cpu_usage_percent,
            active_connections,
            cluster_nodes,
            replication_lag_ms,
            zone_transfers_total,
            dnssec_queries_total,
            dnssec_validations_total,
            dnssec_failures_total,
            query_size_histogram,
            response_size_histogram,
            uptime_seconds,
            start_time: Instant::now(),
        })
    }
    
    /// Start the metrics collection loop
    pub async fn start_collection(&self) -> DnsResult<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        let mut interval = interval(Duration::from_secs(self.config.collection_interval_secs));
        
        loop {
            interval.tick().await;
            self.update_metrics().await?;
        }
    }
    
    /// Update all metrics from the global metrics instance
    async fn update_metrics(&self) -> DnsResult<()> {
        let metrics = global_metrics();
        let snapshot = metrics.snapshot();
        
        // Update query metrics
        self.queries_total.reset();
        self.queries_total.inc_by(snapshot.queries_total);
        self.queries_per_second.set(snapshot.queries_per_second as i64);
        
        // Update response metrics
        self.responses_by_code.with_label_values(&["NOERROR"]).reset();
        self.responses_by_code.with_label_values(&["NOERROR"]).inc_by(snapshot.noerror_responses);
        self.responses_by_code.with_label_values(&["NXDOMAIN"]).reset();
        self.responses_by_code.with_label_values(&["NXDOMAIN"]).inc_by(snapshot.nxdomain_responses);
        self.responses_by_code.with_label_values(&["SERVFAIL"]).reset();
        self.responses_by_code.with_label_values(&["SERVFAIL"]).inc_by(snapshot.servfail_responses);
        self.responses_by_code.with_label_values(&["REFUSED"]).reset();
        self.responses_by_code.with_label_values(&["REFUSED"]).inc_by(snapshot.refused_responses);
        
        // Update cache metrics
        self.cache_hits_total.reset();
        self.cache_hits_total.inc_by(snapshot.cache_hits);
        self.cache_misses_total.reset();
        self.cache_misses_total.inc_by(snapshot.cache_misses);
        self.cache_size.set(snapshot.cache_size as i64);
        self.cache_evictions_total.reset();
        self.cache_evictions_total.inc_by(snapshot.cache_evictions);
        self.cache_hit_ratio.set(snapshot.cache_hit_rate as f64 / 10000.0);
        
        // Update blocklist metrics
        self.blocked_queries_total.reset();
        self.blocked_queries_total.inc_by(snapshot.blocked_queries);
        self.blocklist_size.set(snapshot.blocklist_size as i64);
        
        // Update protocol metrics
        if self.config.per_protocol_metrics {
            self.protocol_queries.with_label_values(&["UDP"]).reset();
            self.protocol_queries.with_label_values(&["UDP"]).inc_by(snapshot.udp_queries);
            self.protocol_queries.with_label_values(&["TCP"]).reset();
            self.protocol_queries.with_label_values(&["TCP"]).inc_by(snapshot.tcp_queries);
            self.protocol_queries.with_label_values(&["DoH"]).reset();
            self.protocol_queries.with_label_values(&["DoH"]).inc_by(snapshot.doh_queries);
            self.protocol_queries.with_label_values(&["DoT"]).reset();
            self.protocol_queries.with_label_values(&["DoT"]).inc_by(snapshot.dot_queries);
            self.protocol_queries.with_label_values(&["DoQ"]).reset();
            self.protocol_queries.with_label_values(&["DoQ"]).inc_by(snapshot.doq_queries);
        }
        
        // Update error metrics
        self.errors_by_category.with_label_values(&["protocol"]).reset();
        self.errors_by_category.with_label_values(&["protocol"]).inc_by(snapshot.protocol_errors);
        self.errors_by_category.with_label_values(&["storage"]).reset();
        self.errors_by_category.with_label_values(&["storage"]).inc_by(snapshot.storage_errors);
        self.errors_by_category.with_label_values(&["network"]).reset();
        self.errors_by_category.with_label_values(&["network"]).inc_by(snapshot.network_errors);
        self.errors_by_category.with_label_values(&["timeout"]).reset();
        self.errors_by_category.with_label_values(&["timeout"]).inc_by(snapshot.timeout_errors);
        
        // Update performance metrics
        self.memory_usage_bytes.set(snapshot.memory_usage_bytes as i64);
        self.active_connections.set(snapshot.active_connections as i64);
        
        // Update cluster metrics
        self.cluster_nodes.set(snapshot.cluster_nodes as i64);
        self.replication_lag_ms.set(snapshot.replication_lag_ms as i64);
        self.zone_transfers_total.reset();
        self.zone_transfers_total.inc_by(snapshot.zone_transfers);
        
        // Update DNSSEC metrics if enabled
        if let Some(ref dnssec_queries) = self.dnssec_queries_total {
            dnssec_queries.reset();
            dnssec_queries.inc_by(snapshot.dnssec_queries);
        }
        if let Some(ref dnssec_validations) = self.dnssec_validations_total {
            dnssec_validations.reset();
            dnssec_validations.inc_by(snapshot.dnssec_validations);
        }
        if let Some(ref dnssec_failures) = self.dnssec_failures_total {
            dnssec_failures.reset();
            dnssec_failures.inc_by(snapshot.dnssec_failures);
        }
        
        // Update uptime
        self.uptime_seconds.set(self.start_time.elapsed().as_secs() as i64);
        
        Ok(())
    }
    
    /// Record a query with timing information
    pub fn record_query(&self, duration: Duration, query_size: Option<usize>) {
        self.query_duration.observe(duration.as_secs_f64());
        
        if let (Some(ref histogram), Some(size)) = (&self.query_size_histogram, query_size) {
            histogram.observe(size as f64);
        }
    }
    
    /// Record a response with size information
    pub fn record_response(&self, response_size: Option<usize>) {
        if let (Some(ref histogram), Some(size)) = (&self.response_size_histogram, response_size) {
            histogram.observe(size as f64);
        }
    }
    
    /// Get metrics in Prometheus text format
    pub fn gather(&self) -> DnsResult<String> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)
            .map_err(|e| DnsError::ConfigError(format!("Failed to encode metrics: {}", e)))?;
        
        String::from_utf8(buffer)
            .map_err(|e| DnsError::ConfigError(format!("Failed to convert metrics to string: {}", e)))
    }
    
    /// Get the Prometheus registry
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}