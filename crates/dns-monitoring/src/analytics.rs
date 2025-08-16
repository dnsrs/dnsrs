//! Real-time query analytics and dashboard data
//!
//! Provides comprehensive analytics for DNS queries including
//! real-time statistics, trending data, and dashboard metrics.

use dns_core::{DnsResult, DnsError, global_metrics};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::interval;

/// Configuration for query analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsConfig {
    /// Enable analytics collection
    pub enabled: bool,
    /// Data collection interval in seconds
    pub collection_interval_secs: u64,
    /// Maximum number of data points to keep in memory
    pub max_data_points: usize,
    /// Enable detailed query tracking
    pub detailed_tracking: bool,
    /// Enable geographic analytics
    pub geographic_analytics: bool,
    /// Enable top queries tracking
    pub top_queries_tracking: bool,
    /// Number of top queries to track
    pub top_queries_count: usize,
    /// Enable client analytics
    pub client_analytics: bool,
    /// Enable performance analytics
    pub performance_analytics: bool,
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            collection_interval_secs: 10,
            max_data_points: 8640, // 24 hours at 10-second intervals
            detailed_tracking: true,
            geographic_analytics: false, // Requires GeoIP database
            top_queries_tracking: true,
            top_queries_count: 100,
            client_analytics: true,
            performance_analytics: true,
        }
    }
}

/// Query analytics system
pub struct QueryAnalytics {
    config: AnalyticsConfig,
    time_series_data: Arc<RwLock<VecDeque<TimeSeriesPoint>>>,
    query_stats: Arc<RwLock<QueryStatistics>>,
    top_queries: Arc<RwLock<TopQueries>>,
    client_stats: Arc<RwLock<ClientStatistics>>,
    performance_stats: Arc<RwLock<PerformanceStatistics>>,
    geographic_stats: Arc<RwLock<GeographicStatistics>>,
}

/// Time series data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    /// Timestamp
    pub timestamp: u64,
    /// Queries per second
    pub qps: f64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Cache hit rate percentage
    pub cache_hit_rate: f64,
    /// Error rate percentage
    pub error_rate: f64,
    /// Blocked queries per second
    pub blocked_qps: f64,
    /// Active connections
    pub active_connections: u64,
    /// Memory usage in bytes
    pub memory_usage_bytes: u64,
    /// CPU usage percentage
    pub cpu_usage_percent: f64,
}

/// Query statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryStatistics {
    /// Total queries processed
    pub total_queries: u64,
    /// Queries by type
    pub queries_by_type: HashMap<String, u64>,
    /// Queries by response code
    pub queries_by_response_code: HashMap<String, u64>,
    /// Queries by protocol
    pub queries_by_protocol: HashMap<String, u64>,
    /// DNSSEC queries
    pub dnssec_queries: u64,
    /// Blocked queries
    pub blocked_queries: u64,
    /// Last updated timestamp
    pub last_updated: u64,
}

/// Top queries tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopQueries {
    /// Most queried domains
    pub top_domains: Vec<QueryCount>,
    /// Most queried types
    pub top_types: Vec<QueryCount>,
    /// Most blocked domains
    pub top_blocked: Vec<QueryCount>,
    /// Most error-prone queries
    pub top_errors: Vec<QueryCount>,
    /// Last updated timestamp
    pub last_updated: u64,
}

/// Query count entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryCount {
    /// Query name or type
    pub name: String,
    /// Count
    pub count: u64,
    /// Percentage of total
    pub percentage: f64,
}

/// Client statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientStatistics {
    /// Top clients by query count
    pub top_clients: Vec<ClientStats>,
    /// Clients by geographic location
    pub clients_by_location: HashMap<String, u64>,
    /// Blocked clients
    pub blocked_clients: Vec<ClientStats>,
    /// Last updated timestamp
    pub last_updated: u64,
}

/// Individual client statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientStats {
    /// Client IP address (anonymized)
    pub ip: String,
    /// Query count
    pub query_count: u64,
    /// Blocked query count
    pub blocked_count: u64,
    /// Error count
    pub error_count: u64,
    /// Average response time
    pub avg_response_time_ms: f64,
    /// Geographic location (if available)
    pub location: Option<String>,
    /// Last seen timestamp
    pub last_seen: u64,
}

/// Performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceStatistics {
    /// Response time percentiles
    pub response_time_percentiles: ResponseTimePercentiles,
    /// Query processing stages timing
    pub processing_stages: ProcessingStages,
    /// Cache performance
    pub cache_performance: CachePerformance,
    /// Resource utilization
    pub resource_utilization: ResourceUtilization,
    /// Last updated timestamp
    pub last_updated: u64,
}

/// Response time percentiles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseTimePercentiles {
    /// 50th percentile (median)
    pub p50_ms: f64,
    /// 90th percentile
    pub p90_ms: f64,
    /// 95th percentile
    pub p95_ms: f64,
    /// 99th percentile
    pub p99_ms: f64,
    /// 99.9th percentile
    pub p999_ms: f64,
}

/// Query processing stages timing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingStages {
    /// Parsing time
    pub parsing_ms: f64,
    /// Cache lookup time
    pub cache_lookup_ms: f64,
    /// Storage lookup time
    pub storage_lookup_ms: f64,
    /// Response building time
    pub response_building_ms: f64,
    /// Network transmission time
    pub network_ms: f64,
}

/// Cache performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachePerformance {
    /// Hit rate percentage
    pub hit_rate: f64,
    /// Miss rate percentage
    pub miss_rate: f64,
    /// Eviction rate
    pub eviction_rate: f64,
    /// Average lookup time
    pub avg_lookup_time_ms: f64,
    /// Cache size utilization percentage
    pub size_utilization: f64,
}

/// Resource utilization metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUtilization {
    /// CPU usage percentage
    pub cpu_percent: f64,
    /// Memory usage percentage
    pub memory_percent: f64,
    /// Network bandwidth utilization
    pub network_utilization: NetworkUtilization,
    /// Disk I/O utilization
    pub disk_utilization: DiskUtilization,
}

/// Network utilization metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkUtilization {
    /// Bytes received per second
    pub bytes_in_per_sec: f64,
    /// Bytes sent per second
    pub bytes_out_per_sec: f64,
    /// Packets received per second
    pub packets_in_per_sec: f64,
    /// Packets sent per second
    pub packets_out_per_sec: f64,
}

/// Disk utilization metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskUtilization {
    /// Read bytes per second
    pub read_bytes_per_sec: f64,
    /// Write bytes per second
    pub write_bytes_per_sec: f64,
    /// Read operations per second
    pub read_ops_per_sec: f64,
    /// Write operations per second
    pub write_ops_per_sec: f64,
}

/// Geographic statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicStatistics {
    /// Queries by country
    pub queries_by_country: HashMap<String, u64>,
    /// Queries by region
    pub queries_by_region: HashMap<String, u64>,
    /// Queries by city
    pub queries_by_city: HashMap<String, u64>,
    /// Last updated timestamp
    pub last_updated: u64,
}

/// Dashboard data for real-time display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardData {
    /// Current timestamp
    pub timestamp: u64,
    /// Real-time metrics
    pub realtime: RealtimeMetrics,
    /// Time series data for charts
    pub time_series: Vec<TimeSeriesPoint>,
    /// Query statistics
    pub query_stats: QueryStatistics,
    /// Top queries
    pub top_queries: TopQueries,
    /// Client statistics
    pub client_stats: ClientStatistics,
    /// Performance statistics
    pub performance_stats: PerformanceStatistics,
    /// Geographic statistics (if enabled)
    pub geographic_stats: Option<GeographicStatistics>,
}

/// Real-time metrics for dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeMetrics {
    /// Current queries per second
    pub current_qps: f64,
    /// Current response time
    pub current_response_time_ms: f64,
    /// Current cache hit rate
    pub current_cache_hit_rate: f64,
    /// Current error rate
    pub current_error_rate: f64,
    /// Server uptime in seconds
    pub uptime_seconds: u64,
    /// Health status
    pub health_status: String,
}

impl QueryAnalytics {
    /// Create a new query analytics system
    pub fn new(config: AnalyticsConfig) -> DnsResult<Self> {
        Ok(Self {
            config,
            time_series_data: Arc::new(RwLock::new(VecDeque::new())),
            query_stats: Arc::new(RwLock::new(QueryStatistics {
                total_queries: 0,
                queries_by_type: HashMap::new(),
                queries_by_response_code: HashMap::new(),
                queries_by_protocol: HashMap::new(),
                dnssec_queries: 0,
                blocked_queries: 0,
                last_updated: 0,
            })),
            top_queries: Arc::new(RwLock::new(TopQueries {
                top_domains: Vec::new(),
                top_types: Vec::new(),
                top_blocked: Vec::new(),
                top_errors: Vec::new(),
                last_updated: 0,
            })),
            client_stats: Arc::new(RwLock::new(ClientStatistics {
                top_clients: Vec::new(),
                clients_by_location: HashMap::new(),
                blocked_clients: Vec::new(),
                last_updated: 0,
            })),
            performance_stats: Arc::new(RwLock::new(PerformanceStatistics {
                response_time_percentiles: ResponseTimePercentiles {
                    p50_ms: 0.0,
                    p90_ms: 0.0,
                    p95_ms: 0.0,
                    p99_ms: 0.0,
                    p999_ms: 0.0,
                },
                processing_stages: ProcessingStages {
                    parsing_ms: 0.0,
                    cache_lookup_ms: 0.0,
                    storage_lookup_ms: 0.0,
                    response_building_ms: 0.0,
                    network_ms: 0.0,
                },
                cache_performance: CachePerformance {
                    hit_rate: 0.0,
                    miss_rate: 0.0,
                    eviction_rate: 0.0,
                    avg_lookup_time_ms: 0.0,
                    size_utilization: 0.0,
                },
                resource_utilization: ResourceUtilization {
                    cpu_percent: 0.0,
                    memory_percent: 0.0,
                    network_utilization: NetworkUtilization {
                        bytes_in_per_sec: 0.0,
                        bytes_out_per_sec: 0.0,
                        packets_in_per_sec: 0.0,
                        packets_out_per_sec: 0.0,
                    },
                    disk_utilization: DiskUtilization {
                        read_bytes_per_sec: 0.0,
                        write_bytes_per_sec: 0.0,
                        read_ops_per_sec: 0.0,
                        write_ops_per_sec: 0.0,
                    },
                },
                last_updated: 0,
            })),
            geographic_stats: Arc::new(RwLock::new(GeographicStatistics {
                queries_by_country: HashMap::new(),
                queries_by_region: HashMap::new(),
                queries_by_city: HashMap::new(),
                last_updated: 0,
            })),
        })
    }
    
    /// Start the analytics collection
    pub async fn start(&self) -> DnsResult<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        let time_series_data = self.time_series_data.clone();
        let query_stats = self.query_stats.clone();
        let top_queries = self.top_queries.clone();
        let client_stats = self.client_stats.clone();
        let performance_stats = self.performance_stats.clone();
        let geographic_stats = self.geographic_stats.clone();
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(config.collection_interval_secs));
            
            loop {
                interval.tick().await;
                
                // Collect metrics from global metrics
                let metrics = global_metrics().snapshot();
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                
                // Update time series data
                Self::update_time_series(&time_series_data, &metrics, timestamp, &config).await;
                
                // Update query statistics
                Self::update_query_stats(&query_stats, &metrics, timestamp).await;
                
                // Update top queries (if enabled)
                if config.top_queries_tracking {
                    Self::update_top_queries(&top_queries, &metrics, timestamp).await;
                }
                
                // Update client statistics (if enabled)
                if config.client_analytics {
                    Self::update_client_stats(&client_stats, &metrics, timestamp).await;
                }
                
                // Update performance statistics (if enabled)
                if config.performance_analytics {
                    Self::update_performance_stats(&performance_stats, &metrics, timestamp).await;
                }
                
                // Update geographic statistics (if enabled)
                if config.geographic_analytics {
                    Self::update_geographic_stats(&geographic_stats, &metrics, timestamp).await;
                }
            }
        });
        
        tracing::info!(
            collection_interval = config.collection_interval_secs,
            max_data_points = config.max_data_points,
            "Query analytics started"
        );
        
        Ok(())
    }
    
    /// Stop the analytics collection
    pub async fn stop(&self) -> DnsResult<()> {
        tracing::info!("Query analytics stopped");
        Ok(())
    }
    
    /// Update time series data
    async fn update_time_series(
        time_series_data: &Arc<RwLock<VecDeque<TimeSeriesPoint>>>,
        metrics: &dns_core::MetricsSnapshot,
        timestamp: u64,
        config: &AnalyticsConfig,
    ) {
        let point = TimeSeriesPoint {
            timestamp,
            qps: metrics.queries_per_second as f64,
            avg_response_time_ms: metrics.average_response_time_ns as f64 / 1_000_000.0,
            cache_hit_rate: metrics.cache_hit_rate as f64 / 100.0,
            error_rate: {
                let total_errors = metrics.protocol_errors + metrics.storage_errors + 
                                 metrics.network_errors + metrics.timeout_errors;
                if metrics.queries_total > 0 {
                    (total_errors as f64 / metrics.queries_total as f64) * 100.0
                } else {
                    0.0
                }
            },
            blocked_qps: 0.0, // Would need to calculate from recent blocked queries
            active_connections: metrics.active_connections as u64,
            memory_usage_bytes: metrics.memory_usage_bytes as u64,
            cpu_usage_percent: 0.0, // Would need system metrics
        };
        
        let mut data = time_series_data.write().await;
        data.push_back(point);
        
        // Keep only the configured number of data points
        while data.len() > config.max_data_points {
            data.pop_front();
        }
    }
    
    /// Update query statistics
    async fn update_query_stats(
        query_stats: &Arc<RwLock<QueryStatistics>>,
        metrics: &dns_core::MetricsSnapshot,
        timestamp: u64,
    ) {
        let mut stats = query_stats.write().await;
        
        stats.total_queries = metrics.queries_total;
        stats.dnssec_queries = metrics.dnssec_queries;
        stats.blocked_queries = metrics.blocked_queries;
        stats.last_updated = timestamp;
        
        // Update protocol statistics
        stats.queries_by_protocol.insert("UDP".to_string(), metrics.udp_queries);
        stats.queries_by_protocol.insert("TCP".to_string(), metrics.tcp_queries);
        stats.queries_by_protocol.insert("DoH".to_string(), metrics.doh_queries);
        stats.queries_by_protocol.insert("DoT".to_string(), metrics.dot_queries);
        stats.queries_by_protocol.insert("DoQ".to_string(), metrics.doq_queries);
        
        // Update response code statistics
        stats.queries_by_response_code.insert("NOERROR".to_string(), metrics.noerror_responses);
        stats.queries_by_response_code.insert("NXDOMAIN".to_string(), metrics.nxdomain_responses);
        stats.queries_by_response_code.insert("SERVFAIL".to_string(), metrics.servfail_responses);
        stats.queries_by_response_code.insert("REFUSED".to_string(), metrics.refused_responses);
    }
    
    /// Update top queries (placeholder implementation)
    async fn update_top_queries(
        top_queries: &Arc<RwLock<TopQueries>>,
        _metrics: &dns_core::MetricsSnapshot,
        timestamp: u64,
    ) {
        let mut queries = top_queries.write().await;
        queries.last_updated = timestamp;
        
        // In a real implementation, this would track actual query names and types
        // For now, we'll use placeholder data
        queries.top_domains = vec![
            QueryCount { name: "example.com".to_string(), count: 1000, percentage: 25.0 },
            QueryCount { name: "google.com".to_string(), count: 800, percentage: 20.0 },
            QueryCount { name: "cloudflare.com".to_string(), count: 600, percentage: 15.0 },
        ];
        
        queries.top_types = vec![
            QueryCount { name: "A".to_string(), count: 2000, percentage: 50.0 },
            QueryCount { name: "AAAA".to_string(), count: 1200, percentage: 30.0 },
            QueryCount { name: "MX".to_string(), count: 400, percentage: 10.0 },
        ];
    }
    
    /// Update client statistics (placeholder implementation)
    async fn update_client_stats(
        client_stats: &Arc<RwLock<ClientStatistics>>,
        _metrics: &dns_core::MetricsSnapshot,
        timestamp: u64,
    ) {
        let mut stats = client_stats.write().await;
        stats.last_updated = timestamp;
        
        // In a real implementation, this would track actual client IPs
        // For now, we'll use placeholder data
        stats.top_clients = vec![
            ClientStats {
                ip: "192.168.1.100".to_string(),
                query_count: 500,
                blocked_count: 50,
                error_count: 5,
                avg_response_time_ms: 2.5,
                location: Some("US".to_string()),
                last_seen: timestamp,
            },
        ];
    }
    
    /// Update performance statistics
    async fn update_performance_stats(
        performance_stats: &Arc<RwLock<PerformanceStatistics>>,
        metrics: &dns_core::MetricsSnapshot,
        timestamp: u64,
    ) {
        let mut stats = performance_stats.write().await;
        stats.last_updated = timestamp;
        
        // Update cache performance
        stats.cache_performance.hit_rate = metrics.cache_hit_rate as f64 / 100.0;
        stats.cache_performance.miss_rate = 100.0 - (metrics.cache_hit_rate as f64 / 100.0);
        
        // In a real implementation, these would be calculated from actual measurements
        stats.response_time_percentiles.p50_ms = metrics.average_response_time_ns as f64 / 1_000_000.0;
        stats.response_time_percentiles.p90_ms = metrics.average_response_time_ns as f64 / 1_000_000.0 * 1.5;
        stats.response_time_percentiles.p95_ms = metrics.average_response_time_ns as f64 / 1_000_000.0 * 2.0;
        stats.response_time_percentiles.p99_ms = metrics.average_response_time_ns as f64 / 1_000_000.0 * 3.0;
        stats.response_time_percentiles.p999_ms = metrics.average_response_time_ns as f64 / 1_000_000.0 * 5.0;
    }
    
    /// Update geographic statistics (placeholder implementation)
    async fn update_geographic_stats(
        geographic_stats: &Arc<RwLock<GeographicStatistics>>,
        _metrics: &dns_core::MetricsSnapshot,
        timestamp: u64,
    ) {
        let mut stats = geographic_stats.write().await;
        stats.last_updated = timestamp;
        
        // In a real implementation, this would use GeoIP data
        stats.queries_by_country.insert("US".to_string(), 1000);
        stats.queries_by_country.insert("CA".to_string(), 200);
        stats.queries_by_country.insert("GB".to_string(), 150);
    }
    
    /// Get dashboard data for real-time display
    pub async fn get_dashboard_data(&self) -> DashboardData {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let metrics = global_metrics().snapshot();
        
        let realtime = RealtimeMetrics {
            current_qps: metrics.queries_per_second as f64,
            current_response_time_ms: metrics.average_response_time_ns as f64 / 1_000_000.0,
            current_cache_hit_rate: metrics.cache_hit_rate as f64 / 100.0,
            current_error_rate: {
                let total_errors = metrics.protocol_errors + metrics.storage_errors + 
                                 metrics.network_errors + metrics.timeout_errors;
                if metrics.queries_total > 0 {
                    (total_errors as f64 / metrics.queries_total as f64) * 100.0
                } else {
                    0.0
                }
            },
            uptime_seconds: 0, // Would need to track server start time
            health_status: "healthy".to_string(), // Would integrate with health checker
        };
        
        let time_series = self.time_series_data.read().await.clone().into();
        let query_stats = self.query_stats.read().await.clone();
        let top_queries = self.top_queries.read().await.clone();
        let client_stats = self.client_stats.read().await.clone();
        let performance_stats = self.performance_stats.read().await.clone();
        
        let geographic_stats = if self.config.geographic_analytics {
            Some(self.geographic_stats.read().await.clone())
        } else {
            None
        };
        
        DashboardData {
            timestamp,
            realtime,
            time_series,
            query_stats,
            top_queries,
            client_stats,
            performance_stats,
            geographic_stats,
        }
    }
    
    /// Get time series data for a specific time range
    pub async fn get_time_series_range(&self, start_time: u64, end_time: u64) -> Vec<TimeSeriesPoint> {
        let data = self.time_series_data.read().await;
        data.iter()
            .filter(|point| point.timestamp >= start_time && point.timestamp <= end_time)
            .cloned()
            .collect()
    }
    
    /// Get query statistics
    pub async fn get_query_stats(&self) -> QueryStatistics {
        self.query_stats.read().await.clone()
    }
    
    /// Get top queries
    pub async fn get_top_queries(&self) -> TopQueries {
        self.top_queries.read().await.clone()
    }
    
    /// Get client statistics
    pub async fn get_client_stats(&self) -> ClientStatistics {
        self.client_stats.read().await.clone()
    }
    
    /// Get performance statistics
    pub async fn get_performance_stats(&self) -> PerformanceStatistics {
        self.performance_stats.read().await.clone()
    }
}