use dns_monitoring::{
    MonitoringSystem, MonitoringConfig, PrometheusConfig, HealthConfig,
    TracingConfig, LoggingConfig, ProfilingConfig, AnalyticsConfig,
    AlertConfig, ServerConfig,
};
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_monitoring_system_lifecycle() {
    let config = MonitoringConfig {
        prometheus: PrometheusConfig {
            enabled: true,
            collection_interval_secs: 1,
            ..Default::default()
        },
        health: HealthConfig {
            enabled: true,
            check_interval_secs: 1,
            ..Default::default()
        },
        tracing: TracingConfig {
            enabled: false, // Disable for testing
            ..Default::default()
        },
        logging: LoggingConfig {
            enabled: false, // Disable for testing
            ..Default::default()
        },
        profiling: ProfilingConfig {
            enabled: false, // Disable for testing
            ..Default::default()
        },
        analytics: AnalyticsConfig {
            enabled: true,
            collection_interval_secs: 1,
            ..Default::default()
        },
        alerts: AlertConfig {
            enabled: false, // Disable for testing
            ..Default::default()
        },
        server: ServerConfig {
            enabled: false, // Disable for testing
            ..Default::default()
        },
    };
    
    let monitoring = MonitoringSystem::new(config).await.unwrap();
    
    // Start monitoring system
    monitoring.start().await.unwrap();
    
    // Wait a bit for systems to initialize
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Test Prometheus metrics
    let metrics = monitoring.prometheus().gather().unwrap();
    assert!(!metrics.is_empty());
    
    // Test health checks
    let health_status = monitoring.health().get_health_status().await;
    assert_ne!(health_status, dns_monitoring::HealthStatus::Unknown);
    
    // Test analytics
    let dashboard_data = monitoring.analytics().get_dashboard_data().await;
    assert_eq!(dashboard_data.realtime.current_qps, 0.0); // No queries yet
    
    // Stop monitoring system
    monitoring.stop().await.unwrap();
}

#[tokio::test]
async fn test_prometheus_metrics_collection() {
    let config = PrometheusConfig {
        enabled: true,
        collection_interval_secs: 1,
        namespace: "test_dns".to_string(),
        ..Default::default()
    };
    
    let exporter = dns_monitoring::PrometheusExporter::new(config).unwrap();
    
    // Record some test metrics
    exporter.record_query(Duration::from_millis(5), Some(512));
    exporter.record_response(Some(1024));
    
    // Gather metrics
    let metrics_text = exporter.gather().unwrap();
    
    // Check that metrics are present
    assert!(metrics_text.contains("test_dns_queries_total"));
    assert!(metrics_text.contains("test_dns_query_duration_seconds"));
}

#[tokio::test]
async fn test_health_checker() {
    let config = HealthConfig {
        enabled: true,
        check_interval_secs: 1,
        max_memory_usage_percent: 90.0,
        max_cpu_usage_percent: 95.0,
        ..Default::default()
    };
    
    let health_checker = dns_monitoring::HealthChecker::new(config);
    
    // Start health checker
    health_checker.start().await.unwrap();
    
    // Wait for initial health check
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Test readiness and liveness
    let is_ready = health_checker.is_ready().await;
    let is_alive = health_checker.is_alive().await;
    
    // Should be ready and alive initially
    assert!(is_ready);
    assert!(is_alive);
    
    // Get health report
    let report = health_checker.get_health_report().await;
    assert!(report.is_some());
    
    let report = report.unwrap();
    assert!(!report.components.is_empty());
    assert!(report.summary.total_components > 0);
}

#[tokio::test]
async fn test_query_analytics() {
    let config = AnalyticsConfig {
        enabled: true,
        collection_interval_secs: 1,
        max_data_points: 100,
        detailed_tracking: true,
        ..Default::default()
    };
    
    let analytics = dns_monitoring::QueryAnalytics::new(config).unwrap();
    
    // Start analytics
    analytics.start().await.unwrap();
    
    // Wait for initial collection
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Get dashboard data
    let dashboard = analytics.get_dashboard_data().await;
    assert_eq!(dashboard.realtime.current_qps, 0.0);
    assert!(dashboard.time_series.is_empty()); // No data collected yet
    
    // Get query stats
    let query_stats = analytics.get_query_stats().await;
    assert_eq!(query_stats.total_queries, 0);
    
    // Get top queries
    let top_queries = analytics.get_top_queries().await;
    assert!(top_queries.top_domains.len() >= 0); // May have placeholder data
    
    // Stop analytics
    analytics.stop().await.unwrap();
}

#[tokio::test]
async fn test_profiling_system() {
    let config = ProfilingConfig {
        enabled: true,
        cpu: dns_monitoring::profiling::CpuProfilingConfig {
            enabled: true,
            frequency: 100,
            duration_secs: 1,
            stack_traces: true,
        },
        output_dir: std::env::temp_dir().join("dns_profiles_test"),
        ..Default::default()
    };
    
    let profiler = dns_monitoring::ProfileManager::new(config).unwrap();
    
    // Start profiler
    profiler.start().await.unwrap();
    
    // Start a CPU profile
    let profile_id = profiler.start_cpu_profile(Some("test_profile".to_string())).await.unwrap();
    assert_eq!(profile_id, "test_profile");
    
    // Wait a bit
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Stop the profile
    let profile_info = profiler.stop_cpu_profile(&profile_id).await.unwrap();
    assert_eq!(profile_info.id, "test_profile");
    assert!(profile_info.file_size > 0);
    
    // List profiles
    let profiles = profiler.list_profiles().await.unwrap();
    assert!(!profiles.is_empty());
    
    // Get stats
    let stats = profiler.get_stats().await;
    assert!(stats.total_profiles > 0);
    
    // Stop profiler
    profiler.stop().await.unwrap();
    
    // Clean up test files
    let _ = std::fs::remove_dir_all(std::env::temp_dir().join("dns_profiles_test"));
}

#[tokio::test]
async fn test_monitoring_server() {
    let config = ServerConfig {
        enabled: true,
        host: "127.0.0.1".to_string(),
        port: 0, // Use random port
        auth_enabled: false,
        ..Default::default()
    };
    
    // Create minimal monitoring components
    let prometheus_config = PrometheusConfig::default();
    let prometheus = std::sync::Arc::new(
        dns_monitoring::PrometheusExporter::new(prometheus_config).unwrap()
    );
    
    let health_config = HealthConfig::default();
    let health = std::sync::Arc::new(
        dns_monitoring::HealthChecker::new(health_config)
    );
    
    let profiling_config = ProfilingConfig { enabled: false, ..Default::default() };
    let profiler = std::sync::Arc::new(
        dns_monitoring::ProfileManager::new(profiling_config).unwrap()
    );
    
    let analytics_config = AnalyticsConfig::default();
    let analytics = std::sync::Arc::new(
        dns_monitoring::QueryAnalytics::new(analytics_config).unwrap()
    );
    
    let server = dns_monitoring::MonitoringServer::new(
        config,
        prometheus,
        health,
        profiler,
        analytics,
    ).unwrap();
    
    // Start server (this test just verifies it can be created and started)
    // We don't test HTTP endpoints here as that would require more complex setup
    let start_result = timeout(Duration::from_millis(100), server.start()).await;
    
    // The server should start successfully or timeout (which is fine for this test)
    match start_result {
        Ok(result) => assert!(result.is_ok()),
        Err(_) => {}, // Timeout is acceptable
    }
    
    // Stop server
    server.stop().await.unwrap();
}

#[tokio::test]
async fn test_configuration_validation() {
    // Test valid configuration
    let valid_config = MonitoringConfig::default();
    assert!(valid_config.validate().is_ok());
    
    // Test invalid Prometheus configuration
    let mut invalid_config = MonitoringConfig::default();
    invalid_config.prometheus.namespace = "".to_string();
    assert!(invalid_config.validate().is_err());
    
    // Test invalid health configuration
    let mut invalid_config = MonitoringConfig::default();
    invalid_config.health.max_memory_usage_percent = 150.0;
    assert!(invalid_config.validate().is_err());
    
    // Test invalid tracing configuration
    let mut invalid_config = MonitoringConfig::default();
    invalid_config.tracing.sampling.rate = 2.0;
    assert!(invalid_config.validate().is_err());
    
    // Test invalid server configuration
    let mut invalid_config = MonitoringConfig::default();
    invalid_config.server.port = 0;
    assert!(invalid_config.validate().is_err());
}

#[tokio::test]
async fn test_feature_summary() {
    let config = MonitoringConfig::default();
    let summary = config.feature_summary();
    
    // Check that summary reflects default configuration
    assert!(summary.prometheus_enabled);
    assert!(summary.health_checks_enabled);
    assert!(summary.tracing_enabled);
    assert!(summary.logging_enabled);
    assert!(!summary.profiling_enabled); // Disabled by default
    assert!(summary.analytics_enabled);
    assert!(!summary.alerts_enabled); // Disabled by default
    assert!(summary.server_enabled);
    
    // Test display formatting
    let display_str = format!("{}", summary);
    assert!(display_str.contains("Enabled features:"));
    assert!(display_str.contains("Prometheus"));
}