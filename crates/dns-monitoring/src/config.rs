//! Configuration management for monitoring system
//!
//! Provides centralized configuration for all monitoring components
//! with validation and default values.

use crate::{
    prometheus::PrometheusConfig,
    health::HealthConfig,
    tracing::TracingConfig,
    logging::LoggingConfig,
    profiling::ProfilingConfig,
    analytics::AnalyticsConfig,
    alerts::AlertConfig,
    server::ServerConfig,
};
use dns_core::{DnsResult, DnsError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Complete monitoring system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Prometheus metrics configuration
    pub prometheus: PrometheusConfig,
    /// Health check configuration
    pub health: HealthConfig,
    /// Distributed tracing configuration
    pub tracing: TracingConfig,
    /// Structured logging configuration
    pub logging: LoggingConfig,
    /// Performance profiling configuration
    pub profiling: ProfilingConfig,
    /// Query analytics configuration
    pub analytics: AnalyticsConfig,
    /// Alert management configuration
    pub alerts: AlertConfig,
    /// Monitoring server configuration
    pub server: ServerConfig,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            prometheus: PrometheusConfig::default(),
            health: HealthConfig::default(),
            tracing: TracingConfig::default(),
            logging: LoggingConfig::default(),
            profiling: ProfilingConfig::default(),
            analytics: AnalyticsConfig::default(),
            alerts: AlertConfig::default(),
            server: ServerConfig::default(),
        }
    }
}

impl MonitoringConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: &PathBuf) -> DnsResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| DnsError::ConfigError(format!("Failed to read config file: {}", e)))?;
        
        let config: Self = toml::from_str(&content)
            .map_err(|e| DnsError::ConfigError(format!("Failed to parse config: {}", e)))?;
        
        config.validate()?;
        Ok(config)
    }
    
    /// Save configuration to a TOML file
    pub fn to_file(&self, path: &PathBuf) -> DnsResult<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| DnsError::ConfigError(format!("Failed to serialize config: {}", e)))?;
        
        std::fs::write(path, content)
            .map_err(|e| DnsError::ConfigError(format!("Failed to write config file: {}", e)))?;
        
        Ok(())
    }
    
    /// Load configuration from environment variables
    pub fn from_env() -> DnsResult<Self> {
        let mut config = Self::default();
        
        // Prometheus configuration
        if let Ok(enabled) = std::env::var("DNS_PROMETHEUS_ENABLED") {
            config.prometheus.enabled = enabled.parse().unwrap_or(true);
        }
        if let Ok(namespace) = std::env::var("DNS_PROMETHEUS_NAMESPACE") {
            config.prometheus.namespace = namespace;
        }
        if let Ok(interval) = std::env::var("DNS_PROMETHEUS_INTERVAL") {
            config.prometheus.collection_interval_secs = interval.parse().unwrap_or(5);
        }
        
        // Health check configuration
        if let Ok(enabled) = std::env::var("DNS_HEALTH_ENABLED") {
            config.health.enabled = enabled.parse().unwrap_or(true);
        }
        if let Ok(interval) = std::env::var("DNS_HEALTH_INTERVAL") {
            config.health.check_interval_secs = interval.parse().unwrap_or(30);
        }
        
        // Tracing configuration
        if let Ok(enabled) = std::env::var("DNS_TRACING_ENABLED") {
            config.tracing.enabled = enabled.parse().unwrap_or(true);
        }
        if let Ok(service_name) = std::env::var("DNS_SERVICE_NAME") {
            config.tracing.service_name = service_name;
        }
        if let Ok(environment) = std::env::var("DNS_ENVIRONMENT") {
            config.tracing.environment = environment;
        }
        if let Ok(endpoint) = std::env::var("DNS_OTLP_ENDPOINT") {
            config.tracing.otlp.endpoint = endpoint;
        }
        
        // Logging configuration
        if let Ok(enabled) = std::env::var("DNS_LOGGING_ENABLED") {
            config.logging.enabled = enabled.parse().unwrap_or(true);
        }
        if let Ok(level) = std::env::var("DNS_LOG_LEVEL") {
            config.logging.level = level;
        }
        
        // Profiling configuration
        if let Ok(enabled) = std::env::var("DNS_PROFILING_ENABLED") {
            config.profiling.enabled = enabled.parse().unwrap_or(false);
        }
        if let Ok(output_dir) = std::env::var("DNS_PROFILE_OUTPUT_DIR") {
            config.profiling.output_dir = PathBuf::from(output_dir);
        }
        
        // Analytics configuration
        if let Ok(enabled) = std::env::var("DNS_ANALYTICS_ENABLED") {
            config.analytics.enabled = enabled.parse().unwrap_or(true);
        }
        if let Ok(interval) = std::env::var("DNS_ANALYTICS_INTERVAL") {
            config.analytics.collection_interval_secs = interval.parse().unwrap_or(10);
        }
        
        // Server configuration
        if let Ok(host) = std::env::var("DNS_MONITORING_HOST") {
            config.server.host = host;
        }
        if let Ok(port) = std::env::var("DNS_MONITORING_PORT") {
            config.server.port = port.parse().unwrap_or(8080);
        }
        
        config.validate()?;
        Ok(config)
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> DnsResult<()> {
        // Validate Prometheus configuration
        if self.prometheus.enabled {
            if self.prometheus.namespace.is_empty() {
                return Err(DnsError::ConfigError("Prometheus namespace cannot be empty".to_string()));
            }
            if self.prometheus.collection_interval_secs == 0 {
                return Err(DnsError::ConfigError("Prometheus collection interval must be greater than 0".to_string()));
            }
        }
        
        // Validate health check configuration
        if self.health.enabled {
            if self.health.check_interval_secs == 0 {
                return Err(DnsError::ConfigError("Health check interval must be greater than 0".to_string()));
            }
            if self.health.max_memory_usage_percent <= 0.0 || self.health.max_memory_usage_percent > 100.0 {
                return Err(DnsError::ConfigError("Max memory usage percent must be between 0 and 100".to_string()));
            }
            if self.health.max_cpu_usage_percent <= 0.0 || self.health.max_cpu_usage_percent > 100.0 {
                return Err(DnsError::ConfigError("Max CPU usage percent must be between 0 and 100".to_string()));
            }
        }
        
        // Validate tracing configuration
        if self.tracing.enabled {
            if self.tracing.service_name.is_empty() {
                return Err(DnsError::ConfigError("Service name cannot be empty".to_string()));
            }
            if self.tracing.otlp.endpoint.is_empty() {
                return Err(DnsError::ConfigError("OTLP endpoint cannot be empty".to_string()));
            }
            if self.tracing.sampling.rate < 0.0 || self.tracing.sampling.rate > 1.0 {
                return Err(DnsError::ConfigError("Sampling rate must be between 0.0 and 1.0".to_string()));
            }
        }
        
        // Validate logging configuration
        if self.logging.enabled {
            let valid_levels = ["trace", "debug", "info", "warn", "error"];
            if !valid_levels.contains(&self.logging.level.as_str()) {
                return Err(DnsError::ConfigError(format!("Invalid log level: {}", self.logging.level)));
            }
            if self.logging.sampling.enabled && (self.logging.sampling.rate < 0.0 || self.logging.sampling.rate > 1.0) {
                return Err(DnsError::ConfigError("Log sampling rate must be between 0.0 and 1.0".to_string()));
            }
        }
        
        // Validate profiling configuration
        if self.profiling.enabled {
            if self.profiling.cpu.frequency <= 0 {
                return Err(DnsError::ConfigError("CPU profiling frequency must be greater than 0".to_string()));
            }
            if self.profiling.cpu.duration_secs == 0 {
                return Err(DnsError::ConfigError("CPU profiling duration must be greater than 0".to_string()));
            }
        }
        
        // Validate analytics configuration
        if self.analytics.enabled {
            if self.analytics.collection_interval_secs == 0 {
                return Err(DnsError::ConfigError("Analytics collection interval must be greater than 0".to_string()));
            }
            if self.analytics.max_data_points == 0 {
                return Err(DnsError::ConfigError("Max data points must be greater than 0".to_string()));
            }
        }
        
        // Validate server configuration
        if self.server.host.is_empty() {
            return Err(DnsError::ConfigError("Server host cannot be empty".to_string()));
        }
        if self.server.port == 0 || self.server.port > 65535 {
            return Err(DnsError::ConfigError("Server port must be between 1 and 65535".to_string()));
        }
        
        Ok(())
    }
    
    /// Create a development configuration
    pub fn development() -> Self {
        let mut config = Self::default();
        
        // Enable all features for development
        config.prometheus.enabled = true;
        config.health.enabled = true;
        config.tracing.enabled = true;
        config.tracing.console_output = true;
        config.logging.enabled = true;
        config.logging.level = "debug".to_string();
        config.profiling.enabled = true;
        config.analytics.enabled = true;
        config.alerts.enabled = false; // Disable alerts in development
        
        // Use development-friendly settings
        config.tracing.environment = "development".to_string();
        config.tracing.sampling.rate = 1.0; // Sample all traces in development
        config.prometheus.collection_interval_secs = 5;
        config.health.check_interval_secs = 10;
        config.analytics.collection_interval_secs = 5;
        
        config
    }
    
    /// Create a production configuration
    pub fn production() -> Self {
        let mut config = Self::default();
        
        // Enable essential features for production
        config.prometheus.enabled = true;
        config.health.enabled = true;
        config.tracing.enabled = true;
        config.tracing.console_output = false;
        config.logging.enabled = true;
        config.logging.level = "info".to_string();
        config.profiling.enabled = false; // Disable profiling in production by default
        config.analytics.enabled = true;
        config.alerts.enabled = true;
        
        // Use production-optimized settings
        config.tracing.environment = "production".to_string();
        config.tracing.sampling.rate = 0.01; // Sample 1% of traces in production
        config.prometheus.collection_interval_secs = 15;
        config.health.check_interval_secs = 30;
        config.analytics.collection_interval_secs = 30;
        
        // Stricter health check thresholds
        config.health.max_memory_usage_percent = 85.0;
        config.health.max_cpu_usage_percent = 90.0;
        config.health.max_response_time_ms = 50;
        config.health.min_cache_hit_rate_percent = 85.0;
        config.health.max_error_rate_percent = 1.0;
        
        config
    }
    
    /// Merge with another configuration (other takes precedence)
    pub fn merge(&mut self, other: &Self) {
        // This would implement a deep merge of configurations
        // For now, we'll just replace the entire sections
        self.prometheus = other.prometheus.clone();
        self.health = other.health.clone();
        self.tracing = other.tracing.clone();
        self.logging = other.logging.clone();
        self.profiling = other.profiling.clone();
        self.analytics = other.analytics.clone();
        self.alerts = other.alerts.clone();
        self.server = other.server.clone();
    }
    
    /// Get a summary of enabled features
    pub fn feature_summary(&self) -> FeatureSummary {
        FeatureSummary {
            prometheus_enabled: self.prometheus.enabled,
            health_checks_enabled: self.health.enabled,
            tracing_enabled: self.tracing.enabled,
            logging_enabled: self.logging.enabled,
            profiling_enabled: self.profiling.enabled,
            analytics_enabled: self.analytics.enabled,
            alerts_enabled: self.alerts.enabled,
            server_enabled: self.server.enabled,
        }
    }
}

/// Summary of enabled monitoring features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureSummary {
    pub prometheus_enabled: bool,
    pub health_checks_enabled: bool,
    pub tracing_enabled: bool,
    pub logging_enabled: bool,
    pub profiling_enabled: bool,
    pub analytics_enabled: bool,
    pub alerts_enabled: bool,
    pub server_enabled: bool,
}

impl std::fmt::Display for FeatureSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let enabled_features: Vec<&str> = [
            ("Prometheus", self.prometheus_enabled),
            ("Health Checks", self.health_checks_enabled),
            ("Tracing", self.tracing_enabled),
            ("Logging", self.logging_enabled),
            ("Profiling", self.profiling_enabled),
            ("Analytics", self.analytics_enabled),
            ("Alerts", self.alerts_enabled),
            ("Server", self.server_enabled),
        ]
        .iter()
        .filter_map(|(name, enabled)| if *enabled { Some(*name) } else { None })
        .collect();
        
        write!(f, "Enabled features: {}", enabled_features.join(", "))
    }
}