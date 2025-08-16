//! Structured logging with configurable levels and formats
//!
//! Provides comprehensive logging for DNS server operations with
//! support for JSON output, log rotation, and filtering.

use dns_core::{DnsResult, DnsError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::{
    fmt::{self, format::Writer, FormatEvent, FormatFields},
    registry::LookupSpan,
    Layer,
};

/// Configuration for structured logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Enable structured logging
    pub enabled: bool,
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Output format (json, pretty, compact)
    pub format: LogFormat,
    /// Output destinations
    pub outputs: Vec<LogOutput>,
    /// Additional fields to include in all log entries
    pub additional_fields: HashMap<String, Value>,
    /// Enable log sampling for high-volume events
    pub sampling: SamplingConfig,
    /// Log rotation configuration
    pub rotation: RotationConfig,
}

/// Log output format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    /// JSON format for structured logging
    Json,
    /// Pretty format for human reading
    Pretty,
    /// Compact format for minimal output
    Compact,
}

/// Log output destination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogOutput {
    /// Output type
    pub output_type: OutputType,
    /// Minimum log level for this output
    pub min_level: String,
    /// File path (for file outputs)
    pub file_path: Option<PathBuf>,
    /// Buffer size for file outputs
    pub buffer_size: Option<usize>,
}

/// Output destination types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputType {
    /// Standard output
    Stdout,
    /// Standard error
    Stderr,
    /// File output
    File,
    /// Syslog output
    Syslog,
}

/// Log sampling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingConfig {
    /// Enable sampling
    pub enabled: bool,
    /// Sample rate (0.0 to 1.0)
    pub rate: f64,
    /// Events to always log (regardless of sampling)
    pub always_log: Vec<String>,
    /// Events to never log
    pub never_log: Vec<String>,
}

/// Log rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    /// Enable log rotation
    pub enabled: bool,
    /// Maximum file size in bytes before rotation
    pub max_size_bytes: u64,
    /// Maximum number of rotated files to keep
    pub max_files: u32,
    /// Rotation schedule (hourly, daily, weekly)
    pub schedule: RotationSchedule,
}

/// Log rotation schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RotationSchedule {
    /// Rotate hourly
    Hourly,
    /// Rotate daily
    Daily,
    /// Rotate weekly
    Weekly,
    /// No scheduled rotation (size-based only)
    Never,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            level: "info".to_string(),
            format: LogFormat::Json,
            outputs: vec![
                LogOutput {
                    output_type: OutputType::Stdout,
                    min_level: "info".to_string(),
                    file_path: None,
                    buffer_size: None,
                },
            ],
            additional_fields: HashMap::new(),
            sampling: SamplingConfig {
                enabled: false,
                rate: 1.0,
                always_log: vec!["error".to_string(), "warn".to_string()],
                never_log: vec![],
            },
            rotation: RotationConfig {
                enabled: false,
                max_size_bytes: 100 * 1024 * 1024, // 100MB
                max_files: 10,
                schedule: RotationSchedule::Daily,
            },
        }
    }
}

/// Structured logger implementation
pub struct StructuredLogger {
    config: LoggingConfig,
    log_writers: Arc<RwLock<HashMap<String, Box<dyn Write + Send + Sync>>>>,
}

impl StructuredLogger {
    /// Create a new structured logger
    pub fn new(config: LoggingConfig) -> DnsResult<Self> {
        Ok(Self {
            config,
            log_writers: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    /// Initialize the logging system
    pub fn initialize(&self) -> DnsResult<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        // This would typically set up the tracing subscriber with custom layers
        // For now, we'll use a basic implementation
        tracing::info!(
            level = %self.config.level,
            format = ?self.config.format,
            outputs = self.config.outputs.len(),
            "Structured logging initialized"
        );
        
        Ok(())
    }
    
    /// Log a DNS query event
    pub async fn log_dns_query(
        &self,
        query_name: &str,
        query_type: &str,
        client_ip: &str,
        response_code: &str,
        response_time_ms: u64,
        cache_hit: bool,
    ) {
        let mut fields = HashMap::new();
        fields.insert("event_type".to_string(), Value::String("dns_query".to_string()));
        fields.insert("query_name".to_string(), Value::String(query_name.to_string()));
        fields.insert("query_type".to_string(), Value::String(query_type.to_string()));
        fields.insert("client_ip".to_string(), Value::String(client_ip.to_string()));
        fields.insert("response_code".to_string(), Value::String(response_code.to_string()));
        fields.insert("response_time_ms".to_string(), Value::Number(response_time_ms.into()));
        fields.insert("cache_hit".to_string(), Value::Bool(cache_hit));
        
        self.log_structured(Level::INFO, "DNS query processed", fields).await;
    }
    
    /// Log a cache operation event
    pub async fn log_cache_operation(
        &self,
        operation: &str,
        key: &str,
        hit: bool,
        size: Option<usize>,
    ) {
        let mut fields = HashMap::new();
        fields.insert("event_type".to_string(), Value::String("cache_operation".to_string()));
        fields.insert("operation".to_string(), Value::String(operation.to_string()));
        fields.insert("key".to_string(), Value::String(key.to_string()));
        fields.insert("hit".to_string(), Value::Bool(hit));
        
        if let Some(size) = size {
            fields.insert("size".to_string(), Value::Number(size.into()));
        }
        
        self.log_structured(Level::DEBUG, "Cache operation", fields).await;
    }
    
    /// Log a storage operation event
    pub async fn log_storage_operation(
        &self,
        operation: &str,
        zone: &str,
        success: bool,
        duration_ms: u64,
    ) {
        let mut fields = HashMap::new();
        fields.insert("event_type".to_string(), Value::String("storage_operation".to_string()));
        fields.insert("operation".to_string(), Value::String(operation.to_string()));
        fields.insert("zone".to_string(), Value::String(zone.to_string()));
        fields.insert("success".to_string(), Value::Bool(success));
        fields.insert("duration_ms".to_string(), Value::Number(duration_ms.into()));
        
        let level = if success { Level::DEBUG } else { Level::WARN };
        self.log_structured(level, "Storage operation", fields).await;
    }
    
    /// Log a cluster operation event
    pub async fn log_cluster_operation(
        &self,
        operation: &str,
        node_id: &str,
        success: bool,
        details: Option<&str>,
    ) {
        let mut fields = HashMap::new();
        fields.insert("event_type".to_string(), Value::String("cluster_operation".to_string()));
        fields.insert("operation".to_string(), Value::String(operation.to_string()));
        fields.insert("node_id".to_string(), Value::String(node_id.to_string()));
        fields.insert("success".to_string(), Value::Bool(success));
        
        if let Some(details) = details {
            fields.insert("details".to_string(), Value::String(details.to_string()));
        }
        
        let level = if success { Level::INFO } else { Level::ERROR };
        self.log_structured(level, "Cluster operation", fields).await;
    }
    
    /// Log a security event
    pub async fn log_security_event(
        &self,
        event_type: &str,
        client_ip: &str,
        action: &str,
        reason: &str,
        severity: &str,
    ) {
        let mut fields = HashMap::new();
        fields.insert("event_type".to_string(), Value::String("security_event".to_string()));
        fields.insert("security_event_type".to_string(), Value::String(event_type.to_string()));
        fields.insert("client_ip".to_string(), Value::String(client_ip.to_string()));
        fields.insert("action".to_string(), Value::String(action.to_string()));
        fields.insert("reason".to_string(), Value::String(reason.to_string()));
        fields.insert("severity".to_string(), Value::String(severity.to_string()));
        
        let level = match severity {
            "critical" | "high" => Level::ERROR,
            "medium" => Level::WARN,
            _ => Level::INFO,
        };
        
        self.log_structured(level, "Security event", fields).await;
    }
    
    /// Log a performance metric event
    pub async fn log_performance_metric(
        &self,
        metric_name: &str,
        value: f64,
        unit: &str,
        tags: Option<HashMap<String, String>>,
    ) {
        let mut fields = HashMap::new();
        fields.insert("event_type".to_string(), Value::String("performance_metric".to_string()));
        fields.insert("metric_name".to_string(), Value::String(metric_name.to_string()));
        fields.insert("value".to_string(), Value::Number(serde_json::Number::from_f64(value).unwrap()));
        fields.insert("unit".to_string(), Value::String(unit.to_string()));
        
        if let Some(tags) = tags {
            for (key, value) in tags {
                fields.insert(format!("tag_{}", key), Value::String(value));
            }
        }
        
        self.log_structured(Level::DEBUG, "Performance metric", fields).await;
    }
    
    /// Log an error event
    pub async fn log_error(
        &self,
        error: &dyn std::error::Error,
        context: Option<HashMap<String, Value>>,
    ) {
        let mut fields = HashMap::new();
        fields.insert("event_type".to_string(), Value::String("error".to_string()));
        fields.insert("error_message".to_string(), Value::String(error.to_string()));
        fields.insert("error_type".to_string(), Value::String(format!("{:?}", error)));
        
        if let Some(context) = context {
            for (key, value) in context {
                fields.insert(key, value);
            }
        }
        
        self.log_structured(Level::ERROR, "Error occurred", fields).await;
    }
    
    /// Log a structured event
    async fn log_structured(
        &self,
        level: Level,
        message: &str,
        mut fields: HashMap<String, Value>,
    ) {
        // Add timestamp
        fields.insert(
            "timestamp".to_string(),
            Value::String(chrono::Utc::now().to_rfc3339()),
        );
        
        // Add additional configured fields
        for (key, value) in &self.config.additional_fields {
            fields.insert(key.clone(), value.clone());
        }
        
        // Check sampling
        if self.should_sample(&fields) {
            match self.config.format {
                LogFormat::Json => {
                    let json_log = serde_json::json!({
                        "level": level.to_string().to_lowercase(),
                        "message": message,
                        "fields": fields
                    });
                    
                    // In a real implementation, this would write to configured outputs
                    match level {
                        Level::ERROR => tracing::error!("{}", json_log),
                        Level::WARN => tracing::warn!("{}", json_log),
                        Level::INFO => tracing::info!("{}", json_log),
                        Level::DEBUG => tracing::debug!("{}", json_log),
                        Level::TRACE => tracing::trace!("{}", json_log),
                    }
                }
                LogFormat::Pretty => {
                    // Pretty format for human reading
                    let formatted = format!(
                        "[{}] {}: {} {:?}",
                        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                        level.to_string().to_uppercase(),
                        message,
                        fields
                    );
                    
                    match level {
                        Level::ERROR => tracing::error!("{}", formatted),
                        Level::WARN => tracing::warn!("{}", formatted),
                        Level::INFO => tracing::info!("{}", formatted),
                        Level::DEBUG => tracing::debug!("{}", formatted),
                        Level::TRACE => tracing::trace!("{}", formatted),
                    }
                }
                LogFormat::Compact => {
                    // Compact format
                    let formatted = format!(
                        "{} {} {}",
                        level.to_string().chars().next().unwrap().to_uppercase(),
                        message,
                        serde_json::to_string(&fields).unwrap_or_default()
                    );
                    
                    match level {
                        Level::ERROR => tracing::error!("{}", formatted),
                        Level::WARN => tracing::warn!("{}", formatted),
                        Level::INFO => tracing::info!("{}", formatted),
                        Level::DEBUG => tracing::debug!("{}", formatted),
                        Level::TRACE => tracing::trace!("{}", formatted),
                    }
                }
            }
        }
    }
    
    /// Check if an event should be sampled
    fn should_sample(&self, fields: &HashMap<String, Value>) -> bool {
        if !self.config.sampling.enabled {
            return true;
        }
        
        // Check if event type is in never_log list
        if let Some(event_type) = fields.get("event_type") {
            if let Some(event_type_str) = event_type.as_str() {
                if self.config.sampling.never_log.contains(&event_type_str.to_string()) {
                    return false;
                }
                
                // Check if event type is in always_log list
                if self.config.sampling.always_log.contains(&event_type_str.to_string()) {
                    return true;
                }
            }
        }
        
        // Apply sampling rate
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        fields.hash(&mut hasher);
        let hash = hasher.finish();
        
        let sample_threshold = (self.config.sampling.rate * u64::MAX as f64) as u64;
        hash <= sample_threshold
    }
    
    /// Rotate log files if needed
    pub async fn rotate_logs(&self) -> DnsResult<()> {
        if !self.config.rotation.enabled {
            return Ok(());
        }
        
        // Implementation would check file sizes and rotate as needed
        tracing::debug!("Log rotation check completed");
        Ok(())
    }
    
    /// Get current log statistics
    pub async fn get_log_stats(&self) -> LogStats {
        // In a real implementation, this would track actual statistics
        LogStats {
            total_events: 0,
            events_by_level: HashMap::new(),
            events_by_type: HashMap::new(),
            sampling_rate: self.config.sampling.rate,
            last_rotation: None,
        }
    }
}

/// Log statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogStats {
    /// Total number of log events
    pub total_events: u64,
    /// Events by log level
    pub events_by_level: HashMap<String, u64>,
    /// Events by event type
    pub events_by_type: HashMap<String, u64>,
    /// Current sampling rate
    pub sampling_rate: f64,
    /// Last log rotation timestamp
    pub last_rotation: Option<chrono::DateTime<chrono::Utc>>,
}

/// Custom JSON formatter for structured logs
pub struct JsonFormatter {
    additional_fields: HashMap<String, Value>,
}

impl JsonFormatter {
    pub fn new(additional_fields: HashMap<String, Value>) -> Self {
        Self { additional_fields }
    }
}

impl<S, N> FormatEvent<S, N> for JsonFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &fmt::FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let mut fields = HashMap::new();
        
        // Add timestamp
        fields.insert(
            "timestamp".to_string(),
            Value::String(chrono::Utc::now().to_rfc3339()),
        );
        
        // Add level
        fields.insert(
            "level".to_string(),
            Value::String(event.metadata().level().to_string().to_lowercase()),
        );
        
        // Add target
        fields.insert(
            "target".to_string(),
            Value::String(event.metadata().target().to_string()),
        );
        
        // Add additional configured fields
        for (key, value) in &self.additional_fields {
            fields.insert(key.clone(), value.clone());
        }
        
        // Create JSON object
        let json_log = serde_json::json!({
            "timestamp": fields.get("timestamp"),
            "level": fields.get("level"),
            "target": fields.get("target"),
            "fields": fields
        });
        
        writeln!(writer, "{}", json_log)
    }
}