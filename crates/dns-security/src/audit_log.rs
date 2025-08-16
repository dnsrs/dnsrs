//! Audit logging for administrative actions
//! 
//! Provides comprehensive audit logging for security events including:
//! - Administrative actions
//! - Security violations
//! - Access control decisions
//! - Authentication events

use crate::{SecurityError, SecurityResult, current_timestamp_ms};
use crate::ddos_protection::ThreatLevel;
use lockfree::queue::Queue as LockFreeQueue;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use std::path::PathBuf;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use serde::{Deserialize, Serialize};
use parking_lot::RwLock;

/// Audit logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable audit logging
    pub enabled: bool,
    /// Log file path
    pub log_file: Option<PathBuf>,
    /// Maximum log file size in bytes
    pub max_file_size: u64,
    /// Number of log files to rotate
    pub max_files: u32,
    /// Log level filter
    pub log_level: AuditLevel,
    /// Buffer size for async logging
    pub buffer_size: usize,
    /// Flush interval in milliseconds
    pub flush_interval_ms: u64,
    /// Enable structured JSON logging
    pub json_format: bool,
    /// Include stack traces for errors
    pub include_stack_traces: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_file: Some(PathBuf::from("/var/log/dns-server/audit.log")),
            max_file_size: 100 * 1024 * 1024, // 100MB
            max_files: 10,
            log_level: AuditLevel::Info,
            buffer_size: 10000,
            flush_interval_ms: 5000, // 5 seconds
            json_format: true,
            include_stack_traces: false,
        }
    }
}

/// Audit log levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditLevel {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
    Critical = 4,
}

impl AuditLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditLevel::Debug => "DEBUG",
            AuditLevel::Info => "INFO",
            AuditLevel::Warn => "WARN",
            AuditLevel::Error => "ERROR",
            AuditLevel::Critical => "CRITICAL",
        }
    }
}

/// Types of audit events
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditEventType {
    /// DNS query blocked by ACL
    AccessBlocked,
    /// DNS query blocked by DDoS protection
    DdosBlocked,
    /// Invalid DNS packet received
    InvalidPacket,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// TSIG authentication failure
    TsigFailure,
    /// Zone transfer authorized
    ZoneTransferAuthorized,
    /// Zone transfer denied
    ZoneTransferDenied,
    /// Administrative action performed
    AdminAction,
    /// Configuration changed
    ConfigurationChanged,
    /// Security policy updated
    SecurityPolicyUpdated,
    /// System startup/shutdown
    SystemEvent,
    /// Error condition
    ErrorEvent,
}

impl AuditEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditEventType::AccessBlocked => "ACCESS_BLOCKED",
            AuditEventType::DdosBlocked => "DDOS_BLOCKED",
            AuditEventType::InvalidPacket => "INVALID_PACKET",
            AuditEventType::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            AuditEventType::TsigFailure => "TSIG_FAILURE",
            AuditEventType::ZoneTransferAuthorized => "ZONE_TRANSFER_AUTHORIZED",
            AuditEventType::ZoneTransferDenied => "ZONE_TRANSFER_DENIED",
            AuditEventType::AdminAction => "ADMIN_ACTION",
            AuditEventType::ConfigurationChanged => "CONFIGURATION_CHANGED",
            AuditEventType::SecurityPolicyUpdated => "SECURITY_POLICY_UPDATED",
            AuditEventType::SystemEvent => "SYSTEM_EVENT",
            AuditEventType::ErrorEvent => "ERROR_EVENT",
        }
    }

    pub fn default_level(&self) -> AuditLevel {
        match self {
            AuditEventType::AccessBlocked => AuditLevel::Warn,
            AuditEventType::DdosBlocked => AuditLevel::Error,
            AuditEventType::InvalidPacket => AuditLevel::Warn,
            AuditEventType::RateLimitExceeded => AuditLevel::Info,
            AuditEventType::TsigFailure => AuditLevel::Error,
            AuditEventType::ZoneTransferAuthorized => AuditLevel::Info,
            AuditEventType::ZoneTransferDenied => AuditLevel::Warn,
            AuditEventType::AdminAction => AuditLevel::Info,
            AuditEventType::ConfigurationChanged => AuditLevel::Info,
            AuditEventType::SecurityPolicyUpdated => AuditLevel::Info,
            AuditEventType::SystemEvent => AuditLevel::Info,
            AuditEventType::ErrorEvent => AuditLevel::Error,
        }
    }
}

/// Audit event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event timestamp
    pub timestamp: u64,
    /// Event type
    pub event_type: AuditEventType,
    /// Log level
    pub level: AuditLevel,
    /// Source IP address (if applicable)
    pub source_ip: Option<IpAddr>,
    /// User or system component that triggered the event
    pub actor: String,
    /// Event description
    pub message: String,
    /// Additional structured data
    pub metadata: serde_json::Value,
    /// Request ID for correlation
    pub request_id: Option<String>,
    /// Session ID for correlation
    pub session_id: Option<String>,
}

impl AuditEvent {
    pub fn new(
        event_type: AuditEventType,
        actor: String,
        message: String,
    ) -> Self {
        Self {
            timestamp: current_timestamp_ms(),
            level: event_type.default_level(),
            event_type,
            source_ip: None,
            actor,
            message,
            metadata: serde_json::Value::Null,
            request_id: None,
            session_id: None,
        }
    }

    pub fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    pub fn with_level(mut self, level: AuditLevel) -> Self {
        self.level = level;
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }

    pub fn with_session_id(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Format event as JSON string
    pub fn to_json(&self) -> SecurityResult<String> {
        serde_json::to_string(self)
            .map_err(|e| SecurityError::audit_failed(format!("JSON serialization failed: {}", e)))
    }

    /// Format event as plain text
    pub fn to_text(&self) -> String {
        let ip_str = self.source_ip
            .map(|ip| format!(" [{}]", ip))
            .unwrap_or_default();
        
        format!(
            "{} {} {} {}{}: {}",
            self.timestamp,
            self.level.as_str(),
            self.event_type.as_str(),
            self.actor,
            ip_str,
            self.message
        )
    }
}

/// Audit logger implementation
pub struct AuditLogger {
    config: AuditConfig,
    event_queue: Arc<LockFreeQueue<Arc<AuditEvent>>>,
    stats: Arc<AuditStats>,
    shutdown: Arc<AtomicBool>,
    current_file_size: Arc<AtomicU64>,
    current_file_path: Arc<RwLock<Option<PathBuf>>>,
}

impl AuditLogger {
    pub fn new(config: AuditConfig) -> SecurityResult<Self> {
        let logger = Self {
            config,
            event_queue: Arc::new(LockFreeQueue::new()),
            stats: Arc::new(AuditStats::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            current_file_size: Arc::new(AtomicU64::new(0)),
            current_file_path: Arc::new(RwLock::new(None)),
        };

        // Start background logging task
        if logger.config.enabled {
            logger.start_background_logger();
        }

        Ok(logger)
    }

    /// Log an audit event
    pub async fn log_event(&self, event: AuditEvent) -> SecurityResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check log level filter
        if event.level < self.config.log_level {
            return Ok(());
        }

        // Add to queue for async processing
        let event_arc = Arc::new(event);
        self.event_queue.push(event_arc);
        
        self.stats.events_queued.fetch_add(1, Ordering::Relaxed);

        // Note: lockfree::queue::Queue doesn't have a len() method
        // We'll rely on the background task to handle overflow

        Ok(())
    }

    /// Log blocked access event
    pub async fn log_blocked_access(&self, client_ip: IpAddr, reason: &str) -> SecurityResult<()> {
        let event = AuditEvent::new(
            AuditEventType::AccessBlocked,
            "access_controller".to_string(),
            format!("Access blocked: {}", reason),
        ).with_source_ip(client_ip);

        self.log_event(event).await
    }

    /// Log DDoS protection block
    pub async fn log_ddos_block(&self, client_ip: IpAddr, threat_level: ThreatLevel) -> SecurityResult<()> {
        let event = AuditEvent::new(
            AuditEventType::DdosBlocked,
            "ddos_protection".to_string(),
            format!("DDoS protection triggered: {:?}", threat_level),
        ).with_source_ip(client_ip);

        self.log_event(event).await
    }

    /// Log invalid packet
    pub async fn log_invalid_packet(&self, client_ip: IpAddr, reason: &str) -> SecurityResult<()> {
        let event = AuditEvent::new(
            AuditEventType::InvalidPacket,
            "packet_validator".to_string(),
            format!("Invalid packet: {}", reason),
        ).with_source_ip(client_ip);

        self.log_event(event).await
    }

    /// Log rate limit exceeded
    pub async fn log_rate_limit_exceeded(&self, client_ip: IpAddr) -> SecurityResult<()> {
        let event = AuditEvent::new(
            AuditEventType::RateLimitExceeded,
            "rate_limiter".to_string(),
            "Rate limit exceeded".to_string(),
        ).with_source_ip(client_ip);

        self.log_event(event).await
    }

    /// Log TSIG authentication failure
    pub async fn log_tsig_failure(&self, client_ip: IpAddr, zone_name: &str) -> SecurityResult<()> {
        let event = AuditEvent::new(
            AuditEventType::TsigFailure,
            "tsig_authenticator".to_string(),
            format!("TSIG authentication failed for zone: {}", zone_name),
        ).with_source_ip(client_ip);

        self.log_event(event).await
    }

    /// Log authorized zone transfer
    pub async fn log_zone_transfer_authorized(&self, client_ip: IpAddr, zone_name: &str) -> SecurityResult<()> {
        let event = AuditEvent::new(
            AuditEventType::ZoneTransferAuthorized,
            "zone_transfer".to_string(),
            format!("Zone transfer authorized for zone: {}", zone_name),
        ).with_source_ip(client_ip);

        self.log_event(event).await
    }

    /// Log unauthorized zone transfer attempt
    pub async fn log_unauthorized_zone_transfer(&self, client_ip: IpAddr, zone_name: &str) -> SecurityResult<()> {
        let event = AuditEvent::new(
            AuditEventType::ZoneTransferDenied,
            "zone_transfer".to_string(),
            format!("Unauthorized zone transfer attempt for zone: {}", zone_name),
        ).with_source_ip(client_ip);

        self.log_event(event).await
    }

    /// Log administrative action
    pub async fn log_admin_action(&self, actor: &str, action: &str, details: &str) -> SecurityResult<()> {
        let event = AuditEvent::new(
            AuditEventType::AdminAction,
            actor.to_string(),
            format!("Admin action: {} - {}", action, details),
        );

        self.log_event(event).await
    }

    /// Log configuration change
    pub async fn log_config_change(&self, actor: &str, component: &str, details: &str) -> SecurityResult<()> {
        let event = AuditEvent::new(
            AuditEventType::ConfigurationChanged,
            actor.to_string(),
            format!("Configuration changed: {} - {}", component, details),
        );

        self.log_event(event).await
    }

    /// Start background logging task
    fn start_background_logger(&self) {
        let queue = self.event_queue.clone();
        let config = self.config.clone();
        let stats = self.stats.clone();
        let shutdown = self.shutdown.clone();
        let current_file_size = self.current_file_size.clone();
        let current_file_path = self.current_file_path.clone();

        tokio::spawn(async move {
            let mut flush_interval = tokio::time::interval(
                std::time::Duration::from_millis(config.flush_interval_ms)
            );

            let mut buffer = Vec::new();

            loop {
                tokio::select! {
                    _ = flush_interval.tick() => {
                        // Flush buffered events
                        Self::flush_events(
                            &queue,
                            &mut buffer,
                            &config,
                            &stats,
                            &current_file_size,
                            &current_file_path,
                        ).await;
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                        // Check for shutdown
                        if shutdown.load(Ordering::Relaxed) {
                            // Final flush
                            Self::flush_events(
                                &queue,
                                &mut buffer,
                                &config,
                                &stats,
                                &current_file_size,
                                &current_file_path,
                            ).await;
                            break;
                        }
                    }
                }
            }
        });
    }

    /// Flush events from queue to log file
    async fn flush_events(
        queue: &LockFreeQueue<Arc<AuditEvent>>,
        buffer: &mut Vec<Arc<AuditEvent>>,
        config: &AuditConfig,
        stats: &AuditStats,
        current_file_size: &AtomicU64,
        current_file_path: &RwLock<Option<PathBuf>>,
    ) {
        // Collect events from queue
        while let Some(event) = queue.pop() {
            buffer.push(event);
            
            if buffer.len() >= config.buffer_size {
                break; // Process in batches
            }
        }

        if buffer.is_empty() {
            return;
        }

        // Write events to file
        if let Some(log_file) = &config.log_file {
            match Self::write_events_to_file(
                buffer,
                log_file,
                config,
                current_file_size,
                current_file_path,
            ).await {
                Ok(written) => {
                    stats.events_written.fetch_add(written as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    stats.write_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::error!("Failed to write audit events: {}", e);
                }
            }
        }

        buffer.clear();
    }

    /// Write events to log file with rotation
    async fn write_events_to_file(
        events: &[Arc<AuditEvent>],
        log_file: &PathBuf,
        config: &AuditConfig,
        current_file_size: &AtomicU64,
        current_file_path: &RwLock<Option<PathBuf>>,
    ) -> SecurityResult<usize> {
        // Check if we need to rotate the log file
        let file_size = current_file_size.load(Ordering::Relaxed);
        if file_size > config.max_file_size {
            Self::rotate_log_file(log_file, config.max_files).await?;
            current_file_size.store(0, Ordering::Relaxed);
        }

        // Open log file for appending
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
            .await
            .map_err(|e| SecurityError::audit_failed(format!("Failed to open log file: {}", e)))?;

        let mut written_count = 0;
        let mut bytes_written = 0u64;

        for event in events {
            let log_line = if config.json_format {
                format!("{}\n", event.to_json()?)
            } else {
                format!("{}\n", event.to_text())
            };

            file.write_all(log_line.as_bytes()).await
                .map_err(|e| SecurityError::audit_failed(format!("Failed to write log entry: {}", e)))?;

            bytes_written += log_line.len() as u64;
            written_count += 1;
        }

        file.flush().await
            .map_err(|e| SecurityError::audit_failed(format!("Failed to flush log file: {}", e)))?;

        current_file_size.fetch_add(bytes_written, Ordering::Relaxed);
        Ok(written_count)
    }

    /// Rotate log files
    async fn rotate_log_file(log_file: &PathBuf, max_files: u32) -> SecurityResult<()> {
        // Move existing files
        for i in (1..max_files).rev() {
            let old_file = log_file.with_extension(format!("log.{}", i));
            let new_file = log_file.with_extension(format!("log.{}", i + 1));
            
            if old_file.exists() {
                tokio::fs::rename(&old_file, &new_file).await
                    .map_err(|e| SecurityError::audit_failed(format!("Failed to rotate log file: {}", e)))?;
            }
        }

        // Move current log file
        if log_file.exists() {
            let rotated_file = log_file.with_extension("log.1");
            tokio::fs::rename(log_file, &rotated_file).await
                .map_err(|e| SecurityError::audit_failed(format!("Failed to rotate current log file: {}", e)))?;
        }

        Ok(())
    }

    /// Shutdown the audit logger
    pub async fn shutdown(&self) -> SecurityResult<()> {
        self.shutdown.store(true, Ordering::Relaxed);
        
        // Give background task time to flush
        tokio::time::sleep(std::time::Duration::from_millis(self.config.flush_interval_ms * 2)).await;
        
        Ok(())
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> SecurityResult<AuditStats> {
        Ok(self.stats.snapshot())
    }
}

/// Audit logging statistics
#[derive(Debug)]
pub struct AuditStats {
    pub events_queued: AtomicU64,
    pub events_written: AtomicU64,
    pub queue_overflows: AtomicU64,
    pub write_errors: AtomicU64,
    pub created_at: AtomicU64,
}

impl AuditStats {
    pub fn new() -> Self {
        Self {
            events_queued: AtomicU64::new(0),
            events_written: AtomicU64::new(0),
            queue_overflows: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
            created_at: AtomicU64::new(current_timestamp_ms()),
        }
    }

    pub fn snapshot(&self) -> Self {
        Self {
            events_queued: AtomicU64::new(self.events_queued.load(Ordering::Relaxed)),
            events_written: AtomicU64::new(self.events_written.load(Ordering::Relaxed)),
            queue_overflows: AtomicU64::new(self.queue_overflows.load(Ordering::Relaxed)),
            write_errors: AtomicU64::new(self.write_errors.load(Ordering::Relaxed)),
            created_at: AtomicU64::new(self.created_at.load(Ordering::Relaxed)),
        }
    }

    /// Calculate write success rate
    pub fn write_success_rate(&self) -> f64 {
        let queued = self.events_queued.load(Ordering::Relaxed);
        let written = self.events_written.load(Ordering::Relaxed);
        
        if queued == 0 {
            0.0
        } else {
            written as f64 / queued as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_audit_event_creation() {
        let event = AuditEvent::new(
            AuditEventType::AccessBlocked,
            "test_actor".to_string(),
            "Test message".to_string(),
        ).with_source_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        assert_eq!(event.event_type.as_str(), "ACCESS_BLOCKED");
        assert_eq!(event.actor, "test_actor");
        assert_eq!(event.message, "Test message");
        assert!(event.source_ip.is_some());
    }

    #[tokio::test]
    async fn test_audit_event_formatting() {
        let event = AuditEvent::new(
            AuditEventType::AdminAction,
            "admin".to_string(),
            "Configuration updated".to_string(),
        );

        let json = event.to_json().unwrap();
        assert!(json.contains("ADMIN_ACTION"));
        assert!(json.contains("admin"));
        assert!(json.contains("Configuration updated"));

        let text = event.to_text();
        assert!(text.contains("ADMIN_ACTION"));
        assert!(text.contains("admin"));
        assert!(text.contains("Configuration updated"));
    }

    #[tokio::test]
    async fn test_audit_logger_basic() {
        let temp_dir = tempdir().unwrap();
        let log_file = temp_dir.path().join("audit.log");
        
        let config = AuditConfig {
            enabled: true,
            log_file: Some(log_file.clone()),
            flush_interval_ms: 100, // Fast flush for testing
            ..Default::default()
        };

        let logger = AuditLogger::new(config).unwrap();

        // Log an event
        logger.log_admin_action("test", "create_zone", "Created test zone").await.unwrap();

        // Wait for flush
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Check that file was created and contains the event
        assert!(log_file.exists());
        
        let content = tokio::fs::read_to_string(&log_file).await.unwrap();
        assert!(content.contains("ADMIN_ACTION"));
        assert!(content.contains("create_zone"));

        logger.shutdown().await.unwrap();
    }
}