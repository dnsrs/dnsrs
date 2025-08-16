//! Comprehensive error handling for the Planet Scale DNS Server
//!
//! This module defines all error types used throughout the DNS server,
//! following Rust best practices for error handling.

use thiserror::Error;

/// Main result type used throughout the DNS server
pub type DnsResult<T> = Result<T, DnsError>;

/// Comprehensive DNS server error types
#[derive(Error, Debug, Clone)]
pub enum DnsError {
    // Protocol errors
    #[error("Invalid DNS packet: {message}")]
    InvalidPacket { message: String },
    
    #[error("Malformed DNS query: {message}")]
    MalformedQuery { message: String },
    
    #[error("Unsupported DNS record type: {record_type}")]
    UnsupportedRecordType { record_type: u16 },
    
    #[error("DNS packet too large: {size} bytes (max: {max_size})")]
    PacketTooLarge { size: usize, max_size: usize },
    
    #[error("Invalid DNS name: {name}")]
    InvalidDnsName { name: String },
    
    // Storage errors
    #[error("Zone not found: {zone_name}")]
    ZoneNotFound { zone_name: String },
    
    #[error("Record not found: {name} {record_type}")]
    RecordNotFound { name: String, record_type: u16 },
    
    #[error("Storage corruption detected: {message}")]
    StorageCorruption { message: String },
    
    #[error("Disk I/O error: {message}")]
    DiskIoError { message: String },
    
    #[error("Memory mapping failed: {message}")]
    MemoryMappingError { message: String },
    
    #[error("Zone version conflict: expected {expected}, got {actual}")]
    VersionConflict { expected: u64, actual: u64 },
    
    // Cache errors
    #[error("Cache miss for key: {key}")]
    CacheMiss { key: String },
    
    #[error("Cache full: cannot store more entries")]
    CacheFull,
    
    #[error("Cache corruption: {message}")]
    CacheCorruption { message: String },
    
    // Network errors
    #[error("Network I/O error: {message}")]
    NetworkError { message: String },
    
    #[error("Connection timeout: {timeout_ms}ms")]
    ConnectionTimeout { timeout_ms: u64 },
    
    #[error("TLS handshake failed: {message}")]
    TlsError { message: String },
    
    #[error("HTTP/2 protocol error: {message}")]
    Http2Error { message: String },
    
    // Cluster errors
    #[error("Node not found: {node_id}")]
    NodeNotFound { node_id: u64 },
    
    #[error("Cluster split-brain detected")]
    SplitBrain,
    
    #[error("Replication failed: {message}")]
    ReplicationError { message: String },
    
    #[error("Consensus timeout: {timeout_ms}ms")]
    ConsensusTimeout { timeout_ms: u64 },
    
    #[error("Zone transfer failed: {message}")]
    ZoneTransferError { message: String },
    
    // Security errors
    #[error("Rate limit exceeded for client: {client_ip}")]
    RateLimitExceeded { client_ip: String },
    
    #[error("Authentication failed: {message}")]
    AuthenticationFailed { message: String },
    
    #[error("Authorization denied: {message}")]
    AuthorizationDenied { message: String },
    
    #[error("DNSSEC validation failed: {message}")]
    DnssecValidationFailed { message: String },
    
    #[error("Cryptographic error: {message}")]
    CryptographicError { message: String },
    
    // Configuration errors
    #[error("Invalid configuration: {message}")]
    InvalidConfiguration { message: String },
    
    #[error("Configuration file not found: {path}")]
    ConfigurationNotFound { path: String },
    
    #[error("Configuration parse error: {message}")]
    ConfigurationParseError { message: String },
    
    // API errors
    #[error("Invalid API request: {message}")]
    InvalidApiRequest { message: String },
    
    #[error("API endpoint not found: {endpoint}")]
    ApiEndpointNotFound { endpoint: String },
    
    #[error("JSON serialization error: {message}")]
    JsonError { message: String },
    
    // Resource errors
    #[error("Out of memory: requested {requested} bytes")]
    OutOfMemory { requested: usize },
    
    #[error("Resource exhausted: {resource}")]
    ResourceExhausted { resource: String },
    
    #[error("Thread pool exhausted")]
    ThreadPoolExhausted,
    
    // FlatBuffers errors
    #[error("FlatBuffers serialization error: {message}")]
    FlatBuffersError { message: String },
    
    #[error("Invalid FlatBuffers data: {message}")]
    InvalidFlatBuffersData { message: String },
    
    // Atomic operation errors
    #[error("Atomic operation failed: {operation}")]
    AtomicOperationFailed { operation: String },
    
    #[error("Lock-free operation timeout: {timeout_ms}ms")]
    LockFreeTimeout { timeout_ms: u64 },
    
    // Generic errors
    #[error("Internal server error: {message}")]
    InternalError { message: String },
    
    #[error("Operation timeout: {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },
    
    #[error("Feature not implemented: {feature}")]
    NotImplemented { feature: String },
    
    #[error("Invalid state: {message}")]
    InvalidState { message: String },
    
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },
    
    #[error("Serialization error: {message}")]
    SerializationError { message: String },
    
    #[error("Zone already exists: {zone_name}")]
    ZoneAlreadyExists { zone_name: String },
    
    #[error("Concurrency error: {message}")]
    ConcurrencyError { message: String },
    
    #[error("Storage error: {message}")]
    StorageError { message: String },
}

impl DnsError {
    /// Create a new invalid packet error
    pub fn invalid_packet(message: impl Into<String>) -> Self {
        Self::InvalidPacket { message: message.into() }
    }
    
    /// Create a new malformed query error
    pub fn malformed_query(message: impl Into<String>) -> Self {
        Self::MalformedQuery { message: message.into() }
    }
    
    /// Create a new zone not found error
    pub fn zone_not_found(zone_name: impl Into<String>) -> Self {
        Self::ZoneNotFound { zone_name: zone_name.into() }
    }
    
    /// Create a new record not found error
    pub fn record_not_found(name: impl Into<String>, record_type: u16) -> Self {
        Self::RecordNotFound { 
            name: name.into(), 
            record_type 
        }
    }
    
    /// Create a new network error
    pub fn network_error(message: impl Into<String>) -> Self {
        Self::NetworkError { message: message.into() }
    }
    
    /// Create a new internal error
    pub fn internal_error(message: impl Into<String>) -> Self {
        Self::InternalError { message: message.into() }
    }
    
    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            // Temporary network issues
            Self::NetworkError { .. } |
            Self::ConnectionTimeout { .. } |
            Self::Timeout { .. } => true,
            
            // Resource exhaustion (might recover)
            Self::CacheFull |
            Self::ThreadPoolExhausted |
            Self::ResourceExhausted { .. } => true,
            
            // Rate limiting (recovers over time)
            Self::RateLimitExceeded { .. } => true,
            
            // Cluster issues (might recover)
            Self::ReplicationError { .. } |
            Self::ConsensusTimeout { .. } |
            Self::ZoneTransferError { .. } => true,
            
            // Lock-free timeouts (might succeed on retry)
            Self::LockFreeTimeout { .. } |
            Self::AtomicOperationFailed { .. } => true,
            
            // Everything else is likely permanent
            _ => false,
        }
    }
    
    /// Get the error category for metrics
    pub fn category(&self) -> &'static str {
        match self {
            Self::InvalidPacket { .. } |
            Self::MalformedQuery { .. } |
            Self::UnsupportedRecordType { .. } |
            Self::PacketTooLarge { .. } |
            Self::InvalidDnsName { .. } => "protocol",
            
            Self::ZoneNotFound { .. } |
            Self::RecordNotFound { .. } |
            Self::StorageCorruption { .. } |
            Self::DiskIoError { .. } |
            Self::MemoryMappingError { .. } |
            Self::VersionConflict { .. } => "storage",
            
            Self::CacheMiss { .. } |
            Self::CacheFull |
            Self::CacheCorruption { .. } => "cache",
            
            Self::NetworkError { .. } |
            Self::ConnectionTimeout { .. } |
            Self::TlsError { .. } |
            Self::Http2Error { .. } => "network",
            
            Self::NodeNotFound { .. } |
            Self::SplitBrain |
            Self::ReplicationError { .. } |
            Self::ConsensusTimeout { .. } |
            Self::ZoneTransferError { .. } => "cluster",
            
            Self::RateLimitExceeded { .. } |
            Self::AuthenticationFailed { .. } |
            Self::AuthorizationDenied { .. } |
            Self::DnssecValidationFailed { .. } |
            Self::CryptographicError { .. } => "security",
            
            Self::InvalidConfiguration { .. } |
            Self::ConfigurationNotFound { .. } |
            Self::ConfigurationParseError { .. } => "configuration",
            
            Self::InvalidApiRequest { .. } |
            Self::ApiEndpointNotFound { .. } |
            Self::JsonError { .. } => "api",
            
            Self::OutOfMemory { .. } |
            Self::ResourceExhausted { .. } |
            Self::ThreadPoolExhausted => "resource",
            
            Self::FlatBuffersError { .. } |
            Self::InvalidFlatBuffersData { .. } => "serialization",
            
            Self::AtomicOperationFailed { .. } |
            Self::LockFreeTimeout { .. } => "atomic",
            
            Self::InternalError { .. } |
            Self::Timeout { .. } |
            Self::NotImplemented { .. } |
            Self::InvalidState { .. } => "internal",
            
            Self::InvalidInput { .. } => "input",
            Self::SerializationError { .. } => "serialization",
            Self::ZoneAlreadyExists { .. } => "storage",
            Self::ConcurrencyError { .. } => "concurrency",
            Self::StorageError { .. } => "storage",
        }
    }
}

/// Convert from std::io::Error
impl From<std::io::Error> for DnsError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::TimedOut => Self::Timeout { timeout_ms: 5000 },
            std::io::ErrorKind::ConnectionRefused |
            std::io::ErrorKind::ConnectionAborted |
            std::io::ErrorKind::ConnectionReset => {
                Self::NetworkError { message: err.to_string() }
            }
            std::io::ErrorKind::OutOfMemory => {
                Self::OutOfMemory { requested: 0 }
            }
            _ => Self::DiskIoError { message: err.to_string() }
        }
    }
}

/// Convert from serde_json::Error (when serde feature is enabled)
#[cfg(feature = "serde")]
impl From<serde_json::Error> for DnsError {
    fn from(err: serde_json::Error) -> Self {
        Self::JsonError { message: err.to_string() }
    }
}

/// Result extension trait for DNS operations
pub trait DnsResultExt<T> {
    /// Convert to internal error with context
    fn with_context(self, context: &str) -> DnsResult<T>;
    
    /// Log error and continue with default value
    fn log_and_default(self, default: T) -> T;
    
    /// Retry operation on recoverable errors
    fn retry_on_recoverable<F>(self, retry_fn: F) -> DnsResult<T>
    where
        F: FnOnce() -> DnsResult<T>;
}

impl<T> DnsResultExt<T> for DnsResult<T> {
    fn with_context(self, context: &str) -> DnsResult<T> {
        self.map_err(|err| {
            DnsError::InternalError {
                message: format!("{}: {}", context, err)
            }
        })
    }
    
    fn log_and_default(self, default: T) -> T {
        match self {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!("Operation failed, using default: {}", err);
                default
            }
        }
    }
    
    fn retry_on_recoverable<F>(self, retry_fn: F) -> DnsResult<T>
    where
        F: FnOnce() -> DnsResult<T>
    {
        match self {
            Ok(value) => Ok(value),
            Err(err) if err.is_recoverable() => {
                tracing::debug!("Retrying recoverable error: {}", err);
                retry_fn()
            }
            Err(err) => Err(err),
        }
    }
}