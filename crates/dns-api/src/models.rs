//! API data models and DTOs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

/// DNS record types
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    PTR,
    SOA,
    TXT,
    SRV,
    CAA,
    HTTPS,
    SVCB,
    TLSA,
    SMIMEA,
    DNSKEY,
    DS,
    RRSIG,
    NSEC,
    NSEC3,
}

/// DNS record data
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", content = "data")]
pub enum RecordData {
    A { address: String },
    AAAA { address: String },
    CNAME { target: String },
    MX { priority: u16, exchange: String },
    NS { nameserver: String },
    PTR { target: String },
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    TXT { text: Vec<String> },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    CAA {
        flags: u8,
        tag: String,
        value: String,
    },
}

/// DNS record
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DnsRecord {
    /// Record ID
    pub id: Uuid,
    /// Domain name
    pub name: String,
    /// Record type
    #[serde(rename = "type")]
    pub record_type: RecordType,
    /// Record data
    pub data: RecordData,
    /// TTL in seconds
    pub ttl: u32,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

/// Create DNS record request
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Validate)]
pub struct CreateRecordRequest {
    /// Domain name
    #[validate(length(min = 1, max = 253))]
    pub name: String,
    /// Record type
    #[serde(rename = "type")]
    pub record_type: RecordType,
    /// Record data
    pub data: RecordData,
    /// TTL in seconds (default: 300)
    #[validate(range(min = 1, max = 86400))]
    pub ttl: Option<u32>,
}

/// Update DNS record request
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Validate)]
pub struct UpdateRecordRequest {
    /// Record data (optional)
    pub data: Option<RecordData>,
    /// TTL in seconds (optional)
    #[validate(range(min = 1, max = 86400))]
    pub ttl: Option<u32>,
}

/// DNS zone
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DnsZone {
    /// Zone ID
    pub id: Uuid,
    /// Zone name
    pub name: String,
    /// Zone serial number
    pub serial: u32,
    /// Number of records
    pub record_count: u32,
    /// Zone size in bytes
    pub size: u64,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Zone status
    pub status: ZoneStatus,
}

/// Zone status
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ZoneStatus {
    Active,
    Inactive,
    Loading,
    Error,
}

/// Create zone request
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Validate)]
pub struct CreateZoneRequest {
    /// Zone name
    #[validate(length(min = 1, max = 253))]
    pub name: String,
    /// Initial SOA record
    pub soa: SoaData,
}

/// SOA record data
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Validate)]
pub struct SoaData {
    /// Primary nameserver
    #[validate(length(min = 1, max = 253))]
    pub mname: String,
    /// Responsible person email
    #[validate(length(min = 1, max = 253))]
    pub rname: String,
    /// Refresh interval
    #[validate(range(min = 1))]
    pub refresh: u32,
    /// Retry interval
    #[validate(range(min = 1))]
    pub retry: u32,
    /// Expire time
    #[validate(range(min = 1))]
    pub expire: u32,
    /// Minimum TTL
    #[validate(range(min = 1))]
    pub minimum: u32,
}

/// Blocklist entry
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlocklistEntry {
    /// Entry ID
    pub id: Uuid,
    /// Domain pattern
    pub domain: String,
    /// Block type
    pub block_type: BlockType,
    /// Custom response (for redirect blocks)
    pub custom_response: Option<String>,
    /// Entry source
    pub source: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Whether entry is active
    pub active: bool,
}

/// Block type
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum BlockType {
    /// Return NXDOMAIN
    Nxdomain,
    /// Redirect to localhost
    Localhost,
    /// Redirect to custom IP
    Redirect,
}

/// Create blocklist entry request
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Validate)]
pub struct CreateBlocklistRequest {
    /// Domain pattern
    #[validate(length(min = 1, max = 253))]
    pub domain: String,
    /// Block type
    pub block_type: BlockType,
    /// Custom response (required for redirect blocks)
    pub custom_response: Option<String>,
    /// Entry source
    pub source: Option<String>,
}

/// Update blocklist entry request
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateBlocklistRequest {
    /// Block type (optional)
    pub block_type: Option<BlockType>,
    /// Custom response (optional)
    pub custom_response: Option<String>,
    /// Whether entry is active (optional)
    pub active: Option<bool>,
}

/// Cluster node information
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClusterNode {
    /// Node ID
    pub id: String,
    /// Node address
    pub address: String,
    /// Node port
    pub port: u16,
    /// Node status
    pub status: NodeStatus,
    /// Node role
    pub role: NodeRole,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// Node version
    pub version: String,
    /// Node metrics
    pub metrics: NodeMetrics,
}

/// Node status
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    Healthy,
    Unhealthy,
    Unknown,
    Joining,
    Leaving,
}

/// Node role
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    Primary,
    Secondary,
    Observer,
}

/// Node metrics
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NodeMetrics {
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Memory usage in bytes
    pub memory_usage: u64,
    /// Queries per second
    pub queries_per_second: f64,
    /// Cache hit ratio
    pub cache_hit_ratio: f64,
    /// Active connections
    pub active_connections: u32,
}

/// Server statistics
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ServerStats {
    /// Total queries processed
    pub total_queries: u64,
    /// Queries per second (current)
    pub queries_per_second: f64,
    /// Cache hit ratio
    pub cache_hit_ratio: f64,
    /// Cache miss ratio
    pub cache_miss_ratio: f64,
    /// Blocked queries
    pub blocked_queries: u64,
    /// NXDOMAIN responses
    pub nxdomain_responses: u64,
    /// Active zones
    pub active_zones: u32,
    /// Total records
    pub total_records: u64,
    /// Memory usage
    pub memory_usage: MemoryStats,
    /// Uptime in seconds
    pub uptime: u64,
}

/// Memory statistics
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MemoryStats {
    /// Total memory usage in bytes
    pub total: u64,
    /// Cache memory usage in bytes
    pub cache: u64,
    /// Zone data memory usage in bytes
    pub zones: u64,
    /// Blocklist memory usage in bytes
    pub blocklist: u64,
}

/// API response wrapper
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiResponse<T> {
    /// Response data
    pub data: T,
    /// Request ID
    pub request_id: String,
    /// Response timestamp
    pub timestamp: DateTime<Utc>,
}

/// Paginated response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PaginatedResponse<T> {
    /// Response data
    pub data: Vec<T>,
    /// Pagination metadata
    pub pagination: PaginationMeta,
    /// Request ID
    pub request_id: String,
    /// Response timestamp
    pub timestamp: DateTime<Utc>,
}

/// Pagination metadata
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PaginationMeta {
    /// Current page number
    pub page: u32,
    /// Items per page
    pub per_page: u32,
    /// Total items
    pub total: u64,
    /// Total pages
    pub total_pages: u32,
    /// Has next page
    pub has_next: bool,
    /// Has previous page
    pub has_prev: bool,
}

/// Query parameters for pagination
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PaginationQuery {
    /// Page number (default: 1)
    pub page: Option<u32>,
    /// Items per page (default: 20, max: 100)
    pub per_page: Option<u32>,
}

/// Authentication request
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Validate)]
pub struct AuthRequest {
    /// API key or username
    #[validate(length(min = 1))]
    pub key: String,
    /// Password (for username/password auth)
    pub password: Option<String>,
}

/// Authentication response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthResponse {
    /// JWT token
    pub token: String,
    /// Token expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Refresh token
    pub refresh_token: String,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HealthResponse {
    /// Service status
    pub status: String,
    /// Service version
    pub version: String,
    /// Uptime in seconds
    pub uptime: u64,
    /// Component health checks
    pub checks: HashMap<String, ComponentHealth>,
}

/// Component health status
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ComponentHealth {
    /// Component status
    pub status: String,
    /// Optional error message
    pub error: Option<String>,
    /// Last check timestamp
    pub last_check: DateTime<Utc>,
}