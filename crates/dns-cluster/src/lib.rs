//! Planet-scale clustering and replication
//!
//! This crate implements the clustering functionality for distributed
//! DNS operations across unlimited nodes using atomic operations and
//! zero-copy data structures for maximum performance.

use std::sync::atomic::{AtomicU64, AtomicU32, AtomicUsize, AtomicBool, Ordering};
use std::sync::Arc;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use bytes::Bytes;
use thiserror::Error;

pub mod discovery;
pub mod hash_ring;
pub mod replication;
pub mod consensus;
pub mod health;
pub mod network;
pub mod manager;

pub use discovery::*;
pub use hash_ring::*;
pub use replication::*;
pub use consensus::*;
pub use health::*;
pub use network::*;
pub use manager::*;

/// Errors that can occur during cluster operations
#[derive(Error, Debug)]
pub enum ClusterError {
    #[error("Node not found: {node_id}")]
    NodeNotFound { node_id: u64 },
    
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Replication failed for zone {zone_hash}")]
    ReplicationFailed { zone_hash: u64 },
    
    #[error("Health check failed for node {node_id}")]
    HealthCheckFailed { node_id: u64 },
    
    #[error("Cluster state inconsistent")]
    InconsistentState,
    
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("Timeout occurred")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, ClusterError>;

/// Node information for cluster membership
#[derive(Debug)]
pub struct NodeInfo {
    pub node_id: u64,
    pub address: SocketAddr,
    pub region: String,
    pub datacenter: String,
    pub capabilities: NodeCapabilities,
    pub metadata: NodeMetadata,
}

impl Clone for NodeInfo {
    fn clone(&self) -> Self {
        Self {
            node_id: self.node_id,
            address: self.address,
            region: self.region.clone(),
            datacenter: self.datacenter.clone(),
            capabilities: self.capabilities.clone(),
            metadata: NodeMetadata::new(self.metadata.version.clone()),
        }
    }
}

/// Node capabilities and features
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCapabilities {
    pub supports_zone_transfer: bool,
    pub supports_replication: bool,
    pub supports_health_checks: bool,
    pub max_zones: u32,
    pub max_connections: u32,
}

/// Node metadata for monitoring and management
#[derive(Debug)]
pub struct NodeMetadata {
    pub version: String,
    pub started_at: u64,
    pub last_seen: AtomicU64,
    pub load_factor: AtomicU64, // Fixed-point percentage (0-10000 = 0-100%)
    pub zone_count: AtomicU32,
    pub connection_count: AtomicU32,
    pub is_healthy: AtomicBool,
}

impl NodeMetadata {
    pub fn new(version: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Self {
            version,
            started_at: now,
            last_seen: AtomicU64::new(now),
            load_factor: AtomicU64::new(0),
            zone_count: AtomicU32::new(0),
            connection_count: AtomicU32::new(0),
            is_healthy: AtomicBool::new(true),
        }
    }
    
    pub fn update_last_seen(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_seen.store(now, Ordering::Relaxed);
    }
    
    pub fn set_load_factor(&self, load_percent: f32) {
        let load_fixed = (load_percent * 100.0) as u64;
        self.load_factor.store(load_fixed, Ordering::Relaxed);
    }
    
    pub fn get_load_factor(&self) -> f32 {
        self.load_factor.load(Ordering::Relaxed) as f32 / 100.0
    }
}

/// Authentication token for cluster operations
#[derive(Debug, Clone)]
pub struct AuthToken {
    pub token: String,
    pub expires_at: u64,
    pub permissions: Vec<String>,
}

impl AuthToken {
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now < self.expires_at
    }
}

/// Zone synchronization request for modern zone transfers
#[derive(Debug, Clone)]
pub struct ZoneSyncRequest {
    pub zone_hash: u64,
    pub last_known_version: u64,
    pub compression: CompressionType,
    pub auth_token: AuthToken,
}

/// Zone synchronization response
#[derive(Debug, Clone)]
pub struct ZoneSyncResponse {
    pub zone_data: Bytes,
    pub version: u64,
    pub delta: bool,
    pub compression: CompressionType,
}

/// Compression types for zone transfers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionType {
    None,
    Lz4,
    Zstd,
}

/// Zone transfer header for network protocol
#[derive(Debug, Clone)]
pub struct ZoneTransferHeader {
    pub zone_hash: u64,
    pub data_size: u64,
    pub compression: CompressionType,
    pub version: u64,
}

impl ZoneTransferHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        // Simple binary serialization for header
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&self.zone_hash.to_be_bytes());
        bytes.extend_from_slice(&self.data_size.to_be_bytes());
        bytes.push(self.compression as u8);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes
    }
    
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 25 {
            return None;
        }
        
        let zone_hash = u64::from_be_bytes(bytes[0..8].try_into().ok()?);
        let data_size = u64::from_be_bytes(bytes[8..16].try_into().ok()?);
        let compression = match bytes[16] {
            0 => CompressionType::None,
            1 => CompressionType::Lz4,
            2 => CompressionType::Zstd,
            _ => return None,
        };
        let version = u64::from_be_bytes(bytes[17..25].try_into().ok()?);
        
        Some(Self {
            zone_hash,
            data_size,
            compression,
            version,
        })
    }
}