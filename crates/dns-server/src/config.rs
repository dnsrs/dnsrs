//! Configuration management

use dns_core::DnsResult;
use serde::{Deserialize, Serialize};

/// Main server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub cluster: ClusterConfig,
    pub api: ApiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind_address: String,
    pub port: u16,
    pub max_connections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub data_dir: String,
    pub cache_size_mb: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub enabled: bool,
    pub node_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
}

impl Config {
    /// Load configuration from file or environment
    pub fn load() -> DnsResult<Self> {
        // For now, return a default configuration
        Ok(Self::default())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                bind_address: "0.0.0.0".to_string(),
                port: 53,
                max_connections: 10000,
            },
            storage: StorageConfig {
                data_dir: "./data".to_string(),
                cache_size_mb: 1024,
            },
            cluster: ClusterConfig {
                enabled: false,
                node_id: None,
            },
            api: ApiConfig {
                enabled: true,
                bind_address: "127.0.0.1".to_string(),
                port: 8080,
            },
        }
    }
}