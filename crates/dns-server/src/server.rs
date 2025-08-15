//! Main DNS server implementation

use crate::Config;
use dns_core::DnsResult;
use tokio::signal;
use tracing::{info, warn};

/// Main DNS server
pub struct DnsServer {
    config: Config,
}

impl DnsServer {
    /// Create a new DNS server with the given configuration
    pub async fn new(config: Config) -> DnsResult<Self> {
        info!("Initializing DNS server with config: {:?}", config);
        
        Ok(Self {
            config,
        })
    }
    
    /// Run the DNS server
    pub async fn run(self) -> DnsResult<()> {
        info!("Starting DNS server on {}:{}", self.config.server.bind_address, self.config.server.port);
        
        // TODO: Initialize all components
        // - Protocol handlers
        // - Storage engine
        // - Cache
        // - Cluster manager
        // - API server
        
        info!("DNS server started successfully");
        
        // Wait for shutdown signal
        match signal::ctrl_c().await {
            Ok(()) => {
                info!("Received shutdown signal, stopping DNS server");
            }
            Err(err) => {
                warn!("Unable to listen for shutdown signal: {}", err);
            }
        }
        
        info!("DNS server stopped");
        Ok(())
    }
}