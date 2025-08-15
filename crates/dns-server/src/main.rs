//! Planet Scale DNS Server
//!
//! A high-performance, planet-scale DNS server implementation in Rust
//! with zero-copy operations, atomic data structures, and unlimited clustering.

use dns_server::{Config, DnsServer};
use std::process;
use tracing::{error, info};
use tracing_subscriber;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into())
        )
        .init();

    info!("Starting Planet Scale DNS Server");

    // Load configuration
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            process::exit(1);
        }
    };

    // Create and start the DNS server
    let server = match DnsServer::new(config).await {
        Ok(server) => server,
        Err(e) => {
            error!("Failed to create DNS server: {}", e);
            process::exit(1);
        }
    };

    // Run the server
    if let Err(e) = server.run().await {
        error!("DNS server error: {}", e);
        process::exit(1);
    }
}