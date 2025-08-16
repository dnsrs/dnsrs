//! REST API server for DNS management
//!
//! This crate provides a comprehensive HTTP API for managing DNS zones, records,
//! blocklist entries, cluster nodes, and server configuration. It includes:
//!
//! - Zone and record management (CRUD operations)
//! - Blocklist management with atomic updates
//! - Cluster node management and monitoring
//! - Real-time metrics and statistics
//! - JWT and API key authentication
//! - OpenAPI/Swagger documentation
//! - Prometheus metrics exposition

pub mod auth;
pub mod error;
pub mod handlers;
pub mod metrics;
pub mod models;
pub mod routes;

use axum::Router;

pub use auth::*;
pub use error::*;
pub use handlers::*;
pub use metrics::*;
pub use models::*;
pub use routes::*;

/// API server configuration
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Server bind address
    pub bind_address: String,
    /// Server port
    pub port: u16,
    /// JWT secret for token signing
    pub jwt_secret: String,
    /// JWT issuer
    pub jwt_issuer: String,
    /// JWT audience
    pub jwt_audience: String,
    /// Enable Swagger UI
    pub enable_swagger: bool,
    /// Enable metrics endpoint
    pub enable_metrics: bool,
    /// Enable CORS
    pub enable_cors: bool,
    /// Request timeout in seconds
    pub request_timeout: u64,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0".to_string(),
            port: 8080,
            jwt_secret: "your-secret-key".to_string(),
            jwt_issuer: "dns-server".to_string(),
            jwt_audience: "dns-api".to_string(),
            enable_swagger: true,
            enable_metrics: true,
            enable_cors: true,
            request_timeout: 30,
        }
    }
}

/// API server instance
pub struct ApiServer {
    config: ApiConfig,
    state: AppState,
    auth_service: AuthService,
    metrics_state: MetricsState,
}

impl ApiServer {
    /// Create new API server
    pub fn new(config: ApiConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let state = AppState::new();
        let auth_service = AuthService::new(
            config.jwt_secret.clone(),
            config.jwt_issuer.clone(),
            config.jwt_audience.clone(),
        );
        let metrics_state = MetricsState::new()?;

        Ok(Self {
            config,
            state,
            auth_service,
            metrics_state,
        })
    }

    /// Start the API server
    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        let bind_addr = format!("{}:{}", self.config.bind_address, self.config.port);
        
        tracing::info!("Starting DNS API server on {}", bind_addr);
        
        // Create the main router
        let app = create_router(self.state.clone());
        
        // Create metrics router if enabled
        let final_app = if self.config.enable_metrics {
            let metrics_router = Router::new()
                .route("/metrics", axum::routing::get(metrics_handler))
                .with_state(self.metrics_state);
            
            app.merge(metrics_router)
        } else {
            app
        };
        
        // Create listener
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        
        tracing::info!("DNS API server listening on {}", bind_addr);
        tracing::info!("Swagger UI available at http://{}/docs", bind_addr);
        tracing::info!("OpenAPI spec available at http://{}/api-docs/openapi.json", bind_addr);
        
        if self.config.enable_metrics {
            tracing::info!("Metrics available at http://{}/metrics", bind_addr);
        }
        
        // Start server
        axum::serve(listener, final_app).await?;
        
        Ok(())
    }

    /// Get application state for testing
    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// Get authentication service
    pub fn auth_service(&self) -> &AuthService {
        &self.auth_service
    }

    /// Get metrics state
    pub fn metrics_state(&self) -> &MetricsState {
        &self.metrics_state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_config_default() {
        let config = ApiConfig::default();
        assert_eq!(config.bind_address, "0.0.0.0");
        assert_eq!(config.port, 8080);
        assert!(config.enable_swagger);
        assert!(config.enable_metrics);
        assert!(config.enable_cors);
    }

    #[test]
    fn test_api_server_creation() {
        let config = ApiConfig::default();
        let server = ApiServer::new(config);
        assert!(server.is_ok());
    }
}