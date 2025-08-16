//! Comprehensive monitoring and observability for the Planet Scale DNS Server
//!
//! This crate provides:
//! - Prometheus metrics collection with atomic counters
//! - Health check endpoints for Kubernetes readiness/liveness probes
//! - Distributed tracing integration using OpenTelemetry
//! - Structured logging with configurable levels
//! - Performance profiling and flame graph generation
//! - Real-time query analytics and dashboard data

pub mod prometheus;
pub mod health;
pub mod tracing;
pub mod logging;
pub mod profiling;
pub mod analytics;
pub mod server;
pub mod config;
pub mod alerts;

pub use prometheus::PrometheusExporter;
pub use health::{HealthChecker, HealthStatus};
pub use tracing::TracingManager;
pub use logging::StructuredLogger;
pub use profiling::ProfileManager;
pub use analytics::QueryAnalytics;
pub use server::MonitoringServer;
pub use config::MonitoringConfig;
pub use alerts::AlertManager;

use dns_core::DnsResult;
use std::sync::Arc;

/// Main monitoring system that coordinates all observability features
pub struct MonitoringSystem {
    prometheus: Arc<PrometheusExporter>,
    health: Arc<HealthChecker>,
    tracing: Arc<TracingManager>,
    logger: Arc<StructuredLogger>,
    profiler: Arc<ProfileManager>,
    analytics: Arc<QueryAnalytics>,
    alerts: Arc<AlertManager>,
    server: Arc<MonitoringServer>,
}

impl MonitoringSystem {
    /// Create a new monitoring system with the given configuration
    pub async fn new(config: MonitoringConfig) -> DnsResult<Self> {
        let prometheus = Arc::new(PrometheusExporter::new(config.prometheus.clone())?);
        let health = Arc::new(HealthChecker::new(config.health.clone()));
        let tracing = Arc::new(TracingManager::new(config.tracing.clone()).await?);
        let logger = Arc::new(StructuredLogger::new(config.logging.clone())?);
        let profiler = Arc::new(ProfileManager::new(config.profiling.clone())?);
        let analytics = Arc::new(QueryAnalytics::new(config.analytics.clone())?);
        let alerts = Arc::new(AlertManager::new(config.alerts.clone())?);
        
        let server = Arc::new(MonitoringServer::new(
            config.server.clone(),
            prometheus.clone(),
            health.clone(),
            profiler.clone(),
            analytics.clone(),
        )?);
        
        Ok(Self {
            prometheus,
            health,
            tracing,
            logger,
            profiler,
            analytics,
            alerts,
            server,
        })
    }
    
    /// Start the monitoring system
    pub async fn start(&self) -> DnsResult<()> {
        // Initialize tracing
        self.tracing.initialize().await?;
        
        // Initialize logger
        self.logger.initialize()?;
        
        // Start profiler if enabled
        if self.profiler.is_enabled() {
            self.profiler.start().await?;
        }
        
        // Start analytics collection
        self.analytics.start().await?;
        
        // Start alert manager
        self.alerts.start().await?;
        
        // Start monitoring server
        self.server.start().await?;
        
        tracing::info!("Monitoring system started successfully");
        Ok(())
    }
    
    /// Stop the monitoring system
    pub async fn stop(&self) -> DnsResult<()> {
        // Stop server
        self.server.stop().await?;
        
        // Stop alert manager
        self.alerts.stop().await?;
        
        // Stop analytics
        self.analytics.stop().await?;
        
        // Stop profiler
        if self.profiler.is_enabled() {
            self.profiler.stop().await?;
        }
        
        // Shutdown tracing
        self.tracing.shutdown().await?;
        
        tracing::info!("Monitoring system stopped");
        Ok(())
    }
    
    /// Get Prometheus exporter
    pub fn prometheus(&self) -> &Arc<PrometheusExporter> {
        &self.prometheus
    }
    
    /// Get health checker
    pub fn health(&self) -> &Arc<HealthChecker> {
        &self.health
    }
    
    /// Get tracing manager
    pub fn tracing(&self) -> &Arc<TracingManager> {
        &self.tracing
    }
    
    /// Get structured logger
    pub fn logger(&self) -> &Arc<StructuredLogger> {
        &self.logger
    }
    
    /// Get profile manager
    pub fn profiler(&self) -> &Arc<ProfileManager> {
        &self.profiler
    }
    
    /// Get query analytics
    pub fn analytics(&self) -> &Arc<QueryAnalytics> {
        &self.analytics
    }
    
    /// Get alert manager
    pub fn alerts(&self) -> &Arc<AlertManager> {
        &self.alerts
    }
}