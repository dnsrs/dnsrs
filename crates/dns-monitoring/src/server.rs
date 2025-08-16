//! HTTP server for monitoring endpoints
//!
//! Provides HTTP endpoints for metrics, health checks, profiling,
//! and analytics data with optional authentication.

use crate::{
    PrometheusExporter, HealthChecker, ProfileManager, QueryAnalytics,
};
use dns_core::{DnsResult, DnsError};
use hyper::{
    Body, Method, Request, Response, Server, StatusCode,
    header::{CONTENT_TYPE, AUTHORIZATION},
    service::{make_service_fn, service_fn},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Configuration for the monitoring server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Enable the monitoring server
    pub enabled: bool,
    /// Server host
    pub host: String,
    /// Server port
    pub port: u16,
    /// Enable authentication
    pub auth_enabled: bool,
    /// API keys for authentication
    pub api_keys: Vec<String>,
    /// Enable CORS
    pub cors_enabled: bool,
    /// Allowed CORS origins
    pub cors_origins: Vec<String>,
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
    /// Maximum request body size in bytes
    pub max_body_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            host: "0.0.0.0".to_string(),
            port: 8080,
            auth_enabled: false,
            api_keys: vec![],
            cors_enabled: true,
            cors_origins: vec!["*".to_string()],
            request_timeout_secs: 30,
            max_body_size: 1024 * 1024, // 1MB
        }
    }
}

/// Monitoring server implementation
pub struct MonitoringServer {
    config: ServerConfig,
    prometheus: Arc<PrometheusExporter>,
    health: Arc<HealthChecker>,
    profiler: Arc<ProfileManager>,
    analytics: Arc<QueryAnalytics>,
    server_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

/// Request context for handlers
#[derive(Clone)]
struct RequestContext {
    prometheus: Arc<PrometheusExporter>,
    health: Arc<HealthChecker>,
    profiler: Arc<ProfileManager>,
    analytics: Arc<QueryAnalytics>,
    config: ServerConfig,
}

impl MonitoringServer {
    /// Create a new monitoring server
    pub fn new(
        config: ServerConfig,
        prometheus: Arc<PrometheusExporter>,
        health: Arc<HealthChecker>,
        profiler: Arc<ProfileManager>,
        analytics: Arc<QueryAnalytics>,
    ) -> DnsResult<Self> {
        Ok(Self {
            config,
            prometheus,
            health,
            profiler,
            analytics,
            server_handle: Arc::new(RwLock::new(None)),
        })
    }
    
    /// Start the monitoring server
    pub async fn start(&self) -> DnsResult<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        let addr: SocketAddr = format!("{}:{}", self.config.host, self.config.port)
            .parse()
            .map_err(|e| DnsError::ConfigError(format!("Invalid server address: {}", e)))?;
        
        let context = RequestContext {
            prometheus: self.prometheus.clone(),
            health: self.health.clone(),
            profiler: self.profiler.clone(),
            analytics: self.analytics.clone(),
            config: self.config.clone(),
        };
        
        let make_svc = make_service_fn(move |_conn| {
            let context = context.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let context = context.clone();
                    async move { handle_request(req, context).await }
                }))
            }
        });
        
        let server = Server::bind(&addr).serve(make_svc);
        
        let handle = tokio::spawn(async move {
            if let Err(e) = server.await {
                tracing::error!(error = %e, "Monitoring server error");
            }
        });
        
        *self.server_handle.write().await = Some(handle);
        
        tracing::info!(
            host = %self.config.host,
            port = self.config.port,
            "Monitoring server started"
        );
        
        Ok(())
    }
    
    /// Stop the monitoring server
    pub async fn stop(&self) -> DnsResult<()> {
        if let Some(handle) = self.server_handle.write().await.take() {
            handle.abort();
            tracing::info!("Monitoring server stopped");
        }
        Ok(())
    }
}

/// Handle HTTP requests
async fn handle_request(
    req: Request<Body>,
    context: RequestContext,
) -> Result<Response<Body>, Infallible> {
    let response = match handle_request_inner(req, context).await {
        Ok(response) => response,
        Err(e) => {
            tracing::error!(error = %e, "Request handling error");
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::json!({
                    "error": "Internal server error",
                    "message": e.to_string()
                }).to_string()))
                .unwrap()
        }
    };
    
    Ok(response)
}

/// Inner request handler that can return errors
async fn handle_request_inner(
    req: Request<Body>,
    context: RequestContext,
) -> DnsResult<Response<Body>> {
    // Check authentication if enabled
    if context.config.auth_enabled {
        if let Err(response) = check_authentication(&req, &context.config) {
            return Ok(response);
        }
    }
    
    // Add CORS headers if enabled
    let mut response_builder = Response::builder();
    if context.config.cors_enabled {
        response_builder = add_cors_headers(response_builder, &context.config);
    }
    
    // Handle preflight requests
    if req.method() == Method::OPTIONS {
        return Ok(response_builder
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap());
    }
    
    // Route requests
    let path = req.uri().path();
    let method = req.method();
    
    match (method, path) {
        // Prometheus metrics
        (&Method::GET, "/metrics") => handle_metrics(context).await,
        
        // Health checks
        (&Method::GET, "/health") => handle_health(context).await,
        (&Method::GET, "/health/ready") => handle_readiness(context).await,
        (&Method::GET, "/health/live") => handle_liveness(context).await,
        
        // Profiling endpoints
        (&Method::POST, "/profile/cpu/start") => handle_start_cpu_profile(req, context).await,
        (&Method::POST, path) if path.starts_with("/profile/cpu/stop/") => {
            let profile_id = path.strip_prefix("/profile/cpu/stop/").unwrap();
            handle_stop_cpu_profile(profile_id, context).await
        }
        (&Method::GET, "/profile/list") => handle_list_profiles(context).await,
        (&Method::GET, "/profile/stats") => handle_profile_stats(context).await,
        
        // Analytics endpoints
        (&Method::GET, "/analytics/dashboard") => handle_dashboard_data(context).await,
        (&Method::GET, "/analytics/query-stats") => handle_query_stats(context).await,
        (&Method::GET, "/analytics/top-queries") => handle_top_queries(context).await,
        (&Method::GET, "/analytics/client-stats") => handle_client_stats(context).await,
        (&Method::GET, "/analytics/performance") => handle_performance_stats(context).await,
        (&Method::GET, "/analytics/timeseries") => handle_timeseries_data(req, context).await,
        
        // Server info
        (&Method::GET, "/info") => handle_server_info(context).await,
        
        // 404 for unknown paths
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::json!({
                "error": "Not found",
                "path": path,
                "method": method.as_str()
            }).to_string()))
            .unwrap()),
    }
}

/// Check API key authentication
fn check_authentication(req: &Request<Body>, config: &ServerConfig) -> Result<(), Response<Body>> {
    if config.api_keys.is_empty() {
        return Ok(()); // No API keys configured, allow all requests
    }
    
    let auth_header = req.headers().get(AUTHORIZATION);
    if let Some(auth_value) = auth_header {
        if let Ok(auth_str) = auth_value.to_str() {
            if let Some(api_key) = auth_str.strip_prefix("Bearer ") {
                if config.api_keys.contains(&api_key.to_string()) {
                    return Ok(());
                }
            }
        }
    }
    
    Err(Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::json!({
            "error": "Unauthorized",
            "message": "Valid API key required"
        }).to_string()))
        .unwrap())
}

/// Add CORS headers to response
fn add_cors_headers(
    mut builder: hyper::http::response::Builder,
    config: &ServerConfig,
) -> hyper::http::response::Builder {
    let origins = if config.cors_origins.contains(&"*".to_string()) {
        "*".to_string()
    } else {
        config.cors_origins.join(", ")
    };
    
    builder = builder
        .header("Access-Control-Allow-Origin", origins)
        .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        .header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        .header("Access-Control-Max-Age", "86400");
    
    builder
}

/// Handle metrics endpoint
async fn handle_metrics(context: RequestContext) -> DnsResult<Response<Body>> {
    let metrics = context.prometheus.gather()?;
    
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(metrics))
        .unwrap())
}

/// Handle health endpoint
async fn handle_health(context: RequestContext) -> DnsResult<Response<Body>> {
    let health_report = context.health.get_health_report().await;
    
    let (status_code, body) = if let Some(report) = health_report {
        let status = match report.status {
            crate::health::HealthStatus::Healthy => StatusCode::OK,
            crate::health::HealthStatus::Degraded => StatusCode::OK,
            crate::health::HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
            crate::health::HealthStatus::Unknown => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, serde_json::to_string(&report).unwrap())
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, serde_json::json!({
            "status": "unknown",
            "message": "Health check not available"
        }).to_string())
    };
    
    Ok(Response::builder()
        .status(status_code)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap())
}

/// Handle readiness probe
async fn handle_readiness(context: RequestContext) -> DnsResult<Response<Body>> {
    let is_ready = context.health.is_ready().await;
    
    let (status_code, body) = if is_ready {
        (StatusCode::OK, serde_json::json!({"status": "ready"}).to_string())
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, serde_json::json!({"status": "not ready"}).to_string())
    };
    
    Ok(Response::builder()
        .status(status_code)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap())
}

/// Handle liveness probe
async fn handle_liveness(context: RequestContext) -> DnsResult<Response<Body>> {
    let is_alive = context.health.is_alive().await;
    
    let (status_code, body) = if is_alive {
        (StatusCode::OK, serde_json::json!({"status": "alive"}).to_string())
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, serde_json::json!({"status": "not alive"}).to_string())
    };
    
    Ok(Response::builder()
        .status(status_code)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap())
}

/// Handle start CPU profile
async fn handle_start_cpu_profile(
    req: Request<Body>,
    context: RequestContext,
) -> DnsResult<Response<Body>> {
    if !context.profiler.is_enabled() {
        return Ok(Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::json!({
                "error": "Profiling is not enabled"
            }).to_string()))
            .unwrap());
    }
    
    // Parse request body for profile ID (optional)
    let body_bytes = hyper::body::to_bytes(req.into_body()).await
        .map_err(|e| DnsError::ConfigError(format!("Failed to read request body: {}", e)))?;
    
    let profile_id = if !body_bytes.is_empty() {
        let request: serde_json::Value = serde_json::from_slice(&body_bytes)
            .map_err(|e| DnsError::ConfigError(format!("Invalid JSON: {}", e)))?;
        request.get("profile_id").and_then(|v| v.as_str()).map(|s| s.to_string())
    } else {
        None
    };
    
    match context.profiler.start_cpu_profile(profile_id).await {
        Ok(id) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::json!({
                "profile_id": id,
                "status": "started"
            }).to_string()))
            .unwrap()),
        Err(e) => Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::json!({
                "error": e.to_string()
            }).to_string()))
            .unwrap()),
    }
}

/// Handle stop CPU profile
async fn handle_stop_cpu_profile(
    profile_id: &str,
    context: RequestContext,
) -> DnsResult<Response<Body>> {
    match context.profiler.stop_cpu_profile(profile_id).await {
        Ok(profile_info) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_string(&profile_info).unwrap()))
            .unwrap()),
        Err(e) => Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::json!({
                "error": e.to_string()
            }).to_string()))
            .unwrap()),
    }
}

/// Handle list profiles
async fn handle_list_profiles(context: RequestContext) -> DnsResult<Response<Body>> {
    match context.profiler.list_profiles().await {
        Ok(profiles) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_string(&profiles).unwrap()))
            .unwrap()),
        Err(e) => Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::json!({
                "error": e.to_string()
            }).to_string()))
            .unwrap()),
    }
}

/// Handle profile stats
async fn handle_profile_stats(context: RequestContext) -> DnsResult<Response<Body>> {
    let stats = context.profiler.get_stats().await;
    
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&stats).unwrap()))
        .unwrap())
}

/// Handle dashboard data
async fn handle_dashboard_data(context: RequestContext) -> DnsResult<Response<Body>> {
    let dashboard_data = context.analytics.get_dashboard_data().await;
    
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&dashboard_data).unwrap()))
        .unwrap())
}

/// Handle query stats
async fn handle_query_stats(context: RequestContext) -> DnsResult<Response<Body>> {
    let query_stats = context.analytics.get_query_stats().await;
    
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&query_stats).unwrap()))
        .unwrap())
}

/// Handle top queries
async fn handle_top_queries(context: RequestContext) -> DnsResult<Response<Body>> {
    let top_queries = context.analytics.get_top_queries().await;
    
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&top_queries).unwrap()))
        .unwrap())
}

/// Handle client stats
async fn handle_client_stats(context: RequestContext) -> DnsResult<Response<Body>> {
    let client_stats = context.analytics.get_client_stats().await;
    
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&client_stats).unwrap()))
        .unwrap())
}

/// Handle performance stats
async fn handle_performance_stats(context: RequestContext) -> DnsResult<Response<Body>> {
    let performance_stats = context.analytics.get_performance_stats().await;
    
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&performance_stats).unwrap()))
        .unwrap())
}

/// Handle timeseries data
async fn handle_timeseries_data(
    req: Request<Body>,
    context: RequestContext,
) -> DnsResult<Response<Body>> {
    // Parse query parameters for time range
    let query = req.uri().query().unwrap_or("");
    let params: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    
    let start_time = params.get("start")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    
    let end_time = params.get("end")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(u64::MAX);
    
    let timeseries_data = context.analytics.get_time_series_range(start_time, end_time).await;
    
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&timeseries_data).unwrap()))
        .unwrap())
}

/// Handle server info
async fn handle_server_info(context: RequestContext) -> DnsResult<Response<Body>> {
    let info = serde_json::json!({
        "server": "DNS Monitoring Server",
        "version": env!("CARGO_PKG_VERSION"),
        "features": {
            "prometheus": true,
            "health_checks": true,
            "profiling": context.profiler.is_enabled(),
            "analytics": true,
            "authentication": context.config.auth_enabled,
            "cors": context.config.cors_enabled
        },
        "endpoints": {
            "metrics": "/metrics",
            "health": "/health",
            "readiness": "/health/ready",
            "liveness": "/health/live",
            "dashboard": "/analytics/dashboard",
            "profile_start": "/profile/cpu/start",
            "profile_stop": "/profile/cpu/stop/{id}",
            "profile_list": "/profile/list"
        }
    });
    
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(info.to_string()))
        .unwrap())
}