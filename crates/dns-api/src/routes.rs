//! API routes configuration

use crate::{handlers::*, models::*, error::ErrorResponse};
use axum::{
    routing::{delete, get, post, put},
    Router,
};
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        // Zone management
        list_zones,
        get_zone,
        create_zone,
        delete_zone,
        
        // Record management
        list_records,
        create_record,
        get_record,
        update_record,
        delete_record,
        
        // Blocklist management
        list_blocklist,
        create_blocklist_entry,
        get_blocklist_entry,
        update_blocklist_entry,
        delete_blocklist_entry,
        
        // Cluster management
        list_cluster_nodes,
        get_cluster_node,
        remove_cluster_node,
        
        // Metrics and health
        get_server_stats,
        health_check,
        
        // Authentication
        authenticate,
    ),
    components(
        schemas(
            // Core models
            DnsZone,
            DnsRecord,
            BlocklistEntry,
            ClusterNode,
            ServerStats,
            HealthResponse,
            
            // Request/Response types
            CreateZoneRequest,
            CreateRecordRequest,
            UpdateRecordRequest,
            CreateBlocklistRequest,
            UpdateBlocklistRequest,
            AuthRequest,
            AuthResponse,
            
            // Data types
            RecordType,
            RecordData,
            ZoneStatus,
            SoaData,
            BlockType,
            NodeStatus,
            NodeRole,
            NodeMetrics,
            MemoryStats,
            ComponentHealth,
            
            // API wrapper types
            ApiResponse<DnsZone>,
            ApiResponse<DnsRecord>,
            ApiResponse<BlocklistEntry>,
            ApiResponse<ClusterNode>,
            ApiResponse<ServerStats>,
            PaginatedResponse<DnsZone>,
            PaginatedResponse<DnsRecord>,
            PaginatedResponse<BlocklistEntry>,
            PaginatedResponse<ClusterNode>,
            PaginationMeta,
            PaginationQuery,
            ErrorResponse,
        )
    ),
    tags(
        (name = "zones", description = "DNS zone management"),
        (name = "records", description = "DNS record management"),
        (name = "blocklist", description = "Ad-blocking and domain filtering"),
        (name = "cluster", description = "Cluster node management"),
        (name = "metrics", description = "Server metrics and statistics"),
        (name = "health", description = "Health checks and monitoring"),
        (name = "auth", description = "Authentication and authorization")
    ),
    security(
        ("bearer_auth" = ["Bearer"]),
        ("api_key" = ["ApiKey"])
    )
)]
pub struct ApiDoc;

/// Create the main API router
pub fn create_router(state: AppState) -> Router {
    let api_routes = Router::new()
        // Zone management routes
        .route("/zones", get(list_zones).post(create_zone))
        .route("/zones/:zone_name", get(get_zone).delete(delete_zone))
        
        // Record management routes
        .route("/zones/:zone_name/records", get(list_records).post(create_record))
        .route("/zones/:zone_name/records/:record_id", 
               get(get_record).put(update_record).delete(delete_record))
        
        // Blocklist management routes
        .route("/blocklist", get(list_blocklist).post(create_blocklist_entry))
        .route("/blocklist/:entry_id", 
               get(get_blocklist_entry).put(update_blocklist_entry).delete(delete_blocklist_entry))
        
        // Cluster management routes
        .route("/cluster/nodes", get(list_cluster_nodes))
        .route("/cluster/nodes/:node_id", get(get_cluster_node).delete(remove_cluster_node))
        
        // Metrics and statistics routes
        .route("/metrics/stats", get(get_server_stats))
        
        // Health check route
        .route("/health", get(health_check))
        
        // Authentication routes
        .route("/auth/login", post(authenticate))
        
        .with_state(state);

    // Create the main router with API versioning
    Router::new()
        .nest("/api/v1", api_routes)
        .merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any)
                )
        )
}

/// Create a minimal router for health checks (no authentication required)
pub fn create_health_router() -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(health_check))
        .route("/live", get(health_check))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use serde_json::json;

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = create_health_router();
        let server = TestServer::new(app).unwrap();

        let response = server.get("/health").await;
        assert_eq!(response.status_code(), StatusCode::OK);
        
        let health: serde_json::Value = response.json();
        assert_eq!(health["status"], "healthy");
    }

    #[tokio::test]
    async fn test_zones_endpoint_requires_auth() {
        let state = AppState::new();
        let app = create_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/api/v1/zones").await;
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_zones_endpoint_with_auth() {
        let state = AppState::new();
        let app = create_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server
            .get("/api/v1/zones")
            .add_header("X-API-Key", "test-key")
            .await;
        
        assert_eq!(response.status_code(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_zone() {
        let state = AppState::new();
        let app = create_router(state);
        let server = TestServer::new(app).unwrap();

        let zone_request = json!({
            "name": "example.com",
            "soa": {
                "mname": "ns1.example.com",
                "rname": "admin.example.com",
                "refresh": 3600,
                "retry": 1800,
                "expire": 604800,
                "minimum": 300
            }
        });

        let response = server
            .post("/api/v1/zones")
            .add_header("X-API-Key", "test-key")
            .json(&zone_request)
            .await;
        
        assert_eq!(response.status_code(), StatusCode::CREATED);
        
        let zone: serde_json::Value = response.json();
        assert_eq!(zone["data"]["name"], "example.com");
    }

    #[tokio::test]
    async fn test_swagger_docs() {
        let state = AppState::new();
        let app = create_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/api-docs/openapi.json").await;
        assert_eq!(response.status_code(), StatusCode::OK);
        
        let openapi: serde_json::Value = response.json();
        assert!(openapi["info"]["title"].is_string());
    }
}