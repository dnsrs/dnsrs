//! Integration tests for DNS API server

use axum::http::StatusCode;
use axum_test::TestServer;
use dns_api::{create_router, AppState};
use serde_json::json;

/// Create test server with authentication
fn create_test_server() -> TestServer {
    let state = AppState::new();
    let app = create_router(state);
    TestServer::new(app).unwrap()
}

#[tokio::test]
async fn test_health_endpoint() {
    let server = create_test_server();

    let response = server.get("/api/v1/health").await;
    response.assert_status_ok();
    
    let health: serde_json::Value = response.json();
    assert_eq!(health["status"], "healthy");
    assert!(health["version"].is_string());
    assert!(health["uptime"].is_number());
    assert!(health["checks"].is_object());
}

#[tokio::test]
async fn test_authentication_required() {
    let server = create_test_server();

    // Test that protected endpoints require authentication
    let endpoints = vec![
        "/api/v1/zones",
        "/api/v1/blocklist",
        "/api/v1/cluster/nodes",
        "/api/v1/metrics/stats",
    ];

    for endpoint in endpoints {
        let response = server.get(endpoint).await;
        response.assert_status_unauthorized();
        
        let error: serde_json::Value = response.json();
        assert_eq!(error["error"], "AUTHENTICATION_FAILED");
    }
}

#[tokio::test]
async fn test_zone_management_crud() {
    let server = create_test_server();

    // Create zone
    let zone_request = json!({
        "name": "test.com",
        "soa": {
            "mname": "ns1.test.com",
            "rname": "admin.test.com",
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
    
    response.assert_status(StatusCode::CREATED);
    let zone: serde_json::Value = response.json();
    assert_eq!(zone["data"]["name"], "test.com");
    assert_eq!(zone["data"]["status"], "active");

    // List zones
    let response = server
        .get("/api/v1/zones")
        .add_header("X-API-Key", "test-key")
        .await;
    
    response.assert_status_ok();
    let zones: serde_json::Value = response.json();
    assert_eq!(zones["pagination"]["total"], 1);
    assert_eq!(zones["data"][0]["name"], "test.com");

    // Get specific zone
    let response = server
        .get("/api/v1/zones/test.com")
        .add_header("X-API-Key", "test-key")
        .await;
    
    response.assert_status_ok();
    let zone: serde_json::Value = response.json();
    assert_eq!(zone["data"]["name"], "test.com");

    // Delete zone
    let response = server
        .delete("/api/v1/zones/test.com")
        .add_header("X-API-Key", "test-key")
        .await;
    
    response.assert_status(StatusCode::NO_CONTENT);

    // Verify zone is deleted
    let response = server
        .get("/api/v1/zones/test.com")
        .add_header("X-API-Key", "test-key")
        .await;
    
    response.assert_status_not_found();
}

#[tokio::test]
async fn test_dns_record_management() {
    let server = create_test_server();

    // First create a zone
    let zone_request = json!({
        "name": "example.org",
        "soa": {
            "mname": "ns1.example.org",
            "rname": "admin.example.org",
            "refresh": 3600,
            "retry": 1800,
            "expire": 604800,
            "minimum": 300
        }
    });

    server
        .post("/api/v1/zones")
        .add_header("X-API-Key", "test-key")
        .json(&zone_request)
        .await
        .assert_status(StatusCode::CREATED);

    // Create A record
    let record_request = json!({
        "name": "www.example.org",
        "type": "A",
        "data": {
            "type": "A",
            "data": {
                "address": "192.168.1.100"
            }
        },
        "ttl": 300
    });

    let response = server
        .post("/api/v1/zones/example.org/records")
        .add_header("X-API-Key", "test-key")
        .json(&record_request)
        .await;
    
    response.assert_status(StatusCode::CREATED);
    let record: serde_json::Value = response.json();
    assert_eq!(record["data"]["name"], "www.example.org");
    assert_eq!(record["data"]["type"], "A");
    assert_eq!(record["data"]["ttl"], 300);

    let record_id = record["data"]["id"].as_str().unwrap();

    // List records
    let response = server
        .get("/api/v1/zones/example.org/records")
        .add_header("X-API-Key", "test-key")
        .await;
    
    response.assert_status_ok();
    let records: serde_json::Value = response.json();
    assert_eq!(records["pagination"]["total"], 1);

    // Get specific record
    let response = server
        .get(&format!("/api/v1/zones/example.org/records/{}", record_id))
        .add_header("X-API-Key", "test-key")
        .await;
    
    response.assert_status_ok();
    let record: serde_json::Value = response.json();
    assert_eq!(record["data"]["name"], "www.example.org");

    // Update record
    let update_request = json!({
        "ttl": 600
    });

    let response = server
        .put(&format!("/api/v1/zones/example.org/records/{}", record_id))
        .add_header("X-API-Key", "test-key")
        .json(&update_request)
        .await;
    
    response.assert_status_ok();
    let updated_record: serde_json::Value = response.json();
    assert_eq!(updated_record["data"]["ttl"], 600);

    // Delete record
    let response = server
        .delete(&format!("/api/v1/zones/example.org/records/{}", record_id))
        .add_header("X-API-Key", "test-key")
        .await;
    
    response.assert_status(StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_blocklist_management() {
    let server = create_test_server();

    // Create blocklist entry
    let blocklist_request = json!({
        "domain": "malicious.com",
        "block_type": "nxdomain",
        "source": "test"
    });

    let response = server
        .post("/api/v1/blocklist")
        .add_header("X-API-Key", "test-key")
        .json(&blocklist_request)
        .await;
    
    response.assert_status(StatusCode::CREATED);
    let entry: serde_json::Value = response.json();
    assert_eq!(entry["data"]["domain"], "malicious.com");
    assert_eq!(entry["data"]["block_type"], "nxdomain");
    assert_eq!(entry["data"]["active"], true);

    let entry_id = entry["data"]["id"].as_str().unwrap();

    // List blocklist entries
    let response = server
        .get("/api/v1/blocklist")
        .add_header("X-API-Key", "test-key")
        .await;
    
    response.assert_status_ok();
    let entries: serde_json::Value = response.json();
    assert_eq!(entries["pagination"]["total"], 1);

    // Get specific entry
    let response = server
        .get(&format!("/api/v1/blocklist/{}", entry_id))
        .add_header("X-API-Key", "test-key")
        .await;
    
    response.assert_status_ok();
    let entry: serde_json::Value = response.json();
    assert_eq!(entry["data"]["domain"], "malicious.com");

    // Update entry
    let update_request = json!({
        "active": false
    });

    let response = server
        .put(&format!("/api/v1/blocklist/{}", entry_id))
        .add_header("X-API-Key", "test-key")
        .json(&update_request)
        .await;
    
    response.assert_status_ok();
    let updated_entry: serde_json::Value = response.json();
    assert_eq!(updated_entry["data"]["active"], false);

    // Delete entry
    let response = server
        .delete(&format!("/api/v1/blocklist/{}", entry_id))
        .add_header("X-API-Key", "test-key")
        .await;
    
    response.assert_status(StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_server_statistics() {
    let server = create_test_server();

    let response = server
        .get("/api/v1/metrics/stats")
        .add_header("X-API-Key", "test-key")
        .await;
    
    response.assert_status_ok();
    let stats: serde_json::Value = response.json();
    
    // Verify statistics structure
    assert!(stats["data"]["total_queries"].is_number());
    assert!(stats["data"]["queries_per_second"].is_number());
    assert!(stats["data"]["cache_hit_ratio"].is_number());
    assert!(stats["data"]["active_zones"].is_number());
    assert!(stats["data"]["memory_usage"].is_object());
    assert!(stats["data"]["uptime"].is_number());
}

#[tokio::test]
async fn test_cluster_node_management() {
    let server = create_test_server();

    // List cluster nodes (should be empty initially)
    let response = server
        .get("/api/v1/cluster/nodes")
        .add_header("X-API-Key", "test-key")
        .await;
    
    response.assert_status_ok();
    let nodes: serde_json::Value = response.json();
    assert_eq!(nodes["pagination"]["total"], 0);

    // Test getting non-existent node
    let response = server
        .get("/api/v1/cluster/nodes/non-existent")
        .add_header("X-API-Key", "test-key")
        .await;
    
    response.assert_status_not_found();
}

#[tokio::test]
async fn test_authentication_endpoint() {
    let server = create_test_server();

    // Test valid authentication
    let auth_request = json!({
        "key": "admin",
        "password": "password"
    });

    let response = server
        .post("/api/v1/auth/login")
        .json(&auth_request)
        .await;
    
    response.assert_status_ok();
    let auth_response: serde_json::Value = response.json();
    assert!(auth_response["token"].is_string());
    assert!(auth_response["expires_at"].is_string());
    assert!(auth_response["refresh_token"].is_string());

    // Test invalid authentication
    let invalid_auth_request = json!({
        "key": "invalid",
        "password": "wrong"
    });

    let response = server
        .post("/api/v1/auth/login")
        .json(&invalid_auth_request)
        .await;
    
    response.assert_status_unauthorized();
}

#[tokio::test]
async fn test_validation_errors() {
    let server = create_test_server();

    // Test invalid zone creation
    let invalid_zone_request = json!({
        "name": "", // Empty name should fail validation
        "soa": {
            "mname": "ns1.test.com",
            "rname": "admin.test.com",
            "refresh": 3600,
            "retry": 1800,
            "expire": 604800,
            "minimum": 300
        }
    });

    let response = server
        .post("/api/v1/zones")
        .add_header("X-API-Key", "test-key")
        .json(&invalid_zone_request)
        .await;
    
    response.assert_status_bad_request();
    let error: serde_json::Value = response.json();
    assert_eq!(error["error"], "VALIDATION_FAILED");

    // Test invalid record creation
    let invalid_record_request = json!({
        "name": "www.test.com",
        "type": "A",
        "data": {
            "type": "A",
            "data": {
                "address": "192.168.1.100"
            }
        },
        "ttl": 0 // TTL of 0 should fail validation
    });

    let response = server
        .post("/api/v1/zones/test.com/records")
        .add_header("X-API-Key", "test-key")
        .json(&invalid_record_request)
        .await;
    
    response.assert_status_bad_request();
}

#[tokio::test]
async fn test_pagination() {
    let server = create_test_server();

    // Create multiple zones for pagination testing
    for i in 1..=25 {
        let zone_request = json!({
            "name": format!("test{}.com", i),
            "soa": {
                "mname": format!("ns1.test{}.com", i),
                "rname": format!("admin.test{}.com", i),
                "refresh": 3600,
                "retry": 1800,
                "expire": 604800,
                "minimum": 300
            }
        });

        server
            .post("/api/v1/zones")
            .add_header("X-API-Key", "test-key")
            .json(&zone_request)
            .await
            .assert_status(StatusCode::CREATED);
    }

    // Test first page
    let response = server
        .get("/api/v1/zones?page=1&per_page=10")
        .add_header("X-API-Key", "test-key")
        .await;
    
    response.assert_status_ok();
    let zones: serde_json::Value = response.json();
    assert_eq!(zones["pagination"]["page"], 1);
    assert_eq!(zones["pagination"]["per_page"], 10);
    assert_eq!(zones["pagination"]["total"], 25);
    assert_eq!(zones["pagination"]["total_pages"], 3);
    assert_eq!(zones["pagination"]["has_next"], true);
    assert_eq!(zones["pagination"]["has_prev"], false);
    assert_eq!(zones["data"].as_array().unwrap().len(), 10);

    // Test second page
    let response = server
        .get("/api/v1/zones?page=2&per_page=10")
        .add_header("X-API-Key", "test-key")
        .await;
    
    response.assert_status_ok();
    let zones: serde_json::Value = response.json();
    assert_eq!(zones["pagination"]["page"], 2);
    assert_eq!(zones["pagination"]["has_next"], true);
    assert_eq!(zones["pagination"]["has_prev"], true);

    // Test last page
    let response = server
        .get("/api/v1/zones?page=3&per_page=10")
        .add_header("X-API-Key", "test-key")
        .await;
    
    response.assert_status_ok();
    let zones: serde_json::Value = response.json();
    assert_eq!(zones["pagination"]["page"], 3);
    assert_eq!(zones["pagination"]["has_next"], false);
    assert_eq!(zones["pagination"]["has_prev"], true);
    assert_eq!(zones["data"].as_array().unwrap().len(), 5); // Remaining 5 zones
}