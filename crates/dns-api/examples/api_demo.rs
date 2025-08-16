//! DNS API Server Demo
//!
//! This example demonstrates the comprehensive REST API functionality
//! including zone management, record operations, blocklist management,
//! cluster monitoring, and metrics collection.

use dns_api::{ApiConfig, ApiServer};
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create API server configuration
    let config = ApiConfig {
        bind_address: "127.0.0.1".to_string(),
        port: 8080,
        jwt_secret: "demo-secret-key-change-in-production".to_string(),
        jwt_issuer: "dns-server-demo".to_string(),
        jwt_audience: "dns-api-demo".to_string(),
        enable_swagger: true,
        enable_metrics: true,
        enable_cors: true,
        request_timeout: 30,
    };

    println!("🚀 Starting DNS API Server Demo");
    println!("📊 Swagger UI: http://127.0.0.1:8080/docs");
    println!("📈 Metrics: http://127.0.0.1:8080/metrics");
    println!("🔍 Health: http://127.0.0.1:8080/api/v1/health");
    println!();

    // Create and configure the server
    let server = ApiServer::new(config)?;

    // Add some demo API keys
    server.auth_service().add_api_key(
        "demo-admin-key".to_string(),
        "Demo Admin Key".to_string(),
        vec!["admin".to_string()],
    ).await;

    server.auth_service().add_api_key(
        "demo-read-key".to_string(),
        "Demo Read-Only Key".to_string(),
        vec!["zones:read".to_string(), "records:read".to_string()],
    ).await;

    println!("🔑 Demo API Keys:");
    println!("   Admin: demo-admin-key");
    println!("   Read-Only: demo-read-key");
    println!();

    // Start demo client in background
    tokio::spawn(async {
        sleep(Duration::from_secs(2)).await;
        if let Err(e) = run_demo_client().await {
            eprintln!("Demo client error: {}", e);
        }
    });

    // Start the server (this will block)
    server.start().await?;

    Ok(())
}

async fn run_demo_client() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let base_url = "http://127.0.0.1:8080/api/v1";

    println!("🧪 Running API Demo Client");
    println!();

    // Test health endpoint
    println!("1. Testing health endpoint...");
    let response = client.get(&format!("{}/health", base_url)).send().await?;
    println!("   Status: {}", response.status());
    let health: serde_json::Value = response.json().await?;
    println!("   Health: {}", health["status"]);
    println!();

    // Test authentication
    println!("2. Testing authentication...");
    let auth_request = json!({
        "key": "admin",
        "password": "password"
    });
    
    let response = client
        .post(&format!("{}/auth/login", base_url))
        .json(&auth_request)
        .send()
        .await?;
    
    println!("   Auth Status: {}", response.status());
    if response.status().is_success() {
        let auth_response: serde_json::Value = response.json().await?;
        println!("   Token received: {}", auth_response["token"].as_str().unwrap_or("N/A"));
    }
    println!();

    // Test zone creation
    println!("3. Testing zone creation...");
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

    let response = client
        .post(&format!("{}/zones", base_url))
        .header("X-API-Key", "demo-admin-key")
        .json(&zone_request)
        .send()
        .await?;

    println!("   Zone Creation Status: {}", response.status());
    if response.status().is_success() {
        let zone: serde_json::Value = response.json().await?;
        println!("   Created zone: {}", zone["data"]["name"]);
    }
    println!();

    // Test record creation
    println!("4. Testing DNS record creation...");
    let record_request = json!({
        "name": "www.example.com",
        "type": "A",
        "data": {
            "type": "A",
            "data": {
                "address": "192.168.1.100"
            }
        },
        "ttl": 300
    });

    let response = client
        .post(&format!("{}/zones/example.com/records", base_url))
        .header("X-API-Key", "demo-admin-key")
        .json(&record_request)
        .send()
        .await?;

    println!("   Record Creation Status: {}", response.status());
    if response.status().is_success() {
        let record: serde_json::Value = response.json().await?;
        println!("   Created record: {} -> {}", 
                record["data"]["name"], 
                record["data"]["data"]["data"]["address"]);
    }
    println!();

    // Test blocklist entry creation
    println!("5. Testing blocklist entry creation...");
    let blocklist_request = json!({
        "domain": "ads.example.com",
        "block_type": "nxdomain",
        "source": "demo"
    });

    let response = client
        .post(&format!("{}/blocklist", base_url))
        .header("X-API-Key", "demo-admin-key")
        .json(&blocklist_request)
        .send()
        .await?;

    println!("   Blocklist Entry Status: {}", response.status());
    if response.status().is_success() {
        let entry: serde_json::Value = response.json().await?;
        println!("   Blocked domain: {}", entry["data"]["domain"]);
    }
    println!();

    // Test listing zones
    println!("6. Testing zone listing...");
    let response = client
        .get(&format!("{}/zones", base_url))
        .header("X-API-Key", "demo-read-key")
        .send()
        .await?;

    println!("   Zone List Status: {}", response.status());
    if response.status().is_success() {
        let zones: serde_json::Value = response.json().await?;
        println!("   Total zones: {}", zones["pagination"]["total"]);
    }
    println!();

    // Test server statistics
    println!("7. Testing server statistics...");
    let response = client
        .get(&format!("{}/metrics/stats", base_url))
        .header("X-API-Key", "demo-admin-key")
        .send()
        .await?;

    println!("   Stats Status: {}", response.status());
    if response.status().is_success() {
        let stats: serde_json::Value = response.json().await?;
        println!("   Active zones: {}", stats["data"]["active_zones"]);
        println!("   Total records: {}", stats["data"]["total_records"]);
        println!("   Memory usage: {} MB", 
                stats["data"]["memory_usage"]["total"].as_u64().unwrap_or(0) / 1024 / 1024);
    }
    println!();

    // Test Prometheus metrics
    println!("8. Testing Prometheus metrics...");
    let response = client
        .get("http://127.0.0.1:8080/metrics")
        .send()
        .await?;

    println!("   Metrics Status: {}", response.status());
    if response.status().is_success() {
        let metrics_text = response.text().await?;
        let lines: Vec<&str> = metrics_text.lines().take(10).collect();
        println!("   Sample metrics (first 10 lines):");
        for line in lines {
            if !line.starts_with('#') && !line.is_empty() {
                println!("     {}", line);
            }
        }
    }
    println!();

    println!("✅ Demo completed successfully!");
    println!("🌐 Visit http://127.0.0.1:8080/docs to explore the interactive API documentation");

    Ok(())
}