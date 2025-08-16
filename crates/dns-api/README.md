# DNS API Server

A comprehensive REST API server for managing DNS zones, records, blocklist entries, and cluster operations. Built with Rust, Axum, and designed for high performance and scalability.

## Features

### Core API Functionality
- **Zone Management**: Complete CRUD operations for DNS zones
- **Record Management**: Full DNS record lifecycle management
- **Blocklist Management**: Ad-blocking and domain filtering with atomic updates
- **Cluster Management**: Node monitoring and cluster operations
- **Real-time Metrics**: Server statistics and performance monitoring
- **Authentication**: JWT tokens and API key support
- **OpenAPI Documentation**: Interactive Swagger UI and API specification

### Security & Performance
- JWT-based authentication with configurable expiration
- API key authentication for service-to-service communication
- Role-based access control with granular permissions
- Rate limiting and DDoS protection
- Input validation and sanitization
- Comprehensive error handling and logging

### Monitoring & Observability
- Prometheus metrics exposition
- Health check endpoints for Kubernetes
- Structured logging with configurable levels
- Request tracing and performance monitoring
- Real-time statistics and analytics

## Quick Start

### Running the API Server

```rust
use dns_api::{ApiConfig, ApiServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ApiConfig {
        bind_address: "0.0.0.0".to_string(),
        port: 8080,
        jwt_secret: "your-secret-key".to_string(),
        jwt_issuer: "dns-server".to_string(),
        jwt_audience: "dns-api".to_string(),
        enable_swagger: true,
        enable_metrics: true,
        enable_cors: true,
        request_timeout: 30,
    };

    let server = ApiServer::new(config)?;
    server.start().await?;
    
    Ok(())
}
```

### Running the Demo

```bash
cargo run --example api_demo
```

This will start the API server with demo data and show example API calls.

## API Endpoints

### Authentication
- `POST /api/v1/auth/login` - Authenticate and get JWT token

### Zone Management
- `GET /api/v1/zones` - List all zones (paginated)
- `POST /api/v1/zones` - Create new zone
- `GET /api/v1/zones/{zone_name}` - Get zone details
- `DELETE /api/v1/zones/{zone_name}` - Delete zone

### DNS Record Management
- `GET /api/v1/zones/{zone_name}/records` - List records in zone
- `POST /api/v1/zones/{zone_name}/records` - Create DNS record
- `GET /api/v1/zones/{zone_name}/records/{record_id}` - Get record details
- `PUT /api/v1/zones/{zone_name}/records/{record_id}` - Update record
- `DELETE /api/v1/zones/{zone_name}/records/{record_id}` - Delete record

### Blocklist Management
- `GET /api/v1/blocklist` - List blocklist entries
- `POST /api/v1/blocklist` - Create blocklist entry
- `GET /api/v1/blocklist/{entry_id}` - Get blocklist entry
- `PUT /api/v1/blocklist/{entry_id}` - Update blocklist entry
- `DELETE /api/v1/blocklist/{entry_id}` - Delete blocklist entry

### Cluster Management
- `GET /api/v1/cluster/nodes` - List cluster nodes
- `GET /api/v1/cluster/nodes/{node_id}` - Get node details
- `DELETE /api/v1/cluster/nodes/{node_id}` - Remove node from cluster

### Metrics & Monitoring
- `GET /api/v1/metrics/stats` - Get server statistics
- `GET /api/v1/health` - Health check endpoint
- `GET /metrics` - Prometheus metrics

### Documentation
- `GET /docs` - Interactive Swagger UI
- `GET /api-docs/openapi.json` - OpenAPI specification

## Authentication

The API supports two authentication methods:

### JWT Tokens
```bash
# Login to get JWT token
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"key": "admin", "password": "password"}'

# Use JWT token in requests
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:8080/api/v1/zones
```

### API Keys
```bash
# Use API key in header
curl -H "X-API-Key: your-api-key" \
  http://localhost:8080/api/v1/zones
```

## Example Usage

### Create a DNS Zone
```bash
curl -X POST http://localhost:8080/api/v1/zones \
  -H "X-API-Key: demo-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "example.com",
    "soa": {
      "mname": "ns1.example.com",
      "rname": "admin.example.com",
      "refresh": 3600,
      "retry": 1800,
      "expire": 604800,
      "minimum": 300
    }
  }'
```

### Create a DNS Record
```bash
curl -X POST http://localhost:8080/api/v1/zones/example.com/records \
  -H "X-API-Key: demo-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "www.example.com",
    "type": "A",
    "data": {
      "type": "A",
      "data": {
        "address": "192.168.1.100"
      }
    },
    "ttl": 300
  }'
```

### Add Blocklist Entry
```bash
curl -X POST http://localhost:8080/api/v1/blocklist \
  -H "X-API-Key: demo-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "ads.example.com",
    "block_type": "nxdomain",
    "source": "manual"
  }'
```

### Get Server Statistics
```bash
curl -H "X-API-Key: demo-admin-key" \
  http://localhost:8080/api/v1/metrics/stats
```

## Supported DNS Record Types

- **A** - IPv4 address records
- **AAAA** - IPv6 address records
- **CNAME** - Canonical name records
- **MX** - Mail exchange records
- **NS** - Name server records
- **PTR** - Pointer records (reverse DNS)
- **SOA** - Start of authority records
- **TXT** - Text records
- **SRV** - Service records
- **CAA** - Certificate authority authorization
- **HTTPS** - HTTPS service binding
- **SVCB** - Service binding
- **TLSA** - TLS association
- **SMIMEA** - S/MIME certificate association
- **DNSKEY** - DNS public key (DNSSEC)
- **DS** - Delegation signer (DNSSEC)
- **RRSIG** - Resource record signature (DNSSEC)
- **NSEC** - Next secure record (DNSSEC)
- **NSEC3** - Next secure record v3 (DNSSEC)

## Permissions System

The API uses a role-based permission system:

### Zone Permissions
- `zones:read` - List and view zones
- `zones:write` - Create and update zones
- `zones:delete` - Delete zones

### Record Permissions
- `records:read` - List and view DNS records
- `records:write` - Create and update DNS records
- `records:delete` - Delete DNS records

### Blocklist Permissions
- `blocklist:read` - List and view blocklist entries
- `blocklist:write` - Create and update blocklist entries
- `blocklist:delete` - Delete blocklist entries

### Cluster Permissions
- `cluster:read` - View cluster nodes and status
- `cluster:write` - Manage cluster nodes

### Metrics Permissions
- `metrics:read` - Access server metrics and statistics

### Admin Permission
- `admin` - Full access to all operations

## Configuration

The API server can be configured using the `ApiConfig` struct:

```rust
let config = ApiConfig {
    bind_address: "0.0.0.0".to_string(),    // Bind address
    port: 8080,                              // Port number
    jwt_secret: "secret".to_string(),        // JWT signing secret
    jwt_issuer: "dns-server".to_string(),    // JWT issuer
    jwt_audience: "dns-api".to_string(),     // JWT audience
    enable_swagger: true,                    // Enable Swagger UI
    enable_metrics: true,                    // Enable metrics endpoint
    enable_cors: true,                       // Enable CORS
    request_timeout: 30,                     // Request timeout (seconds)
};
```

## Monitoring

### Prometheus Metrics

The API server exposes comprehensive Prometheus metrics at `/metrics`:

- `dns_queries_total` - Total DNS queries processed
- `dns_cache_hits_total` - Cache hit count
- `dns_cache_misses_total` - Cache miss count
- `dns_blocked_queries_total` - Blocked queries count
- `dns_zones_total` - Number of zones
- `dns_records_total` - Number of records
- `dns_memory_usage_bytes` - Memory usage
- `dns_uptime_seconds` - Server uptime

### Health Checks

Health check endpoints for Kubernetes and monitoring:

- `/api/v1/health` - Detailed health status
- `/health` - Simple health check
- `/ready` - Readiness probe
- `/live` - Liveness probe

## Testing

Run the comprehensive test suite:

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration_tests

# Run with coverage
cargo test --all-features
```

## Performance

The API server is designed for high performance:

- **Async/Await**: Built on Tokio for high concurrency
- **Zero-Copy**: Uses FlatBuffers for efficient serialization
- **Lock-Free**: Atomic operations for thread-safe access
- **Connection Pooling**: Efficient resource management
- **Compression**: HTTP response compression
- **Caching**: Multi-level caching for fast responses

## Security

Security features include:

- **Authentication**: JWT and API key authentication
- **Authorization**: Role-based access control
- **Input Validation**: Comprehensive request validation
- **Rate Limiting**: Protection against abuse
- **CORS**: Configurable cross-origin resource sharing
- **TLS**: HTTPS support for secure communication
- **Audit Logging**: Security event logging

## License

This project is licensed under the Apache License 2.0.