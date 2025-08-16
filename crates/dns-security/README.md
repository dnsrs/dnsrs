# DNS Security Module

A comprehensive security module for the planet-scale DNS server, providing high-performance security features using atomic operations and lock-free data structures.

## Features

### 🚦 Rate Limiting
- **Atomic token bucket rate limiting** per client IP
- **Global rate limiting** across all clients
- **Lock-free implementation** using atomic operations
- **Automatic cleanup** of unused client buckets
- **Configurable burst capacity** and refill rates

### 🛡️ DDoS Protection
- **Multi-layered DDoS protection** with automatic blacklisting
- **Traffic pattern analysis** with configurable thresholds
- **Bloom filter** for fast blacklist lookups
- **Adaptive thresholds** based on server load
- **Manual IP blacklisting/whitelisting**

### ✅ Packet Validation
- **Comprehensive DNS packet validation** according to RFC 1035
- **Bounds checking** to prevent buffer overflow attacks
- **Malformed packet detection** and rejection
- **Configurable validation rules** and limits
- **Support for all standard DNS record types**

### 🔐 TSIG Authentication
- **Transaction Signature (TSIG)** authentication for zone transfers
- **HMAC-based authentication** with multiple algorithms
- **Automatic key rotation** and lifecycle management
- **Secure key generation** using cryptographic random numbers
- **Key expiration** and validation

### 🚪 Access Control Lists (ACL)
- **IP-based access control** with CIDR support
- **Zone-specific access rules** for fine-grained control
- **Lock-free rule evaluation** with atomic operations
- **Cached decisions** for improved performance
- **Priority-based rule ordering**

### 📝 Audit Logging
- **Comprehensive audit logging** for all security events
- **Structured JSON logging** with configurable levels
- **Asynchronous logging** with buffering for performance
- **Log rotation** and size management
- **Event correlation** with request and session IDs

## Architecture

The security module is designed with performance and scalability in mind:

- **Lock-free data structures** for maximum concurrency
- **Atomic operations** to avoid mutex contention
- **Zero-copy operations** where possible
- **Memory-efficient** bloom filters and caches
- **Async/await** throughout for non-blocking operations

## Usage

### Basic Setup

```rust
use dns_security::*;

#[tokio::main]
async fn main() -> Result<(), SecurityError> {
    // Create security manager with default configurations
    let security_manager = SecurityManager::new(
        RateLimitConfig::default(),
        DdosConfig::default(),
        ValidationConfig::default(),
        TsigConfig::default(),
        AclConfig::default(),
        AuditConfig::default(),
    )?;

    // Check if a client is allowed to make a DNS query
    let client_ip = "192.168.1.100".parse().unwrap();
    let dns_packet = create_dns_query_packet();
    
    let allowed = security_manager
        .check_query_allowed(client_ip, &dns_packet)
        .await?;
    
    if allowed {
        println!("Query allowed");
    } else {
        println!("Query blocked by security policies");
    }

    Ok(())
}
```

### Rate Limiting

```rust
use dns_security::{AtomicRateLimiter, RateLimitConfig};

let config = RateLimitConfig {
    max_tokens: 100,        // 100 query burst
    refill_rate: 10,        // 10 queries per second sustained
    global_rate_limit: Some(10000), // 10k queries/sec global limit
    cleanup_interval: 300,  // Clean up every 5 minutes
    max_clients: 100000,    // Track up to 100k clients
};

let rate_limiter = AtomicRateLimiter::new(config)?;

// Check rate limit for a client
let client_ip = "203.0.113.1".parse().unwrap();
let allowed = rate_limiter.check_rate_limit(client_ip).await?;
```

### DDoS Protection

```rust
use dns_security::{DdosProtection, DdosConfig, ThreatLevel};

let config = DdosConfig {
    suspicious_qps_threshold: 100,
    blacklist_qps_threshold: 500,
    rate_window_seconds: 60,
    blacklist_duration_seconds: 3600, // 1 hour
    max_packet_size: 4096,
    // ... other config options
    ..Default::default()
};

let ddos_protection = DdosProtection::new(config)?;

// Assess threat level for an IP
let threat_level = ddos_protection
    .assess_threat(client_ip, packet_size)
    .await?;

match threat_level {
    ThreatLevel::Normal => { /* Allow request */ },
    ThreatLevel::Suspicious => { /* Log and monitor */ },
    ThreatLevel::Blocked => { /* Temporarily block */ },
    ThreatLevel::Blacklisted => { /* Permanently block */ },
}
```

### Packet Validation

```rust
use dns_security::{PacketValidator, ValidationConfig};

let validator = PacketValidator::new(ValidationConfig::default())?;

// Validate a DNS query packet
let is_valid = validator.validate_query_packet(&packet).await?;

if !is_valid {
    return Err("Invalid DNS packet");
}
```

### Access Control

```rust
use dns_security::{AccessController, AclConfig, IpRange, AclRule, AclAction};

let controller = AccessController::new(AclConfig::default())?;

// Create a rule to deny private networks
let private_range = IpRange::new("192.168.0.0/16".to_string(), "Private network".to_string())?;
let deny_rule = AclRule::new(
    "deny-private".to_string(),
    vec![private_range],
    AclAction::Deny,
    vec![], // All zones
    100,    // High priority
    "Deny private networks".to_string(),
);

controller.add_rule(deny_rule).await?;

// Check if IP is allowed
let allowed = controller.is_allowed(client_ip).await?;
```

### TSIG Authentication

```rust
use dns_security::{TsigAuthenticator, TsigConfig};

let authenticator = TsigAuthenticator::new(TsigConfig::default())?;

// Generate a new TSIG key
let key = authenticator.generate_key(
    "transfer.example.com".to_string(),
    "hmac-sha256".to_string(),
).await?;

// Verify a TSIG signature (simplified)
let valid = authenticator
    .verify_signature("example.com", &signature)
    .await?;
```

## Performance

The security module is designed for high performance:

- **Sub-microsecond** rate limiting checks
- **Lock-free** concurrent access for thousands of clients
- **Memory-efficient** bloom filters for blacklist lookups
- **Atomic operations** instead of mutex locks
- **Zero-copy** packet validation where possible

## Configuration

All security components are highly configurable:

- **Rate limits** can be adjusted per use case
- **DDoS thresholds** can be tuned for different environments
- **Validation rules** can be strict or permissive
- **ACL rules** support complex IP range matching
- **Audit logging** can be customized for compliance needs

## Testing

Run the comprehensive test suite:

```bash
cargo test -p dns-security
```

Run the interactive demo:

```bash
cargo run --example security_demo -p dns-security
```

Run benchmarks:

```bash
cargo bench -p dns-security
```

## Requirements

This module implements the following requirements from the DNS server specification:

- **9.1**: Rate limiting per client IP
- **9.2**: DDoS protection mechanisms  
- **9.3**: Input validation and bounds checking
- **9.4**: Access control based on client networks
- **9.5**: Audit logging for administrative actions
- **9.6**: DNSSEC support (TSIG authentication)
- **9.7**: Encryption support preparation

## License

This project is licensed under the Apache License 2.0.