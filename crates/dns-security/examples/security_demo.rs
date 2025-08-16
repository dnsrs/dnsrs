//! DNS Security Module Demo
//! 
//! This example demonstrates the key features of the DNS security module:
//! - Rate limiting per client IP
//! - DDoS protection with automatic blacklisting
//! - DNS packet validation
//! - Access control lists
//! - Audit logging

use dns_security::*;
use std::net::{IpAddr, Ipv4Addr};
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    println!("🔒 DNS Security Module Demo");
    println!("============================\n");

    // Create security manager with default configurations
    let security_manager = create_security_manager().await?;

    // Demo 1: Rate Limiting
    println!("📊 Demo 1: Rate Limiting");
    demo_rate_limiting(&security_manager).await?;

    // Demo 2: DDoS Protection
    println!("\n🛡️  Demo 2: DDoS Protection");
    demo_ddos_protection().await?;

    // Demo 3: Packet Validation
    println!("\n✅ Demo 3: Packet Validation");
    demo_packet_validation().await?;

    // Demo 4: Access Control
    println!("\n🚪 Demo 4: Access Control Lists");
    demo_access_control().await?;

    // Demo 5: TSIG Authentication
    println!("\n🔐 Demo 5: TSIG Authentication");
    demo_tsig_authentication().await?;

    // Demo 6: Security Statistics
    println!("\n📈 Demo 6: Security Statistics");
    demo_security_statistics(&security_manager).await?;

    println!("\n✨ All demos completed successfully!");
    Ok(())
}

async fn create_security_manager() -> Result<SecurityManager, SecurityError> {
    let rate_limit_config = RateLimitConfig {
        max_tokens: 10,
        refill_rate: 2,
        global_rate_limit: Some(50),
        cleanup_interval: 60,
        max_clients: 1000,
    };

    let ddos_config = DdosConfig {
        suspicious_qps_threshold: 20,
        blacklist_qps_threshold: 50,
        rate_window_seconds: 10,
        blacklist_duration_seconds: 300,
        max_packet_size: 4096,
        bloom_filter_capacity: 10000,
        bloom_filter_fpr: 0.01,
        adaptive_thresholds: false,
        max_tracked_ips: 1000,
    };

    let validation_config = ValidationConfig::default();
    let tsig_config = TsigConfig::default();
    let acl_config = AclConfig::default();
    let audit_config = AuditConfig {
        enabled: false, // Disable for demo
        ..Default::default()
    };

    SecurityManager::new(
        rate_limit_config,
        ddos_config,
        validation_config,
        tsig_config,
        acl_config,
        audit_config,
    )
}

async fn demo_rate_limiting(security_manager: &SecurityManager) -> Result<(), SecurityError> {
    let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    
    // Create a simple DNS query packet
    let query_packet = create_dns_query_packet();

    println!("  Testing rate limiting for client {}", client_ip);
    
    let mut allowed_count = 0;
    let mut blocked_count = 0;

    // Send multiple requests to test rate limiting
    for i in 1..=15 {
        let allowed = security_manager.check_query_allowed(client_ip, &query_packet).await?;
        
        if allowed {
            allowed_count += 1;
            println!("  ✅ Request {}: Allowed", i);
        } else {
            blocked_count += 1;
            println!("  ❌ Request {}: Rate limited", i);
        }
        
        // Small delay between requests
        sleep(Duration::from_millis(100)).await;
    }

    println!("  📊 Results: {} allowed, {} blocked", allowed_count, blocked_count);
    Ok(())
}

async fn demo_ddos_protection() -> Result<(), SecurityError> {
    let ddos_config = DdosConfig {
        suspicious_qps_threshold: 5,
        blacklist_qps_threshold: 10,
        rate_window_seconds: 1,
        blacklist_duration_seconds: 60,
        max_packet_size: 1000,
        bloom_filter_capacity: 1000,
        bloom_filter_fpr: 0.01,
        adaptive_thresholds: false,
        max_tracked_ips: 100,
    };

    let ddos_protection = DdosProtection::new(ddos_config)?;
    let attacker_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));

    println!("  Testing DDoS protection for {}", attacker_ip);

    // Simulate rapid requests from an attacker
    for i in 1..=15 {
        let threat_level = ddos_protection.assess_threat(attacker_ip, 500).await?;
        
        match threat_level {
            ThreatLevel::Normal => println!("  ✅ Request {}: Normal traffic", i),
            ThreatLevel::Suspicious => println!("  ⚠️  Request {}: Suspicious activity detected", i),
            ThreatLevel::Blocked => println!("  🚫 Request {}: Temporarily blocked", i),
            ThreatLevel::Blacklisted => println!("  ⛔ Request {}: Blacklisted", i),
        }
    }

    // Test manual blacklisting
    println!("  🔨 Manually blacklisting IP");
    ddos_protection.blacklist_ip(attacker_ip, 60).await?;
    
    let threat_level = ddos_protection.assess_threat(attacker_ip, 100).await?;
    println!("  📋 Status after manual blacklist: {:?}", threat_level);

    Ok(())
}

async fn demo_packet_validation() -> Result<(), SecurityError> {
    let validator = PacketValidator::new(ValidationConfig::default())?;

    println!("  Testing DNS packet validation");

    // Test valid packet
    let valid_packet = create_dns_query_packet();
    let is_valid = validator.validate_query_packet(&valid_packet).await?;
    println!("  ✅ Valid DNS query: {}", if is_valid { "PASS" } else { "FAIL" });

    // Test invalid packet (too short)
    let invalid_packet = vec![0x12, 0x34, 0x01];
    let is_valid = validator.validate_query_packet(&invalid_packet).await?;
    println!("  ❌ Invalid packet (too short): {}", if is_valid { "PASS" } else { "FAIL" });

    // Test oversized packet
    let oversized_packet = vec![0; 5000];
    let is_valid = validator.validate_query_packet(&oversized_packet).await?;
    println!("  ❌ Oversized packet: {}", if is_valid { "PASS" } else { "FAIL" });

    Ok(())
}

async fn demo_access_control() -> Result<(), SecurityError> {
    let controller = AccessController::new(AclConfig::default())?;

    println!("  Setting up access control rules");

    // Add rule to deny private networks
    let deny_private = AccessController::create_deny_private_rule()?;
    controller.add_rule(deny_private).await?;
    println!("  📝 Added rule: Deny private networks");

    // Add allow-all rule with lower priority
    let allow_all = AccessController::create_allow_all_rule()?;
    controller.add_rule(allow_all).await?;
    println!("  📝 Added rule: Allow all other traffic");

    // Test different IP addresses
    let test_ips = vec![
        (IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), "Private IP"),
        (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), "Public IP (Google DNS)"),
        (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), "Loopback IP"),
    ];

    for (ip, description) in test_ips {
        let allowed = controller.is_allowed(ip).await?;
        let status = if allowed { "✅ ALLOWED" } else { "❌ DENIED" };
        println!("  {} ({}): {}", ip, description, status);
    }

    Ok(())
}

async fn demo_tsig_authentication() -> Result<(), SecurityError> {
    let authenticator = TsigAuthenticator::new(TsigConfig::default())?;

    println!("  Testing TSIG key management");

    // Generate a new TSIG key
    let key = authenticator.generate_key(
        "demo.example.com".to_string(),
        "hmac-sha256".to_string(),
    ).await?;

    println!("  🔑 Generated TSIG key: {}", key.name);
    println!("     Algorithm: {}", key.algorithm);
    println!("     Active: {}", key.active);

    // List all keys
    let keys = authenticator.list_keys().await;
    println!("  📋 Active keys: {:?}", keys);

    // Test key rotation (won't rotate since key is new)
    let rotated = authenticator.rotate_keys().await?;
    println!("  🔄 Keys rotated: {}", rotated);

    Ok(())
}

async fn demo_security_statistics(security_manager: &SecurityManager) -> Result<(), SecurityError> {
    println!("  Collecting security statistics");

    let stats = security_manager.get_security_stats().await?;

    println!("  📊 Rate Limiting Stats:");
    println!("     Allowed requests: {}", stats.rate_limit_stats.allowed_requests.load(std::sync::atomic::Ordering::Relaxed));
    println!("     Rate limit hits: {}", stats.rate_limit_stats.client_rate_limit_hits.load(std::sync::atomic::Ordering::Relaxed));

    println!("  📊 DDoS Protection Stats:");
    println!("     Tracked IPs: {}", stats.ddos_stats.tracked_ips.load(std::sync::atomic::Ordering::Relaxed));
    println!("     Suspicious activity: {}", stats.ddos_stats.suspicious_activity.load(std::sync::atomic::Ordering::Relaxed));

    println!("  📊 Packet Validation Stats:");
    println!("     Total validations: {}", stats.validation_stats.total_validations.load(std::sync::atomic::Ordering::Relaxed));
    println!("     Valid packets: {}", stats.validation_stats.valid_packets.load(std::sync::atomic::Ordering::Relaxed));

    Ok(())
}

fn create_dns_query_packet() -> Vec<u8> {
    // Simple DNS query for "example.com" A record
    vec![
        0x12, 0x34, // ID
        0x01, 0x00, // Flags (standard query)
        0x00, 0x01, // QDCOUNT (1 question)
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        // Question: example.com A IN
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00, // End of name
        0x00, 0x01, // QTYPE (A)
        0x00, 0x01, // QCLASS (IN)
    ]
}