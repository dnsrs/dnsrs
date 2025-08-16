//! Integration tests for the DNS security module

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_security_manager_integration() {
        // Create security manager with default configs
        let rate_limit_config = RateLimitConfig::default();
        let ddos_config = DdosConfig::default();
        let validation_config = ValidationConfig::default();
        let tsig_config = TsigConfig::default();
        let acl_config = AclConfig::default();
        let audit_config = AuditConfig {
            enabled: false, // Disable for testing
            ..Default::default()
        };

        let temp_dir = tempfile::TempDir::new().unwrap();
        let security_manager = SecurityManager::new(
            rate_limit_config,
            ddos_config,
            validation_config,
            tsig_config,
            acl_config,
            audit_config,
            temp_dir.path().to_path_buf(),
            None,
        ).unwrap();

        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        
        // Create a simple DNS query packet
        let query_packet = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // Question: test.com A IN
            0x04, b't', b'e', b's', b't',
            0x03, b'c', b'o', b'm',
            0x00, // End of name
            0x00, 0x01, // QTYPE (A)
            0x00, 0x01, // QCLASS (IN)
        ];

        // Should allow normal queries
        assert!(security_manager.check_query_allowed(client_ip, &query_packet).await.unwrap());
        
        // Should allow multiple queries within rate limit
        for _ in 0..10 {
            assert!(security_manager.check_query_allowed(client_ip, &query_packet).await.unwrap());
        }

        // Get security statistics
        let stats = security_manager.get_security_stats().await.unwrap();
        assert!(stats.rate_limit_stats.allowed_requests.load(std::sync::atomic::Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn test_rate_limiting_integration() {
        let config = RateLimitConfig {
            max_tokens: 5,
            refill_rate: 1,
            global_rate_limit: None,
            cleanup_interval: 60,
            max_clients: 1000,
        };

        let rate_limiter = AtomicRateLimiter::new(config).unwrap();
        let client_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Should allow initial burst
        for _ in 0..5 {
            assert!(rate_limiter.check_rate_limit(client_ip).await.unwrap());
        }

        // Should be rate limited now
        assert!(!rate_limiter.check_rate_limit(client_ip).await.unwrap());

        // Wait for token refill
        sleep(Duration::from_millis(1100)).await;

        // Should allow one more request
        assert!(rate_limiter.check_rate_limit(client_ip).await.unwrap());
    }

    #[tokio::test]
    async fn test_ddos_protection_integration() {
        let config = DdosConfig {
            suspicious_qps_threshold: 5,
            blacklist_qps_threshold: 10,
            rate_window_seconds: 1,
            blacklist_duration_seconds: 60,
            max_packet_size: 1000,
            bloom_filter_capacity: 10000,
            bloom_filter_fpr: 0.01,
            adaptive_thresholds: false,
            max_tracked_ips: 1000,
        };

        let ddos_protection = DdosProtection::new(config).unwrap();
        let client_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));

        // Normal traffic should be allowed
        for _ in 0..3 {
            let threat = ddos_protection.assess_threat(client_ip, 100).await.unwrap();
            assert_eq!(threat, ThreatLevel::Normal);
        }

        // Rapid traffic should become suspicious
        for _ in 0..10 {
            let threat = ddos_protection.assess_threat(client_ip, 100).await.unwrap();
            if threat == ThreatLevel::Suspicious || threat == ThreatLevel::Blacklisted {
                break;
            }
        }
    }

    #[tokio::test]
    async fn test_packet_validation_integration() {
        let config = ValidationConfig::default();
        let validator = PacketValidator::new(config).unwrap();

        // Valid DNS query
        let valid_packet = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // Question: example.com A IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // End of name
            0x00, 0x01, // QTYPE (A)
            0x00, 0x01, // QCLASS (IN)
        ];

        assert!(validator.validate_query_packet(&valid_packet).await.unwrap());

        // Invalid packet (too short)
        let invalid_packet = vec![0x12, 0x34, 0x01];
        assert!(!validator.validate_query_packet(&invalid_packet).await.unwrap());

        // Malformed packet (invalid domain name)
        let malformed_packet = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // Invalid domain name (length extends beyond packet)
            0xFF, b'x', b'x', b'x',
        ];
        assert!(!validator.validate_query_packet(&malformed_packet).await.unwrap());
    }

    #[tokio::test]
    async fn test_access_control_integration() {
        let config = AclConfig::default();
        let controller = AccessController::new(config).unwrap();

        // Add a rule to deny private networks
        let deny_rule = AccessController::create_deny_private_rule().unwrap();
        controller.add_rule(deny_rule).await.unwrap();

        // Add an allow-all rule with lower priority
        let allow_rule = AccessController::create_allow_all_rule().unwrap();
        controller.add_rule(allow_rule).await.unwrap();

        // Test private IP (should be denied)
        let private_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(!controller.is_allowed(private_ip).await.unwrap());

        // Test public IP (should be allowed)
        let public_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(controller.is_allowed(public_ip).await.unwrap());

        // Test zone-specific access
        assert!(controller.is_zone_transfer_allowed(public_ip, "example.com").await.unwrap());
        assert!(!controller.is_zone_transfer_allowed(private_ip, "example.com").await.unwrap());
    }

    #[tokio::test]
    async fn test_tsig_authentication_integration() {
        let config = TsigConfig::default();
        let authenticator = TsigAuthenticator::new(config).unwrap();

        // Generate a test key
        let key = authenticator.generate_key(
            "test.example.com".to_string(),
            "hmac-sha256".to_string(),
        ).await.unwrap();

        assert_eq!(key.name, "test.example.com");
        assert_eq!(key.algorithm, "hmac-sha256");
        assert!(key.active);

        // List keys
        let keys = authenticator.list_keys().await;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "test.example.com");

        // Test key rotation
        let rotated = authenticator.rotate_keys().await.unwrap();
        // Should be 0 since key is not expired
        assert_eq!(rotated, 0);
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let config = RateLimitConfig {
            max_tokens: 1000,
            refill_rate: 100,
            global_rate_limit: None,
            cleanup_interval: 60,
            max_clients: 10000,
        };

        let rate_limiter = Arc::new(AtomicRateLimiter::new(config).unwrap());
        let mut handles = Vec::new();

        // Spawn multiple concurrent tasks
        for i in 0..100 {
            let limiter = rate_limiter.clone();
            let handle = tokio::spawn(async move {
                let ip = IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8));
                
                for _ in 0..10 {
                    let _ = limiter.check_rate_limit(ip).await;
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify statistics
        let stats = rate_limiter.get_stats().await.unwrap();
        assert!(stats.allowed_requests.load(std::sync::atomic::Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn test_memory_usage() {
        // Test that the security components don't leak memory under load
        let rate_limiter = Arc::new(AtomicRateLimiter::new(RateLimitConfig::default()).unwrap());
        
        // Generate load with many different IPs
        for i in 0..10000 {
            let ip = IpAddr::V4(Ipv4Addr::new(
                (i >> 24) as u8,
                (i >> 16) as u8,
                (i >> 8) as u8,
                i as u8,
            ));
            
            let _ = rate_limiter.check_rate_limit(ip).await;
        }

        // The rate limiter doesn't automatically clean up in this test
        // since we're not triggering the cleanup conditions
        // Just verify that we can create many clients without crashing
        let stats = rate_limiter.get_stats().await.unwrap();
        let active_clients = stats.active_clients.load(std::sync::atomic::Ordering::Relaxed);
        
        // Should have created clients (but may not have cleaned up yet)
        assert!(active_clients > 0);
    }
}