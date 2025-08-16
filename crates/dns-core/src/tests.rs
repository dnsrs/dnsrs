//! Tests for the hash-based query processing engine

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DnsQuery, RecordType, DnsClass};
    use crate::query::AtomicQuery;
    use crate::blocklist::{BlockResponse, PatternType};
    use crate::router::AtomicQueryRouter;
    use crate::resolver::{HashIndexedRecord, HashIndexedZone};
    use std::net::IpAddr;
    use std::sync::Arc;
    use tokio;

    #[tokio::test]
    async fn test_atomic_query_creation() {
        let dns_query = DnsQuery::new(
            12345,
            "example.com".to_string(),
            RecordType::A,
            DnsClass::IN,
            "127.0.0.1".parse::<IpAddr>().unwrap(),
        );
        
        let atomic_query = AtomicQuery::from_dns_query(&dns_query);
        
        assert_eq!(atomic_query.id, 12345);
        assert_eq!(atomic_query.record_type, 1); // A record
        assert_eq!(atomic_query.class, 1); // IN class
        assert_ne!(atomic_query.name_hash, 0);
        assert_ne!(atomic_query.query_hash, 0);
        assert_ne!(atomic_query.client_hash, 0);
    }

    #[tokio::test]
    async fn test_blocklist_functionality() {
        let router = AtomicQueryRouter::default().await;
        
        // Add domain to blocklist
        router.add_blocked_domain("ads.example.com", PatternType::Exact, Some(BlockResponse::NxDomain)).await.unwrap();
        
        // Create query for blocked domain
        let dns_query = DnsQuery::new(
            12345,
            "ads.example.com".to_string(),
            RecordType::A,
            DnsClass::IN,
            "127.0.0.1".parse::<IpAddr>().unwrap(),
        );
        
        // Query should be blocked
        let response = router.route_query_atomic(dns_query).await.unwrap();
        
        // Response should be NXDOMAIN (simplified check)
        assert!(response.len() >= 12);
        // Check the response flags - NXDOMAIN is in the lower 4 bits of byte 3
        assert_eq!(response[3] & 0x0F, 3); // NXDOMAIN response code
    }

    #[tokio::test]
    async fn test_whitelist_override() {
        let router = AtomicQueryRouter::default().await;
        
        // Add domain to blocklist
        router.add_blocked_domain("example.com", PatternType::Exact, Some(BlockResponse::NxDomain)).await.unwrap();
        
        // Add same domain to whitelist (should override blocklist)
        router.add_whitelist_domain("example.com").await;
        
        // Create query for whitelisted domain
        let dns_query = DnsQuery::new(
            12345,
            "example.com".to_string(),
            RecordType::A,
            DnsClass::IN,
            "127.0.0.1".parse::<IpAddr>().unwrap(),
        );
        
        // Query should not be blocked due to whitelist
        let response = router.route_query_atomic(dns_query).await.unwrap();
        
        // Should get NXDOMAIN (not blocked, but no records exist)
        assert!(response.len() >= 12);
    }

    #[tokio::test]
    async fn test_hash_indexed_zone() {
        let records = vec![
            HashIndexedRecord::new(
                crate::hash::hash_domain_name("example.com"),
                1, // A record
                1, // IN class
                300, // TTL
                0, // Data offset
                4, // Data length (IPv4)
            ),
        ];
        
        let flatbuffer_data = Arc::from(vec![127, 0, 0, 1]); // 127.0.0.1
        
        let zone = HashIndexedZone::new(
            "example.com".to_string(),
            records,
            flatbuffer_data,
        );
        
        // Test binary search
        let name_hash = crate::hash::hash_domain_name("example.com");
        let found_records = zone.find_records_binary_search(name_hash, 1, 1);
        
        assert_eq!(found_records.len(), 1);
        assert_eq!(found_records[0].record_type, 1);
        assert_eq!(found_records[0].ttl, 300);
    }

    #[tokio::test]
    async fn test_pre_computed_cache() {
        use crate::query::PreComputedResponseCache;
        
        let cache = PreComputedResponseCache::new();
        let query_hash = 12345u64;
        let response_data: Arc<[u8]> = Arc::from(vec![1, 2, 3, 4, 5]);
        
        // Insert response into cache
        assert!(cache.insert(query_hash, response_data.clone(), 300));
        
        // Retrieve response from cache
        let cached_response = cache.get(query_hash, 54321);
        assert!(cached_response.is_some());
        
        let cached = cached_response.unwrap();
        assert_eq!(cached.len(), 5);
        // First two bytes should be updated with query ID
        assert_eq!(cached[0], 0xD4); // 54321 >> 8
        assert_eq!(cached[1], 0x31); // 54321 & 0xFF
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        use crate::query::AtomicRateLimiter;
        
        let rate_limiter = AtomicRateLimiter::new(10, 5); // 10 global, 5 per client
        let client_hash = 12345u64;
        
        // Should allow initial requests
        assert!(rate_limiter.check_rate_limit(client_hash, 1));
        assert!(rate_limiter.check_rate_limit(client_hash, 1));
        
        // Should eventually hit rate limit
        for _ in 0..10 {
            rate_limiter.check_rate_limit(client_hash, 1);
        }
        
        // Should be rate limited now
        assert!(!rate_limiter.check_rate_limit(client_hash, 1));
    }

    #[tokio::test]
    async fn test_comprehensive_stats() {
        let router = AtomicQueryRouter::default().await;
        
        // Add some test data
        router.add_blocked_domain("ads.com", PatternType::Exact, Some(BlockResponse::NxDomain)).await.unwrap();
        
        // Process a query
        let dns_query = DnsQuery::new(
            12345,
            "test.com".to_string(),
            RecordType::A,
            DnsClass::IN,
            "127.0.0.1".parse::<IpAddr>().unwrap(),
        );
        
        let _response = router.route_query_atomic(dns_query).await.unwrap();
        
        // Get comprehensive stats
        let stats = router.get_comprehensive_stats();
        
        assert!(stats.router.total_queries > 0);
        assert_eq!(stats.blocklist.domains_added, 1);
    }

    #[tokio::test]
    async fn test_batch_query_processing() {
        let router = AtomicQueryRouter::default().await;
        
        // Create multiple queries
        let queries = vec![
            DnsQuery::new(
                1,
                "example1.com".to_string(),
                RecordType::A,
                DnsClass::IN,
                "127.0.0.1".parse::<IpAddr>().unwrap(),
            ),
            DnsQuery::new(
                2,
                "example2.com".to_string(),
                RecordType::A,
                DnsClass::IN,
                "127.0.0.1".parse::<IpAddr>().unwrap(),
            ),
            DnsQuery::new(
                3,
                "example3.com".to_string(),
                RecordType::A,
                DnsClass::IN,
                "127.0.0.1".parse::<IpAddr>().unwrap(),
            ),
        ];
        
        // Process queries in batch
        let responses = router.route_queries_batch_atomic(queries).await;
        
        assert_eq!(responses.len(), 3);
        for response in responses {
            assert!(response.is_ok());
            let response_data = response.unwrap();
            assert!(response_data.len() >= 12); // Minimum DNS response size
        }
    }
}