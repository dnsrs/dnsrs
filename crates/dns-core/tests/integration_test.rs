//! Integration test for the hash-based query processing engine

use dns_core::{
    AtomicQueryRouter, HashIndexedRecord, HashIndexedZone, BlockResponse, PatternType,
    DnsQuery, RecordType, DnsClass, hash_domain_name,
};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

#[tokio::test]
async fn test_hash_based_query_processing_integration() {
    println!("🚀 Hash-Based Query Processing Engine Integration Test");
    
    // Create the atomic query router
    let router = AtomicQueryRouter::new(
        1024,    // 1GB cache
        100000,  // 100K cache entries
        50000,   // 50K global QPS
        1000,    // 1K per-client QPS
    ).await;
    
    // Add some domains to the blocklist
    router.add_blocked_domain("ads.example.com", PatternType::Exact, Some(BlockResponse::NxDomain)).await.unwrap();
    router.add_blocked_domain("tracker.evil.com", PatternType::Exact, Some(BlockResponse::CustomIp("0.0.0.0".parse().unwrap()))).await.unwrap();
    
    // Add a whitelisted domain (overrides blocklist)
    router.add_whitelist_domain("ads.example.com").await;
    
    // Create test zone data with hash-indexed records
    let records = vec![
        HashIndexedRecord::new(
            hash_domain_name("example.com"),
            RecordType::A.to_u16(),
            DnsClass::IN.to_u16(),
            300, // TTL
            0,   // Data offset
            4,   // IPv4 address length
        ),
        HashIndexedRecord::new(
            hash_domain_name("www.example.com"),
            RecordType::A.to_u16(),
            DnsClass::IN.to_u16(),
            300,
            4,   // Data offset after first record
            4,   // IPv4 address length
        ),
    ];
    
    // Create FlatBuffer data (simplified - just IP addresses)
    let flatbuffer_data: Arc<[u8]> = Arc::from(vec![
        // example.com -> 93.184.216.34
        93, 184, 216, 34,
        // www.example.com -> 93.184.216.35
        93, 184, 216, 35,
    ]);
    
    // Create hash-indexed zone
    let zone = Arc::new(HashIndexedZone::new(
        "example.com".to_string(),
        records,
        flatbuffer_data,
    ));
    
    // Add zone to resolver
    assert!(router.resolver().add_zone(zone));
    
    // Test 1: Normal domain query
    let query = DnsQuery::new(
        12345,
        "example.com".to_string(),
        RecordType::A,
        DnsClass::IN,
        "127.0.0.1".parse::<IpAddr>().unwrap(),
    );
    
    let response = router.route_query_atomic(query).await.unwrap();
    assert!(response.len() >= 12); // Minimum DNS response size
    
    // Test 2: Blocked domain query
    let blocked_query = DnsQuery::new(
        12346,
        "tracker.evil.com".to_string(),
        RecordType::A,
        DnsClass::IN,
        "127.0.0.1".parse::<IpAddr>().unwrap(),
    );
    
    let blocked_response = router.route_query_atomic(blocked_query).await.unwrap();
    assert!(blocked_response.len() >= 12);
    
    // Test 3: Whitelisted domain (was blocked but now allowed)
    let whitelist_query = DnsQuery::new(
        12347,
        "ads.example.com".to_string(),
        RecordType::A,
        DnsClass::IN,
        "127.0.0.1".parse::<IpAddr>().unwrap(),
    );
    
    let whitelist_response = router.route_query_atomic(whitelist_query).await.unwrap();
    assert!(whitelist_response.len() >= 12);
    
    // Test 4: Cache performance
    let cache_test_query = DnsQuery::new(
        12348,
        "example.com".to_string(),
        RecordType::A,
        DnsClass::IN,
        "127.0.0.1".parse::<IpAddr>().unwrap(),
    );
    
    // First query (cache miss)
    let start = Instant::now();
    let _response1 = router.route_query_atomic(cache_test_query.clone()).await.unwrap();
    let cache_miss_time = start.elapsed();
    
    // Second query (cache hit)
    let start = Instant::now();
    let _response2 = router.route_query_atomic(cache_test_query).await.unwrap();
    let cache_hit_time = start.elapsed();
    
    // Cache hit should be faster
    assert!(cache_hit_time < cache_miss_time);
    
    // Test 5: Batch processing
    let batch_queries: Vec<DnsQuery> = (0..100)
        .map(|i| {
            DnsQuery::new(
                (i as u16) + 1000,
                "example.com".to_string(),
                RecordType::A,
                DnsClass::IN,
                "127.0.0.1".parse::<IpAddr>().unwrap(),
            )
        })
        .collect();
    
    let batch_responses = router.route_queries_batch_atomic(batch_queries).await;
    assert_eq!(batch_responses.len(), 100);
    
    for response in batch_responses {
        assert!(response.is_ok());
        let response_data = response.unwrap();
        assert!(response_data.len() >= 12);
    }
    
    // Test 6: Statistics
    let stats = router.get_comprehensive_stats();
    assert!(stats.router.total_queries > 0);
    assert_eq!(stats.blocklist.domains_added, 2); // Two blocked domains
    assert_eq!(stats.blocklist.whitelist_added, 1); // One whitelisted domain
    
    println!("✅ All integration tests passed!");
    println!("   Total queries processed: {}", stats.router.total_queries);
    println!("   Cache hits: {}", stats.router.cache_hits);
    println!("   Blocked queries: {}", stats.router.blocked_queries);
}

#[tokio::test]
async fn test_binary_search_performance() {
    println!("🔍 Binary Search Performance Test");
    
    // Create a large zone with many records for binary search testing
    let record_count = 10000;
    let mut records = Vec::with_capacity(record_count);
    let mut flatbuffer_data = Vec::new();
    
    for i in 0..record_count {
        let domain = format!("test{}.example.com", i);
        let domain_hash = hash_domain_name(&domain);
        
        records.push(HashIndexedRecord::new(
            domain_hash,
            RecordType::A.to_u16(),
            DnsClass::IN.to_u16(),
            300,
            flatbuffer_data.len() as u32,
            4,
        ));
        
        // Add IP address data
        flatbuffer_data.extend_from_slice(&[192, 168, (i / 256) as u8, (i % 256) as u8]);
    }
    
    let zone = Arc::new(HashIndexedZone::new(
        "example.com".to_string(),
        records,
        Arc::from(flatbuffer_data),
    ));
    
    // Test binary search performance
    let test_domain = "test5000.example.com";
    let test_hash = hash_domain_name(test_domain);
    
    let start = Instant::now();
    let found_records = zone.find_records_binary_search(
        test_hash,
        RecordType::A.to_u16(),
        DnsClass::IN.to_u16(),
    );
    let search_time = start.elapsed();
    
    assert_eq!(found_records.len(), 1);
    assert_eq!(found_records[0].name_hash, test_hash);
    
    println!("   Binary search in {} records: {:?}", record_count, search_time);
    println!("   Found {} matching records", found_records.len());
    
    // Verify O(log n) complexity by testing with different sizes
    let sizes = vec![1000, 5000, 10000];
    for size in sizes {
        let subset_records = &zone.records[..size];
        let start = Instant::now();
        
        // Simulate binary search on subset
        let target_key = test_hash as u128;
        let mut left = 0;
        let mut right = subset_records.len();
        let mut found = false;
        
        while left < right {
            let mid = left + (right - left) / 2;
            let mid_key = subset_records[mid].sort_key();
            
            if mid_key == target_key {
                found = true;
                break;
            } else if mid_key < target_key {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        
        let subset_time = start.elapsed();
        println!("   Binary search in {} records: {:?} (found: {})", 
                 size, subset_time, found);
    }
    
    println!("✅ Binary search performance test completed!");
}

#[tokio::test]
async fn test_hash_collision_handling() {
    println!("🔢 Hash Collision Handling Test");
    
    let router = AtomicQueryRouter::default().await;
    
    // Test with domains that might have hash collisions
    let test_domains = vec![
        "example.com",
        "test.com", 
        "demo.com",
        "sample.com",
        "placeholder.com",
    ];
    
    let mut domain_hashes = Vec::new();
    for domain in &test_domains {
        let hash = hash_domain_name(domain);
        domain_hashes.push((domain, hash));
        println!("   {}: 0x{:016x}", domain, hash);
    }
    
    // Check for hash collisions (should be extremely rare with good hash function)
    let mut unique_hashes = std::collections::HashSet::new();
    let mut collisions = 0;
    
    for (domain, hash) in &domain_hashes {
        if !unique_hashes.insert(*hash) {
            println!("   ⚠️  Hash collision detected for {}: 0x{:016x}", domain, hash);
            collisions += 1;
        }
    }
    
    println!("   Total domains: {}", test_domains.len());
    println!("   Unique hashes: {}", unique_hashes.len());
    println!("   Collisions: {}", collisions);
    
    // Test that the system handles queries correctly even with potential collisions
    for domain in test_domains {
        let query = DnsQuery::new(
            (rand::random::<u64>() % 65536) as u16,
            domain.to_string(),
            RecordType::A,
            DnsClass::IN,
            "127.0.0.1".parse::<IpAddr>().unwrap(),
        );
        
        let response = router.route_query_atomic(query).await.unwrap();
        assert!(response.len() >= 12);
    }
    
    println!("✅ Hash collision handling test completed!");
}

// Simple random number generation for tests
mod rand {
    use std::sync::atomic::{AtomicU64, Ordering};
    
    static SEED: AtomicU64 = AtomicU64::new(1);
    
    pub fn random<T>() -> T 
    where 
        T: From<u64>
    {
        let current = SEED.load(Ordering::Relaxed);
        let next = current.wrapping_mul(1103515245).wrapping_add(12345);
        SEED.store(next, Ordering::Relaxed);
        T::from(next)
    }
}