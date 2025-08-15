//! Tests for atomic data structures

#[cfg(test)]
mod tests {
    use crate::atomic::*;
    use crate::types::NodeInfo;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_atomic_zone_metadata() {
        let metadata = AtomicZoneMetadata::new("example.com".to_string(), 12345);
        
        assert_eq!(metadata.name_hash, 12345);
        assert_eq!(metadata.name.as_ref(), "example.com");
        assert_eq!(metadata.current_version(), 1);
        
        // Test atomic version increment
        let new_version = metadata.increment_version();
        assert_eq!(new_version, 1);
        assert_eq!(metadata.current_version(), 2);
        
        // Test compare and swap
        assert!(metadata.compare_and_swap_version(2, 3).is_ok());
        assert_eq!(metadata.current_version(), 3);
        
        // Test failed compare and swap
        assert!(metadata.compare_and_swap_version(2, 4).is_err());
        assert_eq!(metadata.current_version(), 3);
        
        // Test loading state
        assert!(!metadata.is_loading());
        metadata.set_loading(true);
        assert!(metadata.is_loading());
    }

    #[test]
    fn test_atomic_zone_storage() {
        let storage = AtomicZoneStorage::new();
        let metadata = Arc::new(AtomicZoneMetadata::new("example.com".to_string(), 12345));
        
        // Test insertion
        assert!(storage.insert_zone(12345, metadata.clone()).is_none());
        assert_eq!(storage.zone_count(), 1);
        
        // Test retrieval
        let retrieved = storage.get_zone(12345).unwrap();
        assert_eq!(retrieved.name_hash, 12345);
        
        // Test access counting
        let initial_access = retrieved.access_count.load(std::sync::atomic::Ordering::Relaxed);
        storage.get_zone(12345);
        let after_access = retrieved.access_count.load(std::sync::atomic::Ordering::Relaxed);
        assert!(after_access > initial_access);
        
        // Test removal
        let removed = storage.remove_zone(12345).unwrap();
        assert_eq!(removed.name_hash, 12345);
        assert_eq!(storage.zone_count(), 0);
        assert!(storage.get_zone(12345).is_none());
    }

    #[test]
    fn test_atomic_cache() {
        let cache = AtomicCache::new(1024, 10);
        let data: Arc<[u8]> = Arc::from(vec![1, 2, 3, 4, 5].into_boxed_slice());
        
        // Test insertion and retrieval
        assert!(cache.insert(12345, data.clone(), 60));
        let retrieved = cache.get(12345).unwrap();
        assert_eq!(retrieved.as_ref(), &[1, 2, 3, 4, 5]);
        
        // Test cache statistics
        let stats = cache.stats();
        assert_eq!(stats.entry_count, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);
        assert!(stats.hit_rate > 0);
        
        // Test cache miss
        assert!(cache.get(54321).is_none());
        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        
        // Test removal
        assert!(cache.remove(12345));
        assert!(cache.get(12345).is_none());
        let stats = cache.stats();
        assert_eq!(stats.entry_count, 0);
    }

    #[test]
    fn test_atomic_cache_expiration() {
        let cache = AtomicCache::new(1024, 10);
        let data: Arc<[u8]> = Arc::from(vec![1, 2, 3, 4, 5].into_boxed_slice());
        
        // Insert with very short TTL
        assert!(cache.insert(12345, data.clone(), 1)); // Expires in 1 second
        
        // Should be available immediately
        assert!(cache.get(12345).is_some());
        
        // Wait for expiration
        thread::sleep(Duration::from_secs(2));
        assert!(cache.get(12345).is_none());
    }

    #[test]
    fn test_atomic_consistent_hash_ring() {
        let ring = AtomicConsistentHashRing::new(100);
        
        // Create test nodes
        let node1 = NodeInfo {
            node_id: 1,
            address: "192.168.1.1:53".to_string(),
            region: "us-east-1".to_string(),
            datacenter: "dc1".to_string(),
            capabilities: vec![],
            load_factor: 0.5,
            last_seen: 0,
            is_healthy: true,
        };
        
        let node2 = NodeInfo {
            node_id: 2,
            address: "192.168.1.2:53".to_string(),
            region: "us-east-1".to_string(),
            datacenter: "dc1".to_string(),
            capabilities: vec![],
            load_factor: 0.3,
            last_seen: 0,
            is_healthy: true,
        };
        
        // Add nodes
        assert!(ring.add_node(node1).is_ok());
        assert!(ring.add_node(node2).is_ok());
        
        let stats = ring.stats();
        assert_eq!(stats.total_nodes, 2);
        assert_eq!(stats.healthy_nodes, 2);
        assert_eq!(stats.virtual_nodes_per_node, 100);
        
        // Test zone assignment
        let nodes = ring.find_nodes_for_zone(12345, 2);
        // Should find at least 1 node, possibly 2 depending on hash distribution
        assert!(!nodes.is_empty());
        assert!(nodes.len() <= 2);
        for node_id in &nodes {
            assert!(node_id == &1 || node_id == &2);
        }
        
        // Test node health update
        assert!(ring.update_node_health(1, false));
        let stats = ring.stats();
        assert_eq!(stats.healthy_nodes, 1);
        
        // Test node removal
        assert!(ring.remove_node(1).is_ok());
        let stats = ring.stats();
        assert_eq!(stats.total_nodes, 1);
    }

    #[test]
    fn test_atomic_node_info() {
        let node_info = NodeInfo {
            node_id: 1,
            address: "192.168.1.1:53".to_string(),
            region: "us-east-1".to_string(),
            datacenter: "dc1".to_string(),
            capabilities: vec![],
            load_factor: 0.5,
            last_seen: 0,
            is_healthy: true,
        };
        
        let atomic_node = AtomicNodeInfo::new(node_info);
        
        assert_eq!(atomic_node.node_id, 1);
        assert_eq!(atomic_node.address.as_ref(), "192.168.1.1:53");
        assert_eq!(atomic_node.current_load_factor(), 0.5);
        assert!(atomic_node.is_healthy.load(std::sync::atomic::Ordering::Acquire));
        
        // Test query recording
        atomic_node.record_query(1000000); // 1ms
        atomic_node.record_query(2000000); // 2ms
        
        assert_eq!(atomic_node.query_count.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert_eq!(atomic_node.average_response_time_ns(), 1500000); // 1.5ms average
        
        // Test load factor update
        atomic_node.update_load_factor(0.8);
        assert_eq!(atomic_node.current_load_factor(), 0.8);
        
        // Test health update
        atomic_node.set_healthy(false);
        assert!(!atomic_node.is_healthy.load(std::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn test_atomic_stats_collector() {
        let stats = AtomicStatsCollector::new();
        
        // Test query recording
        stats.record_query(1000000); // 1ms
        stats.record_query(2000000); // 2ms
        
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.queries_processed, 2);
        // EMA calculation: first = 1000000, second = (1000000 * 9 + 2000000) / 10 = 1100000
        assert_eq!(snapshot.average_response_time_ns, 1100000);
        
        // Test QPS update
        stats.update_qps(1000);
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.queries_per_second, 1000);
        assert_eq!(snapshot.peak_qps, 1000);
        
        // Test higher QPS
        stats.update_qps(1500);
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.queries_per_second, 1500);
        assert_eq!(snapshot.peak_qps, 1500);
        
        // Test cache stats
        stats.update_cache_stats(8500, 1024 * 1024, 100); // 85% hit rate, 1MB usage, 100 ops
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.cache_hit_rate, 8500);
        assert_eq!(snapshot.cache_memory_usage, 1024 * 1024);
        
        // Test error recording
        stats.record_error("timeout");
        stats.record_error("network");
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.total_errors, 2);
        assert_eq!(snapshot.timeout_errors, 1);
        assert_eq!(snapshot.network_errors, 1);
        
        // Test reset
        stats.reset();
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.queries_processed, 0);
        assert_eq!(snapshot.total_errors, 0);
    }

    #[test]
    fn test_concurrent_access() {
        let storage = Arc::new(AtomicZoneStorage::new());
        let cache = Arc::new(AtomicCache::new(1024 * 1024, 1000));
        let stats = Arc::new(AtomicStatsCollector::new());
        
        let mut handles = vec![];
        
        // Spawn multiple threads to test concurrent access
        for i in 0..10 {
            let storage_clone = storage.clone();
            let cache_clone = cache.clone();
            let stats_clone = stats.clone();
            
            let handle = thread::spawn(move || {
                // Test concurrent zone operations
                let metadata = Arc::new(AtomicZoneMetadata::new(
                    format!("zone{}.com", i),
                    i as u64
                ));
                storage_clone.insert_zone(i as u64, metadata);
                
                // Test concurrent cache operations
                let data: Arc<[u8]> = Arc::from(vec![i as u8; 100].into_boxed_slice());
                cache_clone.insert(i as u64, data, 60);
                
                // Test concurrent stats updates
                for _ in 0..100 {
                    stats_clone.record_query(1000000 + i as u64 * 1000);
                }
            });
            
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Verify results
        assert_eq!(storage.zone_count(), 10);
        let cache_stats = cache.stats();
        assert_eq!(cache_stats.entry_count, 10);
        
        let stats_snapshot = stats.snapshot();
        assert_eq!(stats_snapshot.queries_processed, 1000); // 10 threads * 100 queries each
    }
}