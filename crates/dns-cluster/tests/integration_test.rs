//! Integration tests for the planet-scale clustering system

use dns_cluster::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_cluster_manager_creation() {
    let node_id = 1;
    let cluster_id = 100;
    
    let local_node = NodeInfo {
        node_id,
        address: "127.0.0.1:8053".parse().unwrap(),
        region: "us-east-1".to_string(),
        datacenter: "us-east-1a".to_string(),
        capabilities: NodeCapabilities {
            supports_zone_transfer: true,
            supports_replication: true,
            supports_health_checks: true,
            max_zones: 1000,
            max_connections: 100,
        },
        metadata: NodeMetadata::new("1.0.0".to_string()),
    };
    
    let config = ClusterManagerConfig::default();
    
    let cluster_manager = PlanetScaleClusterManager::new(
        node_id,
        cluster_id,
        local_node,
        config,
    );
    
    // Test that the cluster manager was created successfully
    assert_eq!(cluster_manager.node_id(), node_id);
    assert_eq!(cluster_manager.cluster_id(), cluster_id);
}

#[tokio::test]
async fn test_hash_ring_operations() {
    let config = HashRingConfig::default();
    let hash_ring = AtomicConsistentHashRing::new(config);
    
    // Create test nodes
    let node1 = NodeInfo {
        node_id: 1,
        address: "127.0.0.1:8053".parse().unwrap(),
        region: "us-east-1".to_string(),
        datacenter: "us-east-1a".to_string(),
        capabilities: NodeCapabilities {
            supports_zone_transfer: true,
            supports_replication: true,
            supports_health_checks: true,
            max_zones: 1000,
            max_connections: 100,
        },
        metadata: NodeMetadata::new("1.0.0".to_string()),
    };
    
    let node2 = NodeInfo {
        node_id: 2,
        address: "127.0.0.1:8054".parse().unwrap(),
        region: "us-east-1".to_string(),
        datacenter: "us-east-1b".to_string(),
        capabilities: NodeCapabilities {
            supports_zone_transfer: true,
            supports_replication: true,
            supports_health_checks: true,
            max_zones: 1000,
            max_connections: 100,
        },
        metadata: NodeMetadata::new("1.0.0".to_string()),
    };
    
    // Add nodes to ring
    assert!(hash_ring.add_node_atomic(node1).await.unwrap());
    assert!(hash_ring.add_node_atomic(node2).await.unwrap());
    
    // Test ring statistics
    let stats = hash_ring.get_stats();
    assert_eq!(stats.total_nodes, 2);
    assert!(stats.total_virtual_nodes > 0);
    
    // Test zone assignment
    let zone_hash = 12345;
    let nodes = hash_ring.find_nodes_for_zone(zone_hash, 2).await;
    assert!(!nodes.is_empty());
    assert!(nodes.len() <= 2);
}

#[tokio::test]
async fn test_replication_system() {
    let config = ReplicationConfig::default();
    let distributor = ZeroCopyZoneDistributor::new(config);
    
    // Test zone data storage
    let zone_hash = 12345;
    let zone_data: Arc<[u8]> = Arc::from(b"test zone data".as_slice());
    
    distributor.store_zone_data(zone_hash, zone_data.clone()).await.unwrap();
    
    // Test zone data retrieval
    let retrieved_data = distributor.get_zone_data(zone_hash).await;
    assert!(retrieved_data.is_some());
    assert_eq!(retrieved_data.unwrap().as_ref(), zone_data.as_ref());
    
    // Test statistics
    let stats = distributor.get_stats();
    assert_eq!(stats.zones_replicated, 0); // No actual replication performed yet
}

#[tokio::test]
async fn test_health_monitoring() {
    let config = HealthConfig::default();
    let health_monitor = ClusterHealthMonitor::new(config);
    
    // Create test node
    let node = NodeInfo {
        node_id: 1,
        address: "127.0.0.1:8053".parse().unwrap(),
        region: "us-east-1".to_string(),
        datacenter: "us-east-1a".to_string(),
        capabilities: NodeCapabilities {
            supports_zone_transfer: true,
            supports_replication: true,
            supports_health_checks: true,
            max_zones: 1000,
            max_connections: 100,
        },
        metadata: NodeMetadata::new("1.0.0".to_string()),
    };
    
    // Add node to monitoring
    health_monitor.add_node(node.clone()).await.unwrap();
    
    // Test health status retrieval
    let health_status = health_monitor.get_node_health(node.node_id);
    assert!(health_status.is_some());
    
    let status = health_status.unwrap();
    assert_eq!(status.node_id, node.node_id);
    assert!(status.is_healthy); // Should start as healthy
    
    // Test statistics
    let stats = health_monitor.get_stats();
    assert_eq!(stats.total_nodes_monitored, 1);
    assert_eq!(stats.healthy_nodes, 1);
    assert_eq!(stats.unhealthy_nodes, 0);
}

#[tokio::test]
async fn test_cluster_state_management() {
    let local_node_id = 1;
    let cluster_id = 100;
    let config = ClusterStateConfig::default();
    
    let cluster_state = AtomicClusterState::new(local_node_id, cluster_id, config);
    
    // Create test node
    let node = NodeInfo {
        node_id: 2,
        address: "127.0.0.1:8054".parse().unwrap(),
        region: "us-east-1".to_string(),
        datacenter: "us-east-1a".to_string(),
        capabilities: NodeCapabilities {
            supports_zone_transfer: true,
            supports_replication: true,
            supports_health_checks: true,
            max_zones: 1000,
            max_connections: 100,
        },
        metadata: NodeMetadata::new("1.0.0".to_string()),
    };
    
    // Add node to cluster state
    cluster_state.add_node(node.clone()).await.unwrap();
    
    // Test node retrieval
    let node_state = cluster_state.get_node_state(node.node_id);
    assert!(node_state.is_some());
    
    let state = node_state.unwrap();
    assert_eq!(state.node_id, node.node_id);
    assert!(state.is_active.load(std::sync::atomic::Ordering::Relaxed));
    
    // Test zone assignment
    let zone_hash = 12345;
    cluster_state.assign_zone(zone_hash, node.node_id).await.unwrap();
    
    // Test zone ownership
    let primary_node = cluster_state.get_zone_primary(zone_hash);
    assert_eq!(primary_node, Some(node.node_id));
    
    // Test statistics
    let stats = cluster_state.get_stats();
    assert_eq!(stats.total_nodes, 1);
    assert_eq!(stats.active_nodes, 1);
    assert_eq!(stats.total_zones, 1);
}

#[tokio::test]
async fn test_discovery_system() {
    let local_node = NodeInfo {
        node_id: 1,
        address: "127.0.0.1:8053".parse().unwrap(),
        region: "us-east-1".to_string(),
        datacenter: "us-east-1a".to_string(),
        capabilities: NodeCapabilities {
            supports_zone_transfer: true,
            supports_replication: true,
            supports_health_checks: true,
            max_zones: 1000,
            max_connections: 100,
        },
        metadata: NodeMetadata::new("1.0.0".to_string()),
    };
    
    let config = DiscoveryConfig::default();
    let discovery = HierarchicalNodeDiscovery::new(local_node.clone(), config);
    
    // Test node registration
    let remote_node = NodeInfo {
        node_id: 2,
        address: "127.0.0.1:8054".parse().unwrap(),
        region: "us-east-1".to_string(),
        datacenter: "us-east-1b".to_string(),
        capabilities: NodeCapabilities {
            supports_zone_transfer: true,
            supports_replication: true,
            supports_health_checks: true,
            max_zones: 1000,
            max_connections: 100,
        },
        metadata: NodeMetadata::new("1.0.0".to_string()),
    };
    
    discovery.register_node(remote_node.clone()).await.unwrap();
    
    // Test node retrieval
    let discovered_nodes = discovery.get_all_nodes().await;
    assert!(!discovered_nodes.is_empty());
    
    // Test statistics
    let stats = discovery.get_stats();
    assert!(stats.total_nodes > 0);
}