//! High-performance hashing utilities for DNS operations
//!
//! This module provides optimized hashing functions for domain names,
//! queries, and other DNS-related data structures.

use ahash::RandomState;
use std::hash::{Hash, Hasher, BuildHasher};

/// Global hash builder for consistent hashing across the application
static HASH_BUILDER: RandomState = RandomState::with_seeds(
    0x1234567890abcdef,
    0xfedcba0987654321,
    0x1111222233334444,
    0x5555666677778888,
);

/// Hash a domain name for fast lookups
/// 
/// Domain names are normalized to lowercase and trailing dots are removed
/// for consistent hashing.
pub fn hash_domain_name(name: &str) -> u64 {
    let normalized = normalize_domain_name(name);
    let mut hasher = HASH_BUILDER.build_hasher();
    normalized.hash(&mut hasher);
    hasher.finish()
}

/// Hash a DNS query for caching
/// 
/// Combines domain name hash, record type, and class for unique query identification.
pub fn hash_query(name_hash: u64, record_type: u16, class: u16) -> u64 {
    let mut hasher = HASH_BUILDER.build_hasher();
    name_hash.hash(&mut hasher);
    record_type.hash(&mut hasher);
    class.hash(&mut hasher);
    hasher.finish()
}

/// Hash a client IP address for rate limiting
pub fn hash_client_ip(ip: &std::net::IpAddr) -> u64 {
    let mut hasher = HASH_BUILDER.build_hasher();
    ip.hash(&mut hasher);
    hasher.finish()
}

/// Hash zone data for versioning and replication
pub fn hash_zone_data(data: &[u8]) -> u64 {
    let mut hasher = HASH_BUILDER.build_hasher();
    data.hash(&mut hasher);
    hasher.finish()
}

/// Hash a node ID for consistent hash ring placement
pub fn hash_node_id(node_id: u64, virtual_node_index: u32) -> u64 {
    let mut hasher = HASH_BUILDER.build_hasher();
    node_id.hash(&mut hasher);
    virtual_node_index.hash(&mut hasher);
    hasher.finish()
}

/// Normalize domain name for consistent hashing
/// 
/// - Convert to lowercase
/// - Remove trailing dot if present
/// - Validate length constraints
fn normalize_domain_name(name: &str) -> String {
    let mut normalized = name.to_lowercase();
    
    // Remove trailing dot
    if normalized.ends_with('.') {
        normalized.pop();
    }
    
    // Validate length
    if normalized.len() > crate::types::MAX_DOMAIN_NAME_LENGTH {
        tracing::warn!("Domain name too long: {} bytes", normalized.len());
    }
    
    normalized
}

/// Fast hash function for bloom filters
/// 
/// Uses a different seed to provide independent hash functions
/// for bloom filter implementations.
pub fn bloom_hash(data: &[u8], seed: u64) -> u64 {
    let mut hasher = HASH_BUILDER.build_hasher();
    hasher.write_u64(seed);
    hasher.write(data);
    hasher.finish()
}

/// Hash function optimized for SIMD operations
/// 
/// When SIMD features are available, this uses vectorized operations
/// for improved performance on large datasets.
#[cfg(feature = "simd")]
pub fn simd_hash_batch(names: &[&str]) -> Vec<u64> {
    // TODO: Implement SIMD-optimized batch hashing
    // For now, fall back to individual hashing
    names.iter().map(|name| hash_domain_name(name)).collect()
}

#[cfg(not(feature = "simd"))]
pub fn simd_hash_batch(names: &[&str]) -> Vec<u64> {
    names.iter().map(|name| hash_domain_name(name)).collect()
}

/// Atomic hasher for thread-safe hashing operations
pub struct AtomicHasher;

impl AtomicHasher {
    /// Hash a domain name atomically
    pub fn hash_domain(name: &str) -> u64 {
        hash_domain_name(name)
    }
    
    /// Hash a query atomically
    pub fn hash_query(name_hash: u64, record_type: u16, class: u16) -> u64 {
        hash_query(name_hash, record_type, class)
    }
    
    /// Hash client IP atomically
    pub fn hash_client_ip(ip: &std::net::IpAddr) -> u64 {
        hash_client_ip(ip)
    }
}

/// Consistent hash ring utilities
pub mod consistent_hash {
    
    /// Calculate the hash ring position for a key
    pub fn ring_position(key: u64) -> u64 {
        // Use the key directly as ring position
        key
    }
    
    /// Find the next position in the ring
    pub fn next_position(current: u64) -> u64 {
        current.wrapping_add(1)
    }
    
    /// Calculate distance between two positions on the ring
    pub fn ring_distance(from: u64, to: u64) -> u64 {
        if to >= from {
            to - from
        } else {
            (u64::MAX - from) + to + 1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_domain_name_hashing() {
        let hash1 = hash_domain_name("example.com");
        let hash2 = hash_domain_name("EXAMPLE.COM");
        let hash3 = hash_domain_name("example.com.");
        
        // All should be the same due to normalization
        assert_eq!(hash1, hash2);
        assert_eq!(hash1, hash3);
    }
    
    #[test]
    fn test_query_hashing() {
        let name_hash = hash_domain_name("example.com");
        let hash1 = hash_query(name_hash, 1, 1); // A record, IN class
        let hash2 = hash_query(name_hash, 28, 1); // AAAA record, IN class
        
        // Different record types should produce different hashes
        assert_ne!(hash1, hash2);
    }
    
    #[test]
    fn test_normalize_domain_name() {
        assert_eq!(normalize_domain_name("Example.COM"), "example.com");
        assert_eq!(normalize_domain_name("example.com."), "example.com");
        assert_eq!(normalize_domain_name("EXAMPLE.COM."), "example.com");
    }
    
    #[test]
    fn test_consistent_hash_ring() {
        let pos1 = consistent_hash::ring_position(12345);
        let pos2 = consistent_hash::next_position(pos1);
        let distance = consistent_hash::ring_distance(pos1, pos2);
        
        assert_eq!(distance, 1);
    }
}