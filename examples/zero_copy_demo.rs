//! Zero-copy DNS foundations demonstration
//!
//! This example demonstrates the key zero-copy components implemented:
//! 1. FlatBuffers schema for DNS records
//! 2. Zero-copy DNS packet parsing
//! 3. Hash-based indexing system
//! 4. Memory-mapped file utilities

use dns_core::hash::*;
use dns_protocol::ZeroCopyDnsParser;
use dns_storage::{HashDomainIndex, MmapDiskStorage};

use tempfile::TempDir;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    println!("🚀 Planet Scale DNS Server - Zero-Copy Foundations Demo");
    println!("========================================================");
    
    // 1. Demonstrate hash-based indexing
    println!("\n1. Hash-based Domain Indexing:");
    demo_hash_indexing().await?;
    
    // 2. Demonstrate zero-copy DNS packet parsing
    println!("\n2. Zero-Copy DNS Packet Parsing:");
    demo_packet_parsing().await?;
    
    // 3. Demonstrate memory-mapped storage
    println!("\n3. Memory-Mapped Zero-Copy Storage:");
    demo_mmap_storage().await?;
    
    // 4. Performance comparison
    println!("\n4. Performance Characteristics:");
    demo_performance().await?;
    
    println!("\n✅ Zero-copy foundations successfully demonstrated!");
    println!("   Ready for planet-scale DNS operations with minimal memory overhead.");
    
    Ok(())
}

async fn demo_hash_indexing() -> Result<(), Box<dyn std::error::Error>> {
    let index = HashDomainIndex::new();
    
    // Add some zones and domain mappings
    index.add_zone("example.com", 0x1000, 100)?;
    index.add_zone("test.org", 0x2000, 50)?;
    
    // Add domain mappings
    index.add_domain_mapping("www.example.com", "example.com")?;
    index.add_domain_mapping("api.example.com", "example.com")?;
    index.add_domain_mapping("*.test.org", "test.org")?;
    
    // Demonstrate O(1) hash-based lookups
    let domain_names = ["www.example.com", "api.example.com", "sub.test.org"];
    
    for domain in &domain_names {
        let domain_hash = hash_domain_name(domain);
        let zone_hash = index.lookup_zone_by_domain_hash(domain_hash);
        
        println!("  {} (hash: {}) -> zone hash: {:?}", 
                 domain, domain_hash, zone_hash);
        
        if let Some(zh) = zone_hash {
            if let Some(zone_data) = index.get_zone_data_pointer(zh) {
                println!("    Zone: {} ({} records, version: {})",
                         zone_data.zone_name,
                         zone_data.record_count.load(std::sync::atomic::Ordering::Relaxed),
                         zone_data.version.load(std::sync::atomic::Ordering::Relaxed));
            }
        }
    }
    
    let stats = index.get_statistics();
    println!("  Index stats: {} domains, {} zones, {:.1}% hit rate",
             stats.total_domains, stats.total_zones, stats.hit_rate);
    
    Ok(())
}

async fn demo_packet_parsing() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = ZeroCopyDnsParser::new();
    
    // Create a sample DNS query packet for example.com A record
    let query_packet = create_sample_dns_query();
    
    println!("  Original packet size: {} bytes", query_packet.len());
    
    // Parse with zero-copy operations
    let parsed = parser.parse_packet(&query_packet)?;
    println!("  Parsed packet size: {} bytes", parsed.len());
    
    // Demonstrate response building
    let records = vec![
        dns_protocol::DnsRecordData {
            name: "example.com".to_string(),
            record_type: 1, // A record
            class: 1,       // IN class
            ttl: 300,
            data: dns_protocol::RecordDataType::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        }
    ];
    
    let response = parser.build_response(&query_packet, &records)?;
    println!("  Response packet size: {} bytes", response.len());
    
    // Calculate hash for caching
    let query_hash = hash_query(
        hash_domain_name("example.com"),
        1, // A record
        1  // IN class
    );
    println!("  Query hash for caching: {}", query_hash);
    
    Ok(())
}

async fn demo_mmap_storage() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let storage = MmapDiskStorage::new(temp_dir.path())?;
    
    // Create some sample zone data
    let zone_data = b"example.com. 300 IN A 192.0.2.1\nexample.com. 300 IN NS ns1.example.com.\n";
    let zone_hash = hash_domain_name("example.com");
    
    println!("  Writing zone data ({} bytes) to memory-mapped file...", zone_data.len());
    
    // Write with zero-copy operations
    storage.write_zone_data(zone_hash, "example.com.zone", zone_data).await?;
    
    // Read back with zero-copy
    let read_data = storage.read_zone_data(zone_hash).await?;
    println!("  Read back {} bytes (zero-copy)", read_data.len());
    
    // Verify data integrity
    assert_eq!(&read_data[..], zone_data);
    println!("  ✓ Data integrity verified");
    
    // Get direct mapped file reference
    let mapped_file = storage.get_mapped_zone_file(zone_hash).unwrap();
    println!("  Mapped file: {} bytes, version: {}, access count: {}",
             mapped_file.size(),
             mapped_file.version(),
             mapped_file.access_count());
    
    let stats = storage.get_statistics();
    println!("  Storage stats: {} files, {} bytes total, {} reads, {} writes",
             stats.total_mapped_files,
             stats.total_mapped_bytes,
             stats.read_operations,
             stats.write_operations);
    
    Ok(())
}

async fn demo_performance() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Instant;
    
    // Hash-based lookup performance
    let start = Instant::now();
    let domain_names = vec!["example.com"; 10000000];
    let hashes: Vec<u64> = domain_names.iter().map(|name| hash_domain_name(name)).collect();
    let hash_time = start.elapsed();
    
    println!("  Hashed 10,000,000 domain names in {:?} ({:.2} ns/hash)",
             hash_time, hash_time.as_nanos() as f64 / 10000000.0);
    
    // Memory usage comparison
    let string_size = domain_names.iter().map(|s| s.len()).sum::<usize>();
    let hash_size = hashes.len() * 8; // 8 bytes per u64 hash
    
    println!("  Memory usage: {} bytes (strings) vs {} bytes (hashes) = {:.1}x reduction",
             string_size, hash_size, string_size as f64 / hash_size as f64);
    
    // Zero-copy benefits
    println!("  Zero-copy benefits:");
    println!("    - No string allocations during lookups");
    println!("    - No data copying for memory-mapped files");
    println!("    - Atomic operations for lock-free concurrency");
    println!("    - SIMD-ready hash-based operations");
    
    Ok(())
}

fn create_sample_dns_query() -> Vec<u8> {
    // Simple DNS query for example.com A record
    vec![
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // Question section: example.com
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00, // End of name
        0x00, 0x01, // Type: A (1)
        0x00, 0x01, // Class: IN (1)
    ]
}