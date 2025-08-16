//! DDoS protection with automatic blacklisting
//! 
//! Implements multi-layered DDoS protection including:
//! - Traffic pattern analysis
//! - Automatic blacklisting of malicious IPs
//! - Adaptive thresholds based on server load
//! - Bloom filter for fast blacklist lookups

use crate::{SecurityError, SecurityResult, current_timestamp_ms, hash_ip_address};
use lockfree::map::Map as LockFreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use bloom::{BloomFilter, ASMS};

/// DDoS protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosConfig {
    /// Queries per second threshold for suspicious activity
    pub suspicious_qps_threshold: u32,
    /// Queries per second threshold for automatic blacklisting
    pub blacklist_qps_threshold: u32,
    /// Time window for rate calculation (seconds)
    pub rate_window_seconds: u32,
    /// Blacklist duration (seconds)
    pub blacklist_duration_seconds: u64,
    /// Maximum packet size before considering suspicious
    pub max_packet_size: usize,
    /// Bloom filter capacity for blacklist
    pub bloom_filter_capacity: usize,
    /// Bloom filter false positive rate
    pub bloom_filter_fpr: f64,
    /// Enable adaptive thresholds based on server load
    pub adaptive_thresholds: bool,
    /// Maximum number of tracked IPs
    pub max_tracked_ips: usize,
}

impl Default for DdosConfig {
    fn default() -> Self {
        Self {
            suspicious_qps_threshold: 100,
            blacklist_qps_threshold: 500,
            rate_window_seconds: 60,
            blacklist_duration_seconds: 3600, // 1 hour
            max_packet_size: 4096,
            bloom_filter_capacity: 1000000,
            bloom_filter_fpr: 0.01,
            adaptive_thresholds: true,
            max_tracked_ips: 100000,
        }
    }
}

/// Threat level assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatLevel {
    /// Normal traffic
    Normal,
    /// Suspicious but not blocked
    Suspicious,
    /// Temporarily blocked
    Blocked,
    /// Permanently blacklisted
    Blacklisted,
}

impl ThreatLevel {
    pub fn is_blocked(&self) -> bool {
        matches!(self, ThreatLevel::Blocked | ThreatLevel::Blacklisted)
    }

    pub fn is_suspicious(&self) -> bool {
        matches!(self, ThreatLevel::Suspicious | ThreatLevel::Blocked | ThreatLevel::Blacklisted)
    }
}

/// Traffic statistics for an IP address
struct IpTrafficStats {
    /// Query count in current window
    query_count: AtomicU32,
    /// Total bytes received in current window
    bytes_received: AtomicU64,
    /// Window start timestamp
    window_start: AtomicU64,
    /// Last query timestamp
    last_query: AtomicU64,
    /// Current threat level
    threat_level: AtomicU32, // ThreatLevel as u32
    /// Blacklist expiry timestamp (0 if not blacklisted)
    blacklist_expiry: AtomicU64,
    /// Suspicious activity counter
    suspicious_count: AtomicU32,
}

impl IpTrafficStats {
    fn new() -> Self {
        let now = current_timestamp_ms();
        Self {
            query_count: AtomicU32::new(0),
            bytes_received: AtomicU64::new(0),
            window_start: AtomicU64::new(now),
            last_query: AtomicU64::new(now),
            threat_level: AtomicU32::new(ThreatLevel::Normal as u32),
            blacklist_expiry: AtomicU64::new(0),
            suspicious_count: AtomicU32::new(0),
        }
    }

    fn get_threat_level(&self) -> ThreatLevel {
        match self.threat_level.load(Ordering::Relaxed) {
            0 => ThreatLevel::Normal,
            1 => ThreatLevel::Suspicious,
            2 => ThreatLevel::Blocked,
            3 => ThreatLevel::Blacklisted,
            _ => ThreatLevel::Normal,
        }
    }

    fn set_threat_level(&self, level: ThreatLevel) {
        self.threat_level.store(level as u32, Ordering::Relaxed);
    }

    fn is_blacklisted(&self, now: u64) -> bool {
        let expiry = self.blacklist_expiry.load(Ordering::Relaxed);
        expiry > 0 && now < expiry
    }

    fn blacklist_until(&self, expiry: u64) {
        self.blacklist_expiry.store(expiry, Ordering::Relaxed);
        self.set_threat_level(ThreatLevel::Blacklisted);
    }

    fn clear_blacklist(&self) {
        self.blacklist_expiry.store(0, Ordering::Relaxed);
        self.set_threat_level(ThreatLevel::Normal);
    }
}

/// DDoS protection engine
pub struct DdosProtection {
    /// Configuration
    config: DdosConfig,
    /// Per-IP traffic statistics
    ip_stats: Arc<LockFreeMap<u64, Arc<IpTrafficStats>>>,
    /// Bloom filter for fast blacklist lookups
    blacklist_bloom: parking_lot::RwLock<BloomFilter>,
    /// Global statistics
    stats: Arc<DdosStats>,
    /// Last cleanup timestamp
    last_cleanup: AtomicU64,
}

impl DdosProtection {
    pub fn new(config: DdosConfig) -> SecurityResult<Self> {
        let bloom_filter = BloomFilter::with_rate(
            config.bloom_filter_fpr as f32,
            config.bloom_filter_capacity as u32,
        );

        Ok(Self {
            config,
            ip_stats: Arc::new(LockFreeMap::new()),
            blacklist_bloom: parking_lot::RwLock::new(bloom_filter),
            stats: Arc::new(DdosStats::new()),
            last_cleanup: AtomicU64::new(current_timestamp_ms()),
        })
    }

    /// Assess threat level for an IP address
    pub async fn assess_threat(&self, client_ip: IpAddr, packet_size: usize) -> SecurityResult<ThreatLevel> {
        let now = current_timestamp_ms();
        let ip_hash = hash_ip_address(client_ip);

        // Quick bloom filter check for blacklisted IPs (may have false positives)
        if self.is_blacklisted_bloom(ip_hash) {
            // Verify with actual IP stats
            if let Some(ip_stats) = self.ip_stats.get(&ip_hash) {
                if ip_stats.val().is_blacklisted(now) {
                    self.stats.blacklist_hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(ThreatLevel::Blacklisted);
                }
            }
        }

        // Check packet size
        if packet_size > self.config.max_packet_size {
            self.stats.oversized_packets.fetch_add(1, Ordering::Relaxed);
            return Ok(ThreatLevel::Suspicious);
        }

        // Get or create IP statistics
        let ip_stats = self.get_or_create_ip_stats(ip_hash).await?;

        // Check if currently blacklisted
        if ip_stats.is_blacklisted(now) {
            return Ok(ThreatLevel::Blacklisted);
        }

        // Update traffic statistics
        self.update_traffic_stats(&ip_stats, now, packet_size).await?;

        // Calculate current query rate
        let qps = self.calculate_qps(&ip_stats, now);

        // Determine threat level based on query rate
        let threat_level = if qps >= self.get_blacklist_threshold() {
            // Automatic blacklisting
            let expiry = now + (self.config.blacklist_duration_seconds * 1000);
            ip_stats.blacklist_until(expiry);
            self.add_to_blacklist_bloom(ip_hash);
            self.stats.ips_blacklisted.fetch_add(1, Ordering::Relaxed);
            ThreatLevel::Blacklisted
        } else if qps >= self.get_suspicious_threshold() {
            ip_stats.suspicious_count.fetch_add(1, Ordering::Relaxed);
            self.stats.suspicious_activity.fetch_add(1, Ordering::Relaxed);
            ThreatLevel::Suspicious
        } else {
            ThreatLevel::Normal
        };

        ip_stats.set_threat_level(threat_level);
        Ok(threat_level)
    }

    /// Get or create IP statistics
    async fn get_or_create_ip_stats(&self, ip_hash: u64) -> SecurityResult<Arc<IpTrafficStats>> {
        // Try to get existing stats
        if let Some(stats) = self.ip_stats.get(&ip_hash) {
            return Ok(stats.val().clone());
        }

        // Create new stats
        let stats = Arc::new(IpTrafficStats::new());
        
        if let Some(_) = self.ip_stats.insert(ip_hash, stats.clone()) {
            // Key already existed, use the existing one
            Ok(self.ip_stats.get(&ip_hash)
                .ok_or_else(|| SecurityError::internal_error("IP stats disappeared after insert"))?
                .val().clone())
        } else {
            // Successfully inserted new stats
            self.stats.tracked_ips.fetch_add(1, Ordering::Relaxed);
            Ok(stats)
        }
    }

    /// Update traffic statistics for an IP
    async fn update_traffic_stats(
        &self,
        stats: &IpTrafficStats,
        now: u64,
        packet_size: usize,
    ) -> SecurityResult<()> {
        stats.last_query.store(now, Ordering::Relaxed);

        // Check if we need to reset the window
        let window_start = stats.window_start.load(Ordering::Relaxed);
        let window_duration_ms = self.config.rate_window_seconds as u64 * 1000;

        if now - window_start >= window_duration_ms {
            // Reset window
            stats.window_start.store(now, Ordering::Relaxed);
            stats.query_count.store(1, Ordering::Relaxed);
            stats.bytes_received.store(packet_size as u64, Ordering::Relaxed);
        } else {
            // Update counters
            stats.query_count.fetch_add(1, Ordering::Relaxed);
            stats.bytes_received.fetch_add(packet_size as u64, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Calculate queries per second for an IP
    fn calculate_qps(&self, stats: &IpTrafficStats, now: u64) -> u32 {
        let window_start = stats.window_start.load(Ordering::Relaxed);
        let query_count = stats.query_count.load(Ordering::Relaxed);
        
        let elapsed_seconds = ((now - window_start) / 1000).max(1);
        query_count / elapsed_seconds as u32
    }

    /// Get suspicious threshold (may be adaptive)
    fn get_suspicious_threshold(&self) -> u32 {
        if self.config.adaptive_thresholds {
            // TODO: Implement adaptive thresholds based on server load
            self.config.suspicious_qps_threshold
        } else {
            self.config.suspicious_qps_threshold
        }
    }

    /// Get blacklist threshold (may be adaptive)
    fn get_blacklist_threshold(&self) -> u32 {
        if self.config.adaptive_thresholds {
            // TODO: Implement adaptive thresholds based on server load
            self.config.blacklist_qps_threshold
        } else {
            self.config.blacklist_qps_threshold
        }
    }

    /// Check if IP is in blacklist bloom filter
    fn is_blacklisted_bloom(&self, ip_hash: u64) -> bool {
        let bloom = self.blacklist_bloom.read();
        bloom.contains(&ip_hash)
    }

    /// Add IP to blacklist bloom filter
    fn add_to_blacklist_bloom(&self, ip_hash: u64) {
        let mut bloom = self.blacklist_bloom.write();
        bloom.insert(&ip_hash);
    }

    /// Clean up old IP statistics
    async fn cleanup_old_stats(&self) -> SecurityResult<()> {
        let now = current_timestamp_ms();
        let last_cleanup = self.last_cleanup.load(Ordering::Relaxed);
        
        // Only cleanup every 5 minutes
        if now - last_cleanup < 300_000 {
            return Ok(());
        }

        if self.last_cleanup.compare_exchange_weak(
            last_cleanup,
            now,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ).is_err() {
            return Ok(()); // Another thread is cleaning up
        }

        let cleanup_threshold = now - 3600_000; // 1 hour old
        let mut removed_count = 0;
        let mut keys_to_remove = Vec::new();

        // Collect keys for removal
        for entry in self.ip_stats.iter() {
            let stats = entry.val();
            let last_query = stats.last_query.load(Ordering::Relaxed);
            if last_query < cleanup_threshold && !stats.is_blacklisted(now) {
                keys_to_remove.push(*entry.key());
            }
        }

        // Remove old stats
        for key in keys_to_remove {
            if self.ip_stats.remove(&key).is_some() {
                removed_count += 1;
            }
        }

        if removed_count > 0 {
            self.stats.tracked_ips.fetch_sub(removed_count, Ordering::Relaxed);
        }
        self.stats.cleanup_operations.fetch_add(1, Ordering::Relaxed);

        tracing::debug!("DDoS protection cleanup removed {} old IP stats", removed_count);
        Ok(())
    }

    /// Manually blacklist an IP
    pub async fn blacklist_ip(&self, client_ip: IpAddr, duration_seconds: u64) -> SecurityResult<()> {
        let ip_hash = hash_ip_address(client_ip);
        let now = current_timestamp_ms();
        let expiry = now + (duration_seconds * 1000);

        let stats = self.get_or_create_ip_stats(ip_hash).await?;
        stats.blacklist_until(expiry);
        self.add_to_blacklist_bloom(ip_hash);

        self.stats.manual_blacklists.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Remove IP from blacklist
    pub async fn unblacklist_ip(&self, client_ip: IpAddr) -> SecurityResult<()> {
        let ip_hash = hash_ip_address(client_ip);
        
        if let Some(stats) = self.ip_stats.get(&ip_hash) {
            stats.val().clear_blacklist();
        }

        // Note: We can't remove from bloom filter, but the IP stats will override it
        self.stats.manual_unblacklists.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> SecurityResult<DdosStats> {
        Ok(self.stats.snapshot())
    }
}

/// DDoS protection statistics
#[derive(Debug)]
pub struct DdosStats {
    /// Number of blacklist hits (bloom filter)
    pub blacklist_hits: AtomicU64,
    /// Number of IPs automatically blacklisted
    pub ips_blacklisted: AtomicU64,
    /// Number of suspicious activity detections
    pub suspicious_activity: AtomicU64,
    /// Number of oversized packets detected
    pub oversized_packets: AtomicU64,
    /// Number of currently tracked IPs
    pub tracked_ips: AtomicU64,
    /// Number of manual blacklists
    pub manual_blacklists: AtomicU64,
    /// Number of manual unblacklists
    pub manual_unblacklists: AtomicU64,
    /// Number of cleanup operations
    pub cleanup_operations: AtomicU64,
    /// Statistics creation timestamp
    pub created_at: AtomicU64,
}

impl DdosStats {
    pub fn new() -> Self {
        Self {
            blacklist_hits: AtomicU64::new(0),
            ips_blacklisted: AtomicU64::new(0),
            suspicious_activity: AtomicU64::new(0),
            oversized_packets: AtomicU64::new(0),
            tracked_ips: AtomicU64::new(0),
            manual_blacklists: AtomicU64::new(0),
            manual_unblacklists: AtomicU64::new(0),
            cleanup_operations: AtomicU64::new(0),
            created_at: AtomicU64::new(current_timestamp_ms()),
        }
    }

    pub fn snapshot(&self) -> Self {
        Self {
            blacklist_hits: AtomicU64::new(self.blacklist_hits.load(Ordering::Relaxed)),
            ips_blacklisted: AtomicU64::new(self.ips_blacklisted.load(Ordering::Relaxed)),
            suspicious_activity: AtomicU64::new(self.suspicious_activity.load(Ordering::Relaxed)),
            oversized_packets: AtomicU64::new(self.oversized_packets.load(Ordering::Relaxed)),
            tracked_ips: AtomicU64::new(self.tracked_ips.load(Ordering::Relaxed)),
            manual_blacklists: AtomicU64::new(self.manual_blacklists.load(Ordering::Relaxed)),
            manual_unblacklists: AtomicU64::new(self.manual_unblacklists.load(Ordering::Relaxed)),
            cleanup_operations: AtomicU64::new(self.cleanup_operations.load(Ordering::Relaxed)),
            created_at: AtomicU64::new(self.created_at.load(Ordering::Relaxed)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_normal_traffic() {
        let config = DdosConfig::default();
        let ddos = DdosProtection::new(config).unwrap();
        let client = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Normal traffic should not be blocked
        for _ in 0..10 {
            let threat = ddos.assess_threat(client, 100).await.unwrap();
            assert_eq!(threat, ThreatLevel::Normal);
        }
    }

    #[tokio::test]
    async fn test_oversized_packet() {
        let config = DdosConfig {
            max_packet_size: 1000,
            ..Default::default()
        };
        let ddos = DdosProtection::new(config).unwrap();
        let client = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Oversized packet should be suspicious
        let threat = ddos.assess_threat(client, 2000).await.unwrap();
        assert_eq!(threat, ThreatLevel::Suspicious);
    }

    #[tokio::test]
    async fn test_manual_blacklist() {
        let config = DdosConfig::default();
        let ddos = DdosProtection::new(config).unwrap();
        let client = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Manually blacklist IP
        ddos.blacklist_ip(client, 3600).await.unwrap();

        // Should be blacklisted
        let threat = ddos.assess_threat(client, 100).await.unwrap();
        assert_eq!(threat, ThreatLevel::Blacklisted);

        // Unblacklist
        ddos.unblacklist_ip(client).await.unwrap();

        // Should be normal again
        let threat = ddos.assess_threat(client, 100).await.unwrap();
        assert_eq!(threat, ThreatLevel::Normal);
    }
}