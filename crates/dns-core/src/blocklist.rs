//! Advanced Ad-Blocking Engine with atomic operations and SIMD optimization
//!
//! This module implements a high-performance ad-blocking system using:
//! - Atomic bloom filters for fast negative lookups
//! - SIMD-optimized domain pattern matching
//! - Automatic blocklist updates from remote sources
//! - Whitelist override functionality with atomic operations
//! - Custom block response generation
//! - Comprehensive analytics and logging

use crate::{DnsError, DnsResult, AtomicHasher};
use bytes::Bytes;
use lockfree::map::Map as LockFreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{error, info, warn};

#[cfg(feature = "simd")]
use wide::*;

/// Configuration for the ad-blocking engine
#[derive(Debug, Clone)]
pub struct BlocklistConfig {
    /// Maximum number of domains in the blocklist
    pub max_domains: usize,
    /// Bloom filter false positive rate (0.01 = 1%)
    pub bloom_filter_fpr: f64,
    /// Enable SIMD optimizations
    pub enable_simd: bool,
    /// Automatic update interval in seconds
    pub update_interval_secs: u64,
    /// Remote blocklist sources
    pub remote_sources: Vec<BlocklistSource>,
    /// Default block response type
    pub default_block_response: BlockResponse,
    /// Enable analytics collection
    pub enable_analytics: bool,
    /// Maximum analytics entries to keep in memory
    pub max_analytics_entries: usize,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            max_domains: 10_000_000, // 10M domains
            bloom_filter_fpr: 0.01,  // 1% false positive rate
            enable_simd: true,
            update_interval_secs: 3600, // 1 hour
            remote_sources: Vec::new(),
            default_block_response: BlockResponse::NxDomain,
            enable_analytics: true,
            max_analytics_entries: 100_000,
        }
    }
}

/// Remote blocklist source configuration
#[derive(Debug, Clone)]
pub struct BlocklistSource {
    pub name: String,
    pub url: String,
    pub format: BlocklistFormat,
    pub enabled: bool,
    pub priority: u8, // Higher priority sources override lower ones
}

/// Supported blocklist formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlocklistFormat {
    /// Plain text, one domain per line
    PlainText,
    /// Hosts file format (127.0.0.1 domain.com)
    HostsFile,
    /// AdBlock Plus format
    AdBlockPlus,
    /// Pi-hole format
    PiHole,
}

/// Block response types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockResponse {
    /// Return NXDOMAIN
    NxDomain,
    /// Redirect to localhost (127.0.0.1)
    Localhost,
    /// Redirect to specific IP address
    CustomIp(IpAddr),
    /// Return empty response
    Empty,
}

/// Atomic bloom filter for fast negative lookups
pub struct AtomicBloomFilter {
    /// Bit array for the bloom filter
    bits: Vec<AtomicU64>,
    /// Number of hash functions
    num_hashes: usize,
    /// Size of the bit array in bits
    size_bits: usize,
    /// Number of elements added
    count: AtomicUsize,
    /// Expected false positive rate
    fpr: f64,
}

impl AtomicBloomFilter {
    /// Create a new atomic bloom filter
    pub fn new(expected_elements: usize, fpr: f64) -> Self {
        let size_bits = Self::optimal_size(expected_elements, fpr);
        let num_hashes = Self::optimal_hash_count(size_bits, expected_elements);
        let num_u64s = (size_bits + 63) / 64; // Round up to nearest u64

        let bits = (0..num_u64s)
            .map(|_| AtomicU64::new(0))
            .collect();

        Self {
            bits,
            num_hashes,
            size_bits,
            count: AtomicUsize::new(0),
            fpr,
        }
    }

    /// Calculate optimal bloom filter size
    fn optimal_size(expected_elements: usize, fpr: f64) -> usize {
        let ln2_squared = std::f64::consts::LN_2 * std::f64::consts::LN_2;
        (-(expected_elements as f64) * fpr.ln() / ln2_squared).ceil() as usize
    }

    /// Calculate optimal number of hash functions
    fn optimal_hash_count(size_bits: usize, expected_elements: usize) -> usize {
        ((size_bits as f64 / expected_elements as f64) * std::f64::consts::LN_2).ceil() as usize
    }

    /// Add a domain hash to the bloom filter atomically
    pub fn add_atomic(&self, domain_hash: u64) -> bool {
        let hashes = self.generate_hashes(domain_hash);
        
        for &hash in &hashes {
            let bit_index = hash % self.size_bits as u64;
            let word_index = bit_index / 64;
            let bit_offset = bit_index % 64;
            
            if word_index < self.bits.len() as u64 {
                self.bits[word_index as usize].fetch_or(1u64 << bit_offset, Ordering::Relaxed);
            }
        }
        
        self.count.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Check if a domain hash might be in the bloom filter
    pub fn contains_atomic(&self, domain_hash: u64) -> bool {
        let hashes = self.generate_hashes(domain_hash);
        
        for &hash in &hashes {
            let bit_index = hash % self.size_bits as u64;
            let word_index = bit_index / 64;
            let bit_offset = bit_index % 64;
            
            if word_index < self.bits.len() as u64 {
                let word = self.bits[word_index as usize].load(Ordering::Relaxed);
                if (word & (1u64 << bit_offset)) == 0 {
                    return false; // Definitely not in set
                }
            } else {
                return false;
            }
        }
        
        true // Might be in set (could be false positive)
    }

    /// Generate multiple hash values for a domain
    fn generate_hashes(&self, domain_hash: u64) -> Vec<u64> {
        let mut hashes = Vec::with_capacity(self.num_hashes);
        
        // Use double hashing: h1(x) + i * h2(x)
        let h1 = domain_hash;
        let h2 = domain_hash.wrapping_mul(0x9e3779b97f4a7c15); // Golden ratio hash
        
        for i in 0..self.num_hashes {
            let hash = h1.wrapping_add((i as u64).wrapping_mul(h2));
            hashes.push(hash);
        }
        
        hashes
    }

    /// Get current statistics
    pub fn stats(&self) -> BloomFilterStats {
        let count = self.count.load(Ordering::Relaxed);
        let estimated_fpr = if count > 0 {
            (1.0 - (-((self.num_hashes as f64) * (count as f64) / (self.size_bits as f64))).exp()).powi(self.num_hashes as i32)
        } else {
            0.0
        };

        BloomFilterStats {
            size_bits: self.size_bits,
            num_hashes: self.num_hashes,
            count,
            estimated_fpr,
            configured_fpr: self.fpr,
        }
    }

    /// Clear the bloom filter
    pub fn clear(&self) {
        for bit in &self.bits {
            bit.store(0, Ordering::Relaxed);
        }
        self.count.store(0, Ordering::Relaxed);
    }
}

/// Bloom filter statistics
#[derive(Debug, Clone)]
pub struct BloomFilterStats {
    pub size_bits: usize,
    pub num_hashes: usize,
    pub count: usize,
    pub estimated_fpr: f64,
    pub configured_fpr: f64,
}

/// SIMD-optimized domain pattern matcher
pub struct SimdPatternMatcher {
    /// Compiled patterns for SIMD matching
    patterns: Vec<SimdPattern>,
    /// Enable SIMD optimizations
    simd_enabled: bool,
}

/// SIMD pattern for domain matching
#[derive(Debug, Clone)]
pub struct SimdPattern {
    /// Pattern hash for quick comparison
    pub hash: u64,
    /// Pattern bytes for SIMD comparison
    pub bytes: Vec<u8>,
    /// Pattern type (exact, wildcard, regex)
    pub pattern_type: PatternType,
}

/// Pattern matching types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternType {
    /// Exact domain match
    Exact,
    /// Wildcard pattern (*.example.com)
    Wildcard,
    /// Subdomain match (blocks all subdomains)
    Subdomain,
}

impl SimdPatternMatcher {
    /// Create a new SIMD pattern matcher
    pub fn new(simd_enabled: bool) -> Self {
        Self {
            patterns: Vec::new(),
            simd_enabled,
        }
    }

    /// Add a pattern to the matcher
    pub fn add_pattern(&mut self, domain: &str, pattern_type: PatternType) {
        let normalized = domain.to_lowercase();
        let hash = AtomicHasher::hash_domain(&normalized);
        let bytes = normalized.into_bytes();

        let pattern = SimdPattern {
            hash,
            bytes,
            pattern_type,
        };

        self.patterns.push(pattern);
    }

    /// Check if a domain matches any pattern using SIMD optimization
    pub fn matches(&self, domain_hash: u64, domain: &str) -> Option<&SimdPattern> {
        // First, try hash-based exact matching (fastest)
        for pattern in &self.patterns {
            if pattern.pattern_type == PatternType::Exact && pattern.hash == domain_hash {
                return Some(pattern);
            }
        }

        // Then try SIMD-optimized pattern matching
        if self.simd_enabled {
            self.simd_match(domain)
        } else {
            self.scalar_match(domain)
        }
    }

    #[cfg(feature = "simd")]
    /// SIMD-optimized pattern matching
    fn simd_match(&self, domain: &str) -> Option<&SimdPattern> {
        let domain_bytes = domain.as_bytes();
        
        for pattern in &self.patterns {
            match pattern.pattern_type {
                PatternType::Exact => {
                    if self.simd_exact_match(domain_bytes, &pattern.bytes) {
                        return Some(pattern);
                    }
                }
                PatternType::Wildcard => {
                    if self.simd_wildcard_match(domain_bytes, &pattern.bytes) {
                        return Some(pattern);
                    }
                }
                PatternType::Subdomain => {
                    if self.simd_subdomain_match(domain_bytes, &pattern.bytes) {
                        return Some(pattern);
                    }
                }
            }
        }
        
        None
    }

    #[cfg(not(feature = "simd"))]
    /// SIMD-optimized pattern matching (fallback to scalar)
    fn simd_match(&self, domain: &str) -> Option<&SimdPattern> {
        self.scalar_match(domain)
    }

    /// Scalar pattern matching fallback
    fn scalar_match(&self, domain: &str) -> Option<&SimdPattern> {
        for pattern in &self.patterns {
            match pattern.pattern_type {
                PatternType::Exact => {
                    if domain.as_bytes() == pattern.bytes {
                        return Some(pattern);
                    }
                }
                PatternType::Wildcard => {
                    if self.wildcard_match(domain, &String::from_utf8_lossy(&pattern.bytes)) {
                        return Some(pattern);
                    }
                }
                PatternType::Subdomain => {
                    if self.subdomain_match(domain, &String::from_utf8_lossy(&pattern.bytes)) {
                        return Some(pattern);
                    }
                }
            }
        }
        
        None
    }

    #[cfg(feature = "simd")]
    /// SIMD exact match using vectorized comparison
    fn simd_exact_match(&self, domain: &[u8], pattern: &[u8]) -> bool {
        if domain.len() != pattern.len() {
            return false;
        }

        let len = domain.len();
        let simd_len = len & !31; // Process 32 bytes at a time

        // SIMD comparison for bulk of the data
        for i in (0..simd_len).step_by(32) {
            let domain_chunk = u8x32::new([
                domain[i], domain[i+1], domain[i+2], domain[i+3],
                domain[i+4], domain[i+5], domain[i+6], domain[i+7],
                domain[i+8], domain[i+9], domain[i+10], domain[i+11],
                domain[i+12], domain[i+13], domain[i+14], domain[i+15],
                domain[i+16], domain[i+17], domain[i+18], domain[i+19],
                domain[i+20], domain[i+21], domain[i+22], domain[i+23],
                domain[i+24], domain[i+25], domain[i+26], domain[i+27],
                domain[i+28], domain[i+29], domain[i+30], domain[i+31],
            ]);
            
            let pattern_chunk = u8x32::new([
                pattern[i], pattern[i+1], pattern[i+2], pattern[i+3],
                pattern[i+4], pattern[i+5], pattern[i+6], pattern[i+7],
                pattern[i+8], pattern[i+9], pattern[i+10], pattern[i+11],
                pattern[i+12], pattern[i+13], pattern[i+14], pattern[i+15],
                pattern[i+16], pattern[i+17], pattern[i+18], pattern[i+19],
                pattern[i+20], pattern[i+21], pattern[i+22], pattern[i+23],
                pattern[i+24], pattern[i+25], pattern[i+26], pattern[i+27],
                pattern[i+28], pattern[i+29], pattern[i+30], pattern[i+31],
            ]);

            if domain_chunk != pattern_chunk {
                return false;
            }
        }

        // Handle remaining bytes
        for i in simd_len..len {
            if domain[i] != pattern[i] {
                return false;
            }
        }

        true
    }

    #[cfg(feature = "simd")]
    /// SIMD wildcard matching
    fn simd_wildcard_match(&self, domain: &[u8], pattern: &[u8]) -> bool {
        // Simple wildcard implementation - can be enhanced with more sophisticated SIMD algorithms
        let pattern_str = String::from_utf8_lossy(pattern);
        let domain_str = String::from_utf8_lossy(domain);
        self.wildcard_match(&domain_str, &pattern_str)
    }

    #[cfg(feature = "simd")]
    /// SIMD subdomain matching
    fn simd_subdomain_match(&self, domain: &[u8], pattern: &[u8]) -> bool {
        let pattern_str = String::from_utf8_lossy(pattern);
        let domain_str = String::from_utf8_lossy(domain);
        self.subdomain_match(&domain_str, &pattern_str)
    }

    /// Wildcard pattern matching
    fn wildcard_match(&self, domain: &str, pattern: &str) -> bool {
        if pattern.starts_with("*.") {
            let suffix = &pattern[2..];
            domain.ends_with(suffix) && (domain == suffix || domain.ends_with(&format!(".{}", suffix)))
        } else {
            domain == pattern
        }
    }

    /// Subdomain pattern matching
    fn subdomain_match(&self, domain: &str, pattern: &str) -> bool {
        domain == pattern || domain.ends_with(&format!(".{}", pattern))
    }

    /// Get pattern statistics
    pub fn stats(&self) -> PatternMatcherStats {
        let exact_count = self.patterns.iter().filter(|p| p.pattern_type == PatternType::Exact).count();
        let wildcard_count = self.patterns.iter().filter(|p| p.pattern_type == PatternType::Wildcard).count();
        let subdomain_count = self.patterns.iter().filter(|p| p.pattern_type == PatternType::Subdomain).count();

        PatternMatcherStats {
            total_patterns: self.patterns.len(),
            exact_patterns: exact_count,
            wildcard_patterns: wildcard_count,
            subdomain_patterns: subdomain_count,
            simd_enabled: self.simd_enabled,
        }
    }

    /// Clear all patterns
    pub fn clear(&mut self) {
        self.patterns.clear();
    }
}

/// Pattern matcher statistics
#[derive(Debug, Clone)]
pub struct PatternMatcherStats {
    pub total_patterns: usize,
    pub exact_patterns: usize,
    pub wildcard_patterns: usize,
    pub subdomain_patterns: usize,
    pub simd_enabled: bool,
}

/// Blocklist analytics entry
#[derive(Debug, Clone)]
pub struct BlocklistAnalytics {
    pub timestamp: u64,
    pub domain: String,
    pub domain_hash: u64,
    pub client_ip: IpAddr,
    pub query_type: u16,
    pub block_reason: BlockReason,
    pub response_type: BlockResponse,
}

/// Reason for blocking a domain
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    /// Blocked by exact domain match
    ExactMatch,
    /// Blocked by wildcard pattern
    WildcardMatch,
    /// Blocked by subdomain rule
    SubdomainMatch,
    /// Blocked by bloom filter (might be false positive)
    BloomFilter,
}

/// Atomic blocklist analytics collector
pub struct AtomicBlocklistAnalytics {
    /// Analytics entries (ring buffer)
    entries: RwLock<Vec<BlocklistAnalytics>>,
    /// Current write position
    write_pos: AtomicUsize,
    /// Maximum entries to keep
    max_entries: usize,
    /// Total blocks counter
    total_blocks: AtomicU64,
    /// Blocks by reason counters
    exact_blocks: AtomicU64,
    wildcard_blocks: AtomicU64,
    subdomain_blocks: AtomicU64,
    bloom_blocks: AtomicU64,
    /// Analytics enabled flag
    enabled: AtomicBool,
}

impl AtomicBlocklistAnalytics {
    /// Create new analytics collector
    pub fn new(max_entries: usize, enabled: bool) -> Self {
        Self {
            entries: RwLock::new(Vec::with_capacity(max_entries)),
            write_pos: AtomicUsize::new(0),
            max_entries,
            total_blocks: AtomicU64::new(0),
            exact_blocks: AtomicU64::new(0),
            wildcard_blocks: AtomicU64::new(0),
            subdomain_blocks: AtomicU64::new(0),
            bloom_blocks: AtomicU64::new(0),
            enabled: AtomicBool::new(enabled),
        }
    }

    /// Record a blocked query
    pub async fn record_block(&self, analytics: BlocklistAnalytics) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }

        // Update counters atomically
        self.total_blocks.fetch_add(1, Ordering::Relaxed);
        match analytics.block_reason {
            BlockReason::ExactMatch => self.exact_blocks.fetch_add(1, Ordering::Relaxed),
            BlockReason::WildcardMatch => self.wildcard_blocks.fetch_add(1, Ordering::Relaxed),
            BlockReason::SubdomainMatch => self.subdomain_blocks.fetch_add(1, Ordering::Relaxed),
            BlockReason::BloomFilter => self.bloom_blocks.fetch_add(1, Ordering::Relaxed),
        };

        // Add to ring buffer
        let mut entries = self.entries.write().await;
        let pos = self.write_pos.fetch_add(1, Ordering::Relaxed) % self.max_entries;
        
        if entries.len() <= pos {
            entries.resize(pos + 1, analytics.clone());
        }
        entries[pos] = analytics;
    }

    /// Get analytics statistics
    pub fn stats(&self) -> AnalyticsStats {
        AnalyticsStats {
            total_blocks: self.total_blocks.load(Ordering::Relaxed),
            exact_blocks: self.exact_blocks.load(Ordering::Relaxed),
            wildcard_blocks: self.wildcard_blocks.load(Ordering::Relaxed),
            subdomain_blocks: self.subdomain_blocks.load(Ordering::Relaxed),
            bloom_blocks: self.bloom_blocks.load(Ordering::Relaxed),
            enabled: self.enabled.load(Ordering::Relaxed),
        }
    }

    /// Get recent blocked domains
    pub async fn recent_blocks(&self, limit: usize) -> Vec<BlocklistAnalytics> {
        let entries = self.entries.read().await;
        let current_pos = self.write_pos.load(Ordering::Relaxed);
        let start_pos = if current_pos >= limit { current_pos - limit } else { 0 };
        
        entries.iter()
            .skip(start_pos)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Enable or disable analytics
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Clear all analytics data
    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
        self.write_pos.store(0, Ordering::Relaxed);
        self.total_blocks.store(0, Ordering::Relaxed);
        self.exact_blocks.store(0, Ordering::Relaxed);
        self.wildcard_blocks.store(0, Ordering::Relaxed);
        self.subdomain_blocks.store(0, Ordering::Relaxed);
        self.bloom_blocks.store(0, Ordering::Relaxed);
    }
}

/// Analytics statistics
#[derive(Debug, Clone)]
pub struct AnalyticsStats {
    pub total_blocks: u64,
    pub exact_blocks: u64,
    pub wildcard_blocks: u64,
    pub subdomain_blocks: u64,
    pub bloom_blocks: u64,
    pub enabled: bool,
}

/// Main atomic blocklist engine
pub struct AtomicBlocklistEngine {
    /// Configuration
    config: Arc<BlocklistConfig>,
    
    /// Atomic bloom filter for fast negative lookups
    bloom_filter: Arc<AtomicBloomFilter>,
    
    /// SIMD pattern matcher for complex patterns
    pattern_matcher: Arc<RwLock<SimdPatternMatcher>>,
    
    /// Whitelist domains (atomic hash set)
    whitelist: Arc<LockFreeMap<u64, Arc<str>>>,
    
    /// Custom block responses per domain
    custom_responses: Arc<LockFreeMap<u64, BlockResponse>>,
    
    /// Analytics collector
    analytics: Arc<AtomicBlocklistAnalytics>,
    
    /// Update manager for remote sources
    update_manager: Arc<BlocklistUpdateManager>,
    
    /// Engine statistics
    stats: Arc<AtomicBlocklistStats>,
    
    /// Engine enabled flag
    enabled: AtomicBool,
}

impl AtomicBlocklistEngine {
    /// Create a new atomic blocklist engine
    pub async fn new(config: BlocklistConfig) -> DnsResult<Self> {
        let bloom_filter = Arc::new(AtomicBloomFilter::new(
            config.max_domains,
            config.bloom_filter_fpr,
        ));

        let pattern_matcher = Arc::new(RwLock::new(
            SimdPatternMatcher::new(config.enable_simd)
        ));

        let analytics = Arc::new(AtomicBlocklistAnalytics::new(
            config.max_analytics_entries,
            config.enable_analytics,
        ));

        let update_manager = Arc::new(BlocklistUpdateManager::new(
            config.remote_sources.clone(),
            config.update_interval_secs,
        ));

        let stats = Arc::new(AtomicBlocklistStats::new());

        let engine = Self {
            config: Arc::new(config),
            bloom_filter,
            pattern_matcher,
            whitelist: Arc::new(LockFreeMap::new()),
            custom_responses: Arc::new(LockFreeMap::new()),
            analytics,
            update_manager,
            stats,
            enabled: AtomicBool::new(true),
        };

        // Start automatic updates if configured
        if !engine.config.remote_sources.is_empty() {
            engine.start_automatic_updates().await?;
        }

        Ok(engine)
    }

    /// Check if a domain is blocked atomically
    pub async fn is_blocked_atomic(&self, domain_hash: u64, domain: &str, client_ip: IpAddr, query_type: u16) -> Option<BlockResponse> {
        if !self.enabled.load(Ordering::Relaxed) {
            return None;
        }

        // Increment query counter
        self.stats.total_queries.fetch_add(1, Ordering::Relaxed);

        // 1. Check whitelist first (highest priority)
        if self.whitelist.get(&domain_hash).is_some() {
            self.stats.whitelist_hits.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // 2. Check bloom filter for fast negative lookup
        if !self.bloom_filter.contains_atomic(domain_hash) {
            // Definitely not blocked
            return None;
        }

        // 3. Check pattern matcher for exact match
        let pattern_type = {
            let pattern_matcher = self.pattern_matcher.read().await;
            if let Some(pattern) = pattern_matcher.matches(domain_hash, domain) {
                Some(pattern.pattern_type)
            } else {
                None
            }
        };

        if let Some(pattern_type) = pattern_type {
            let block_reason = match pattern_type {
                PatternType::Exact => BlockReason::ExactMatch,
                PatternType::Wildcard => BlockReason::WildcardMatch,
                PatternType::Subdomain => BlockReason::SubdomainMatch,
            };

            // Get custom response or use default
            let response = self.custom_responses.get(&domain_hash)
                .map(|guard| guard.val().clone())
                .unwrap_or_else(|| self.config.default_block_response.clone());

            // Record analytics
            let analytics = BlocklistAnalytics {
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                domain: domain.to_string(),
                domain_hash,
                client_ip,
                query_type,
                block_reason: block_reason.clone(),
                response_type: response.clone(),
            };

            tokio::spawn({
                let analytics_collector = Arc::clone(&self.analytics);
                async move {
                    analytics_collector.record_block(analytics).await;
                }
            });

            // Update stats
            match block_reason {
                BlockReason::ExactMatch => self.stats.exact_blocks.fetch_add(1, Ordering::Relaxed),
                BlockReason::WildcardMatch => self.stats.wildcard_blocks.fetch_add(1, Ordering::Relaxed),
                BlockReason::SubdomainMatch => self.stats.subdomain_blocks.fetch_add(1, Ordering::Relaxed),
                BlockReason::BloomFilter => self.stats.bloom_blocks.fetch_add(1, Ordering::Relaxed),
            };

            return Some(response);
        }

        // 4. Bloom filter false positive
        self.stats.bloom_false_positives.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Add a domain to the blocklist atomically
    pub async fn add_domain_atomic(&self, domain: &str, pattern_type: PatternType, custom_response: Option<BlockResponse>) -> DnsResult<()> {
        let normalized = domain.to_lowercase();
        let domain_hash = AtomicHasher::hash_domain(&normalized);

        // Add to bloom filter
        self.bloom_filter.add_atomic(domain_hash);

        // Add to pattern matcher
        let mut pattern_matcher = self.pattern_matcher.write().await;
        pattern_matcher.add_pattern(&normalized, pattern_type);
        drop(pattern_matcher);

        // Add custom response if specified
        if let Some(response) = custom_response {
            self.custom_responses.insert(domain_hash, response);
        }

        self.stats.domains_added.fetch_add(1, Ordering::Relaxed);
        info!("Added domain to blocklist: {} (hash: {})", normalized, domain_hash);

        Ok(())
    }

    /// Add a domain to the whitelist atomically
    pub async fn add_whitelist_domain_atomic(&self, domain: &str) -> DnsResult<()> {
        let normalized = domain.to_lowercase();
        let domain_hash = AtomicHasher::hash_domain(&normalized);

        self.whitelist.insert(domain_hash, Arc::from(normalized.as_str()));
        self.stats.whitelist_added.fetch_add(1, Ordering::Relaxed);
        
        info!("Added domain to whitelist: {} (hash: {})", normalized, domain_hash);
        Ok(())
    }

    /// Remove a domain from the whitelist atomically
    pub async fn remove_whitelist_domain_atomic(&self, domain: &str) -> DnsResult<bool> {
        let normalized = domain.to_lowercase();
        let domain_hash = AtomicHasher::hash_domain(&normalized);

        let removed = self.whitelist.remove(&domain_hash).is_some();
        if removed {
            self.stats.whitelist_removed.fetch_add(1, Ordering::Relaxed);
            info!("Removed domain from whitelist: {} (hash: {})", normalized, domain_hash);
        }

        Ok(removed)
    }

    /// Bulk add domains to blocklist
    pub async fn add_domains_bulk(&self, domains: Vec<(String, PatternType, Option<BlockResponse>)>) -> DnsResult<usize> {
        let mut added_count = 0;

        for (domain, pattern_type, custom_response) in domains {
            if self.add_domain_atomic(&domain, pattern_type, custom_response).await.is_ok() {
                added_count += 1;
            }
        }

        info!("Bulk added {} domains to blocklist", added_count);
        Ok(added_count)
    }

    /// Generate block response based on type
    pub fn generate_block_response(&self, query_id: u16, response_type: &BlockResponse) -> Bytes {
        match response_type {
            BlockResponse::NxDomain => self.generate_nxdomain_response(query_id),
            BlockResponse::Localhost => self.generate_localhost_response(query_id),
            BlockResponse::CustomIp(ip) => self.generate_custom_ip_response(query_id, *ip),
            BlockResponse::Empty => self.generate_empty_response(query_id),
        }
    }

    /// Generate NXDOMAIN response
    fn generate_nxdomain_response(&self, query_id: u16) -> Bytes {
        // DNS header: ID + flags (NXDOMAIN) + counts
        let mut response = Vec::with_capacity(12);
        
        // ID (2 bytes)
        response.extend_from_slice(&query_id.to_be_bytes());
        
        // Flags: QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=3 (NXDOMAIN)
        response.extend_from_slice(&[0x81, 0x83]);
        
        // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        
        Bytes::from(response)
    }

    /// Generate localhost redirect response
    fn generate_localhost_response(&self, query_id: u16) -> Bytes {
        self.generate_custom_ip_response(query_id, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
    }

    /// Generate custom IP redirect response
    fn generate_custom_ip_response(&self, query_id: u16, ip: IpAddr) -> Bytes {
        let mut response = Vec::with_capacity(32);
        
        // DNS header: ID + flags + counts
        response.extend_from_slice(&query_id.to_be_bytes());
        response.extend_from_slice(&[0x81, 0x80]); // Standard response flags
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]); // 1 question, 1 answer
        
        // Answer section (simplified - would need full question section in real implementation)
        match ip {
            IpAddr::V4(ipv4) => {
                // A record response
                response.extend_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                // AAAA record response
                response.extend_from_slice(&ipv6.octets());
            }
        }
        
        Bytes::from(response)
    }

    /// Generate empty response
    fn generate_empty_response(&self, query_id: u16) -> Bytes {
        let mut response = Vec::with_capacity(12);
        
        // DNS header with no answers
        response.extend_from_slice(&query_id.to_be_bytes());
        response.extend_from_slice(&[0x81, 0x80]); // Standard response flags
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // 1 question, 0 answers
        
        Bytes::from(response)
    }

    /// Start automatic blocklist updates
    async fn start_automatic_updates(&self) -> DnsResult<()> {
        let update_manager = Arc::clone(&self.update_manager);
        let engine = Arc::new(self.clone());
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(engine.config.update_interval_secs));
            
            loop {
                interval.tick().await;
                
                if let Err(e) = update_manager.update_all_sources(&engine).await {
                    error!("Failed to update blocklist sources: {}", e);
                }
            }
        });
        
        Ok(())
    }

    /// Get engine statistics
    pub fn stats(&self) -> BlocklistEngineStats {
        let bloom_stats = self.bloom_filter.stats();
        let analytics_stats = self.analytics.stats();
        
        BlocklistEngineStats {
            enabled: self.enabled.load(Ordering::Relaxed),
            total_queries: self.stats.total_queries.load(Ordering::Relaxed),
            total_blocks: analytics_stats.total_blocks,
            exact_blocks: analytics_stats.exact_blocks,
            wildcard_blocks: analytics_stats.wildcard_blocks,
            subdomain_blocks: analytics_stats.subdomain_blocks,
            bloom_blocks: analytics_stats.bloom_blocks,
            whitelist_hits: self.stats.whitelist_hits.load(Ordering::Relaxed),
            bloom_false_positives: self.stats.bloom_false_positives.load(Ordering::Relaxed),
            domains_added: self.stats.domains_added.load(Ordering::Relaxed),
            whitelist_added: self.stats.whitelist_added.load(Ordering::Relaxed),
            whitelist_removed: self.stats.whitelist_removed.load(Ordering::Relaxed),
            bloom_filter: bloom_stats,
        }
    }

    /// Enable or disable the engine
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
        info!("Blocklist engine {}", if enabled { "enabled" } else { "disabled" });
    }

    /// Clear all blocklist data
    pub async fn clear_all(&self) -> DnsResult<()> {
        // Clear bloom filter
        self.bloom_filter.clear();
        
        // Clear pattern matcher
        let mut pattern_matcher = self.pattern_matcher.write().await;
        pattern_matcher.clear();
        drop(pattern_matcher);
        
        // Clear whitelist
        // Note: LockFreeMap doesn't have a clear method, so we'd need to iterate and remove
        // For now, we'll just log that it should be cleared
        warn!("Whitelist clearing not implemented for LockFreeMap");
        
        // Clear custom responses
        warn!("Custom responses clearing not implemented for LockFreeMap");
        
        // Clear analytics
        self.analytics.clear().await;
        
        info!("Cleared all blocklist data");
        Ok(())
    }
}

// Implement Clone for AtomicBlocklistEngine (needed for async spawning)
impl Clone for AtomicBlocklistEngine {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            bloom_filter: Arc::clone(&self.bloom_filter),
            pattern_matcher: Arc::clone(&self.pattern_matcher),
            whitelist: Arc::clone(&self.whitelist),
            custom_responses: Arc::clone(&self.custom_responses),
            analytics: Arc::clone(&self.analytics),
            update_manager: Arc::clone(&self.update_manager),
            stats: Arc::clone(&self.stats),
            enabled: AtomicBool::new(self.enabled.load(Ordering::Relaxed)),
        }
    }
}

/// Atomic blocklist statistics
pub struct AtomicBlocklistStats {
    pub total_queries: AtomicU64,
    pub exact_blocks: AtomicU64,
    pub wildcard_blocks: AtomicU64,
    pub subdomain_blocks: AtomicU64,
    pub bloom_blocks: AtomicU64,
    pub whitelist_hits: AtomicU64,
    pub bloom_false_positives: AtomicU64,
    pub domains_added: AtomicU64,
    pub whitelist_added: AtomicU64,
    pub whitelist_removed: AtomicU64,
}

impl AtomicBlocklistStats {
    pub fn new() -> Self {
        Self {
            total_queries: AtomicU64::new(0),
            exact_blocks: AtomicU64::new(0),
            wildcard_blocks: AtomicU64::new(0),
            subdomain_blocks: AtomicU64::new(0),
            bloom_blocks: AtomicU64::new(0),
            whitelist_hits: AtomicU64::new(0),
            bloom_false_positives: AtomicU64::new(0),
            domains_added: AtomicU64::new(0),
            whitelist_added: AtomicU64::new(0),
            whitelist_removed: AtomicU64::new(0),
        }
    }
}

/// Blocklist engine statistics
#[derive(Debug, Clone)]
pub struct BlocklistEngineStats {
    pub enabled: bool,
    pub total_queries: u64,
    pub total_blocks: u64,
    pub exact_blocks: u64,
    pub wildcard_blocks: u64,
    pub subdomain_blocks: u64,
    pub bloom_blocks: u64,
    pub whitelist_hits: u64,
    pub bloom_false_positives: u64,
    pub domains_added: u64,
    pub whitelist_added: u64,
    pub whitelist_removed: u64,
    pub bloom_filter: BloomFilterStats,
}

/// Blocklist update manager for remote sources
pub struct BlocklistUpdateManager {
    /// Remote sources configuration
    sources: Vec<BlocklistSource>,
    /// Update interval
    update_interval: Duration,
    /// HTTP client for fetching remote lists
    client: reqwest::Client,
    /// Last update timestamps
    last_updates: Arc<LockFreeMap<String, u64>>,
}

impl BlocklistUpdateManager {
    /// Create a new update manager
    pub fn new(sources: Vec<BlocklistSource>, update_interval_secs: u64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("PlanetScale-DNS-Server/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            sources,
            update_interval: Duration::from_secs(update_interval_secs),
            client,
            last_updates: Arc::new(LockFreeMap::new()),
        }
    }

    /// Update all enabled sources
    pub async fn update_all_sources(&self, engine: &AtomicBlocklistEngine) -> DnsResult<()> {
        let mut update_tasks = Vec::new();

        for source in &self.sources {
            if !source.enabled {
                continue;
            }

            let source_clone = source.clone();
            let client = self.client.clone();
            let engine_clone = engine.clone();
            let last_updates = Arc::clone(&self.last_updates);

            let task = tokio::spawn(async move {
                if let Err(e) = Self::update_source(&source_clone, &client, &engine_clone, &last_updates).await {
                    error!("Failed to update source {}: {}", source_clone.name, e);
                }
            });

            update_tasks.push(task);
        }

        // Wait for all updates to complete
        for task in update_tasks {
            let _ = task.await;
        }

        Ok(())
    }

    /// Update a single source
    async fn update_source(
        source: &BlocklistSource,
        client: &reqwest::Client,
        engine: &AtomicBlocklistEngine,
        last_updates: &LockFreeMap<String, u64>,
    ) -> DnsResult<()> {
        info!("Updating blocklist source: {}", source.name);

        // Fetch the blocklist data
        let response = client.get(&source.url).send().await
            .map_err(|e| DnsError::BlocklistUpdate(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(DnsError::BlocklistUpdate(format!("HTTP {} for source {}", response.status(), source.name)));
        }

        let content = response.text().await
            .map_err(|e| DnsError::BlocklistUpdate(format!("Failed to read response: {}", e)))?;

        // Parse the content based on format
        let domains = Self::parse_blocklist_content(&content, source.format)?;

        // Add domains to the engine
        let mut added_count = 0;
        for domain in domains {
            if engine.add_domain_atomic(&domain, PatternType::Exact, None).await.is_ok() {
                added_count += 1;
            }
        }

        // Update last update timestamp
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        last_updates.insert(source.name.clone(), now);

        info!("Updated source {} with {} domains", source.name, added_count);
        Ok(())
    }

    /// Parse blocklist content based on format
    fn parse_blocklist_content(content: &str, format: BlocklistFormat) -> DnsResult<Vec<String>> {
        let mut domains = Vec::new();

        match format {
            BlocklistFormat::PlainText => {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        domains.push(line.to_lowercase());
                    }
                }
            }
            BlocklistFormat::HostsFile => {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    
                    // Parse "127.0.0.1 domain.com" format
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let domain = parts[1].to_lowercase();
                        if !domain.is_empty() && domain != "localhost" {
                            domains.push(domain);
                        }
                    }
                }
            }
            BlocklistFormat::AdBlockPlus => {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('!') {
                        continue;
                    }
                    
                    // Simple AdBlock Plus parsing (can be enhanced)
                    if line.starts_with("||") && line.ends_with("^") {
                        let domain = &line[2..line.len()-1];
                        domains.push(domain.to_lowercase());
                    }
                }
            }
            BlocklistFormat::PiHole => {
                // Pi-hole format is similar to hosts file
                return Self::parse_blocklist_content(content, BlocklistFormat::HostsFile);
            }
        }

        Ok(domains)
    }

    /// Get update statistics
    pub fn stats(&self) -> UpdateManagerStats {
        let total_sources = self.sources.len();
        let enabled_sources = self.sources.iter().filter(|s| s.enabled).count();

        UpdateManagerStats {
            total_sources,
            enabled_sources,
            update_interval_secs: self.update_interval.as_secs(),
        }
    }
}

/// Update manager statistics
#[derive(Debug, Clone)]
pub struct UpdateManagerStats {
    pub total_sources: usize,
    pub enabled_sources: usize,
    pub update_interval_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_bloom_filter_basic() {
        let bloom = AtomicBloomFilter::new(1000, 0.01);
        
        let domain_hash = AtomicHasher::hash_domain("example.com");
        
        // Should not contain initially
        assert!(!bloom.contains_atomic(domain_hash));
        
        // Add domain
        bloom.add_atomic(domain_hash);
        
        // Should contain after adding
        assert!(bloom.contains_atomic(domain_hash));
    }

    #[tokio::test]
    async fn test_pattern_matcher() {
        let mut matcher = SimdPatternMatcher::new(false);
        
        // Add exact pattern
        matcher.add_pattern("example.com", PatternType::Exact);
        
        // Add wildcard pattern
        matcher.add_pattern("*.ads.com", PatternType::Wildcard);
        
        let exact_hash = AtomicHasher::hash_domain("example.com");
        assert!(matcher.matches(exact_hash, "example.com").is_some());
        
        assert!(matcher.matches(0, "tracker.ads.com").is_some());
        assert!(matcher.matches(0, "notblocked.com").is_none());
    }

    #[tokio::test]
    async fn test_blocklist_engine() {
        let config = BlocklistConfig::default();
        let engine = AtomicBlocklistEngine::new(config).await.unwrap();
        
        // Add a domain to blocklist
        engine.add_domain_atomic("ads.example.com", PatternType::Exact, None).await.unwrap();
        
        // Check if blocked
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let result = engine.is_blocked_atomic(
            AtomicHasher::hash_domain("ads.example.com"),
            "ads.example.com",
            client_ip,
            1, // A record
        ).await;
        
        assert!(result.is_some());
        
        // Add to whitelist
        engine.add_whitelist_domain_atomic("ads.example.com").await.unwrap();
        
        // Should not be blocked now
        let result = engine.is_blocked_atomic(
            AtomicHasher::hash_domain("ads.example.com"),
            "ads.example.com",
            client_ip,
            1,
        ).await;
        
        assert!(result.is_none());
    }

    #[test]
    fn test_blocklist_parsing() {
        let hosts_content = "127.0.0.1 ads.example.com\n127.0.0.1 tracker.com\n# Comment line\n";
        let domains = BlocklistUpdateManager::parse_blocklist_content(hosts_content, BlocklistFormat::HostsFile).unwrap();
        
        assert_eq!(domains.len(), 2);
        assert!(domains.contains(&"ads.example.com".to_string()));
        assert!(domains.contains(&"tracker.com".to_string()));
    }
}