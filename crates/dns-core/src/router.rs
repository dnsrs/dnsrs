//! Atomic Query Router with Hash-Based Processing
//!
//! This module implements the main query routing engine that coordinates
//! blocklist checking, caching, rate limiting, and record resolution using
//! atomic operations for maximum performance.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::Instant;

use crate::types::{DnsQuery, ResponseCode};
use crate::hash::{hash_domain_name, hash_query, hash_client_ip};
use crate::error::{DnsError, DnsResult};
use crate::query::{
    AtomicQuery, PreComputedResponseCache, AtomicRateLimiter,
    RateLimitStats, PreComputedCacheStats
};
use crate::blocklist::{AtomicBlocklistEngine, BlockResponse, BlocklistEngineStats};
use crate::resolver::{AtomicZeroCopyResolver, ResolverStatsSnapshot};
use crate::atomic::AtomicStatsCollector;

/// Main atomic query router for hash-based DNS processing
pub struct AtomicQueryRouter {
    /// Zero-copy resolver for record lookups
    resolver: Arc<AtomicZeroCopyResolver>,
    /// Pre-computed response cache
    cache: Arc<PreComputedResponseCache>,
    /// Atomic blocklist engine
    blocklist: Arc<AtomicBlocklistEngine>,
    /// Atomic rate limiter
    rate_limiter: Arc<AtomicRateLimiter>,
    /// Statistics collector
    stats: Arc<AtomicStatsCollector>,
    /// Router-specific metrics
    router_stats: Arc<RouterStats>,
}

/// Router-specific statistics
#[derive(Debug)]
pub struct RouterStats {
    /// Total queries processed
    pub total_queries: AtomicU64,
    /// Queries per second (updated periodically)
    pub queries_per_second: AtomicU64,
    /// Successful queries
    pub successful_queries: AtomicU64,
    /// Blocked queries
    pub blocked_queries: AtomicU64,
    /// Rate limited queries
    pub rate_limited_queries: AtomicU64,
    /// Cache hits
    pub cache_hits: AtomicU64,
    /// Cache misses
    pub cache_misses: AtomicU64,
    /// NXDOMAIN responses
    pub nxdomain_responses: AtomicU64,
    /// Error responses
    pub error_responses: AtomicU64,
    /// Average response time (nanoseconds)
    pub avg_response_time_ns: AtomicU64,
    /// Peak QPS observed
    pub peak_qps: AtomicU64,
    /// Last statistics update
    pub last_stats_update: AtomicU64,
    /// Active queries counter
    pub active_queries: AtomicUsize,
}

impl RouterStats {
    /// Create new router statistics
    pub fn new() -> Self {
        Self {
            total_queries: AtomicU64::new(0),
            queries_per_second: AtomicU64::new(0),
            successful_queries: AtomicU64::new(0),
            blocked_queries: AtomicU64::new(0),
            rate_limited_queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            nxdomain_responses: AtomicU64::new(0),
            error_responses: AtomicU64::new(0),
            avg_response_time_ns: AtomicU64::new(0),
            peak_qps: AtomicU64::new(0),
            last_stats_update: AtomicU64::new(0),
            active_queries: AtomicUsize::new(0),
        }
    }
    
    /// Record query processing
    pub fn record_query(&self, response_time_ns: u64, result: &QueryResult) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        
        match result {
            QueryResult::Success(_) => self.successful_queries.fetch_add(1, Ordering::Relaxed),
            QueryResult::RateLimited => self.rate_limited_queries.fetch_add(1, Ordering::Relaxed),
            QueryResult::CacheHit(_) => self.cache_hits.fetch_add(1, Ordering::Relaxed),
            QueryResult::Resolved(_) => self.cache_misses.fetch_add(1, Ordering::Relaxed),
            QueryResult::NxDomain => self.nxdomain_responses.fetch_add(1, Ordering::Relaxed),
            QueryResult::Error(_) => self.error_responses.fetch_add(1, Ordering::Relaxed),
        };
        
        // Update average response time (simplified moving average)
        let current_avg = self.avg_response_time_ns.load(Ordering::Relaxed);
        let new_avg = if current_avg == 0 {
            response_time_ns
        } else {
            (current_avg * 7 + response_time_ns) / 8 // Weighted moving average
        };
        self.avg_response_time_ns.store(new_avg, Ordering::Relaxed);
    }
    
    /// Update QPS statistics
    pub fn update_qps(&self, current_qps: u64) {
        self.queries_per_second.store(current_qps, Ordering::Relaxed);
        
        let current_peak = self.peak_qps.load(Ordering::Relaxed);
        if current_qps > current_peak {
            self.peak_qps.store(current_qps, Ordering::Relaxed);
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_stats_update.store(now, Ordering::Relaxed);
    }
    
    /// Get statistics snapshot
    pub fn snapshot(&self) -> RouterStatsSnapshot {
        RouterStatsSnapshot {
            total_queries: self.total_queries.load(Ordering::Relaxed),
            queries_per_second: self.queries_per_second.load(Ordering::Relaxed),
            blocked_queries: self.blocked_queries.load(Ordering::Relaxed),
            rate_limited_queries: self.rate_limited_queries.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            nxdomain_responses: self.nxdomain_responses.load(Ordering::Relaxed),
            error_responses: self.error_responses.load(Ordering::Relaxed),
            avg_response_time_ns: self.avg_response_time_ns.load(Ordering::Relaxed),
            peak_qps: self.peak_qps.load(Ordering::Relaxed),
            active_queries: self.active_queries.load(Ordering::Relaxed),
        }
    }
}

/// Router statistics snapshot
#[derive(Debug, Clone)]
pub struct RouterStatsSnapshot {
    pub total_queries: u64,
    pub queries_per_second: u64,
    pub blocked_queries: u64,
    pub rate_limited_queries: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub nxdomain_responses: u64,
    pub error_responses: u64,
    pub avg_response_time_ns: u64,
    pub peak_qps: u64,
    pub active_queries: usize,
}

/// Query processing result
#[derive(Debug)]
pub enum QueryResult {
    /// Query was successfully processed
    Success(Arc<[u8]>),
    /// Query was rate limited
    RateLimited,
    /// Response served from cache
    CacheHit(Arc<[u8]>),
    /// Response resolved from zone data
    Resolved(Arc<[u8]>),
    /// Domain not found
    NxDomain,
    /// Error occurred during processing
    Error(DnsError),
}

impl AtomicQueryRouter {
    /// Create new atomic query router
    pub async fn new(
        max_cache_size_mb: u64,
        max_cache_entries: usize,
        global_max_qps: u64,
        per_client_max_qps: u64,
    ) -> Self {
        Self {
            resolver: Arc::new(AtomicZeroCopyResolver::new()),
            cache: Arc::new(PreComputedResponseCache::new()),
            blocklist: Arc::new(AtomicBlocklistEngine::new(crate::blocklist::BlocklistConfig::default()).await.unwrap()),
            rate_limiter: Arc::new(AtomicRateLimiter::new(global_max_qps, per_client_max_qps)),
            stats: Arc::new(AtomicStatsCollector::new()),
            router_stats: Arc::new(RouterStats::new()),
        }
    }
    
    /// Route query using atomic hash-based processing
    pub async fn route_query_atomic(&self, query: DnsQuery) -> DnsResult<Arc<[u8]>> {
        let start_time = Instant::now();
        self.router_stats.active_queries.fetch_add(1, Ordering::Relaxed);
        
        // Convert to atomic query for hash-based processing
        let atomic_query = AtomicQuery::from_dns_query(&query);
        
        // Process query through atomic pipeline
        let result = self.process_query_pipeline(&atomic_query, &query).await;
        
        // Record statistics
        let response_time_ns = start_time.elapsed().as_nanos() as u64;
        self.router_stats.record_query(response_time_ns, &result);
        self.router_stats.active_queries.fetch_sub(1, Ordering::Relaxed);
        
        // Return response based on result
        match result {
            QueryResult::Success(response) => Ok(response),

            QueryResult::RateLimited => {
                Ok(self.build_refused_response(atomic_query.id))
            }
            QueryResult::CacheHit(response) => Ok(response),
            QueryResult::Resolved(response) => Ok(response),
            QueryResult::NxDomain => {
                Ok(self.build_nxdomain_response(atomic_query.id))
            }
            QueryResult::Error(error) => {
                Ok(self.build_servfail_response(atomic_query.id))
            }
        }
    }
    
    /// Process query through atomic pipeline
    async fn process_query_pipeline(&self, query: &AtomicQuery, original_query: &DnsQuery) -> QueryResult {
        // 1. Rate limiting check (fastest rejection)
        if !self.rate_limiter.check_rate_limit(query.client_hash, 1) {
            return QueryResult::RateLimited;
        }
        
        // 2. Blocklist check (second fastest rejection)
        if let Some(block_response) = self.blocklist.is_blocked_atomic(original_query.name_hash, &original_query.name, original_query.client_addr, original_query.record_type.to_u16()).await {
            let response_bytes = self.blocklist.generate_block_response(query.id, &block_response);
            return QueryResult::Success(Arc::from(response_bytes.as_ref()));
        }
        
        // 3. Pre-computed cache lookup (fastest positive response)
        if let Some(cached_response) = self.cache.get(query.query_hash, query.id) {
            return QueryResult::CacheHit(cached_response);
        }
        
        // 4. Resolve from zone data using binary search
        match self.resolver.resolve_fast_atomic(query).await {
            Ok(Some(response)) => {
                // Cache the response for future queries
                let ttl = self.extract_ttl_from_response(&response).unwrap_or(300);
                self.cache.insert(query.query_hash, response.clone(), ttl);
                QueryResult::Resolved(response)
            }
            Ok(None) => QueryResult::NxDomain,
            Err(error) => QueryResult::Error(error),
        }
    }
    
    /// Batch process multiple queries atomically
    pub async fn route_queries_batch_atomic(&self, queries: Vec<DnsQuery>) -> Vec<DnsResult<Arc<[u8]>>> {
        // Convert all queries to atomic queries
        let atomic_queries: Vec<AtomicQuery> = queries
            .iter()
            .map(AtomicQuery::from_dns_query)
            .collect();
        
        // Process queries in parallel
        let futures = atomic_queries.iter().zip(queries.iter()).map(|(atomic_query, original_query)| {
            let router = self.clone();
            async move {
                let start_time = Instant::now();
                router.router_stats.active_queries.fetch_add(1, Ordering::Relaxed);
                
                let result = router.process_query_pipeline(atomic_query, original_query).await;
                
                let response_time_ns = start_time.elapsed().as_nanos() as u64;
                router.router_stats.record_query(response_time_ns, &result);
                router.router_stats.active_queries.fetch_sub(1, Ordering::Relaxed);
                
                // Convert result to response
                match result {
                    QueryResult::Success(response) => Ok(response),

                    QueryResult::RateLimited => Ok(router.build_refused_response(original_query.id)),
                    QueryResult::CacheHit(response) => Ok(response),
                    QueryResult::Resolved(response) => Ok(response),
                    QueryResult::NxDomain => Ok(router.build_nxdomain_response(original_query.id)),
                    QueryResult::Error(_) => Ok(router.build_servfail_response(original_query.id)),
                }
            }
        });
        
        futures::future::join_all(futures).await
    }
    
    /// Add domain to blocklist
    pub async fn add_blocked_domain(&self, domain: &str, pattern_type: crate::blocklist::PatternType, custom_response: Option<BlockResponse>) -> DnsResult<()> {
        self.blocklist.add_domain_atomic(domain, pattern_type, custom_response).await
    }
    
    /// Add domain to whitelist
    pub async fn add_whitelist_domain(&self, domain: &str) -> bool {
        self.blocklist.add_whitelist_domain_atomic(domain).await.is_ok()
    }
    
    /// Remove domain from blocklist
    pub fn remove_blocked_domain(&self, domain: &str) -> bool {
        false // TODO: Implement remove_blocked_domain_atomic
    }
    
    /// Remove domain from whitelist
    pub async fn remove_whitelist_domain(&self, domain: &str) -> bool {
        self.blocklist.remove_whitelist_domain_atomic(domain).await.unwrap_or(false)
    }
    
    /// Get comprehensive statistics
    pub fn get_comprehensive_stats(&self) -> ComprehensiveStats {
        ComprehensiveStats {
            router: self.router_stats.snapshot(),
            resolver: self.resolver.stats(),
            cache: self.cache.stats(),
            blocklist: self.blocklist.stats(),
            rate_limiter: self.rate_limiter.stats(),
        }
    }
    
    /// Extract TTL from DNS response (simplified)
    fn extract_ttl_from_response(&self, response: &[u8]) -> Option<u32> {
        // Simplified TTL extraction from DNS response
        // In practice, this would parse the DNS response properly
        if response.len() >= 16 {
            // Assume TTL is at a fixed offset (this is simplified)
            Some(300) // Default 5 minutes
        } else {
            None
        }
    }
    
    /// Build NXDOMAIN response
    fn build_nxdomain_response(&self, query_id: u16) -> Arc<[u8]> {
        let mut response = Vec::with_capacity(12);
        
        // Header
        response.extend_from_slice(&query_id.to_be_bytes());  // ID
        response.extend_from_slice(&[0x81, 0x83]);            // Flags: Response, NXDOMAIN
        response.extend_from_slice(&[0x00, 0x01]);            // QDCOUNT: 1
        response.extend_from_slice(&[0x00, 0x00]);            // ANCOUNT: 0
        response.extend_from_slice(&[0x00, 0x00]);            // NSCOUNT: 0
        response.extend_from_slice(&[0x00, 0x00]);            // ARCOUNT: 0
        
        Arc::from(response)
    }
    
    /// Build REFUSED response
    fn build_refused_response(&self, query_id: u16) -> Arc<[u8]> {
        let mut response = Vec::with_capacity(12);
        
        // Header
        response.extend_from_slice(&query_id.to_be_bytes());  // ID
        response.extend_from_slice(&[0x81, 0x85]);            // Flags: Response, REFUSED
        response.extend_from_slice(&[0x00, 0x01]);            // QDCOUNT: 1
        response.extend_from_slice(&[0x00, 0x00]);            // ANCOUNT: 0
        response.extend_from_slice(&[0x00, 0x00]);            // NSCOUNT: 0
        response.extend_from_slice(&[0x00, 0x00]);            // ARCOUNT: 0
        
        Arc::from(response)
    }
    
    /// Build SERVFAIL response
    fn build_servfail_response(&self, query_id: u16) -> Arc<[u8]> {
        let mut response = Vec::with_capacity(12);
        
        // Header
        response.extend_from_slice(&query_id.to_be_bytes());  // ID
        response.extend_from_slice(&[0x81, 0x82]);            // Flags: Response, SERVFAIL
        response.extend_from_slice(&[0x00, 0x01]);            // QDCOUNT: 1
        response.extend_from_slice(&[0x00, 0x00]);            // ANCOUNT: 0
        response.extend_from_slice(&[0x00, 0x00]);            // NSCOUNT: 0
        response.extend_from_slice(&[0x00, 0x00]);            // ARCOUNT: 0
        
        Arc::from(response)
    }
    
    /// Get resolver reference
    pub fn resolver(&self) -> &Arc<AtomicZeroCopyResolver> {
        &self.resolver
    }
    
    /// Get cache reference
    pub fn cache(&self) -> &Arc<PreComputedResponseCache> {
        &self.cache
    }
    
    /// Get blocklist reference
    pub fn blocklist(&self) -> &Arc<AtomicBlocklistEngine> {
        &self.blocklist
    }
    
    /// Get rate limiter reference
    pub fn rate_limiter(&self) -> &Arc<AtomicRateLimiter> {
        &self.rate_limiter
    }
}

impl Clone for AtomicQueryRouter {
    fn clone(&self) -> Self {
        Self {
            resolver: Arc::clone(&self.resolver),
            cache: Arc::clone(&self.cache),
            blocklist: Arc::clone(&self.blocklist),
            rate_limiter: Arc::clone(&self.rate_limiter),
            stats: Arc::clone(&self.stats),
            router_stats: Arc::clone(&self.router_stats),
        }
    }
}

/// Comprehensive statistics from all components
#[derive(Debug, Clone)]
pub struct ComprehensiveStats {
    pub router: RouterStatsSnapshot,
    pub resolver: ResolverStatsSnapshot,
    pub cache: PreComputedCacheStats,
    pub blocklist: BlocklistEngineStats,
    pub rate_limiter: RateLimitStats,
}

impl AtomicQueryRouter {
    /// Create default router configuration
    pub async fn default() -> Self {
        Self::new(
            1024,    // 1GB cache
            1000000, // 1M cache entries
            100000,  // 100K global QPS
            1000,    // 1K per-client QPS
        ).await
    }
}