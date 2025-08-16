//! Access control lists with atomic IP range checking
//! 
//! Implements high-performance access control using:
//! - Atomic IP range checking with CIDR support
//! - Lock-free rule evaluation
//! - Zone-specific access controls
//! - Fast IP address classification

use crate::{SecurityError, SecurityResult, current_timestamp_ms, hash_ip_address};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use lockfree::map::Map as LockFreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Access control configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclConfig {
    /// Default action when no rules match
    pub default_action: AclAction,
    /// Enable zone-specific access controls
    pub zone_specific_acls: bool,
    /// Maximum number of ACL rules
    pub max_rules: usize,
    /// Enable IP geolocation checking
    pub enable_geolocation: bool,
    /// Cache size for IP classification results
    pub cache_size: usize,
}

impl Default for AclConfig {
    fn default() -> Self {
        Self {
            default_action: AclAction::Allow,
            zone_specific_acls: true,
            max_rules: 10000,
            enable_geolocation: false,
            cache_size: 100000,
        }
    }
}

/// ACL action to take
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclAction {
    Allow,
    Deny,
    Drop, // Silently drop without response
}

impl AclAction {
    pub fn is_allowed(&self) -> bool {
        matches!(self, AclAction::Allow)
    }
}

/// IP address range for ACL rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRange {
    /// Network address (CIDR notation)
    pub network: String,
    /// Parsed network for fast matching
    #[serde(skip)]
    pub parsed_net: Option<IpNet>,
    /// Description of this range
    pub description: String,
}

impl IpRange {
    pub fn new(network: String, description: String) -> SecurityResult<Self> {
        let parsed_net = network.parse::<IpNet>()
            .map_err(|_| SecurityError::config_error("Invalid IP network format"))?;
        
        Ok(Self {
            network,
            parsed_net: Some(parsed_net),
            description,
        })
    }

    /// Check if an IP address is within this range
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.parsed_net
            .as_ref()
            .map(|net| net.contains(&ip))
            .unwrap_or(false)
    }

    /// Get the network size (number of addresses)
    pub fn size(&self) -> u128 {
        self.parsed_net
            .as_ref()
            .map(|net| match net {
                IpNet::V4(v4) => v4.hosts().count() as u128,
                IpNet::V6(v6) => {
                    let prefix_len = v6.prefix_len();
                    if prefix_len >= 128 {
                        1
                    } else {
                        2u128.pow(128 - prefix_len as u32)
                    }
                }
            })
            .unwrap_or(0)
    }
}

/// ACL rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclRule {
    /// Rule identifier
    pub id: String,
    /// IP ranges this rule applies to
    pub ip_ranges: Vec<IpRange>,
    /// Action to take for matching IPs
    pub action: AclAction,
    /// Zones this rule applies to (empty = all zones)
    pub zones: Vec<String>,
    /// Rule priority (lower = higher priority)
    pub priority: u32,
    /// Whether this rule is enabled
    pub enabled: bool,
    /// Rule description
    pub description: String,
    /// Rule creation timestamp
    pub created_at: u64,
}

impl AclRule {
    pub fn new(
        id: String,
        ip_ranges: Vec<IpRange>,
        action: AclAction,
        zones: Vec<String>,
        priority: u32,
        description: String,
    ) -> Self {
        Self {
            id,
            ip_ranges,
            action,
            zones,
            priority,
            enabled: true,
            description,
            created_at: current_timestamp_ms(),
        }
    }

    /// Check if this rule matches an IP and zone
    pub fn matches(&self, ip: IpAddr, zone: Option<&str>) -> bool {
        if !self.enabled {
            return false;
        }

        // Check zone match
        if !self.zones.is_empty() {
            if let Some(zone_name) = zone {
                if !self.zones.iter().any(|z| z == zone_name) {
                    return false;
                }
            } else {
                return false; // Rule has zones but no zone provided
            }
        }

        // Check IP match
        self.ip_ranges.iter().any(|range| range.contains(ip))
    }
}

/// Cached access control decision
#[derive(Debug)]
struct CachedDecision {
    action: AclAction,
    rule_id: String,
    timestamp: AtomicU64,
    hit_count: AtomicU64,
}

impl CachedDecision {
    fn new(action: AclAction, rule_id: String) -> Self {
        Self {
            action,
            rule_id,
            timestamp: AtomicU64::new(current_timestamp_ms()),
            hit_count: AtomicU64::new(1),
        }
    }

    fn is_expired(&self, cache_ttl_ms: u64) -> bool {
        let now = current_timestamp_ms();
        let timestamp = self.timestamp.load(Ordering::Relaxed);
        now - timestamp > cache_ttl_ms
    }

    fn touch(&self) {
        self.timestamp.store(current_timestamp_ms(), Ordering::Relaxed);
        self.hit_count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Access controller
pub struct AccessController {
    config: AclConfig,
    rules: Arc<RwLock<Vec<AclRule>>>,
    decision_cache: Arc<LockFreeMap<u64, Arc<CachedDecision>>>,
    stats: Arc<AclStats>,
    cache_ttl_ms: u64,
}

impl AccessController {
    pub fn new(config: AclConfig) -> SecurityResult<Self> {
        Ok(Self {
            config,
            rules: Arc::new(RwLock::new(Vec::new())),
            decision_cache: Arc::new(LockFreeMap::new()),
            stats: Arc::new(AclStats::new()),
            cache_ttl_ms: 300_000, // 5 minutes
        })
    }

    /// Check if an IP is allowed to make DNS queries
    pub async fn is_allowed(&self, client_ip: IpAddr) -> SecurityResult<bool> {
        self.check_access(client_ip, None).await.map(|action| action.is_allowed())
    }

    /// Check if an IP is allowed to perform zone transfers for a specific zone
    pub async fn is_zone_transfer_allowed(
        &self,
        client_ip: IpAddr,
        zone_name: &str,
    ) -> SecurityResult<bool> {
        self.check_access(client_ip, Some(zone_name)).await.map(|action| action.is_allowed())
    }

    /// Check access and return the action to take
    pub async fn check_access(
        &self,
        client_ip: IpAddr,
        zone: Option<&str>,
    ) -> SecurityResult<AclAction> {
        self.stats.access_checks.fetch_add(1, Ordering::Relaxed);

        // Generate cache key
        let cache_key = self.generate_cache_key(client_ip, zone);

        // Check cache first
        if let Some(cached) = self.get_cached_decision(cache_key).await? {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(cached.action);
        }

        // Evaluate rules
        let action = self.evaluate_rules(client_ip, zone).await?;

        // Cache the decision
        self.cache_decision(cache_key, action.clone(), "evaluated").await?;

        match action {
            AclAction::Allow => { self.stats.allowed_requests.fetch_add(1, Ordering::Relaxed); },
            AclAction::Deny => { self.stats.denied_requests.fetch_add(1, Ordering::Relaxed); },
            AclAction::Drop => { self.stats.dropped_requests.fetch_add(1, Ordering::Relaxed); },
        }

        Ok(action)
    }

    /// Generate cache key for IP and zone combination
    fn generate_cache_key(&self, client_ip: IpAddr, zone: Option<&str>) -> u64 {
        let ip_hash = hash_ip_address(client_ip);
        
        if let Some(zone_name) = zone {
            // Combine IP hash with zone hash
            use std::hash::{Hash, Hasher};
            use ahash::AHasher;
            
            let mut hasher = AHasher::default();
            ip_hash.hash(&mut hasher);
            zone_name.hash(&mut hasher);
            hasher.finish()
        } else {
            ip_hash
        }
    }

    /// Get cached decision if available and not expired
    async fn get_cached_decision(&self, cache_key: u64) -> SecurityResult<Option<Arc<CachedDecision>>> {
        if let Some(cached) = self.decision_cache.get(&cache_key) {
            let decision = cached.val().clone();
            
            if !decision.is_expired(self.cache_ttl_ms) {
                decision.touch();
                return Ok(Some(decision));
            } else {
                // Remove expired entry
                self.decision_cache.remove(&cache_key);
            }
        }
        
        Ok(None)
    }

    /// Cache an access control decision
    async fn cache_decision(
        &self,
        cache_key: u64,
        action: AclAction,
        rule_id: &str,
    ) -> SecurityResult<()> {
        // Periodically cleanup expired entries
        self.cleanup_expired_cache_entries().await?;

        let decision = Arc::new(CachedDecision::new(action, rule_id.to_string()));
        self.decision_cache.insert(cache_key, decision);
        
        Ok(())
    }

    /// Evaluate ACL rules for an IP and zone
    async fn evaluate_rules(&self, client_ip: IpAddr, zone: Option<&str>) -> SecurityResult<AclAction> {
        let rules = self.rules.read();
        
        // Sort rules by priority (lower number = higher priority)
        let mut sorted_rules: Vec<_> = rules.iter().collect();
        sorted_rules.sort_by_key(|rule| rule.priority);

        // Find first matching rule
        for rule in sorted_rules {
            if rule.matches(client_ip, zone) {
                self.stats.rule_matches.fetch_add(1, Ordering::Relaxed);
                return Ok(rule.action);
            }
        }

        // No rules matched, use default action
        self.stats.default_actions.fetch_add(1, Ordering::Relaxed);
        Ok(self.config.default_action)
    }

    /// Add an ACL rule
    pub async fn add_rule(&self, rule: AclRule) -> SecurityResult<()> {
        let mut rules = self.rules.write();
        
        if rules.len() >= self.config.max_rules {
            return Err(SecurityError::config_error("Maximum number of ACL rules reached"));
        }

        // Check for duplicate rule ID
        if rules.iter().any(|r| r.id == rule.id) {
            return Err(SecurityError::config_error("Rule ID already exists"));
        }

        rules.push(rule);
        self.stats.rules_added.fetch_add(1, Ordering::Relaxed);
        
        // Clear cache since rules changed
        self.clear_cache().await?;
        
        Ok(())
    }

    /// Remove an ACL rule
    pub async fn remove_rule(&self, rule_id: &str) -> SecurityResult<bool> {
        let mut rules = self.rules.write();
        let initial_len = rules.len();
        
        rules.retain(|rule| rule.id != rule_id);
        
        let removed = rules.len() < initial_len;
        if removed {
            self.stats.rules_removed.fetch_add(1, Ordering::Relaxed);
            // Clear cache since rules changed
            drop(rules); // Release lock before clearing cache
            self.clear_cache().await?;
        }
        
        Ok(removed)
    }

    /// Update an existing ACL rule
    pub async fn update_rule(&self, rule: AclRule) -> SecurityResult<bool> {
        let mut rules = self.rules.write();
        
        if let Some(existing) = rules.iter_mut().find(|r| r.id == rule.id) {
            *existing = rule;
            self.stats.rules_updated.fetch_add(1, Ordering::Relaxed);
            
            // Clear cache since rules changed
            drop(rules); // Release lock before clearing cache
            self.clear_cache().await?;
            
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// List all ACL rules
    pub async fn list_rules(&self) -> Vec<AclRule> {
        self.rules.read().clone()
    }

    /// Clear the decision cache
    pub async fn clear_cache(&self) -> SecurityResult<()> {
        // Clear by removing all entries
        let mut keys_to_remove = Vec::new();
        for entry in self.decision_cache.iter() {
            keys_to_remove.push(*entry.key());
        }
        
        for key in keys_to_remove {
            self.decision_cache.remove(&key);
        }
        
        self.stats.cache_clears.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Clean up expired cache entries
    async fn cleanup_expired_cache_entries(&self) -> SecurityResult<()> {
        let mut removed_count = 0;
        let mut keys_to_remove = Vec::new();
        
        // Collect expired entries
        for entry in self.decision_cache.iter() {
            if entry.val().is_expired(self.cache_ttl_ms) {
                keys_to_remove.push(*entry.key());
            }
        }
        
        // Remove expired entries
        for key in keys_to_remove {
            if self.decision_cache.remove(&key).is_some() {
                removed_count += 1;
            }
        }

        if removed_count > 0 {
            self.stats.cache_cleanups.fetch_add(1, Ordering::Relaxed);
            tracing::debug!("Cleaned up {} expired ACL cache entries", removed_count);
        }

        Ok(())
    }

    /// Create a default allow-all rule
    pub fn create_allow_all_rule() -> SecurityResult<AclRule> {
        let ipv4_range = IpRange::new("0.0.0.0/0".to_string(), "All IPv4 addresses".to_string())?;
        let ipv6_range = IpRange::new("::/0".to_string(), "All IPv6 addresses".to_string())?;
        
        Ok(AclRule::new(
            "allow-all".to_string(),
            vec![ipv4_range, ipv6_range],
            AclAction::Allow,
            vec![], // All zones
            1000,   // Low priority
            "Allow all traffic (default rule)".to_string(),
        ))
    }

    /// Create a rule to deny private networks
    pub fn create_deny_private_rule() -> SecurityResult<AclRule> {
        let private_ranges = vec![
            IpRange::new("10.0.0.0/8".to_string(), "Private Class A".to_string())?,
            IpRange::new("172.16.0.0/12".to_string(), "Private Class B".to_string())?,
            IpRange::new("192.168.0.0/16".to_string(), "Private Class C".to_string())?,
            IpRange::new("127.0.0.0/8".to_string(), "Loopback".to_string())?,
            IpRange::new("169.254.0.0/16".to_string(), "Link-local".to_string())?,
        ];
        
        Ok(AclRule::new(
            "deny-private".to_string(),
            private_ranges,
            AclAction::Deny,
            vec![], // All zones
            100,    // High priority
            "Deny private network ranges".to_string(),
        ))
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> SecurityResult<AclStats> {
        Ok(self.stats.snapshot())
    }
}

/// Access control statistics
#[derive(Debug)]
pub struct AclStats {
    pub access_checks: AtomicU64,
    pub allowed_requests: AtomicU64,
    pub denied_requests: AtomicU64,
    pub dropped_requests: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub rule_matches: AtomicU64,
    pub default_actions: AtomicU64,
    pub rules_added: AtomicU64,
    pub rules_removed: AtomicU64,
    pub rules_updated: AtomicU64,
    pub cache_clears: AtomicU64,
    pub cache_cleanups: AtomicU64,
    pub created_at: AtomicU64,
}

impl AclStats {
    pub fn new() -> Self {
        Self {
            access_checks: AtomicU64::new(0),
            allowed_requests: AtomicU64::new(0),
            denied_requests: AtomicU64::new(0),
            dropped_requests: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            rule_matches: AtomicU64::new(0),
            default_actions: AtomicU64::new(0),
            rules_added: AtomicU64::new(0),
            rules_removed: AtomicU64::new(0),
            rules_updated: AtomicU64::new(0),
            cache_clears: AtomicU64::new(0),
            cache_cleanups: AtomicU64::new(0),
            created_at: AtomicU64::new(current_timestamp_ms()),
        }
    }

    pub fn snapshot(&self) -> Self {
        Self {
            access_checks: AtomicU64::new(self.access_checks.load(Ordering::Relaxed)),
            allowed_requests: AtomicU64::new(self.allowed_requests.load(Ordering::Relaxed)),
            denied_requests: AtomicU64::new(self.denied_requests.load(Ordering::Relaxed)),
            dropped_requests: AtomicU64::new(self.dropped_requests.load(Ordering::Relaxed)),
            cache_hits: AtomicU64::new(self.cache_hits.load(Ordering::Relaxed)),
            cache_misses: AtomicU64::new(self.cache_misses.load(Ordering::Relaxed)),
            rule_matches: AtomicU64::new(self.rule_matches.load(Ordering::Relaxed)),
            default_actions: AtomicU64::new(self.default_actions.load(Ordering::Relaxed)),
            rules_added: AtomicU64::new(self.rules_added.load(Ordering::Relaxed)),
            rules_removed: AtomicU64::new(self.rules_removed.load(Ordering::Relaxed)),
            rules_updated: AtomicU64::new(self.rules_updated.load(Ordering::Relaxed)),
            cache_clears: AtomicU64::new(self.cache_clears.load(Ordering::Relaxed)),
            cache_cleanups: AtomicU64::new(self.cache_cleanups.load(Ordering::Relaxed)),
            created_at: AtomicU64::new(self.created_at.load(Ordering::Relaxed)),
        }
    }

    /// Calculate cache hit ratio
    pub fn cache_hit_ratio(&self) -> f64 {
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let total = hits + self.cache_misses.load(Ordering::Relaxed);
        
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    /// Calculate allow ratio
    pub fn allow_ratio(&self) -> f64 {
        let allowed = self.allowed_requests.load(Ordering::Relaxed);
        let total = allowed + self.denied_requests.load(Ordering::Relaxed) + 
                   self.dropped_requests.load(Ordering::Relaxed);
        
        if total == 0 {
            0.0
        } else {
            allowed as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_ip_range_matching() {
        let range = IpRange::new("192.168.1.0/24".to_string(), "Test range".to_string()).unwrap();
        
        assert!(range.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(range.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254))));
        assert!(!range.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
    }

    #[tokio::test]
    async fn test_acl_rule_matching() {
        let range = IpRange::new("192.168.0.0/16".to_string(), "Private network".to_string()).unwrap();
        let rule = AclRule::new(
            "test-rule".to_string(),
            vec![range],
            AclAction::Deny,
            vec!["example.com".to_string()],
            100,
            "Test rule".to_string(),
        );

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Should match with correct zone
        assert!(rule.matches(ip, Some("example.com")));
        
        // Should not match with wrong zone
        assert!(!rule.matches(ip, Some("other.com")));
        
        // Should not match without zone when rule has zones
        assert!(!rule.matches(ip, None));
    }

    #[tokio::test]
    async fn test_access_controller() {
        let config = AclConfig::default();
        let controller = AccessController::new(config).unwrap();

        // Add a deny rule for private networks
        let deny_rule = AccessController::create_deny_private_rule().unwrap();
        controller.add_rule(deny_rule).await.unwrap();

        // Add an allow-all rule with lower priority
        let allow_rule = AccessController::create_allow_all_rule().unwrap();
        controller.add_rule(allow_rule).await.unwrap();

        // Private IP should be denied
        let private_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(!controller.is_allowed(private_ip).await.unwrap());

        // Public IP should be allowed
        let public_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(controller.is_allowed(public_ip).await.unwrap());
    }

    #[tokio::test]
    async fn test_cache_functionality() {
        let config = AclConfig::default();
        let controller = AccessController::new(config).unwrap();

        let allow_rule = AccessController::create_allow_all_rule().unwrap();
        controller.add_rule(allow_rule).await.unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        // First check should miss cache
        assert!(controller.is_allowed(ip).await.unwrap());
        
        // Second check should hit cache
        assert!(controller.is_allowed(ip).await.unwrap());

        let stats = controller.get_stats().await.unwrap();
        assert!(stats.cache_hits.load(Ordering::Relaxed) > 0);
    }
}