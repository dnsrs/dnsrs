//! NSEC/NSEC3 Chain Generation and Validation
//!
//! This module provides:
//! - NSEC chain generation and validation for authenticated denial of existence
//! - NSEC3 chain generation with configurable iterations and salt
//! - Efficient chain traversal and validation algorithms
//! - Atomic operations for chain updates

use crate::dnssec::{DnssecAlgorithm, RrsigRecord};
use crate::{SecurityError, SecurityResult};
use bytes::Bytes;
use ring::digest;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// NSEC record for authenticated denial of existence
#[derive(Debug, Clone)]
pub struct NsecRecord {
    pub owner_name: String,
    pub next_domain_name: String,
    pub type_bit_maps: Bytes,
    pub ttl: u32,
}

impl NsecRecord {
    /// Create a new NSEC record
    pub fn new(
        owner_name: String,
        next_domain_name: String,
        record_types: &[u16],
        ttl: u32,
    ) -> Self {
        let type_bit_maps = Self::encode_type_bit_maps(record_types);
        
        Self {
            owner_name,
            next_domain_name,
            type_bit_maps,
            ttl,
        }
    }

    /// Encode record types into type bit maps format (RFC 4034)
    fn encode_type_bit_maps(record_types: &[u16]) -> Bytes {
        let mut bit_maps = Vec::new();
        let mut current_window = None;
        let mut window_bitmap = [0u8; 32];

        for &rr_type in record_types {
            let window = rr_type / 256;
            let bit_position = rr_type % 256;
            let byte_index = bit_position / 8;
            let bit_index = 7 - (bit_position % 8);

            // Start new window if needed
            if current_window != Some(window) {
                // Finish previous window
                if let Some(prev_window) = current_window {
                    let bitmap_length = Self::find_bitmap_length(&window_bitmap);
                    if bitmap_length > 0 {
                        bit_maps.push(prev_window as u8);
                        bit_maps.push(bitmap_length);
                        bit_maps.extend_from_slice(&window_bitmap[..bitmap_length as usize]);
                    }
                    window_bitmap.fill(0);
                }
                current_window = Some(window);
            }

            // Set bit in current window
            if byte_index < 32 {
                window_bitmap[byte_index as usize] |= 1 << bit_index;
            }
        }

        // Finish last window
        if current_window.is_some() {
            let bitmap_length = Self::find_bitmap_length(&window_bitmap);
            if bitmap_length > 0 {
                bit_maps.push(current_window.unwrap() as u8);
                bit_maps.push(bitmap_length);
                bit_maps.extend_from_slice(&window_bitmap[..bitmap_length as usize]);
            }
        }

        Bytes::from(bit_maps)
    }

    /// Find the length of the bitmap (last non-zero byte + 1)
    fn find_bitmap_length(bitmap: &[u8; 32]) -> u8 {
        for i in (0..32).rev() {
            if bitmap[i] != 0 {
                return (i + 1) as u8;
            }
        }
        0
    }

    /// Check if a record type is present in the type bit maps
    pub fn has_record_type(&self, rr_type: u16) -> bool {
        let window = rr_type / 256;
        let bit_position = rr_type % 256;
        let byte_index = bit_position / 8;
        let bit_index = 7 - (bit_position % 8);

        let mut offset = 0;
        while offset < self.type_bit_maps.len() {
            if offset + 1 >= self.type_bit_maps.len() {
                break;
            }

            let window_number = self.type_bit_maps[offset];
            let bitmap_length = self.type_bit_maps[offset + 1] as usize;
            offset += 2;

            if window_number == window as u8 {
                if (byte_index as usize) < bitmap_length && offset + (byte_index as usize) < self.type_bit_maps.len() {
                    let byte_value = self.type_bit_maps[offset + (byte_index as usize)];
                    return (byte_value & (1 << bit_index)) != 0;
                }
                return false;
            }

            offset += bitmap_length;
        }

        false
    }

    /// Validate that this NSEC record covers a name for denial of existence
    pub fn covers_name(&self, query_name: &str) -> bool {
        let owner_canonical = self.owner_name.to_lowercase();
        let next_canonical = self.next_domain_name.to_lowercase();
        let query_canonical = query_name.to_lowercase();

        // Handle wrap-around case (last name in zone)
        if owner_canonical > next_canonical {
            return query_canonical > owner_canonical || query_canonical < next_canonical;
        }

        // Normal case
        query_canonical > owner_canonical && query_canonical < next_canonical
    }
}

/// NSEC3 record for hashed authenticated denial of existence
#[derive(Debug, Clone)]
pub struct Nsec3Record {
    pub hash_algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Bytes,
    pub next_hashed_owner_name: Bytes,
    pub type_bit_maps: Bytes,
    pub owner_name: String,
    pub hashed_owner_name: Bytes,
    pub ttl: u32,
}

impl Nsec3Record {
    /// Create a new NSEC3 record
    pub fn new(
        owner_name: String,
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Bytes,
        next_hashed_owner_name: Bytes,
        record_types: &[u16],
        ttl: u32,
    ) -> SecurityResult<Self> {
        let hashed_owner_name = Self::hash_name(&owner_name, hash_algorithm, iterations, &salt)?;
        let type_bit_maps = NsecRecord::encode_type_bit_maps(record_types);

        Ok(Self {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner_name,
            type_bit_maps,
            owner_name,
            hashed_owner_name,
            ttl,
        })
    }

    /// Hash a domain name using NSEC3 algorithm
    pub fn hash_name(
        name: &str,
        hash_algorithm: u8,
        iterations: u16,
        salt: &[u8],
    ) -> SecurityResult<Bytes> {
        if hash_algorithm != 1 {
            return Err(SecurityError::UnsupportedAlgorithm(
                format!("NSEC3 hash algorithm {} not supported", hash_algorithm)
            ));
        }

        // Convert name to wire format
        let wire_name = Self::name_to_wire(name)?;
        
        // Initial hash with salt
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&wire_name);
        hash_input.extend_from_slice(salt);
        
        let mut hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &hash_input);
        
        // Additional iterations
        for _ in 0..iterations {
            hash_input.clear();
            hash_input.extend_from_slice(hash.as_ref());
            hash_input.extend_from_slice(salt);
            hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &hash_input);
        }

        Ok(Bytes::from(hash.as_ref().to_vec()))
    }

    /// Convert domain name to wire format
    fn name_to_wire(name: &str) -> SecurityResult<Vec<u8>> {
        let mut wire = Vec::new();
        
        if name == "." {
            wire.push(0);
            return Ok(wire);
        }

        for label in name.to_lowercase().split('.') {
            if !label.is_empty() {
                if label.len() > 63 {
                    return Err(SecurityError::InvalidData("Label too long".to_string()));
                }
                wire.push(label.len() as u8);
                wire.extend_from_slice(label.as_bytes());
            }
        }
        wire.push(0); // Root label

        Ok(wire)
    }

    /// Check if a record type is present in the type bit maps
    pub fn has_record_type(&self, rr_type: u16) -> bool {
        // Reuse NSEC logic for type bit maps
        let temp_nsec = NsecRecord {
            owner_name: self.owner_name.clone(),
            next_domain_name: String::new(),
            type_bit_maps: self.type_bit_maps.clone(),
            ttl: self.ttl,
        };
        temp_nsec.has_record_type(rr_type)
    }

    /// Check if this NSEC3 record covers a hashed name
    pub fn covers_hash(&self, target_hash: &[u8]) -> bool {
        // Compare hashes lexicographically
        let owner_hash = &self.hashed_owner_name;
        let next_hash = &self.next_hashed_owner_name;

        // Handle wrap-around case
        if owner_hash > next_hash {
            return target_hash > owner_hash || target_hash < next_hash;
        }

        // Normal case
        target_hash > owner_hash && target_hash < next_hash
    }

    /// Validate that this NSEC3 record covers a name for denial of existence
    pub fn covers_name(&self, query_name: &str) -> SecurityResult<bool> {
        let target_hash = Self::hash_name(query_name, self.hash_algorithm, self.iterations, &self.salt)?;
        Ok(self.covers_hash(&target_hash))
    }
}

/// NSEC3PARAM record for zone-wide NSEC3 parameters
#[derive(Debug, Clone)]
pub struct Nsec3ParamRecord {
    pub hash_algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Bytes,
    pub ttl: u32,
}

/// NSEC/NSEC3 chain manager for a DNS zone
pub struct NsecChainManager {
    /// Zone name this manager handles
    zone_name: String,
    /// NSEC records indexed by owner name
    nsec_records: Arc<RwLock<BTreeMap<String, NsecRecord>>>,
    /// NSEC3 records indexed by hashed owner name
    nsec3_records: Arc<RwLock<BTreeMap<Vec<u8>, Nsec3Record>>>,
    /// NSEC3 parameters for the zone
    nsec3_params: Arc<RwLock<Option<Nsec3ParamRecord>>>,
    /// All domain names in the zone (for chain generation)
    zone_names: Arc<RwLock<BTreeSet<String>>>,
    /// Statistics
    stats: Arc<NsecChainStats>,
}

/// NSEC chain statistics
#[derive(Debug)]
pub struct NsecChainStats {
    pub nsec_records_generated: AtomicU64,
    pub nsec3_records_generated: AtomicU64,
    pub chain_validations: AtomicU64,
    pub denial_proofs: AtomicU64,
    pub chain_updates: AtomicU64,
}

impl NsecChainStats {
    pub fn new() -> Self {
        Self {
            nsec_records_generated: AtomicU64::new(0),
            nsec3_records_generated: AtomicU64::new(0),
            chain_validations: AtomicU64::new(0),
            denial_proofs: AtomicU64::new(0),
            chain_updates: AtomicU64::new(0),
        }
    }
}

impl NsecChainManager {
    /// Create a new NSEC chain manager for a zone
    pub fn new(zone_name: String) -> Self {
        Self {
            zone_name,
            nsec_records: Arc::new(RwLock::new(BTreeMap::new())),
            nsec3_records: Arc::new(RwLock::new(BTreeMap::new())),
            nsec3_params: Arc::new(RwLock::new(None)),
            zone_names: Arc::new(RwLock::new(BTreeSet::new())),
            stats: Arc::new(NsecChainStats::new()),
        }
    }

    /// Add a domain name to the zone
    pub async fn add_zone_name(&self, name: String, _record_types: Vec<u16>) {
        let mut zone_names = self.zone_names.write().await;
        zone_names.insert(name.clone());
        
        // Store record types for this name (simplified - in practice would be more complex)
        drop(zone_names);
        
        // Regenerate chains if needed
        self.regenerate_chains_if_needed().await;
    }

    /// Remove a domain name from the zone
    pub async fn remove_zone_name(&self, name: &str) {
        let mut zone_names = self.zone_names.write().await;
        zone_names.remove(name);
        drop(zone_names);
        
        // Remove associated NSEC/NSEC3 records
        {
            let mut nsec_records = self.nsec_records.write().await;
            nsec_records.remove(name);
        }
        
        // Regenerate chains
        self.regenerate_chains_if_needed().await;
    }

    /// Set NSEC3 parameters for the zone
    pub async fn set_nsec3_params(
        &self,
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Bytes,
        ttl: u32,
    ) -> SecurityResult<()> {
        let nsec3_param = Nsec3ParamRecord {
            hash_algorithm,
            flags,
            iterations,
            salt,
            ttl,
        };

        {
            let mut params = self.nsec3_params.write().await;
            *params = Some(nsec3_param);
        }

        // Regenerate NSEC3 chain
        self.generate_nsec3_chain().await?;
        
        info!("Set NSEC3 parameters for zone: {}", self.zone_name);
        Ok(())
    }

    /// Generate NSEC chain for the zone
    pub async fn generate_nsec_chain(&self) -> SecurityResult<()> {
        let zone_names = self.zone_names.read().await;
        let names: Vec<String> = zone_names.iter().cloned().collect();
        drop(zone_names);

        if names.is_empty() {
            return Ok(());
        }

        let mut sorted_names = names;
        sorted_names.sort();

        let mut nsec_records = BTreeMap::new();

        for (i, name) in sorted_names.iter().enumerate() {
            let next_name = if i + 1 < sorted_names.len() {
                sorted_names[i + 1].clone()
            } else {
                sorted_names[0].clone() // Wrap around to first name
            };

            // In practice, would get actual record types for this name
            let record_types = vec![1, 2, 5]; // A, NS, CNAME as example
            
            let nsec_record = NsecRecord::new(
                name.clone(),
                next_name,
                &record_types,
                3600, // Default TTL
            );

            nsec_records.insert(name.clone(), nsec_record);
        }

        {
            let mut records = self.nsec_records.write().await;
            *records = nsec_records;
        }

        self.stats.nsec_records_generated.store(sorted_names.len() as u64, Ordering::Release);
        self.stats.chain_updates.fetch_add(1, Ordering::Relaxed);
        
        info!("Generated NSEC chain with {} records for zone: {}", sorted_names.len(), self.zone_name);
        Ok(())
    }

    /// Generate NSEC3 chain for the zone
    pub async fn generate_nsec3_chain(&self) -> SecurityResult<()> {
        let nsec3_params = {
            let params = self.nsec3_params.read().await;
            params.clone()
        };

        let params = nsec3_params.ok_or_else(|| {
            SecurityError::ConfigurationError { reason: "NSEC3 parameters not set".to_string() }
        })?;

        let zone_names = self.zone_names.read().await;
        let names: Vec<String> = zone_names.iter().cloned().collect();
        drop(zone_names);

        if names.is_empty() {
            return Ok(());
        }

        // Hash all names and sort by hash
        let mut hashed_names = Vec::new();
        for name in &names {
            let hash = Nsec3Record::hash_name(
                name,
                params.hash_algorithm,
                params.iterations,
                &params.salt,
            )?;
            hashed_names.push((hash, name.clone()));
        }

        hashed_names.sort_by(|a, b| a.0.cmp(&b.0));

        let mut nsec3_records = BTreeMap::new();

        for (i, (hash, name)) in hashed_names.iter().enumerate() {
            let next_hash = if i + 1 < hashed_names.len() {
                hashed_names[i + 1].0.clone()
            } else {
                hashed_names[0].0.clone() // Wrap around
            };

            // In practice, would get actual record types for this name
            let record_types = vec![1, 2, 5]; // A, NS, CNAME as example

            let nsec3_record = Nsec3Record::new(
                name.clone(),
                params.hash_algorithm,
                params.flags,
                params.iterations,
                params.salt.clone(),
                next_hash,
                &record_types,
                params.ttl,
            )?;

            nsec3_records.insert(hash.to_vec(), nsec3_record);
        }

        {
            let mut records = self.nsec3_records.write().await;
            *records = nsec3_records;
        }

        self.stats.nsec3_records_generated.store(hashed_names.len() as u64, Ordering::Release);
        self.stats.chain_updates.fetch_add(1, Ordering::Relaxed);
        
        info!("Generated NSEC3 chain with {} records for zone: {}", hashed_names.len(), self.zone_name);
        Ok(())
    }

    /// Find NSEC record that covers a name for denial of existence
    pub async fn find_covering_nsec(&self, query_name: &str) -> Option<NsecRecord> {
        let nsec_records = self.nsec_records.read().await;
        
        for nsec_record in nsec_records.values() {
            if nsec_record.covers_name(query_name) {
                self.stats.denial_proofs.fetch_add(1, Ordering::Relaxed);
                return Some(nsec_record.clone());
            }
        }
        
        None
    }

    /// Find NSEC3 record that covers a name for denial of existence
    pub async fn find_covering_nsec3(&self, query_name: &str) -> SecurityResult<Option<Nsec3Record>> {
        let nsec3_params = {
            let params = self.nsec3_params.read().await;
            params.clone()
        };

        let params = nsec3_params.ok_or_else(|| {
            SecurityError::ConfigurationError { reason: "NSEC3 parameters not set".to_string() }
        })?;

        let target_hash = Nsec3Record::hash_name(
            query_name,
            params.hash_algorithm,
            params.iterations,
            &params.salt,
        )?;

        let nsec3_records = self.nsec3_records.read().await;
        
        for nsec3_record in nsec3_records.values() {
            if nsec3_record.covers_hash(&target_hash) {
                self.stats.denial_proofs.fetch_add(1, Ordering::Relaxed);
                return Ok(Some(nsec3_record.clone()));
            }
        }
        
        Ok(None)
    }

    /// Validate NSEC chain integrity
    pub async fn validate_nsec_chain(&self) -> SecurityResult<bool> {
        let nsec_records = self.nsec_records.read().await;
        let records: Vec<NsecRecord> = nsec_records.values().cloned().collect();
        drop(nsec_records);

        if records.is_empty() {
            return Ok(true);
        }

        // Check that chain forms a complete cycle
        let mut visited = std::collections::HashSet::new();
        let mut current_name = records[0].owner_name.clone();
        
        loop {
            if visited.contains(&current_name) {
                // Should only revisit the starting name to complete the cycle
                if current_name == records[0].owner_name && visited.len() == records.len() {
                    break;
                } else {
                    warn!("NSEC chain has cycle or missing records");
                    return Ok(false);
                }
            }
            
            visited.insert(current_name.clone());
            
            // Find next record
            let next_record = records.iter()
                .find(|r| r.owner_name == current_name);
                
            match next_record {
                Some(record) => {
                    current_name = record.next_domain_name.clone();
                }
                None => {
                    warn!("NSEC chain is broken - missing record for: {}", current_name);
                    return Ok(false);
                }
            }
        }

        self.stats.chain_validations.fetch_add(1, Ordering::Relaxed);
        info!("NSEC chain validation successful for zone: {}", self.zone_name);
        Ok(true)
    }

    /// Validate NSEC3 chain integrity
    pub async fn validate_nsec3_chain(&self) -> SecurityResult<bool> {
        let nsec3_records = self.nsec3_records.read().await;
        let records: Vec<Nsec3Record> = nsec3_records.values().cloned().collect();
        drop(nsec3_records);

        if records.is_empty() {
            return Ok(true);
        }

        // Check that chain forms a complete cycle
        let mut visited = std::collections::HashSet::new();
        let mut current_hash = records[0].hashed_owner_name.to_vec();
        
        loop {
            if visited.contains(&current_hash) {
                // Should only revisit the starting hash to complete the cycle
                if current_hash == records[0].hashed_owner_name && visited.len() == records.len() {
                    break;
                } else {
                    warn!("NSEC3 chain has cycle or missing records");
                    return Ok(false);
                }
            }
            
            visited.insert(current_hash.clone());
            
            // Find next record
            let next_record = records.iter()
                .find(|r| r.hashed_owner_name == current_hash);
                
            match next_record {
                Some(record) => {
                    current_hash = record.next_hashed_owner_name.to_vec();
                }
                None => {
                    warn!("NSEC3 chain is broken - missing record for hash");
                    return Ok(false);
                }
            }
        }

        self.stats.chain_validations.fetch_add(1, Ordering::Relaxed);
        info!("NSEC3 chain validation successful for zone: {}", self.zone_name);
        Ok(true)
    }

    /// Get NSEC3 parameters for the zone
    pub async fn get_nsec3_params(&self) -> Option<Nsec3ParamRecord> {
        let params = self.nsec3_params.read().await;
        params.clone()
    }

    /// Get all NSEC records
    pub async fn get_nsec_records(&self) -> Vec<NsecRecord> {
        let nsec_records = self.nsec_records.read().await;
        nsec_records.values().cloned().collect()
    }

    /// Get all NSEC3 records
    pub async fn get_nsec3_records(&self) -> Vec<Nsec3Record> {
        let nsec3_records = self.nsec3_records.read().await;
        nsec3_records.values().cloned().collect()
    }

    /// Regenerate chains if needed (called after zone changes)
    async fn regenerate_chains_if_needed(&self) {
        // Check if NSEC3 is enabled
        let has_nsec3_params = {
            let params = self.nsec3_params.read().await;
            params.is_some()
        };

        if has_nsec3_params {
            if let Err(e) = self.generate_nsec3_chain().await {
                warn!("Failed to regenerate NSEC3 chain: {}", e);
            }
        } else {
            if let Err(e) = self.generate_nsec_chain().await {
                warn!("Failed to regenerate NSEC chain: {}", e);
            }
        }
    }

    /// Get chain statistics
    pub fn get_stats(&self) -> Arc<NsecChainStats> {
        self.stats.clone()
    }
}

/// NSEC/NSEC3 proof generator for denial of existence responses
pub struct DenialProofGenerator {
    /// Chain managers per zone
    zone_managers: Arc<RwLock<HashMap<String, Arc<NsecChainManager>>>>,
}

impl DenialProofGenerator {
    pub fn new() -> Self {
        Self {
            zone_managers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a zone manager
    pub async fn add_zone_manager(&self, zone_name: String, manager: Arc<NsecChainManager>) {
        let mut managers = self.zone_managers.write().await;
        managers.insert(zone_name, manager);
    }

    /// Generate denial of existence proof for a query
    pub async fn generate_denial_proof(
        &self,
        zone_name: &str,
        query_name: &str,
        _query_type: u16,
    ) -> SecurityResult<DenialProof> {
        let managers = self.zone_managers.read().await;
        let manager = managers.get(zone_name)
            .ok_or_else(|| SecurityError::ZoneNotFound(format!("Zone not found: {}", zone_name)))?;

        // Try NSEC3 first, then NSEC
        if let Some(nsec3_params) = manager.get_nsec3_params().await {
            if let Some(nsec3_record) = manager.find_covering_nsec3(query_name).await? {
                return Ok(DenialProof::Nsec3 {
                    nsec3_record,
                    nsec3_params,
                });
            }
        }

        if let Some(nsec_record) = manager.find_covering_nsec(query_name).await {
            return Ok(DenialProof::Nsec { nsec_record });
        }

        Err(SecurityError::ProofGenerationFailed(
            format!("No denial proof found for {} in zone {}", query_name, zone_name)
        ))
    }
}

/// Denial of existence proof
#[derive(Debug, Clone)]
pub enum DenialProof {
    Nsec {
        nsec_record: NsecRecord,
    },
    Nsec3 {
        nsec3_record: Nsec3Record,
        nsec3_params: Nsec3ParamRecord,
    },
}

impl Default for DenialProofGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nsec_record_creation() {
        let nsec = NsecRecord::new(
            "example.com".to_string(),
            "mail.example.com".to_string(),
            &[1, 2, 15], // A, NS, MX
            3600,
        );

        assert_eq!(nsec.owner_name, "example.com");
        assert_eq!(nsec.next_domain_name, "mail.example.com");
        assert!(nsec.has_record_type(1)); // A
        assert!(nsec.has_record_type(2)); // NS
        assert!(nsec.has_record_type(15)); // MX
        assert!(!nsec.has_record_type(5)); // CNAME
    }

    #[tokio::test]
    async fn test_nsec3_hashing() {
        let hash = Nsec3Record::hash_name(
            "example.com",
            1, // SHA-1
            10, // iterations
            b"salt",
        ).unwrap();

        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 20); // SHA-1 produces 20 bytes
    }

    #[tokio::test]
    async fn test_nsec_chain_generation() {
        let manager = NsecChainManager::new("example.com".to_string());
        
        manager.add_zone_name("example.com".to_string(), vec![1, 2]).await;
        manager.add_zone_name("mail.example.com".to_string(), vec![1]).await;
        manager.add_zone_name("www.example.com".to_string(), vec![1]).await;
        
        manager.generate_nsec_chain().await.unwrap();
        
        let nsec_records = manager.get_nsec_records().await;
        assert_eq!(nsec_records.len(), 3);
        
        // Validate chain integrity
        assert!(manager.validate_nsec_chain().await.unwrap());
    }

    #[tokio::test]
    async fn test_nsec3_chain_generation() {
        let manager = NsecChainManager::new("example.com".to_string());
        
        manager.add_zone_name("example.com".to_string(), vec![1, 2]).await;
        manager.add_zone_name("mail.example.com".to_string(), vec![1]).await;
        
        manager.set_nsec3_params(1, 0, 10, Bytes::from("salt"), 3600).await.unwrap();
        
        let nsec3_records = manager.get_nsec3_records().await;
        assert_eq!(nsec3_records.len(), 2);
        
        // Validate chain integrity
        assert!(manager.validate_nsec3_chain().await.unwrap());
    }
}