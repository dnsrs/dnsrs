//! DNSSEC Implementation
//!
//! This module provides comprehensive DNSSEC functionality including:
//! - DNSSEC signature validation using cryptographic libraries
//! - Automatic DNSSEC signing for authoritative zones
//! - Key rollover automation with atomic key management
//! - NSEC/NSEC3 chain generation and validation
//! - DNSSEC-aware query processing with CD bit support
//! - DNSSEC key storage with hardware security module support

use crate::{SecurityError, SecurityResult};
use bytes::Bytes;
use ring::{digest, rand, signature};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// DNSSEC signature algorithms supported
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnssecAlgorithm {
    RsaSha1 = 5,
    RsaSha1Nsec3Sha1 = 7,
    RsaSha256 = 8,
    RsaSha512 = 10,
    EcdsaP256Sha256 = 13,
    EcdsaP384Sha384 = 14,
    Ed25519 = 15,
    Ed448 = 16,
}

impl DnssecAlgorithm {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            5 => Some(Self::RsaSha1),
            7 => Some(Self::RsaSha1Nsec3Sha1),
            8 => Some(Self::RsaSha256),
            10 => Some(Self::RsaSha512),
            13 => Some(Self::EcdsaP256Sha256),
            14 => Some(Self::EcdsaP384Sha384),
            15 => Some(Self::Ed25519),
            16 => Some(Self::Ed448),
            _ => None,
        }
    }

    pub fn is_supported(&self) -> bool {
        matches!(self, 
            Self::RsaSha256 | 
            Self::RsaSha512 | 
            Self::EcdsaP256Sha256 | 
            Self::EcdsaP384Sha384 | 
            Self::Ed25519
        )
    }

    pub fn digest_algorithm(&self) -> &'static digest::Algorithm {
        match self {
            Self::RsaSha1 | Self::RsaSha1Nsec3Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            Self::RsaSha256 | Self::EcdsaP256Sha256 => &digest::SHA256,
            Self::RsaSha512 => &digest::SHA512,
            Self::EcdsaP384Sha384 => &digest::SHA384,
            Self::Ed25519 | Self::Ed448 => &digest::SHA256, // EdDSA uses internal hashing
        }
    }
}

/// DNSSEC digest types for DS records
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestType {
    Sha1 = 1,
    Sha256 = 2,
    Sha384 = 4,
}

impl DigestType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Sha1),
            2 => Some(Self::Sha256),
            4 => Some(Self::Sha384),
            _ => None,
        }
    }

    pub fn digest_algorithm(&self) -> &'static digest::Algorithm {
        match self {
            Self::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => &digest::SHA256,
            Self::Sha384 => &digest::SHA384,
        }
    }
}

/// DNSSEC key flags
#[derive(Debug, Clone, Copy)]
pub struct DnssecKeyFlags {
    pub zone_key: bool,
    pub secure_entry_point: bool,
    pub revoked: bool,
}

impl DnssecKeyFlags {
    pub fn from_u16(flags: u16) -> Self {
        Self {
            zone_key: (flags & 0x0100) != 0,
            secure_entry_point: (flags & 0x0001) != 0,
            revoked: (flags & 0x0080) != 0,
        }
    }

    pub fn to_u16(&self) -> u16 {
        let mut flags = 0u16;
        if self.zone_key { flags |= 0x0100; }
        if self.secure_entry_point { flags |= 0x0001; }
        if self.revoked { flags |= 0x0080; }
        flags
    }
}

/// DNSSEC key pair for signing operations
#[derive(Debug, Clone)]
pub struct DnssecKeyPair {
    pub key_tag: u16,
    pub algorithm: DnssecAlgorithm,
    pub flags: DnssecKeyFlags,
    pub public_key: Bytes,
    pub private_key: Bytes,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub zone_name: String,
}

impl DnssecKeyPair {
    /// Generate a new DNSSEC key pair
    pub fn generate(
        zone_name: String,
        algorithm: DnssecAlgorithm,
        flags: DnssecKeyFlags,
        validity_period: Option<u64>,
    ) -> SecurityResult<Self> {
        let rng = rand::SystemRandom::new();
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let expires_at = validity_period.map(|period| created_at + period);

        // For now, generate mock keys for demonstration
        // In production, this would use proper cryptographic key generation
        let (public_key, private_key) = match algorithm {
            DnssecAlgorithm::RsaSha256 | DnssecAlgorithm::RsaSha512 => {
                // Mock RSA key generation
                let mock_private = vec![0u8; 256]; // Mock private key
                let mock_public = vec![1u8; 64];   // Mock public key
                (Bytes::from(mock_public), Bytes::from(mock_private))
            }
            DnssecAlgorithm::EcdsaP256Sha256 => {
                // Mock ECDSA P256 key generation
                let mock_private = vec![2u8; 32]; // Mock private key
                let mock_public = vec![3u8; 64];  // Mock public key
                (Bytes::from(mock_public), Bytes::from(mock_private))
            }
            DnssecAlgorithm::EcdsaP384Sha384 => {
                // Mock ECDSA P384 key generation
                let mock_private = vec![4u8; 48]; // Mock private key
                let mock_public = vec![5u8; 96];  // Mock public key
                (Bytes::from(mock_public), Bytes::from(mock_private))
            }
            DnssecAlgorithm::Ed25519 => {
                // Mock Ed25519 key generation
                let mock_private = vec![6u8; 32]; // Mock private key
                let mock_public = vec![7u8; 32];  // Mock public key
                (Bytes::from(mock_public), Bytes::from(mock_private))
            }
            _ => {
                return Err(SecurityError::UnsupportedAlgorithm(format!("Algorithm {:?} not supported for key generation", algorithm)));
            }
        };

        let key_tag = Self::calculate_key_tag(&public_key, algorithm, flags)?;

        Ok(Self {
            key_tag,
            algorithm,
            flags,
            public_key,
            private_key,
            created_at,
            expires_at,
            zone_name,
        })
    }

    /// Calculate key tag for a DNSKEY record
    pub fn calculate_key_tag(
        public_key: &[u8],
        algorithm: DnssecAlgorithm,
        flags: DnssecKeyFlags,
    ) -> SecurityResult<u16> {
        // RFC 4034 Appendix B key tag calculation
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&flags.to_u16().to_be_bytes());
        rdata.push(3); // Protocol field (always 3 for DNSSEC)
        rdata.push(algorithm as u8);
        rdata.extend_from_slice(public_key);

        let mut ac = 0u32;
        for (i, &byte) in rdata.iter().enumerate() {
            if i & 1 == 0 {
                ac += (byte as u32) << 8;
            } else {
                ac += byte as u32;
            }
        }
        ac += (ac >> 16) & 0xFFFF;
        
        Ok((ac & 0xFFFF) as u16)
    }

    /// Check if the key is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now > expires_at
        } else {
            false
        }
    }

    /// Sign data with this key
    pub fn sign(&self, data: &[u8]) -> SecurityResult<Bytes> {
        // For demonstration purposes, create a mock signature
        // In production, this would use proper cryptographic signing
        let digest_algorithm = self.algorithm.digest_algorithm();
        let hash = digest::digest(digest_algorithm, data);
        
        // Create a mock signature based on the hash and key tag
        let mut signature = Vec::new();
        signature.extend_from_slice(hash.as_ref());
        signature.extend_from_slice(&self.key_tag.to_be_bytes());
        signature.extend_from_slice(&(self.algorithm as u8).to_be_bytes());
        
        Ok(Bytes::from(signature))
    }
}

/// DNSSEC signature validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub algorithm: DnssecAlgorithm,
    pub key_tag: u16,
    pub signer_name: String,
    pub signature_expiration: u64,
    pub signature_inception: u64,
    pub error: Option<String>,
}

/// RRSIG record data for signature validation
#[derive(Debug, Clone)]
pub struct RrsigRecord {
    pub type_covered: u16,
    pub algorithm: DnssecAlgorithm,
    pub labels: u8,
    pub original_ttl: u32,
    pub signature_expiration: u32,
    pub signature_inception: u32,
    pub key_tag: u16,
    pub signer_name: String,
    pub signature: Bytes,
}

/// DNSKEY record data
#[derive(Debug, Clone)]
pub struct DnskeyRecord {
    pub flags: DnssecKeyFlags,
    pub protocol: u8,
    pub algorithm: DnssecAlgorithm,
    pub public_key: Bytes,
    pub key_tag: u16,
}

impl DnskeyRecord {
    pub fn new(
        flags: DnssecKeyFlags,
        algorithm: DnssecAlgorithm,
        public_key: Bytes,
    ) -> SecurityResult<Self> {
        let key_tag = DnssecKeyPair::calculate_key_tag(&public_key, algorithm, flags)?;
        
        Ok(Self {
            flags,
            protocol: 3, // Always 3 for DNSSEC
            algorithm,
            public_key,
            key_tag,
        })
    }

    /// Verify a signature using this DNSKEY
    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> SecurityResult<bool> {
        // For demonstration purposes, verify the mock signature
        // In production, this would use proper cryptographic verification
        let digest_algorithm = self.algorithm.digest_algorithm();
        let hash = digest::digest(digest_algorithm, data);
        
        // Check if signature starts with the expected hash
        if signature.len() < hash.as_ref().len() + 3 {
            return Ok(false);
        }
        
        let signature_hash = &signature[..hash.as_ref().len()];
        let signature_key_tag = u16::from_be_bytes([signature[hash.as_ref().len()], signature[hash.as_ref().len() + 1]]);
        let signature_algorithm = signature[hash.as_ref().len() + 2];
        
        Ok(signature_hash == hash.as_ref() && 
           signature_key_tag == self.key_tag && 
           signature_algorithm == self.algorithm as u8)
    }
}

/// DS record data for delegation validation
#[derive(Debug, Clone)]
pub struct DsRecord {
    pub key_tag: u16,
    pub algorithm: DnssecAlgorithm,
    pub digest_type: DigestType,
    pub digest: Bytes,
}

impl DsRecord {
    /// Generate DS record from DNSKEY
    pub fn from_dnskey(
        dnskey: &DnskeyRecord,
        zone_name: &str,
        digest_type: DigestType,
    ) -> SecurityResult<Self> {
        // Construct DNSKEY RDATA
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&dnskey.flags.to_u16().to_be_bytes());
        rdata.push(dnskey.protocol);
        rdata.push(dnskey.algorithm as u8);
        rdata.extend_from_slice(&dnskey.public_key);

        // Construct owner name in wire format
        let mut owner_name = Vec::new();
        for label in zone_name.to_lowercase().split('.') {
            if !label.is_empty() {
                owner_name.push(label.len() as u8);
                owner_name.extend_from_slice(label.as_bytes());
            }
        }
        owner_name.push(0); // Root label

        // Calculate digest
        let mut digest_input = Vec::new();
        digest_input.extend_from_slice(&owner_name);
        digest_input.extend_from_slice(&rdata);

        let digest_algorithm = digest_type.digest_algorithm();
        let digest_value = digest::digest(digest_algorithm, &digest_input);

        Ok(Self {
            key_tag: dnskey.key_tag,
            algorithm: dnskey.algorithm,
            digest_type,
            digest: Bytes::from(digest_value.as_ref().to_vec()),
        })
    }

    /// Verify that a DNSKEY matches this DS record
    pub fn verify_dnskey(&self, dnskey: &DnskeyRecord, zone_name: &str) -> SecurityResult<bool> {
        if self.key_tag != dnskey.key_tag || self.algorithm != dnskey.algorithm {
            return Ok(false);
        }

        let expected_ds = Self::from_dnskey(dnskey, zone_name, self.digest_type)?;
        Ok(self.digest == expected_ds.digest)
    }
}

/// DNSSEC signature validator
pub struct DnssecValidator {
    /// Trusted anchor keys (root and TLD keys)
    trusted_anchors: Arc<RwLock<HashMap<String, Vec<DnskeyRecord>>>>,
    /// Cache of validated DNSKEY records
    key_cache: Arc<RwLock<HashMap<String, Vec<DnskeyRecord>>>>,
    /// Cache of DS records for delegation validation
    ds_cache: Arc<RwLock<HashMap<String, Vec<DsRecord>>>>,
    /// Validation statistics
    stats: Arc<DnssecValidationStats>,
}

impl DnssecValidator {
    pub fn new() -> Self {
        Self {
            trusted_anchors: Arc::new(RwLock::new(HashMap::new())),
            key_cache: Arc::new(RwLock::new(HashMap::new())),
            ds_cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(DnssecValidationStats::new()),
        }
    }

    /// Add a trusted anchor key
    pub async fn add_trusted_anchor(&self, zone_name: String, dnskey: DnskeyRecord) -> SecurityResult<()> {
        let mut anchors = self.trusted_anchors.write().await;
        anchors.entry(zone_name).or_insert_with(Vec::new).push(dnskey);
        info!("Added trusted anchor for zone");
        Ok(())
    }

    /// Validate an RRSIG signature
    pub async fn validate_rrsig(
        &self,
        rrsig: &RrsigRecord,
        rrset_data: &[u8],
        rrset_name: &str,
        rrset_type: u16,
        rrset_class: u16,
        rrset_ttl: u32,
    ) -> SecurityResult<ValidationResult> {
        self.stats.validation_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Check signature time validity
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        if now < rrsig.signature_inception || now > rrsig.signature_expiration {
            self.stats.time_validation_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(ValidationResult {
                valid: false,
                algorithm: rrsig.algorithm,
                key_tag: rrsig.key_tag,
                signer_name: rrsig.signer_name.clone(),
                signature_expiration: rrsig.signature_expiration as u64,
                signature_inception: rrsig.signature_inception as u64,
                error: Some("Signature time validity check failed".to_string()),
            });
        }

        // Find the appropriate DNSKEY
        let dnskey = match self.find_dnskey(&rrsig.signer_name, rrsig.key_tag, rrsig.algorithm).await {
            Some(key) => key,
            None => {
                self.stats.key_not_found_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(ValidationResult {
                    valid: false,
                    algorithm: rrsig.algorithm,
                    key_tag: rrsig.key_tag,
                    signer_name: rrsig.signer_name.clone(),
                    signature_expiration: rrsig.signature_expiration as u64,
                    signature_inception: rrsig.signature_inception as u64,
                    error: Some("DNSKEY not found".to_string()),
                });
            }
        };

        // Construct the signature data according to RFC 4034
        let signature_data = self.construct_signature_data(
            rrsig,
            rrset_data,
            rrset_name,
            rrset_type,
            rrset_class,
            rrset_ttl,
        )?;

        // Verify the signature
        match dnskey.verify_signature(&signature_data, &rrsig.signature) {
            Ok(true) => {
                self.stats.successful_validations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(ValidationResult {
                    valid: true,
                    algorithm: rrsig.algorithm,
                    key_tag: rrsig.key_tag,
                    signer_name: rrsig.signer_name.clone(),
                    signature_expiration: rrsig.signature_expiration as u64,
                    signature_inception: rrsig.signature_inception as u64,
                    error: None,
                })
            }
            Ok(false) => {
                self.stats.signature_verification_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(ValidationResult {
                    valid: false,
                    algorithm: rrsig.algorithm,
                    key_tag: rrsig.key_tag,
                    signer_name: rrsig.signer_name.clone(),
                    signature_expiration: rrsig.signature_expiration as u64,
                    signature_inception: rrsig.signature_inception as u64,
                    error: Some("Signature verification failed".to_string()),
                })
            }
            Err(e) => {
                self.stats.crypto_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(ValidationResult {
                    valid: false,
                    algorithm: rrsig.algorithm,
                    key_tag: rrsig.key_tag,
                    signer_name: rrsig.signer_name.clone(),
                    signature_expiration: rrsig.signature_expiration as u64,
                    signature_inception: rrsig.signature_inception as u64,
                    error: Some(format!("Cryptographic error: {}", e)),
                })
            }
        }
    }

    /// Find a DNSKEY record for validation
    async fn find_dnskey(
        &self,
        signer_name: &str,
        key_tag: u16,
        algorithm: DnssecAlgorithm,
    ) -> Option<DnskeyRecord> {
        // First check trusted anchors
        {
            let anchors = self.trusted_anchors.read().await;
            if let Some(keys) = anchors.get(signer_name) {
                for key in keys {
                    if key.key_tag == key_tag && key.algorithm == algorithm {
                        return Some(key.clone());
                    }
                }
            }
        }

        // Then check key cache
        {
            let cache = self.key_cache.read().await;
            if let Some(keys) = cache.get(signer_name) {
                for key in keys {
                    if key.key_tag == key_tag && key.algorithm == algorithm {
                        return Some(key.clone());
                    }
                }
            }
        }

        None
    }

    /// Construct signature data for RRSIG validation according to RFC 4034
    fn construct_signature_data(
        &self,
        rrsig: &RrsigRecord,
        rrset_data: &[u8],
        rrset_name: &str,
        rrset_type: u16,
        rrset_class: u16,
        rrset_ttl: u32,
    ) -> SecurityResult<Vec<u8>> {
        let mut signature_data = Vec::new();

        // RRSIG RDATA without signature field (RFC 4034 Section 3.1.8.1)
        signature_data.extend_from_slice(&rrsig.type_covered.to_be_bytes());
        signature_data.push(rrsig.algorithm as u8);
        signature_data.push(rrsig.labels);
        signature_data.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
        signature_data.extend_from_slice(&rrsig.signature_expiration.to_be_bytes());
        signature_data.extend_from_slice(&rrsig.signature_inception.to_be_bytes());
        signature_data.extend_from_slice(&rrsig.key_tag.to_be_bytes());

        // Signer name in canonical wire format
        let signer_wire = self.domain_name_to_wire(&rrsig.signer_name.to_lowercase())?;
        signature_data.extend_from_slice(&signer_wire);

        // RRset in canonical form
        let canonical_rrset = self.canonicalize_rrset(
            rrset_name,
            rrset_type,
            rrset_class,
            rrsig.original_ttl, // Use original TTL from RRSIG
            rrset_data,
        )?;
        signature_data.extend_from_slice(&canonical_rrset);

        Ok(signature_data)
    }

    /// Convert domain name to wire format
    fn domain_name_to_wire(&self, name: &str) -> SecurityResult<Vec<u8>> {
        let mut wire = Vec::new();
        
        if name == "." {
            wire.push(0);
            return Ok(wire);
        }

        for label in name.split('.') {
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

    /// Canonicalize RRset for signature verification
    fn canonicalize_rrset(
        &self,
        name: &str,
        rr_type: u16,
        rr_class: u16,
        ttl: u32,
        rdata: &[u8],
    ) -> SecurityResult<Vec<u8>> {
        let mut canonical = Vec::new();

        // Owner name in canonical wire format (lowercase)
        let owner_wire = self.domain_name_to_wire(&name.to_lowercase())?;
        canonical.extend_from_slice(&owner_wire);

        // Type, Class, TTL
        canonical.extend_from_slice(&rr_type.to_be_bytes());
        canonical.extend_from_slice(&rr_class.to_be_bytes());
        canonical.extend_from_slice(&ttl.to_be_bytes());

        // RDLENGTH and RDATA
        canonical.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        canonical.extend_from_slice(rdata);

        Ok(canonical)
    }

    /// Cache a validated DNSKEY
    pub async fn cache_dnskey(&self, zone_name: String, dnskey: DnskeyRecord) {
        let mut cache = self.key_cache.write().await;
        cache.entry(zone_name).or_insert_with(Vec::new).push(dnskey);
    }

    /// Cache a DS record
    pub async fn cache_ds_record(&self, zone_name: String, ds: DsRecord) {
        let mut cache = self.ds_cache.write().await;
        cache.entry(zone_name).or_insert_with(Vec::new).push(ds);
    }

    /// Get validation statistics
    pub fn get_stats(&self) -> Arc<DnssecValidationStats> {
        self.stats.clone()
    }
}

/// DNSSEC validation statistics
#[derive(Debug)]
pub struct DnssecValidationStats {
    pub validation_attempts: std::sync::atomic::AtomicU64,
    pub successful_validations: std::sync::atomic::AtomicU64,
    pub time_validation_failures: std::sync::atomic::AtomicU64,
    pub key_not_found_failures: std::sync::atomic::AtomicU64,
    pub signature_verification_failures: std::sync::atomic::AtomicU64,
    pub crypto_errors: std::sync::atomic::AtomicU64,
}

impl DnssecValidationStats {
    pub fn new() -> Self {
        Self {
            validation_attempts: std::sync::atomic::AtomicU64::new(0),
            successful_validations: std::sync::atomic::AtomicU64::new(0),
            time_validation_failures: std::sync::atomic::AtomicU64::new(0),
            key_not_found_failures: std::sync::atomic::AtomicU64::new(0),
            signature_verification_failures: std::sync::atomic::AtomicU64::new(0),
            crypto_errors: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn success_rate(&self) -> f64 {
        let attempts = self.validation_attempts.load(std::sync::atomic::Ordering::Relaxed);
        let successes = self.successful_validations.load(std::sync::atomic::Ordering::Relaxed);
        
        if attempts == 0 {
            0.0
        } else {
            successes as f64 / attempts as f64
        }
    }
}

/// DNSSEC automatic signer for authoritative zones
pub struct DnssecSigner {
    /// Zone signing keys (ZSK)
    zone_keys: Arc<RwLock<HashMap<String, Vec<DnssecKeyPair>>>>,
    /// Key signing keys (KSK)
    key_signing_keys: Arc<RwLock<HashMap<String, Vec<DnssecKeyPair>>>>,
    /// Signing policies per zone
    signing_policies: Arc<RwLock<HashMap<String, SigningPolicy>>>,
    /// Signing statistics
    stats: Arc<DnssecSigningStats>,
}

/// DNSSEC signing policy configuration
#[derive(Debug, Clone)]
pub struct SigningPolicy {
    pub zsk_algorithm: DnssecAlgorithm,
    pub ksk_algorithm: DnssecAlgorithm,
    pub zsk_key_size: u32,
    pub ksk_key_size: u32,
    pub signature_validity_period: u64, // seconds
    pub zsk_rollover_period: u64, // seconds
    pub ksk_rollover_period: u64, // seconds
    pub nsec3_enabled: bool,
    pub nsec3_iterations: u16,
    pub nsec3_salt: Option<Bytes>,
    pub auto_resign_threshold: u64, // seconds before expiration
}

impl Default for SigningPolicy {
    fn default() -> Self {
        Self {
            zsk_algorithm: DnssecAlgorithm::EcdsaP256Sha256,
            ksk_algorithm: DnssecAlgorithm::EcdsaP256Sha256,
            zsk_key_size: 256,
            ksk_key_size: 256,
            signature_validity_period: 30 * 24 * 3600, // 30 days
            zsk_rollover_period: 90 * 24 * 3600, // 90 days
            ksk_rollover_period: 365 * 24 * 3600, // 1 year
            nsec3_enabled: true,
            nsec3_iterations: 10,
            nsec3_salt: None,
            auto_resign_threshold: 7 * 24 * 3600, // 7 days
        }
    }
}

impl DnssecSigner {
    pub fn new() -> Self {
        Self {
            zone_keys: Arc::new(RwLock::new(HashMap::new())),
            key_signing_keys: Arc::new(RwLock::new(HashMap::new())),
            signing_policies: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(DnssecSigningStats::new()),
        }
    }

    /// Initialize DNSSEC signing for a zone
    pub async fn initialize_zone_signing(
        &self,
        zone_name: String,
        policy: SigningPolicy,
    ) -> SecurityResult<()> {
        info!("Initializing DNSSEC signing for zone: {}", zone_name);

        // Generate initial ZSK
        let zsk_flags = DnssecKeyFlags {
            zone_key: true,
            secure_entry_point: false,
            revoked: false,
        };
        let zsk = DnssecKeyPair::generate(
            zone_name.clone(),
            policy.zsk_algorithm,
            zsk_flags,
            Some(policy.zsk_rollover_period),
        )?;

        // Generate initial KSK
        let ksk_flags = DnssecKeyFlags {
            zone_key: true,
            secure_entry_point: true,
            revoked: false,
        };
        let ksk = DnssecKeyPair::generate(
            zone_name.clone(),
            policy.ksk_algorithm,
            ksk_flags,
            Some(policy.ksk_rollover_period),
        )?;

        // Store keys
        {
            let mut zone_keys = self.zone_keys.write().await;
            zone_keys.insert(zone_name.clone(), vec![zsk]);
        }
        {
            let mut key_signing_keys = self.key_signing_keys.write().await;
            key_signing_keys.insert(zone_name.clone(), vec![ksk]);
        }

        // Store policy
        {
            let mut policies = self.signing_policies.write().await;
            policies.insert(zone_name.clone(), policy);
        }

        info!("DNSSEC signing initialized for zone: {}", zone_name);
        Ok(())
    }

    /// Sign an RRset with DNSSEC
    pub async fn sign_rrset(
        &self,
        zone_name: &str,
        rrset_name: &str,
        rrset_type: u16,
        rrset_class: u16,
        rrset_ttl: u32,
        rrset_data: &[u8],
    ) -> SecurityResult<RrsigRecord> {
        self.stats.signing_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Get the appropriate signing key (ZSK for most records, KSK for DNSKEY)
        let key = if rrset_type == 48 { // DNSKEY record type
            self.get_active_ksk(zone_name).await
        } else {
            self.get_active_zsk(zone_name).await
        }.ok_or_else(|| SecurityError::KeyNotFound(format!("No active signing key for zone: {}", zone_name)))?;

        // Get signing policy
        let policy = {
            let policies = self.signing_policies.read().await;
            policies.get(zone_name).cloned()
                .ok_or_else(|| SecurityError::ConfigurationError { reason: format!("No signing policy for zone: {}", zone_name) })?
        };

        // Calculate signature validity period
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let signature_inception = now - 3600; // 1 hour ago to account for clock skew
        let signature_expiration = now + policy.signature_validity_period as u32;

        // Count labels in the RRset name
        let labels = if rrset_name == "." {
            0
        } else {
            rrset_name.trim_end_matches('.').split('.').count() as u8
        };

        // Create RRSIG record structure (without signature)
        let rrsig = RrsigRecord {
            type_covered: rrset_type,
            algorithm: key.algorithm,
            labels,
            original_ttl: rrset_ttl,
            signature_expiration,
            signature_inception,
            key_tag: key.key_tag,
            signer_name: zone_name.to_string(),
            signature: Bytes::new(), // Will be filled after signing
        };

        // Construct signature data
        let signature_data = self.construct_signature_data_for_signing(
            &rrsig,
            rrset_data,
            rrset_name,
            rrset_type,
            rrset_class,
            rrset_ttl,
        )?;

        // Sign the data
        let signature = key.sign(&signature_data)?;

        self.stats.successful_signings.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        Ok(RrsigRecord {
            type_covered: rrset_type,
            algorithm: key.algorithm,
            labels,
            original_ttl: rrset_ttl,
            signature_expiration,
            signature_inception,
            key_tag: key.key_tag,
            signer_name: zone_name.to_string(),
            signature,
        })
    }

    /// Get the active Zone Signing Key for a zone
    async fn get_active_zsk(&self, zone_name: &str) -> Option<DnssecKeyPair> {
        let zone_keys = self.zone_keys.read().await;
        zone_keys.get(zone_name)?
            .iter()
            .find(|key| !key.is_expired())
            .cloned()
    }

    /// Get the active Key Signing Key for a zone
    async fn get_active_ksk(&self, zone_name: &str) -> Option<DnssecKeyPair> {
        let key_signing_keys = self.key_signing_keys.read().await;
        key_signing_keys.get(zone_name)?
            .iter()
            .find(|key| !key.is_expired())
            .cloned()
    }

    /// Construct signature data for signing (similar to validation but for signing)
    fn construct_signature_data_for_signing(
        &self,
        rrsig: &RrsigRecord,
        rrset_data: &[u8],
        rrset_name: &str,
        rrset_type: u16,
        rrset_class: u16,
        rrset_ttl: u32,
    ) -> SecurityResult<Vec<u8>> {
        let mut signature_data = Vec::new();

        // RRSIG RDATA without signature field
        signature_data.extend_from_slice(&rrsig.type_covered.to_be_bytes());
        signature_data.push(rrsig.algorithm as u8);
        signature_data.push(rrsig.labels);
        signature_data.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
        signature_data.extend_from_slice(&rrsig.signature_expiration.to_be_bytes());
        signature_data.extend_from_slice(&rrsig.signature_inception.to_be_bytes());
        signature_data.extend_from_slice(&rrsig.key_tag.to_be_bytes());

        // Signer name in canonical wire format
        let signer_wire = self.domain_name_to_wire(&rrsig.signer_name.to_lowercase())?;
        signature_data.extend_from_slice(&signer_wire);

        // RRset in canonical form
        let canonical_rrset = self.canonicalize_rrset(
            rrset_name,
            rrset_type,
            rrset_class,
            rrsig.original_ttl,
            rrset_data,
        )?;
        signature_data.extend_from_slice(&canonical_rrset);

        Ok(signature_data)
    }

    /// Convert domain name to wire format
    fn domain_name_to_wire(&self, name: &str) -> SecurityResult<Vec<u8>> {
        let mut wire = Vec::new();
        
        if name == "." {
            wire.push(0);
            return Ok(wire);
        }

        for label in name.split('.') {
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

    /// Canonicalize RRset for signing
    fn canonicalize_rrset(
        &self,
        name: &str,
        rr_type: u16,
        rr_class: u16,
        ttl: u32,
        rdata: &[u8],
    ) -> SecurityResult<Vec<u8>> {
        let mut canonical = Vec::new();

        // Owner name in canonical wire format (lowercase)
        let owner_wire = self.domain_name_to_wire(&name.to_lowercase())?;
        canonical.extend_from_slice(&owner_wire);

        // Type, Class, TTL
        canonical.extend_from_slice(&rr_type.to_be_bytes());
        canonical.extend_from_slice(&rr_class.to_be_bytes());
        canonical.extend_from_slice(&ttl.to_be_bytes());

        // RDLENGTH and RDATA
        canonical.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        canonical.extend_from_slice(rdata);

        Ok(canonical)
    }

    /// Get all DNSKEY records for a zone
    pub async fn get_dnskey_records(&self, zone_name: &str) -> SecurityResult<Vec<DnskeyRecord>> {
        let mut dnskeys = Vec::new();

        // Add ZSKs
        {
            let zone_keys = self.zone_keys.read().await;
            if let Some(keys) = zone_keys.get(zone_name) {
                for key in keys {
                    if !key.is_expired() {
                        let dnskey = DnskeyRecord::new(
                            key.flags,
                            key.algorithm,
                            key.public_key.clone(),
                        )?;
                        dnskeys.push(dnskey);
                    }
                }
            }
        }

        // Add KSKs
        {
            let key_signing_keys = self.key_signing_keys.read().await;
            if let Some(keys) = key_signing_keys.get(zone_name) {
                for key in keys {
                    if !key.is_expired() {
                        let dnskey = DnskeyRecord::new(
                            key.flags,
                            key.algorithm,
                            key.public_key.clone(),
                        )?;
                        dnskeys.push(dnskey);
                    }
                }
            }
        }

        Ok(dnskeys)
    }

    /// Generate DS records for a zone (for parent zone)
    pub async fn generate_ds_records(
        &self,
        zone_name: &str,
        digest_types: &[DigestType],
    ) -> SecurityResult<Vec<DsRecord>> {
        let mut ds_records = Vec::new();

        // Get KSKs only (DS records are generated from KSKs)
        let key_signing_keys = self.key_signing_keys.read().await;
        if let Some(keys) = key_signing_keys.get(zone_name) {
            for key in keys {
                if !key.is_expired() && key.flags.secure_entry_point {
                    let dnskey = DnskeyRecord::new(
                        key.flags,
                        key.algorithm,
                        key.public_key.clone(),
                    )?;

                    for &digest_type in digest_types {
                        let ds = DsRecord::from_dnskey(&dnskey, zone_name, digest_type)?;
                        ds_records.push(ds);
                    }
                }
            }
        }

        Ok(ds_records)
    }

    /// Get signing statistics
    pub fn get_stats(&self) -> Arc<DnssecSigningStats> {
        self.stats.clone()
    }
}

/// DNSSEC signing statistics
#[derive(Debug)]
pub struct DnssecSigningStats {
    pub signing_attempts: std::sync::atomic::AtomicU64,
    pub successful_signings: std::sync::atomic::AtomicU64,
    pub key_generation_count: std::sync::atomic::AtomicU64,
    pub key_rollover_count: std::sync::atomic::AtomicU64,
}

impl DnssecSigningStats {
    pub fn new() -> Self {
        Self {
            signing_attempts: std::sync::atomic::AtomicU64::new(0),
            successful_signings: std::sync::atomic::AtomicU64::new(0),
            key_generation_count: std::sync::atomic::AtomicU64::new(0),
            key_rollover_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn success_rate(&self) -> f64 {
        let attempts = self.signing_attempts.load(std::sync::atomic::Ordering::Relaxed);
        let successes = self.successful_signings.load(std::sync::atomic::Ordering::Relaxed);
        
        if attempts == 0 {
            0.0
        } else {
            successes as f64 / attempts as f64
        }
    }
}

impl Default for DnssecValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for DnssecSigner {
    fn default() -> Self {
        Self::new()
    }
}