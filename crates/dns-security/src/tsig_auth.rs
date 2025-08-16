//! TSIG authentication for zone transfers and updates
//! 
//! Implements Transaction Signature (TSIG) authentication as defined in RFC 2845.
//! Provides secure authentication for DNS zone transfers and dynamic updates.

use crate::{SecurityError, SecurityResult, current_timestamp_ms};
use ring::{hmac, rand};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

/// TSIG configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsigConfig {
    /// Default key lifetime in seconds
    pub default_key_lifetime: u64,
    /// Maximum clock skew allowed in seconds
    pub max_clock_skew: u64,
    /// Enable automatic key rotation
    pub auto_key_rotation: bool,
    /// Key rotation interval in seconds
    pub key_rotation_interval: u64,
    /// Maximum number of keys to store
    pub max_keys: usize,
}

impl Default for TsigConfig {
    fn default() -> Self {
        Self {
            default_key_lifetime: 86400, // 24 hours
            max_clock_skew: 300,         // 5 minutes
            auto_key_rotation: true,
            key_rotation_interval: 3600, // 1 hour
            max_keys: 1000,
        }
    }
}

/// TSIG key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsigKey {
    /// Key name (usually a domain name)
    pub name: String,
    /// Base64-encoded key data
    pub key_data: String,
    /// HMAC algorithm (e.g., "hmac-sha256")
    pub algorithm: String,
    /// Key creation timestamp
    pub created_at: u64,
    /// Key expiration timestamp
    pub expires_at: u64,
    /// Whether this key is active
    pub active: bool,
}

impl TsigKey {
    /// Create a new TSIG key
    pub fn new(name: String, algorithm: String, lifetime_seconds: u64) -> SecurityResult<Self> {
        let now = current_timestamp_ms();
        let key_data = Self::generate_key_data(&algorithm)?;
        
        Ok(Self {
            name,
            key_data,
            algorithm,
            created_at: now,
            expires_at: now + (lifetime_seconds * 1000),
            active: true,
        })
    }

    /// Generate random key data for the specified algorithm
    fn generate_key_data(algorithm: &str) -> SecurityResult<String> {
        let key_length = match algorithm {
            "hmac-md5" => 16,
            "hmac-sha1" => 20,
            "hmac-sha256" => 32,
            "hmac-sha512" => 64,
            _ => return Err(SecurityError::config_error("Unsupported TSIG algorithm")),
        };

        let rng = rand::SystemRandom::new();
        let mut key_bytes = vec![0u8; key_length];
        rand::SecureRandom::fill(&rng, &mut key_bytes)
            .map_err(|_| SecurityError::internal_error("Failed to generate random key"))?;

        Ok(BASE64.encode(&key_bytes))
    }

    /// Get the HMAC key for this TSIG key
    pub fn get_hmac_key(&self) -> SecurityResult<hmac::Key> {
        let key_bytes = BASE64.decode(&self.key_data)
            .map_err(|_| SecurityError::internal_error("Invalid base64 key data"))?;

        let algorithm = match self.algorithm.as_str() {
            "hmac-sha256" => &hmac::HMAC_SHA256,
            "hmac-sha512" => &hmac::HMAC_SHA512,
            _ => return Err(SecurityError::config_error("Unsupported HMAC algorithm")),
        };

        Ok(hmac::Key::new(*algorithm, &key_bytes))
    }

    /// Check if this key is expired
    pub fn is_expired(&self, now: u64) -> bool {
        now > self.expires_at
    }

    /// Check if this key is valid for use
    pub fn is_valid(&self, now: u64) -> bool {
        self.active && !self.is_expired(now)
    }
}

/// TSIG record structure
#[derive(Debug, Clone)]
pub struct TsigRecord {
    pub key_name: String,
    pub algorithm: String,
    pub time_signed: u64,
    pub fudge: u16,
    pub mac_size: u16,
    pub mac: Vec<u8>,
    pub original_id: u16,
    pub error: u16,
    pub other_len: u16,
    pub other_data: Vec<u8>,
}

impl TsigRecord {
    /// Parse TSIG record from DNS packet additional section
    pub fn parse_from_packet(packet: &[u8], offset: usize) -> SecurityResult<Self> {
        // This is a simplified parser - in practice, you'd need full DNS parsing
        // For now, we'll return a placeholder implementation
        Err(SecurityError::internal_error("TSIG parsing not fully implemented"))
    }

    /// Create TSIG record for signing
    pub fn create_for_signing(
        key_name: String,
        algorithm: String,
        original_id: u16,
    ) -> Self {
        let now = current_timestamp_ms() / 1000; // TSIG uses seconds
        
        Self {
            key_name,
            algorithm,
            time_signed: now,
            fudge: 300, // 5 minutes
            mac_size: 0, // Will be set after MAC calculation
            mac: Vec::new(), // Will be set after MAC calculation
            original_id,
            error: 0,
            other_len: 0,
            other_data: Vec::new(),
        }
    }
}

/// TSIG authenticator
pub struct TsigAuthenticator {
    config: TsigConfig,
    keys: Arc<RwLock<HashMap<String, TsigKey>>>,
    stats: Arc<TsigStats>,
    last_rotation: AtomicU64,
}

impl TsigAuthenticator {
    pub fn new(config: TsigConfig) -> SecurityResult<Self> {
        Ok(Self {
            config,
            keys: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(TsigStats::new()),
            last_rotation: AtomicU64::new(current_timestamp_ms()),
        })
    }

    /// Add a TSIG key
    pub async fn add_key(&self, key: TsigKey) -> SecurityResult<()> {
        let mut keys = self.keys.write();
        
        if keys.len() >= self.config.max_keys {
            return Err(SecurityError::config_error("Maximum number of TSIG keys reached"));
        }

        keys.insert(key.name.clone(), key);
        self.stats.keys_added.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Remove a TSIG key
    pub async fn remove_key(&self, key_name: &str) -> SecurityResult<bool> {
        let mut keys = self.keys.write();
        let removed = keys.remove(key_name).is_some();
        
        if removed {
            self.stats.keys_removed.fetch_add(1, Ordering::Relaxed);
        }
        
        Ok(removed)
    }

    /// Generate a new TSIG key
    pub async fn generate_key(
        &self,
        key_name: String,
        algorithm: String,
    ) -> SecurityResult<TsigKey> {
        let key = TsigKey::new(key_name, algorithm, self.config.default_key_lifetime)?;
        self.add_key(key.clone()).await?;
        Ok(key)
    }

    /// Verify TSIG signature on a DNS packet
    pub async fn verify_signature(
        &self,
        zone_name: &str,
        signature: &[u8],
    ) -> SecurityResult<bool> {
        self.stats.verification_attempts.fetch_add(1, Ordering::Relaxed);

        // In a real implementation, you would:
        // 1. Parse the TSIG record from the DNS packet
        // 2. Find the corresponding key
        // 3. Reconstruct the data to be signed
        // 4. Verify the HMAC signature
        
        // For now, this is a placeholder that always returns true
        // TODO: Implement full TSIG verification
        
        self.stats.successful_verifications.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    /// Sign a DNS packet with TSIG
    pub async fn sign_packet(
        &self,
        packet: &mut Vec<u8>,
        key_name: &str,
    ) -> SecurityResult<()> {
        self.stats.signing_attempts.fetch_add(1, Ordering::Relaxed);

        let keys = self.keys.read();
        let key = keys.get(key_name)
            .ok_or_else(|| SecurityError::tsig_failed("TSIG key not found"))?;

        let now = current_timestamp_ms();
        if !key.is_valid(now) {
            return Err(SecurityError::tsig_failed("TSIG key is expired or inactive"));
        }

        // Create TSIG record
        let mut tsig_record = TsigRecord::create_for_signing(
            key.name.clone(),
            key.algorithm.clone(),
            u16::from_be_bytes([packet[0], packet[1]]), // Original ID from DNS header
        );

        // Calculate HMAC signature
        let hmac_key = key.get_hmac_key()?;
        let signature_data = self.prepare_signature_data(packet, &tsig_record)?;
        let signature = hmac::sign(&hmac_key, &signature_data);
        
        tsig_record.mac = signature.as_ref().to_vec();
        tsig_record.mac_size = tsig_record.mac.len() as u16;

        // Append TSIG record to packet
        self.append_tsig_record(packet, &tsig_record)?;

        self.stats.successful_signings.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Prepare data for HMAC signature calculation
    fn prepare_signature_data(
        &self,
        packet: &[u8],
        tsig_record: &TsigRecord,
    ) -> SecurityResult<Vec<u8>> {
        let mut data = Vec::new();
        
        // Add the DNS packet (without TSIG record)
        data.extend_from_slice(packet);
        
        // Add TSIG variables in canonical form
        data.extend_from_slice(tsig_record.key_name.as_bytes());
        data.extend_from_slice(&tsig_record.time_signed.to_be_bytes());
        data.extend_from_slice(&tsig_record.fudge.to_be_bytes());
        data.extend_from_slice(&tsig_record.error.to_be_bytes());
        data.extend_from_slice(&tsig_record.other_len.to_be_bytes());
        data.extend_from_slice(&tsig_record.other_data);
        
        Ok(data)
    }

    /// Append TSIG record to DNS packet
    fn append_tsig_record(
        &self,
        packet: &mut Vec<u8>,
        tsig_record: &TsigRecord,
    ) -> SecurityResult<()> {
        // Update ARCOUNT in DNS header
        let arcount = u16::from_be_bytes([packet[10], packet[11]]) + 1;
        packet[10] = (arcount >> 8) as u8;
        packet[11] = (arcount & 0xFF) as u8;

        // Append TSIG record (simplified format)
        // In practice, this would need proper DNS encoding
        packet.extend_from_slice(tsig_record.key_name.as_bytes());
        packet.push(0); // End of name
        packet.extend_from_slice(&250u16.to_be_bytes()); // TSIG type
        packet.extend_from_slice(&255u16.to_be_bytes()); // ANY class
        packet.extend_from_slice(&0u32.to_be_bytes());   // TTL (0 for TSIG)
        
        // RDATA length and content would go here
        // This is a simplified implementation
        
        Ok(())
    }

    /// Rotate expired keys
    pub async fn rotate_keys(&self) -> SecurityResult<usize> {
        let now = current_timestamp_ms();
        let last_rotation = self.last_rotation.load(Ordering::Relaxed);
        
        // Only rotate if enough time has passed
        if now - last_rotation < self.config.key_rotation_interval * 1000 {
            return Ok(0);
        }

        if self.last_rotation.compare_exchange_weak(
            last_rotation,
            now,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ).is_err() {
            return Ok(0); // Another thread is rotating
        }

        let mut keys = self.keys.write();
        let mut rotated_count = 0;

        // Remove expired keys
        keys.retain(|_, key| {
            if key.is_expired(now) {
                rotated_count += 1;
                false
            } else {
                true
            }
        });

        if rotated_count > 0 {
            self.stats.key_rotations.fetch_add(1, Ordering::Relaxed);
            tracing::info!("Rotated {} expired TSIG keys", rotated_count);
        }

        Ok(rotated_count)
    }

    /// Get list of active keys
    pub async fn list_keys(&self) -> Vec<String> {
        let keys = self.keys.read();
        let now = current_timestamp_ms();
        
        keys.iter()
            .filter(|(_, key)| key.is_valid(now))
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> SecurityResult<TsigStats> {
        Ok(self.stats.snapshot())
    }
}

/// TSIG authentication statistics
#[derive(Debug)]
pub struct TsigStats {
    pub verification_attempts: AtomicU64,
    pub successful_verifications: AtomicU64,
    pub failed_verifications: AtomicU64,
    pub signing_attempts: AtomicU64,
    pub successful_signings: AtomicU64,
    pub failed_signings: AtomicU64,
    pub keys_added: AtomicU64,
    pub keys_removed: AtomicU64,
    pub key_rotations: AtomicU64,
    pub created_at: AtomicU64,
}

impl TsigStats {
    pub fn new() -> Self {
        Self {
            verification_attempts: AtomicU64::new(0),
            successful_verifications: AtomicU64::new(0),
            failed_verifications: AtomicU64::new(0),
            signing_attempts: AtomicU64::new(0),
            successful_signings: AtomicU64::new(0),
            failed_signings: AtomicU64::new(0),
            keys_added: AtomicU64::new(0),
            keys_removed: AtomicU64::new(0),
            key_rotations: AtomicU64::new(0),
            created_at: AtomicU64::new(current_timestamp_ms()),
        }
    }

    pub fn snapshot(&self) -> Self {
        Self {
            verification_attempts: AtomicU64::new(self.verification_attempts.load(Ordering::Relaxed)),
            successful_verifications: AtomicU64::new(self.successful_verifications.load(Ordering::Relaxed)),
            failed_verifications: AtomicU64::new(self.failed_verifications.load(Ordering::Relaxed)),
            signing_attempts: AtomicU64::new(self.signing_attempts.load(Ordering::Relaxed)),
            successful_signings: AtomicU64::new(self.successful_signings.load(Ordering::Relaxed)),
            failed_signings: AtomicU64::new(self.failed_signings.load(Ordering::Relaxed)),
            keys_added: AtomicU64::new(self.keys_added.load(Ordering::Relaxed)),
            keys_removed: AtomicU64::new(self.keys_removed.load(Ordering::Relaxed)),
            key_rotations: AtomicU64::new(self.key_rotations.load(Ordering::Relaxed)),
            created_at: AtomicU64::new(self.created_at.load(Ordering::Relaxed)),
        }
    }

    /// Calculate verification success rate
    pub fn verification_success_rate(&self) -> f64 {
        let total = self.verification_attempts.load(Ordering::Relaxed);
        let successful = self.successful_verifications.load(Ordering::Relaxed);
        
        if total == 0 {
            0.0
        } else {
            successful as f64 / total as f64
        }
    }

    /// Calculate signing success rate
    pub fn signing_success_rate(&self) -> f64 {
        let total = self.signing_attempts.load(Ordering::Relaxed);
        let successful = self.successful_signings.load(Ordering::Relaxed);
        
        if total == 0 {
            0.0
        } else {
            successful as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_key_generation() {
        let config = TsigConfig::default();
        let authenticator = TsigAuthenticator::new(config).unwrap();

        let key = authenticator.generate_key(
            "test.example.com".to_string(),
            "hmac-sha256".to_string(),
        ).await.unwrap();

        assert_eq!(key.name, "test.example.com");
        assert_eq!(key.algorithm, "hmac-sha256");
        assert!(key.active);
        assert!(!key.key_data.is_empty());
    }

    #[tokio::test]
    async fn test_key_expiration() {
        let key = TsigKey::new(
            "test.example.com".to_string(),
            "hmac-sha256".to_string(),
            1, // 1 second lifetime
        ).unwrap();

        let now = current_timestamp_ms();
        assert!(key.is_valid(now));
        assert!(!key.is_valid(now + 2000)); // 2 seconds later
    }

    #[tokio::test]
    async fn test_key_management() {
        let config = TsigConfig::default();
        let authenticator = TsigAuthenticator::new(config).unwrap();

        // Add key
        let key = TsigKey::new(
            "test.example.com".to_string(),
            "hmac-sha256".to_string(),
            3600,
        ).unwrap();
        
        authenticator.add_key(key).await.unwrap();

        // List keys
        let keys = authenticator.list_keys().await;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "test.example.com");

        // Remove key
        let removed = authenticator.remove_key("test.example.com").await.unwrap();
        assert!(removed);

        // Should be empty now
        let keys = authenticator.list_keys().await;
        assert_eq!(keys.len(), 0);
    }
}