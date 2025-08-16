//! DNSSEC Key Management
//!
//! This module provides atomic key management operations including:
//! - Atomic key rollover automation
//! - Hardware Security Module (HSM) support
//! - Key storage and retrieval with atomic operations
//! - Key lifecycle management

use crate::dnssec::{DnssecKeyPair, DnssecAlgorithm, DnssecKeyFlags, SigningPolicy};
use crate::{SecurityError, SecurityResult};
use bytes::Bytes;
use lockfree::map::Map as LockFreeMap;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Hardware Security Module interface
#[async_trait::async_trait]
pub trait HsmInterface: Send + Sync {
    /// Generate a key pair in the HSM
    async fn generate_key_pair(
        &self,
        key_id: &str,
        algorithm: DnssecAlgorithm,
        key_size: u32,
    ) -> SecurityResult<HsmKeyHandle>;

    /// Sign data using a key in the HSM
    async fn sign(&self, key_handle: &HsmKeyHandle, data: &[u8]) -> SecurityResult<Bytes>;

    /// Get public key from HSM
    async fn get_public_key(&self, key_handle: &HsmKeyHandle) -> SecurityResult<Bytes>;

    /// Delete a key from the HSM
    async fn delete_key(&self, key_handle: &HsmKeyHandle) -> SecurityResult<()>;

    /// Check if HSM is available and operational
    async fn health_check(&self) -> SecurityResult<bool>;
}

/// HSM key handle for referencing keys in hardware
#[derive(Debug, Clone)]
pub struct HsmKeyHandle {
    pub key_id: String,
    pub algorithm: DnssecAlgorithm,
    pub key_size: u32,
    pub created_at: u64,
    pub hsm_type: HsmType,
}

/// Supported HSM types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmType {
    SoftHsm,
    Pkcs11,
    AwsCloudHsm,
    AzureKeyVault,
    GoogleCloudKms,
}

/// Mock HSM implementation for testing and development
pub struct MockHsm {
    keys: Arc<RwLock<HashMap<String, MockHsmKey>>>,
    operational: AtomicBool,
}

#[derive(Debug, Clone)]
struct MockHsmKey {
    key_id: String,
    algorithm: DnssecAlgorithm,
    public_key: Bytes,
    private_key: Bytes,
    created_at: u64,
}

impl MockHsm {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            operational: AtomicBool::new(true),
        }
    }

    pub fn set_operational(&self, operational: bool) {
        self.operational.store(operational, Ordering::Release);
    }
}

#[async_trait::async_trait]
impl HsmInterface for MockHsm {
    async fn generate_key_pair(
        &self,
        key_id: &str,
        algorithm: DnssecAlgorithm,
        _key_size: u32,
    ) -> SecurityResult<HsmKeyHandle> {
        if !self.operational.load(Ordering::Acquire) {
            return Err(SecurityError::HsmError("HSM not operational".to_string()));
        }

        // Generate key pair using software implementation
        let zone_name = format!("hsm-key-{}", key_id);
        let flags = DnssecKeyFlags {
            zone_key: true,
            secure_entry_point: true,
            revoked: false,
        };

        let key_pair = DnssecKeyPair::generate(zone_name, algorithm, flags, None)?;
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mock_key = MockHsmKey {
            key_id: key_id.to_string(),
            algorithm,
            public_key: key_pair.public_key.clone(),
            private_key: key_pair.private_key.clone(),
            created_at,
        };

        {
            let mut keys = self.keys.write().await;
            keys.insert(key_id.to_string(), mock_key);
        }

        Ok(HsmKeyHandle {
            key_id: key_id.to_string(),
            algorithm,
            key_size: 256, // Default for mock
            created_at,
            hsm_type: HsmType::SoftHsm,
        })
    }

    async fn sign(&self, key_handle: &HsmKeyHandle, data: &[u8]) -> SecurityResult<Bytes> {
        if !self.operational.load(Ordering::Acquire) {
            return Err(SecurityError::HsmError("HSM not operational".to_string()));
        }

        let keys = self.keys.read().await;
        let mock_key = keys.get(&key_handle.key_id)
            .ok_or_else(|| SecurityError::KeyNotFound(format!("Key not found in HSM: {}", key_handle.key_id)))?;

        // Create temporary key pair for signing
        let temp_key_pair = DnssecKeyPair {
            key_tag: 0, // Not used for signing
            algorithm: mock_key.algorithm,
            flags: DnssecKeyFlags {
                zone_key: true,
                secure_entry_point: true,
                revoked: false,
            },
            public_key: mock_key.public_key.clone(),
            private_key: mock_key.private_key.clone(),
            created_at: mock_key.created_at,
            expires_at: None,
            zone_name: "hsm-zone".to_string(),
        };

        temp_key_pair.sign(data)
    }

    async fn get_public_key(&self, key_handle: &HsmKeyHandle) -> SecurityResult<Bytes> {
        if !self.operational.load(Ordering::Acquire) {
            return Err(SecurityError::HsmError("HSM not operational".to_string()));
        }

        let keys = self.keys.read().await;
        let mock_key = keys.get(&key_handle.key_id)
            .ok_or_else(|| SecurityError::KeyNotFound(format!("Key not found in HSM: {}", key_handle.key_id)))?;

        Ok(mock_key.public_key.clone())
    }

    async fn delete_key(&self, key_handle: &HsmKeyHandle) -> SecurityResult<()> {
        if !self.operational.load(Ordering::Acquire) {
            return Err(SecurityError::HsmError("HSM not operational".to_string()));
        }

        let mut keys = self.keys.write().await;
        keys.remove(&key_handle.key_id);
        Ok(())
    }

    async fn health_check(&self) -> SecurityResult<bool> {
        Ok(self.operational.load(Ordering::Acquire))
    }
}

/// Atomic key manager for DNSSEC operations
pub struct AtomicKeyManager {
    /// Software keys stored in memory with atomic operations
    software_keys: Arc<LockFreeMap<String, Arc<AtomicKeyEntry>>>,
    /// HSM interface for hardware-backed keys
    hsm: Option<Arc<MockHsm>>,
    /// Key storage directory for persistence
    key_storage_dir: PathBuf,
    /// Key rollover policies per zone
    rollover_policies: Arc<RwLock<HashMap<String, KeyRolloverPolicy>>>,
    /// Atomic counters for statistics
    stats: Arc<KeyManagementStats>,
}

/// Atomic key entry for lock-free operations
#[derive(Debug)]
pub struct AtomicKeyEntry {
    pub key_data: Arc<DnssecKeyPair>,
    pub is_active: AtomicBool,
    pub last_used: AtomicU64,
    pub usage_count: AtomicU64,
    pub hsm_handle: Option<HsmKeyHandle>,
}

impl AtomicKeyEntry {
    pub fn new(key_data: DnssecKeyPair, hsm_handle: Option<HsmKeyHandle>) -> Self {
        Self {
            key_data: Arc::new(key_data),
            is_active: AtomicBool::new(true),
            last_used: AtomicU64::new(0),
            usage_count: AtomicU64::new(0),
            hsm_handle,
        }
    }

    pub fn mark_used(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_used.store(now, Ordering::Release);
        self.usage_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn deactivate(&self) {
        self.is_active.store(false, Ordering::Release);
    }

    pub fn is_active(&self) -> bool {
        self.is_active.load(Ordering::Acquire)
    }
}

/// Key rollover policy configuration
#[derive(Debug, Clone)]
pub struct KeyRolloverPolicy {
    pub zsk_rollover_interval: u64, // seconds
    pub ksk_rollover_interval: u64, // seconds
    pub signature_validity_period: u64, // seconds
    pub rollover_overlap_period: u64, // seconds
    pub auto_rollover_enabled: bool,
    pub pre_publish_period: u64, // seconds
    pub retire_period: u64, // seconds
}

impl Default for KeyRolloverPolicy {
    fn default() -> Self {
        Self {
            zsk_rollover_interval: 90 * 24 * 3600, // 90 days
            ksk_rollover_interval: 365 * 24 * 3600, // 1 year
            signature_validity_period: 30 * 24 * 3600, // 30 days
            rollover_overlap_period: 7 * 24 * 3600, // 7 days
            auto_rollover_enabled: true,
            pre_publish_period: 24 * 3600, // 1 day
            retire_period: 7 * 24 * 3600, // 7 days
        }
    }
}

/// Key management statistics with atomic counters
#[derive(Debug)]
pub struct KeyManagementStats {
    pub keys_generated: AtomicU64,
    pub keys_rolled_over: AtomicU64,
    pub hsm_operations: AtomicU64,
    pub software_operations: AtomicU64,
    pub key_usage_count: AtomicU64,
    pub rollover_failures: AtomicU64,
}

impl KeyManagementStats {
    pub fn new() -> Self {
        Self {
            keys_generated: AtomicU64::new(0),
            keys_rolled_over: AtomicU64::new(0),
            hsm_operations: AtomicU64::new(0),
            software_operations: AtomicU64::new(0),
            key_usage_count: AtomicU64::new(0),
            rollover_failures: AtomicU64::new(0),
        }
    }
}

impl AtomicKeyManager {
    pub fn new<P: AsRef<Path>>(
        key_storage_dir: P,
        hsm: Option<Arc<MockHsm>>,
    ) -> SecurityResult<Self> {
        let key_storage_dir = key_storage_dir.as_ref().to_path_buf();
        
        Ok(Self {
            software_keys: Arc::new(LockFreeMap::new()),
            hsm,
            key_storage_dir,
            rollover_policies: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(KeyManagementStats::new()),
        })
    }

    /// Generate a new key pair atomically
    pub async fn generate_key_atomic(
        &self,
        zone_name: &str,
        algorithm: DnssecAlgorithm,
        flags: DnssecKeyFlags,
        use_hsm: bool,
    ) -> SecurityResult<String> {
        let key_id = format!("{}_{}_{}_{}", 
            zone_name, 
            algorithm as u8, 
            if flags.secure_entry_point { "ksk" } else { "zsk" },
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
        );

        let (key_pair, hsm_handle) = if use_hsm && self.hsm.is_some() {
            // Generate key in HSM
            let hsm = self.hsm.as_ref().unwrap();
            let handle = hsm.generate_key_pair(&key_id, algorithm, 256).await?;
            let public_key = hsm.get_public_key(&handle).await?;
            
            let key_pair = DnssecKeyPair {
                key_tag: DnssecKeyPair::calculate_key_tag(&public_key, algorithm, flags)?,
                algorithm,
                flags,
                public_key,
                private_key: Bytes::new(), // Not stored for HSM keys
                created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                expires_at: None,
                zone_name: zone_name.to_string(),
            };

            self.stats.hsm_operations.fetch_add(1, Ordering::Relaxed);
            (key_pair, Some(handle))
        } else {
            // Generate software key
            let key_pair = DnssecKeyPair::generate(
                zone_name.to_string(),
                algorithm,
                flags,
                None,
            )?;

            self.stats.software_operations.fetch_add(1, Ordering::Relaxed);
            (key_pair, None)
        };

        // Store key atomically
        let key_entry = Arc::new(AtomicKeyEntry::new(key_pair, hsm_handle));
        self.software_keys.insert(key_id.clone(), key_entry);

        // Persist key to disk
        self.persist_key(&key_id).await?;

        self.stats.keys_generated.fetch_add(1, Ordering::Relaxed);
        info!("Generated new DNSSEC key: {} for zone: {}", key_id, zone_name);

        Ok(key_id)
    }

    /// Get a key atomically
    pub async fn get_key_atomic(&self, key_id: &str) -> Option<Arc<AtomicKeyEntry>> {
        if let Some(entry) = self.software_keys.get(key_id) {
            let key_entry = entry.val();
            if key_entry.is_active() {
                key_entry.mark_used();
                self.stats.key_usage_count.fetch_add(1, Ordering::Relaxed);
                return Some(key_entry.clone());
            }
        }
        None
    }

    /// Sign data using a key atomically
    pub async fn sign_with_key_atomic(
        &self,
        key_id: &str,
        data: &[u8],
    ) -> SecurityResult<Bytes> {
        let key_entry = self.get_key_atomic(key_id).await
            .ok_or_else(|| SecurityError::KeyNotFound(format!("Key not found: {}", key_id)))?;

        if let Some(hsm_handle) = &key_entry.hsm_handle {
            // Use HSM for signing
            let hsm = self.hsm.as_ref()
                .ok_or_else(|| SecurityError::HsmError("HSM not available".to_string()))?;
            
            let signature = hsm.sign(hsm_handle, data).await?;
            self.stats.hsm_operations.fetch_add(1, Ordering::Relaxed);
            Ok(signature)
        } else {
            // Use software key for signing
            let signature = key_entry.key_data.sign(data)?;
            self.stats.software_operations.fetch_add(1, Ordering::Relaxed);
            Ok(signature)
        }
    }

    /// Perform atomic key rollover
    pub async fn rollover_key_atomic(
        &self,
        zone_name: &str,
        old_key_id: &str,
        algorithm: DnssecAlgorithm,
        flags: DnssecKeyFlags,
        use_hsm: bool,
    ) -> SecurityResult<String> {
        info!("Starting atomic key rollover for zone: {} old_key: {}", zone_name, old_key_id);

        // Generate new key
        let new_key_id = self.generate_key_atomic(zone_name, algorithm, flags, use_hsm).await?;

        // Deactivate old key atomically
        if let Some(old_entry) = self.software_keys.get(old_key_id) {
            old_entry.val().deactivate();
            info!("Deactivated old key: {}", old_key_id);
        }

        self.stats.keys_rolled_over.fetch_add(1, Ordering::Relaxed);
        info!("Completed atomic key rollover: {} -> {}", old_key_id, new_key_id);

        Ok(new_key_id)
    }

    /// Set rollover policy for a zone
    pub async fn set_rollover_policy(
        &self,
        zone_name: String,
        policy: KeyRolloverPolicy,
    ) -> SecurityResult<()> {
        let mut policies = self.rollover_policies.write().await;
        policies.insert(zone_name, policy);
        Ok(())
    }

    /// Check if any keys need rollover
    pub async fn check_rollover_needed(&self) -> Vec<String> {
        let mut keys_needing_rollover = Vec::new();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Iterate through all keys
        for entry in self.software_keys.iter() {
            let key_entry = entry.val();
            if !key_entry.is_active() {
                continue;
            }

            let key_data = &key_entry.key_data;
            let key_age = now - key_data.created_at;

            // Check if key needs rollover based on policy
            let policies = self.rollover_policies.read().await;
            if let Some(policy) = policies.get(&key_data.zone_name) {
                let rollover_interval = if key_data.flags.secure_entry_point {
                    policy.ksk_rollover_interval
                } else {
                    policy.zsk_rollover_interval
                };

                if policy.auto_rollover_enabled && key_age > rollover_interval {
                    keys_needing_rollover.push(entry.key().clone());
                }
            }
        }

        keys_needing_rollover
    }

    /// Perform automatic key rollover for all zones
    pub async fn perform_automatic_rollover(&self) -> SecurityResult<usize> {
        let keys_needing_rollover = self.check_rollover_needed().await;
        let mut rollover_count = 0;

        for key_id in keys_needing_rollover {
            if let Some(key_entry) = self.software_keys.get(&key_id) {
                let key_data = &key_entry.val().key_data;
                let zone_name = key_data.zone_name.clone();
                let algorithm = key_data.algorithm;
                let flags = key_data.flags;
                let use_hsm = key_entry.val().hsm_handle.is_some();

                match self.rollover_key_atomic(&zone_name, &key_id, algorithm, flags, use_hsm).await {
                    Ok(_) => {
                        rollover_count += 1;
                        info!("Successfully rolled over key: {}", key_id);
                    }
                    Err(e) => {
                        error!("Failed to rollover key {}: {}", key_id, e);
                        self.stats.rollover_failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        Ok(rollover_count)
    }

    /// Persist key to disk storage
    async fn persist_key(&self, key_id: &str) -> SecurityResult<()> {
        if let Some(key_entry) = self.software_keys.get(key_id) {
            let key_data = &key_entry.val().key_data;
            
            // Create key file path
            let key_file = self.key_storage_dir.join(format!("{}.key", key_id));
            
            // Serialize key data (in production, this should be encrypted)
            let key_json = serde_json::to_string_pretty(&**key_data)
                .map_err(|e| SecurityError::SerializationError(format!("Failed to serialize key: {}", e)))?;
            
            // Ensure directory exists
            if let Some(parent) = key_file.parent() {
                fs::create_dir_all(parent).await
                    .map_err(|e| SecurityError::SerializationError(format!("Failed to create key directory: {}", e)))?;
            }
            
            // Write key file
            fs::write(&key_file, key_json).await
                .map_err(|e| SecurityError::SerializationError(format!("Failed to write key file: {}", e)))?;
            
            debug!("Persisted key to: {:?}", key_file);
        }
        
        Ok(())
    }

    /// Load keys from disk storage
    pub async fn load_keys_from_storage(&self) -> SecurityResult<usize> {
        let mut loaded_count = 0;
        
        if !self.key_storage_dir.exists() {
            return Ok(0);
        }
        
        let mut entries = fs::read_dir(&self.key_storage_dir).await
            .map_err(|e| SecurityError::SerializationError(format!("Failed to read key directory: {}", e)))?;
        
        while let Some(entry) = entries.next_entry().await
            .map_err(|e| SecurityError::SerializationError(format!("Failed to read directory entry: {}", e)))? {
            
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("key") {
                match self.load_key_from_file(&path).await {
                    Ok(key_id) => {
                        loaded_count += 1;
                        debug!("Loaded key: {}", key_id);
                    }
                    Err(e) => {
                        warn!("Failed to load key from {:?}: {}", path, e);
                    }
                }
            }
        }
        
        info!("Loaded {} keys from storage", loaded_count);
        Ok(loaded_count)
    }

    /// Load a single key from file
    async fn load_key_from_file(&self, path: &Path) -> SecurityResult<String> {
        let key_json = fs::read_to_string(path).await
            .map_err(|e| SecurityError::SerializationError(format!("Failed to read key file: {}", e)))?;
        
        let key_data: DnssecKeyPair = serde_json::from_str(&key_json)
            .map_err(|e| SecurityError::SerializationError(format!("Failed to deserialize key: {}", e)))?;
        
        let key_id = path.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| SecurityError::InvalidData("Invalid key filename".to_string()))?
            .to_string();
        
        let key_entry = Arc::new(AtomicKeyEntry::new(key_data, None));
        self.software_keys.insert(key_id.clone(), key_entry);
        
        Ok(key_id)
    }

    /// Get key management statistics
    pub fn get_stats(&self) -> Arc<KeyManagementStats> {
        self.stats.clone()
    }

    /// Health check for HSM connectivity
    pub async fn hsm_health_check(&self) -> SecurityResult<bool> {
        if let Some(hsm) = &self.hsm {
            hsm.health_check().await
        } else {
            Ok(true) // No HSM configured, consider healthy
        }
    }

    /// List all active keys
    pub async fn list_active_keys(&self) -> Vec<String> {
        let mut active_keys = Vec::new();
        
        for entry in self.software_keys.iter() {
            if entry.val().is_active() {
                active_keys.push(entry.key().clone());
            }
        }
        
        active_keys
    }

    /// Get key information
    pub async fn get_key_info(&self, key_id: &str) -> Option<KeyInfo> {
        if let Some(entry) = self.software_keys.get(key_id) {
            let key_entry = entry.val();
            let key_data = &key_entry.key_data;
            
            Some(KeyInfo {
                key_id: key_id.to_string(),
                zone_name: key_data.zone_name.clone(),
                algorithm: key_data.algorithm,
                flags: key_data.flags,
                key_tag: key_data.key_tag,
                created_at: key_data.created_at,
                expires_at: key_data.expires_at,
                is_active: key_entry.is_active(),
                usage_count: key_entry.usage_count.load(Ordering::Acquire),
                last_used: key_entry.last_used.load(Ordering::Acquire),
                is_hsm_backed: key_entry.hsm_handle.is_some(),
            })
        } else {
            None
        }
    }
}

/// Key information structure
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub key_id: String,
    pub zone_name: String,
    pub algorithm: DnssecAlgorithm,
    pub flags: DnssecKeyFlags,
    pub key_tag: u16,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub is_active: bool,
    pub usage_count: u64,
    pub last_used: u64,
    pub is_hsm_backed: bool,
}

// Add serde support for DnssecKeyPair (needed for persistence)
impl serde::Serialize for DnssecKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("DnssecKeyPair", 8)?;
        state.serialize_field("key_tag", &self.key_tag)?;
        state.serialize_field("algorithm", &(self.algorithm as u8))?;
        state.serialize_field("flags", &self.flags.to_u16())?;
        state.serialize_field("public_key", &self.public_key.as_ref())?;
        state.serialize_field("private_key", &self.private_key.as_ref())?;
        state.serialize_field("created_at", &self.created_at)?;
        state.serialize_field("expires_at", &self.expires_at)?;
        state.serialize_field("zone_name", &self.zone_name)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for DnssecKeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        struct DnssecKeyPairVisitor;

        impl<'de> Visitor<'de> for DnssecKeyPairVisitor {
            type Value = DnssecKeyPair;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct DnssecKeyPair")
            }

            fn visit_map<V>(self, mut map: V) -> Result<DnssecKeyPair, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut key_tag = None;
                let mut algorithm = None;
                let mut flags = None;
                let mut public_key = None;
                let mut private_key = None;
                let mut created_at = None;
                let mut expires_at = None;
                let mut zone_name = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "key_tag" => key_tag = Some(map.next_value()?),
                        "algorithm" => {
                            let alg_u8: u8 = map.next_value()?;
                            algorithm = DnssecAlgorithm::from_u8(alg_u8);
                        }
                        "flags" => {
                            let flags_u16: u16 = map.next_value()?;
                            flags = Some(DnssecKeyFlags::from_u16(flags_u16));
                        }
                        "public_key" => {
                            let key_bytes: Vec<u8> = map.next_value()?;
                            public_key = Some(Bytes::from(key_bytes));
                        }
                        "private_key" => {
                            let key_bytes: Vec<u8> = map.next_value()?;
                            private_key = Some(Bytes::from(key_bytes));
                        }
                        "created_at" => created_at = Some(map.next_value()?),
                        "expires_at" => expires_at = Some(map.next_value()?),
                        "zone_name" => zone_name = Some(map.next_value()?),
                        _ => {
                            let _: serde_json::Value = map.next_value()?;
                        }
                    }
                }

                Ok(DnssecKeyPair {
                    key_tag: key_tag.ok_or_else(|| de::Error::missing_field("key_tag"))?,
                    algorithm: algorithm.ok_or_else(|| de::Error::missing_field("algorithm"))?,
                    flags: flags.ok_or_else(|| de::Error::missing_field("flags"))?,
                    public_key: public_key.ok_or_else(|| de::Error::missing_field("public_key"))?,
                    private_key: private_key.ok_or_else(|| de::Error::missing_field("private_key"))?,
                    created_at: created_at.ok_or_else(|| de::Error::missing_field("created_at"))?,
                    expires_at,
                    zone_name: zone_name.ok_or_else(|| de::Error::missing_field("zone_name"))?,
                })
            }
        }

        deserializer.deserialize_struct(
            "DnssecKeyPair",
            &["key_tag", "algorithm", "flags", "public_key", "private_key", "created_at", "expires_at", "zone_name"],
            DnssecKeyPairVisitor,
        )
    }
}

impl Default for MockHsm {
    fn default() -> Self {
        Self::new()
    }
}