//! Zero-Copy Storage Engine
//!
//! This module implements the core zero-copy storage engine with FlatBuffers,
//! memory mapping, atomic operations, and optimistic concurrency control.

use crate::{MmapDiskStorage, HashDomainIndex, AtomicVersionLog, BackupManager};
use dns_core::{DnsResult, DnsError, hash::*};
use lockfree::map::Map as LockFreeMap;
use memmap2::Mmap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, AtomicPtr, AtomicU32, Ordering};
use std::path::{Path, PathBuf};
use bytes::Bytes;
use flatbuffers::{FlatBufferBuilder, WIPOffset};

/// Zero-copy storage engine with atomic operations and optimistic concurrency control
pub struct ZeroCopyStorageEngine {
    /// Memory-mapped disk storage
    disk_storage: Arc<MmapDiskStorage>,
    
    /// Hash-based domain index for O(1) lookups
    domain_index: Arc<HashDomainIndex>,
    
    /// Version log for incremental synchronization
    version_log: Arc<AtomicVersionLog>,
    
    /// Backup manager for atomic backup/restore
    backup_manager: Arc<BackupManager>,
    
    /// Lock-free zone metadata cache
    pub zone_metadata: Arc<LockFreeMap<u64, Arc<AtomicZoneMetadata>>>,
    
    /// Lock-free memory-mapped zone data
    zone_data: Arc<LockFreeMap<u64, Arc<AtomicPtr<MappedZone>>>>,
    
    /// Global version counter for optimistic concurrency control
    global_version: AtomicU64,
    
    /// Atomic statistics
    total_zones: AtomicUsize,
    total_operations: AtomicU64,
    successful_updates: AtomicU64,
    failed_updates: AtomicU64,
    
    /// Configuration
    base_path: PathBuf,
    max_zone_size: u64,
    enable_compression: bool,
    gc_threshold: usize,
}

/// Atomic zone metadata for lock-free operations
pub struct AtomicZoneMetadata {
    pub hash: u64,                              // Immutable after creation
    pub name: Arc<str>,                         // Immutable string
    pub current_version: AtomicU64,             // Atomic version updates
    pub file_path: Arc<Path>,                   // Immutable path
    pub size: AtomicU64,                        // Atomic size updates
    pub last_modified: AtomicU64,               // Atomic timestamp
    pub record_count: AtomicU32,                // Atomic record count
    pub access_count: AtomicU64,                // Lock-free access tracking
    pub is_loading: AtomicBool,                 // Atomic loading state
    pub needs_gc: AtomicBool,                   // Garbage collection flag
    pub backup_version: AtomicU64,              // Last backed up version
}

/// Memory-mapped zone data for zero-copy access
pub struct MappedZone {
    /// Memory-mapped file
    mmap: Arc<Mmap>,
    
    /// Zone metadata
    metadata: Arc<AtomicZoneMetadata>,
    
    /// FlatBuffer root table (zero-copy access)
    zone_data: Option<flatbuffers::Table<'static>>,
    
    /// Atomic flags
    is_valid: AtomicBool,
    is_compressed: AtomicBool,
}

/// Zone update operation for atomic updates
#[derive(Debug, Clone)]
pub struct ZoneUpdateOperation {
    pub zone_hash: u64,
    pub expected_version: u64,
    pub new_data: Bytes,
    pub operation_type: UpdateOperationType,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UpdateOperationType {
    FullReplace,
    IncrementalUpdate,
    RecordAdd,
    RecordRemove,
    RecordUpdate,
}

/// Result of zone update operation
#[derive(Debug)]
pub struct ZoneUpdateResult {
    pub success: bool,
    pub old_version: u64,
    pub new_version: u64,
    pub bytes_written: u64,
    pub operation_id: u64,
}

impl ZeroCopyStorageEngine {
    /// Create a new zero-copy storage engine
    pub async fn new<P: AsRef<Path>>(base_path: P) -> DnsResult<Self> {
        let base_path = base_path.as_ref().to_path_buf();
        
        // Initialize components
        let disk_storage = Arc::new(MmapDiskStorage::new(&base_path)?);
        let domain_index = Arc::new(HashDomainIndex::new());
        let version_log = Arc::new(AtomicVersionLog::new());
        let backup_manager = Arc::new(BackupManager::new(&base_path)?);
        
        let engine = Self {
            disk_storage,
            domain_index,
            version_log,
            backup_manager,
            zone_metadata: Arc::new(LockFreeMap::new()),
            zone_data: Arc::new(LockFreeMap::new()),
            global_version: AtomicU64::new(1),
            total_zones: AtomicUsize::new(0),
            total_operations: AtomicU64::new(0),
            successful_updates: AtomicU64::new(0),
            failed_updates: AtomicU64::new(0),
            base_path,
            max_zone_size: 100 * 1024 * 1024, // 100MB default
            enable_compression: true,
            gc_threshold: 1000,
        };
        
        // Load existing zones
        engine.load_existing_zones().await?;
        
        tracing::info!("Zero-copy storage engine initialized at {}", engine.base_path.display());
        
        Ok(engine)
    }

    /// Store zone data atomically with optimistic concurrency control
    pub async fn store_zone_atomic(
        &self,
        zone_hash: u64,
        zone_name: &str,
        data: &[u8],
        expected_version: u64,
    ) -> DnsResult<ZoneUpdateResult> {
        self.total_operations.fetch_add(1, Ordering::Relaxed);
        
        // Validate input
        if data.len() > self.max_zone_size as usize {
            return Err(DnsError::InvalidInput {
                message: format!("Zone data too large: {} bytes", data.len()),
            });
        }
        
        // Get or create metadata
        let metadata = self.get_or_create_metadata(zone_hash, zone_name).await?;
        
        // Optimistic concurrency control - check version
        let current_version = metadata.current_version.load(Ordering::Acquire);
        if expected_version != 0 && current_version != expected_version {
            self.failed_updates.fetch_add(1, Ordering::Relaxed);
            return Ok(ZoneUpdateResult {
                success: false,
                old_version: current_version,
                new_version: current_version,
                bytes_written: 0,
                operation_id: 0,
            });
        }
        
        // Generate new version
        let new_version = self.global_version.fetch_add(1, Ordering::AcqRel);
        let operation_id = self.total_operations.load(Ordering::Relaxed);
        
        // Create file name with version
        let file_name = format!("zone_{:016x}_v{}.fb", zone_hash, new_version);
        
        // Write data to disk atomically
        self.disk_storage.write_zone_data(zone_hash, &file_name, data).await?;
        
        // Memory-map the new file
        let mapped_file = self.disk_storage.mmap_zone_file(zone_hash, &file_name).await?;
        
        // Create mapped zone
        let mapped_zone = Arc::new(AtomicPtr::new(Box::into_raw(Box::new(MappedZone {
            mmap: mapped_file.mmap.clone(),
            metadata: metadata.clone(),
            zone_data: None, // Will be populated on first access
            is_valid: AtomicBool::new(true),
            is_compressed: AtomicBool::new(false),
        }))));
        
        // Update metadata atomically
        let old_version = metadata.current_version.swap(new_version, Ordering::AcqRel);
        metadata.size.store(data.len() as u64, Ordering::Release);
        metadata.last_modified.store(Self::current_timestamp(), Ordering::Release);
        metadata.is_loading.store(false, Ordering::Release);
        
        // Update zone data mapping
        self.zone_data.insert(zone_hash, mapped_zone);
        
        // Log the operation for incremental sync
        self.version_log.log_zone_update(zone_hash, old_version, new_version, data.len()).await;
        
        // Update domain index
        self.domain_index.add_zone(zone_name, zone_hash as u64, 0)?;
        
        self.successful_updates.fetch_add(1, Ordering::Relaxed);
        
        tracing::debug!(
            "Stored zone {} atomically: v{} -> v{} ({} bytes)",
            zone_name, old_version, new_version, data.len()
        );
        
        Ok(ZoneUpdateResult {
            success: true,
            old_version,
            new_version,
            bytes_written: data.len() as u64,
            operation_id,
        })
    }

    /// Load zone data with zero-copy access
    pub async fn load_zone_atomic(&self, zone_hash: u64) -> DnsResult<Bytes> {
        // Get mapped zone
        let mapped_zone_ptr = self.zone_data.get(&zone_hash)
            .ok_or_else(|| DnsError::ZoneNotFound {
                zone_name: format!("hash:{:016x}", zone_hash),
            })?;
        
        let mapped_zone_ptr = mapped_zone_ptr.val();
        let mapped_zone = unsafe { &*mapped_zone_ptr.load(Ordering::Acquire) };
        
        // Update access statistics
        mapped_zone.metadata.access_count.fetch_add(1, Ordering::Relaxed);
        
        // Return zero-copy bytes
        Ok(Bytes::from_static(unsafe {
            std::slice::from_raw_parts(
                mapped_zone.mmap.as_ptr(),
                mapped_zone.metadata.size.load(Ordering::Acquire) as usize,
            )
        }))
    }

    /// Get zone version atomically
    pub fn get_zone_version_atomic(&self, zone_hash: u64) -> Option<u64> {
        self.zone_metadata.get(&zone_hash)
            .map(|metadata| metadata.val().current_version.load(Ordering::Acquire))
    }

    /// Compare and swap zone data (atomic update with version check)
    pub async fn compare_and_swap_zone(
        &self,
        zone_hash: u64,
        expected_version: u64,
        new_data: Bytes,
    ) -> DnsResult<ZoneUpdateResult> {
        let zone_name = self.get_zone_name(zone_hash)?;
        self.store_zone_atomic(zone_hash, &zone_name, &new_data, expected_version).await
    }

    /// Get zone delta for incremental synchronization
    pub async fn get_zone_delta_atomic(
        &self,
        zone_hash: u64,
        from_version: u64,
        to_version: u64,
    ) -> DnsResult<Bytes> {
        self.version_log.get_zone_delta(zone_hash, from_version, to_version).await
    }

    /// List all zones atomically
    pub async fn list_zones_atomic(&self) -> Vec<u64> {
        self.zone_metadata.iter().map(|entry| *entry.key()).collect()
    }

    /// Update zone metadata atomically
    pub async fn update_metadata_atomic(
        &self,
        zone_hash: u64,
        updater: impl FnOnce(&AtomicZoneMetadata),
    ) -> bool {
        if let Some(metadata) = self.zone_metadata.get(&zone_hash) {
            updater(metadata.val());
            true
        } else {
            false
        }
    }

    /// Garbage collect old zone versions
    pub async fn gc_old_versions_atomic(&self, keep_versions: u32) -> usize {
        let mut removed_count = 0;
        
        for entry in self.zone_metadata.iter() {
            let zone_hash = *entry.key();
            let metadata = entry.val();
            
            // Check if GC is needed
            if metadata.needs_gc.load(Ordering::Acquire) {
                let current_version = metadata.current_version.load(Ordering::Acquire);
                
                // Remove old version files
                let gc_count = self.gc_zone_versions(zone_hash, current_version, keep_versions).await;
                removed_count += gc_count;
                
                // Clear GC flag
                metadata.needs_gc.store(false, Ordering::Release);
            }
        }
        
        tracing::info!("Garbage collected {} old zone versions", removed_count);
        removed_count
    }

    /// Compact storage by removing unused zones and old versions
    pub async fn compact_storage_atomic(&self) -> DnsResult<usize> {
        let mut total_removed = 0;
        
        // Run garbage collection
        total_removed += self.gc_old_versions_atomic(3).await;
        
        // Compact disk storage
        total_removed += self.disk_storage.compact().await;
        
        // Compact domain index
        total_removed += self.domain_index.compact();
        
        // Compact version log
        total_removed += self.version_log.compact().await;
        
        tracing::info!("Storage compaction completed: removed {} items", total_removed);
        Ok(total_removed)
    }

    /// Create atomic backup
    pub async fn backup_incremental_atomic(
        &self,
        since_version: u64,
        target_path: &Path,
    ) -> DnsResult<u64> {
        self.backup_manager.create_incremental_backup(since_version, target_path).await
    }

    /// Restore from atomic backup
    pub async fn restore_incremental_atomic(&self, backup_path: &Path) -> DnsResult<u64> {
        let restored_version = self.backup_manager.restore_incremental_backup(backup_path).await?;
        
        // Reload zones after restore
        self.load_existing_zones().await?;
        
        Ok(restored_version)
    }

    /// Get storage statistics
    pub fn get_statistics(&self) -> StorageEngineStatistics {
        StorageEngineStatistics {
            total_zones: self.total_zones.load(Ordering::Relaxed),
            total_operations: self.total_operations.load(Ordering::Relaxed),
            successful_updates: self.successful_updates.load(Ordering::Relaxed),
            failed_updates: self.failed_updates.load(Ordering::Relaxed),
            current_version: self.global_version.load(Ordering::Relaxed),
            disk_stats: self.disk_storage.get_statistics(),
            index_stats: self.domain_index.get_statistics(),
        }
    }

    // Private helper methods

    async fn get_or_create_metadata(
        &self,
        zone_hash: u64,
        zone_name: &str,
    ) -> DnsResult<Arc<AtomicZoneMetadata>> {
        if let Some(existing) = self.zone_metadata.get(&zone_hash) {
            return Ok(existing.val().clone());
        }
        
        let file_path = self.base_path.join(format!("zone_{:016x}", zone_hash));
        
        let metadata = Arc::new(AtomicZoneMetadata {
            hash: zone_hash,
            name: Arc::from(zone_name),
            current_version: AtomicU64::new(0),
            file_path: Arc::from(file_path.as_path()),
            size: AtomicU64::new(0),
            last_modified: AtomicU64::new(Self::current_timestamp()),
            record_count: AtomicU32::new(0),
            access_count: AtomicU64::new(0),
            is_loading: AtomicBool::new(true),
            needs_gc: AtomicBool::new(false),
            backup_version: AtomicU64::new(0),
        });
        
        self.zone_metadata.insert(zone_hash, metadata.clone());
        self.total_zones.fetch_add(1, Ordering::Relaxed);
        
        Ok(metadata)
    }

    async fn load_existing_zones(&self) -> DnsResult<()> {
        // Scan base directory for existing zone files
        let mut entries = tokio::fs::read_dir(&self.base_path).await
            .map_err(|e| DnsError::DiskIoError {
                message: format!("Failed to read directory: {}", e),
            })?;
        
        let mut loaded_count = 0;
        
        while let Some(entry) = entries.next_entry().await
            .map_err(|e| DnsError::DiskIoError {
                message: format!("Failed to read directory entry: {}", e),
            })? {
            
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();
            
            // Parse zone files (format: zone_<hash>_v<version>.fb)
            if file_name_str.starts_with("zone_") && file_name_str.ends_with(".fb") {
                if let Some(zone_hash) = self.parse_zone_hash_from_filename(&file_name_str) {
                    // Load the zone
                    match self.load_zone_from_file(zone_hash, &file_name_str).await {
                        Ok(_) => loaded_count += 1,
                        Err(e) => tracing::warn!("Failed to load zone file {}: {}", file_name_str, e),
                    }
                }
            }
        }
        
        tracing::info!("Loaded {} existing zones", loaded_count);
        Ok(())
    }

    fn parse_zone_hash_from_filename(&self, filename: &str) -> Option<u64> {
        // Parse format: zone_<hash>_v<version>.fb
        let parts: Vec<&str> = filename.split('_').collect();
        if parts.len() >= 2 {
            u64::from_str_radix(parts[1], 16).ok()
        } else {
            None
        }
    }

    async fn load_zone_from_file(&self, zone_hash: u64, filename: &str) -> DnsResult<()> {
        // Memory-map the file
        let mapped_file = self.disk_storage.mmap_zone_file(zone_hash, filename).await?;
        
        // Create metadata (zone name will be extracted from file if needed)
        let zone_name = format!("zone_{:016x}", zone_hash); // Placeholder
        let metadata = self.get_or_create_metadata(zone_hash, &zone_name).await?;
        
        // Update metadata from file
        metadata.size.store(mapped_file.size(), Ordering::Release);
        metadata.is_loading.store(false, Ordering::Release);
        
        // Create mapped zone
        let mapped_zone = Arc::new(AtomicPtr::new(Box::into_raw(Box::new(MappedZone {
            mmap: mapped_file.mmap.clone(),
            metadata: metadata.clone(),
            zone_data: None,
            is_valid: AtomicBool::new(true),
            is_compressed: AtomicBool::new(false),
        }))));
        
        self.zone_data.insert(zone_hash, mapped_zone);
        
        Ok(())
    }

    async fn gc_zone_versions(&self, zone_hash: u64, current_version: u64, keep_versions: u32) -> usize {
        // This would implement garbage collection of old zone version files
        // For now, return 0 as placeholder
        let _ = (zone_hash, current_version, keep_versions);
        0
    }

    fn get_zone_name(&self, zone_hash: u64) -> DnsResult<String> {
        self.zone_metadata.get(&zone_hash)
            .map(|metadata| metadata.val().name.to_string())
            .ok_or_else(|| DnsError::ZoneNotFound {
                zone_name: format!("hash:{:016x}", zone_hash),
            })
    }

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

/// Storage engine statistics
#[derive(Debug, Clone)]
pub struct StorageEngineStatistics {
    pub total_zones: usize,
    pub total_operations: u64,
    pub successful_updates: u64,
    pub failed_updates: u64,
    pub current_version: u64,
    pub disk_stats: crate::MmapStorageStatistics,
    pub index_stats: crate::IndexStatistics,
}

// Implement Drop for proper cleanup
impl Drop for MappedZone {
    fn drop(&mut self) {
        self.is_valid.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_storage_engine_basic_operations() {
        let temp_dir = TempDir::new().unwrap();
        let engine = ZeroCopyStorageEngine::new(temp_dir.path()).await.unwrap();
        
        let zone_hash = hash_domain_name("example.com");
        let zone_data = b"test zone data";
        
        // Store zone
        let result = engine.store_zone_atomic(zone_hash, "example.com", zone_data, 0).await.unwrap();
        assert!(result.success);
        assert_eq!(result.bytes_written, zone_data.len() as u64);
        
        // Load zone
        let loaded_data = engine.load_zone_atomic(zone_hash).await.unwrap();
        assert_eq!(&loaded_data[..], zone_data);
        
        // Check version
        let version = engine.get_zone_version_atomic(zone_hash).unwrap();
        assert_eq!(version, result.new_version);
    }

    #[tokio::test]
    async fn test_optimistic_concurrency_control() {
        let temp_dir = TempDir::new().unwrap();
        let engine = ZeroCopyStorageEngine::new(temp_dir.path()).await.unwrap();
        
        let zone_hash = hash_domain_name("example.com");
        let zone_data1 = b"version 1";
        let zone_data2 = b"version 2";
        
        // Store initial version
        let result1 = engine.store_zone_atomic(zone_hash, "example.com", zone_data1, 0).await.unwrap();
        assert!(result1.success);
        
        // Try to update with wrong expected version
        let result2 = engine.store_zone_atomic(zone_hash, "example.com", zone_data2, 999).await.unwrap();
        assert!(!result2.success);
        
        // Update with correct expected version
        let result3 = engine.store_zone_atomic(zone_hash, "example.com", zone_data2, result1.new_version).await.unwrap();
        assert!(result3.success);
        assert_eq!(result3.old_version, result1.new_version);
    }

    #[tokio::test]
    async fn test_compare_and_swap() {
        let temp_dir = TempDir::new().unwrap();
        let engine = ZeroCopyStorageEngine::new(temp_dir.path()).await.unwrap();
        
        let zone_hash = hash_domain_name("example.com");
        let zone_data1 = Bytes::from_static(b"version 1");
        let zone_data2 = Bytes::from_static(b"version 2");
        
        // Store initial version
        let result1 = engine.store_zone_atomic(zone_hash, "example.com", &zone_data1, 0).await.unwrap();
        
        // Compare and swap
        let result2 = engine.compare_and_swap_zone(zone_hash, result1.new_version, zone_data2).await.unwrap();
        assert!(result2.success);
        
        // Verify data was updated
        let loaded_data = engine.load_zone_atomic(zone_hash).await.unwrap();
        assert_eq!(&loaded_data[..], b"version 2");
    }
}