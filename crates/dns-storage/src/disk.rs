//! Memory-mapped disk storage for zero-copy access
//!
//! This module provides high-performance disk storage using memory mapping
//! to enable zero-copy access to zone data and DNS records.

use dns_core::{DnsError, DnsResult};
use memmap2::{Mmap, MmapMut, MmapOptions};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
use lockfree::map::Map as LockFreeMap;
use bytes::Bytes;


/// Memory-mapped disk storage manager
pub struct MmapDiskStorage {
    /// Base directory for zone files
    base_path: PathBuf,
    
    /// Lock-free map of zone hash to memory-mapped file
    mapped_zones: Arc<LockFreeMap<u64, Arc<MappedZoneFile>>>,
    
    /// Lock-free map of file paths to prevent duplicate mappings
    file_mappings: Arc<LockFreeMap<u64, Arc<str>>>, // path_hash -> path
    
    /// Atomic statistics
    total_mapped_files: AtomicUsize,
    total_mapped_bytes: AtomicU64,
    read_operations: AtomicU64,
    write_operations: AtomicU64,
    
    /// Configuration
    max_file_size: u64,
    enable_prefault: bool,
}

/// Memory-mapped zone file with atomic metadata
pub struct MappedZoneFile {
    /// Memory-mapped file data
    pub mmap: Arc<Mmap>,
    
    /// File metadata
    file_path: PathBuf,
    file_size: AtomicU64,
    zone_hash: u64,
    
    /// Access tracking
    last_accessed: AtomicU64,
    access_count: AtomicU64,
    
    /// Version tracking for atomic updates
    version: AtomicU64,
    
    /// Flags
    is_readonly: AtomicBool,
    needs_sync: AtomicBool,
}

/// Mutable memory-mapped file for atomic writes
pub struct MmapWriter {
    mmap_mut: MmapMut,
    file_path: PathBuf,
    current_size: usize,
    capacity: usize,
}

impl MmapDiskStorage {
    /// Create a new memory-mapped disk storage
    pub fn new<P: AsRef<Path>>(base_path: P) -> DnsResult<Self> {
        let base_path = base_path.as_ref().to_path_buf();
        
        // Ensure base directory exists
        std::fs::create_dir_all(&base_path)
            .map_err(|e| DnsError::DiskIoError { 
                message: format!("Failed to create base directory: {}", e) 
            })?;
        
        Ok(Self {
            base_path,
            mapped_zones: Arc::new(LockFreeMap::new()),
            file_mappings: Arc::new(LockFreeMap::new()),
            total_mapped_files: AtomicUsize::new(0),
            total_mapped_bytes: AtomicU64::new(0),
            read_operations: AtomicU64::new(0),
            write_operations: AtomicU64::new(0),
            max_file_size: 1024 * 1024 * 1024, // 1GB default
            enable_prefault: true,
        })
    }

    /// Memory-map a zone file for zero-copy access
    pub async fn mmap_zone_file(&self, zone_hash: u64, file_name: &str) -> DnsResult<Arc<MappedZoneFile>> {
        // Check if already mapped
        if let Some(existing) = self.mapped_zones.get(&zone_hash) {
            let mapped_file = existing.val().clone();
            mapped_file.update_access_time();
            return Ok(mapped_file);
        }
        
        let file_path = self.base_path.join(file_name);
        let path_hash = dns_core::hash::hash_zone_data(file_path.to_string_lossy().as_bytes());
        
        // Check if file path is already mapped to prevent duplicate mappings
        if let Some(_existing_path) = self.file_mappings.get(&path_hash) {
            return Err(DnsError::InvalidState { 
                message: format!("File already mapped: {}", file_path.display()) 
            });
        }
        
        // Open and memory-map the file
        let file = File::open(&file_path)
            .map_err(|e| DnsError::DiskIoError { 
                message: format!("Failed to open zone file {}: {}", file_path.display(), e) 
            })?;
        
        let file_size = file.metadata()
            .map_err(|e| DnsError::DiskIoError { 
                message: format!("Failed to get file metadata: {}", e) 
            })?
            .len();
        
        if file_size > self.max_file_size {
            return Err(DnsError::DiskIoError { 
                message: format!("File too large: {} bytes (max: {})", file_size, self.max_file_size) 
            });
        }
        
        // Create memory mapping
        let mut mmap_options = MmapOptions::new();
        
        if self.enable_prefault {
            mmap_options.populate();
        }
        
        let mmap = unsafe {
            mmap_options.map(&file)
                .map_err(|e| DnsError::MemoryMappingError { 
                    message: format!("Failed to memory-map file: {}", e) 
                })?
        };
        
        let mapped_file = Arc::new(MappedZoneFile {
            mmap: Arc::new(mmap),
            file_path: file_path.clone(),
            file_size: AtomicU64::new(file_size),
            zone_hash,
            last_accessed: AtomicU64::new(Self::current_timestamp()),
            access_count: AtomicU64::new(0),
            version: AtomicU64::new(1),
            is_readonly: AtomicBool::new(true),
            needs_sync: AtomicBool::new(false),
        });
        
        // Store mappings
        self.mapped_zones.insert(zone_hash, mapped_file.clone());
        self.file_mappings.insert(path_hash, Arc::from(file_path.to_string_lossy().as_ref()));
        
        // Update statistics
        self.total_mapped_files.fetch_add(1, Ordering::Relaxed);
        self.total_mapped_bytes.fetch_add(file_size, Ordering::Relaxed);
        
        tracing::info!(
            "Memory-mapped zone file: {} ({} bytes, hash: {})",
            file_path.display(), file_size, zone_hash
        );
        
        Ok(mapped_file)
    }

    /// Create a new mutable memory-mapped file for writing
    pub async fn create_mmap_writer(&self, _zone_hash: u64, file_name: &str, initial_size: usize) -> DnsResult<MmapWriter> {
        let file_path = self.base_path.join(file_name);
        
        // Create file with initial size
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)
            .map_err(|e| DnsError::DiskIoError { 
                message: format!("Failed to create file {}: {}", file_path.display(), e) 
            })?;
        
        // Set file size
        file.set_len(initial_size as u64)
            .map_err(|e| DnsError::DiskIoError { 
                message: format!("Failed to set file size: {}", e) 
            })?;
        
        // Create mutable memory mapping
        let mmap_mut = unsafe {
            MmapOptions::new()
                .map_mut(&file)
                .map_err(|e| DnsError::MemoryMappingError { 
                    message: format!("Failed to create mutable memory mapping: {}", e) 
                })?
        };
        
        self.write_operations.fetch_add(1, Ordering::Relaxed);
        
        Ok(MmapWriter {
            mmap_mut,
            file_path,
            current_size: 0,
            capacity: initial_size,
        })
    }

    /// Read zone data with zero-copy access
    pub async fn read_zone_data(&self, zone_hash: u64) -> DnsResult<Bytes> {
        let mapped_file = self.mapped_zones.get(&zone_hash)
            .ok_or_else(|| DnsError::ZoneNotFound { 
                zone_name: format!("hash:{}", zone_hash) 
            })?;
        
        let file = mapped_file.val();
        file.update_access_time();
        
        self.read_operations.fetch_add(1, Ordering::Relaxed);
        
        // Return zero-copy bytes that reference the memory-mapped data
        Ok(Bytes::from_static(unsafe {
            std::slice::from_raw_parts(
                file.mmap.as_ptr(),
                file.file_size.load(Ordering::Acquire) as usize
            )
        }))
    }

    /// Get a reference to the mapped zone file (caller manages lifetime)
    pub fn get_mapped_zone_file(&self, zone_hash: u64) -> Option<Arc<MappedZoneFile>> {
        if let Some(mapped_file) = self.mapped_zones.get(&zone_hash) {
            let file = mapped_file.val().clone();
            file.update_access_time();
            
            self.read_operations.fetch_add(1, Ordering::Relaxed);
            
            Some(file)
        } else {
            None
        }
    }

    /// Write zone data atomically
    pub async fn write_zone_data(&self, zone_hash: u64, file_name: &str, data: &[u8]) -> DnsResult<()> {
        let mut writer = self.create_mmap_writer(zone_hash, file_name, data.len()).await?;
        writer.write_all(data)?;
        writer.sync().await?;
        
        // Update mapping after successful write
        self.mmap_zone_file(zone_hash, file_name).await?;
        
        Ok(())
    }

    /// Unmap a zone file
    pub async fn unmap_zone(&self, zone_hash: u64) -> bool {
        if let Some(mapped_file) = self.mapped_zones.remove(&zone_hash) {
            let file = mapped_file.val();
            let file_size = file.file_size.load(Ordering::Acquire);
            
            // Remove file path mapping
            let path_hash = dns_core::hash::hash_zone_data(
                file.file_path.to_string_lossy().as_bytes()
            );
            self.file_mappings.remove(&path_hash);
            
            // Update statistics
            self.total_mapped_files.fetch_sub(1, Ordering::Relaxed);
            self.total_mapped_bytes.fetch_sub(file_size, Ordering::Relaxed);
            
            tracing::info!(
                "Unmapped zone file: {} (hash: {})",
                file.file_path.display(), zone_hash
            );
            
            true
        } else {
            false
        }
    }

    /// Get storage statistics
    pub fn get_statistics(&self) -> MmapStorageStatistics {
        MmapStorageStatistics {
            total_mapped_files: self.total_mapped_files.load(Ordering::Relaxed),
            total_mapped_bytes: self.total_mapped_bytes.load(Ordering::Relaxed),
            read_operations: self.read_operations.load(Ordering::Relaxed),
            write_operations: self.write_operations.load(Ordering::Relaxed),
        }
    }

    /// Compact storage by unmapping unused files
    pub async fn compact(&self) -> usize {
        let mut unmapped_count = 0;
        let now = Self::current_timestamp();
        let cutoff_time = now.saturating_sub(3600); // 1 hour ago
        
        // Collect zones to unmap (avoid modifying map while iterating)
        let mut zones_to_unmap = Vec::new();
        
        for entry in self.mapped_zones.iter() {
            let zone_hash = *entry.key();
            let mapped_file = entry.val();
            
            let last_accessed = mapped_file.last_accessed.load(Ordering::Relaxed);
            let access_count = mapped_file.access_count.load(Ordering::Relaxed);
            
            // Unmap files that haven't been accessed recently and have low usage
            if access_count < 10 && last_accessed < cutoff_time {
                zones_to_unmap.push(zone_hash);
            }
        }
        
        // Unmap selected zones
        for zone_hash in zones_to_unmap {
            if self.unmap_zone(zone_hash).await {
                unmapped_count += 1;
            }
        }
        
        tracing::info!("Compacted storage: unmapped {} unused files", unmapped_count);
        unmapped_count
    }

    /// Get current timestamp in seconds
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

impl MappedZoneFile {
    /// Update access time atomically
    pub fn update_access_time(&self) {
        let now = MmapDiskStorage::current_timestamp();
        self.last_accessed.store(now, Ordering::Relaxed);
        self.access_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get zone data as bytes reference
    pub fn data(&self) -> &[u8] {
        &self.mmap[..self.file_size.load(Ordering::Acquire) as usize]
    }

    /// Get zone data size
    pub fn size(&self) -> u64 {
        self.file_size.load(Ordering::Acquire)
    }

    /// Get zone version
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// Check if file needs synchronization
    pub fn needs_sync(&self) -> bool {
        self.needs_sync.load(Ordering::Acquire)
    }

    /// Get access count
    pub fn access_count(&self) -> u64 {
        self.access_count.load(Ordering::Acquire)
    }
}

impl MmapWriter {
    /// Write data to the memory-mapped file
    pub fn write_all(&mut self, data: &[u8]) -> DnsResult<()> {
        if self.current_size + data.len() > self.capacity {
            return Err(DnsError::DiskIoError { 
                message: format!(
                    "Write would exceed capacity: {} + {} > {}",
                    self.current_size, data.len(), self.capacity
                ) 
            });
        }
        
        let start = self.current_size;
        let end = start + data.len();
        
        self.mmap_mut[start..end].copy_from_slice(data);
        self.current_size = end;
        
        Ok(())
    }

    /// Synchronize changes to disk
    pub async fn sync(&mut self) -> DnsResult<()> {
        self.mmap_mut.flush()
            .map_err(|e| DnsError::DiskIoError { 
                message: format!("Failed to sync memory-mapped file: {}", e) 
            })?;
        
        Ok(())
    }

    /// Get current write position
    pub fn position(&self) -> usize {
        self.current_size
    }

    /// Get remaining capacity
    pub fn remaining_capacity(&self) -> usize {
        self.capacity - self.current_size
    }
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct MmapStorageStatistics {
    pub total_mapped_files: usize,
    pub total_mapped_bytes: u64,
    pub read_operations: u64,
    pub write_operations: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_mmap_storage_basic_operations() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MmapDiskStorage::new(temp_dir.path()).unwrap();
        
        let zone_hash = 12345u64;
        let test_data = b"test zone data";
        
        // Write data
        storage.write_zone_data(zone_hash, "test.zone", test_data).await.unwrap();
        
        // Read data back
        let read_data = storage.read_zone_data(zone_hash).await.unwrap();
        assert_eq!(&read_data[..], test_data);
        
        // Test mapped file access
        let mapped_file = storage.get_mapped_zone_file(zone_hash).unwrap();
        assert_eq!(mapped_file.data(), test_data);
        
        // Check statistics
        let stats = storage.get_statistics();
        assert_eq!(stats.total_mapped_files, 1);
        assert!(stats.read_operations > 0);
        assert!(stats.write_operations > 0);
    }

    #[tokio::test]
    async fn test_mmap_writer() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MmapDiskStorage::new(temp_dir.path()).unwrap();
        
        let mut writer = storage.create_mmap_writer(123, "test.dat", 1024).await.unwrap();
        
        let test_data = b"Hello, memory-mapped world!";
        writer.write_all(test_data).unwrap();
        
        assert_eq!(writer.position(), test_data.len());
        assert_eq!(writer.remaining_capacity(), 1024 - test_data.len());
        
        writer.sync().await.unwrap();
    }

    #[tokio::test]
    async fn test_storage_compaction() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MmapDiskStorage::new(temp_dir.path()).unwrap();
        
        // Create multiple zone files
        for i in 0..5 {
            let zone_hash = i as u64;
            let data = format!("zone data {}", i);
            storage.write_zone_data(zone_hash, &format!("zone{}.dat", i), data.as_bytes()).await.unwrap();
        }
        
        assert_eq!(storage.get_statistics().total_mapped_files, 5);
        
        // Compact should not remove recently accessed files
        let removed = storage.compact().await;
        assert_eq!(removed, 0); // Files were just created, so they're recent
        
        assert_eq!(storage.get_statistics().total_mapped_files, 5);
    }
}