//! Atomic Version Log for Incremental Zone Synchronization
//!
//! This module implements a lock-free version log that tracks all zone changes
//! to enable efficient incremental synchronization between nodes.

use dns_core::{DnsResult, DnsError};
use lockfree::queue::Queue as LockFreeQueue;
use lockfree::map::Map as LockFreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, AtomicPtr, Ordering};
use bytes::Bytes;
use flatbuffers::{FlatBufferBuilder, WIPOffset};

/// Lock-free version log using atomic operations
pub struct AtomicVersionLog {
    /// Lock-free append-only log using atomic linked list
    change_log: Arc<LockFreeQueue<Arc<AtomicChangeEntry>>>,
    
    /// Atomic version index using lock-free map (version -> log entries)
    version_index: Arc<LockFreeMap<u64, Arc<LockFreeQueue<usize>>>>,
    
    /// Zone-specific change logs (zone_hash -> change entries)
    zone_logs: Arc<LockFreeMap<u64, Arc<LockFreeQueue<Arc<AtomicChangeEntry>>>>>,
    
    /// Atomic log size counter
    log_size: AtomicUsize,
    
    /// Atomic compaction trigger
    needs_compaction: AtomicBool,
    
    /// Global sequence number for ordering
    sequence_number: AtomicU64,
    
    /// Configuration
    max_log_size: usize,
    compaction_threshold: usize,
}

/// Atomic change entry for lock-free logging
pub struct AtomicChangeEntry {
    /// Unique sequence number for ordering
    pub sequence: u64,
    
    /// Zone hash this change applies to
    pub zone_hash: u64,
    
    /// Version information
    pub from_version: u64,
    pub to_version: u64,
    
    /// Timestamp when change occurred
    pub timestamp: AtomicU64,
    
    /// Change operation details
    pub operation: Arc<ChangeOperation>,
    
    /// Size of the change in bytes
    pub change_size: AtomicU64,
    
    /// Application status
    pub applied: AtomicBool,
    
    /// Atomic linked list pointer for lock-free traversal
    pub next: AtomicPtr<AtomicChangeEntry>,
}

/// Types of change operations
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ChangeOperation {
    ZoneUpdate {
        old_size: u64,
        new_size: u64,
        delta_data: Option<Vec<u8>>,
    },
    RecordAdd {
        name_hash: u64,
        record_type: u16,
        record_data: Vec<u8>,
    },
    RecordRemove {
        name_hash: u64,
        record_type: u16,
    },
    RecordUpdate {
        name_hash: u64,
        record_type: u16,
        old_data: Vec<u8>,
        new_data: Vec<u8>,
    },
    ZoneCreate {
        zone_name: String,
        initial_size: u64,
    },
    ZoneDelete {
        zone_name: String,
    },
}

/// Delta information for incremental sync
#[derive(Debug, Clone)]
pub struct ZoneDelta {
    pub zone_hash: u64,
    pub from_version: u64,
    pub to_version: u64,
    pub operations: Vec<ChangeOperation>,
    pub compressed_data: Option<Bytes>,
    pub total_size: u64,
}

impl AtomicVersionLog {
    /// Create a new atomic version log
    pub fn new() -> Self {
        Self {
            change_log: Arc::new(LockFreeQueue::new()),
            version_index: Arc::new(LockFreeMap::new()),
            zone_logs: Arc::new(LockFreeMap::new()),
            log_size: AtomicUsize::new(0),
            needs_compaction: AtomicBool::new(false),
            sequence_number: AtomicU64::new(1),
            max_log_size: 1_000_000, // 1M entries
            compaction_threshold: 100_000, // Compact when 100K entries
        }
    }

    /// Log a zone update operation atomically
    pub async fn log_zone_update(
        &self,
        zone_hash: u64,
        from_version: u64,
        to_version: u64,
        change_size: usize,
    ) {
        let sequence = self.sequence_number.fetch_add(1, Ordering::AcqRel);
        let timestamp = Self::current_timestamp();
        
        let operation = Arc::new(ChangeOperation::ZoneUpdate {
            old_size: 0, // Would be filled from actual data
            new_size: change_size as u64,
            delta_data: None, // Could store compressed delta
        });
        
        let entry = Arc::new(AtomicChangeEntry {
            sequence,
            zone_hash,
            from_version,
            to_version,
            timestamp: AtomicU64::new(timestamp),
            operation,
            change_size: AtomicU64::new(change_size as u64),
            applied: AtomicBool::new(true),
            next: AtomicPtr::new(std::ptr::null_mut()),
        });
        
        // Add to main log
        self.change_log.push(entry.clone());
        
        // Add to zone-specific log
        self.add_to_zone_log(zone_hash, entry.clone());
        
        // Add to version index
        self.add_to_version_index(to_version, sequence);
        
        // Update counters
        let new_size = self.log_size.fetch_add(1, Ordering::AcqRel);
        
        // Check if compaction is needed
        if new_size > self.compaction_threshold {
            self.needs_compaction.store(true, Ordering::Release);
        }
        
        tracing::debug!(
            "Logged zone update: zone={:016x}, v{} -> v{}, seq={}, size={}",
            zone_hash, from_version, to_version, sequence, change_size
        );
    }

    /// Log a record-level change
    pub async fn log_record_change(
        &self,
        zone_hash: u64,
        version: u64,
        operation: ChangeOperation,
    ) {
        let sequence = self.sequence_number.fetch_add(1, Ordering::AcqRel);
        let timestamp = Self::current_timestamp();
        
        let change_size = match &operation {
            ChangeOperation::RecordAdd { record_data, .. } => record_data.len(),
            ChangeOperation::RecordUpdate { new_data, .. } => new_data.len(),
            _ => 0,
        };
        
        let entry = Arc::new(AtomicChangeEntry {
            sequence,
            zone_hash,
            from_version: version,
            to_version: version,
            timestamp: AtomicU64::new(timestamp),
            operation: Arc::new(operation),
            change_size: AtomicU64::new(change_size as u64),
            applied: AtomicBool::new(true),
            next: AtomicPtr::new(std::ptr::null_mut()),
        });
        
        // Add to logs
        self.change_log.push(entry.clone());
        self.add_to_zone_log(zone_hash, entry);
        self.add_to_version_index(version, sequence);
        
        self.log_size.fetch_add(1, Ordering::AcqRel);
        
        tracing::debug!(
            "Logged record change: zone={:016x}, v{}, seq={}, size={}",
            zone_hash, version, sequence, change_size
        );
    }

    /// Get zone delta for incremental synchronization
    pub async fn get_zone_delta(
        &self,
        zone_hash: u64,
        from_version: u64,
        to_version: u64,
    ) -> DnsResult<Bytes> {
        if from_version >= to_version {
            return Err(DnsError::InvalidInput {
                message: format!("Invalid version range: {} >= {}", from_version, to_version),
            });
        }
        
        // Get zone-specific log
        let zone_log = self.zone_logs.get(&zone_hash)
            .ok_or_else(|| DnsError::ZoneNotFound {
                zone_name: format!("hash:{:016x}", zone_hash),
            })?;
        
        // Collect changes in version range
        let mut operations = Vec::new();
        let mut total_size = 0u64;
        
        // Iterate through zone log to find relevant changes
        while let Some(entry) = zone_log.val().pop() {
            if entry.from_version >= from_version && entry.to_version <= to_version {
                total_size += entry.change_size.load(Ordering::Acquire);
                operations.push((*entry.operation).clone());
            }
        }
        
        // Create delta structure
        let delta = ZoneDelta {
            zone_hash,
            from_version,
            to_version,
            operations,
            compressed_data: None, // Could implement compression here
            total_size,
        };
        
        // Serialize delta to FlatBuffer
        self.serialize_zone_delta(&delta)
    }

    /// Get changes since a specific version
    pub async fn get_changes_since(&self, since_version: u64) -> Vec<Arc<AtomicChangeEntry>> {
        let mut changes = Vec::new();
        
        // Iterate through change log
        while let Some(entry) = self.change_log.pop() {
            if entry.to_version > since_version {
                changes.push(entry);
            }
        }
        
        // Sort by sequence number to maintain order
        changes.sort_by_key(|entry| entry.sequence);
        
        changes
    }

    /// Get the latest version number
    pub fn get_latest_version(&self) -> u64 {
        // Find the highest version in the log
        let mut max_version = 0u64;
        
        while let Some(entry) = self.change_log.pop() {
            max_version = max_version.max(entry.to_version);
        }
        
        max_version
    }

    /// Compact the log by removing old entries
    pub async fn compact(&self) -> usize {
        if !self.needs_compaction.load(Ordering::Acquire) {
            return 0;
        }
        
        let current_size = self.log_size.load(Ordering::Acquire);
        if current_size <= self.compaction_threshold {
            return 0;
        }
        
        let mut removed_count = 0;
        let cutoff_time = Self::current_timestamp() - 86400; // 24 hours ago
        
        // Remove old entries (this is a simplified approach)
        // In production, you'd want more sophisticated compaction
        while let Some(entry) = self.change_log.pop() {
            let entry_time = entry.timestamp.load(Ordering::Acquire);
            if entry_time < cutoff_time {
                removed_count += 1;
            } else {
                // Put it back (this is inefficient, but demonstrates the concept)
                self.change_log.push(entry);
                break;
            }
        }
        
        // Update counters
        self.log_size.fetch_sub(removed_count, Ordering::AcqRel);
        
        // Clear compaction flag if we're under threshold
        if self.log_size.load(Ordering::Acquire) <= self.compaction_threshold {
            self.needs_compaction.store(false, Ordering::Release);
        }
        
        tracing::info!("Compacted version log: removed {} old entries", removed_count);
        removed_count
    }

    /// Get log statistics
    pub fn get_statistics(&self) -> VersionLogStatistics {
        VersionLogStatistics {
            total_entries: self.log_size.load(Ordering::Relaxed),
            sequence_number: self.sequence_number.load(Ordering::Relaxed),
            needs_compaction: self.needs_compaction.load(Ordering::Relaxed),
            total_zones: self.zone_logs.iter().count(),
        }
    }

    // Private helper methods

    fn add_to_zone_log(&self, zone_hash: u64, entry: Arc<AtomicChangeEntry>) {
        // Get or create zone-specific log
        let zone_log = if let Some(existing) = self.zone_logs.get(&zone_hash) {
            existing.val().clone()
        } else {
            let new_log = Arc::new(LockFreeQueue::new());
            self.zone_logs.insert(zone_hash, new_log.clone());
            new_log
        };
        
        zone_log.push(entry);
    }

    fn add_to_version_index(&self, version: u64, sequence: u64) {
        // Get or create version entry list
        let version_entries = if let Some(existing) = self.version_index.get(&version) {
            existing.val().clone()
        } else {
            let new_entries = Arc::new(LockFreeQueue::new());
            self.version_index.insert(version, new_entries.clone());
            new_entries
        };
        
        version_entries.push(sequence as usize);
    }

    fn serialize_zone_delta(&self, delta: &ZoneDelta) -> DnsResult<Bytes> {
        // Create FlatBuffer for delta
        let mut builder = FlatBufferBuilder::new();
        
        // Serialize operations (simplified)
        let operations_data = bincode::serialize(&delta.operations)
            .map_err(|e| DnsError::SerializationError {
                message: format!("Failed to serialize operations: {}", e),
            })?;
        
        let operations_vector = builder.create_vector(&operations_data);
        
        // Create delta table (this would use the actual FlatBuffer schema)
        // For now, just return the serialized operations
        Ok(Bytes::from(operations_data))
    }

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

/// Version log statistics
#[derive(Debug, Clone)]
pub struct VersionLogStatistics {
    pub total_entries: usize,
    pub sequence_number: u64,
    pub needs_compaction: bool,
    pub total_zones: usize,
}

impl Default for AtomicVersionLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_core::hash::hash_domain_name;

    #[tokio::test]
    async fn test_version_log_basic_operations() {
        let log = AtomicVersionLog::new();
        
        let zone_hash = hash_domain_name("example.com");
        
        // Log a zone update
        log.log_zone_update(zone_hash, 1, 2, 1024).await;
        
        // Check statistics
        let stats = log.get_statistics();
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.sequence_number, 2); // Started at 1, incremented to 2
        
        // Get latest version
        let latest = log.get_latest_version();
        assert_eq!(latest, 2);
    }

    #[tokio::test]
    async fn test_record_level_changes() {
        let log = AtomicVersionLog::new();
        
        let zone_hash = hash_domain_name("example.com");
        let record_data = Bytes::from_static(b"192.168.1.1");
        
        // Log record addition
        let operation = ChangeOperation::RecordAdd {
            name_hash: hash_domain_name("www.example.com"),
            record_type: 1, // A record
            record_data: record_data.to_vec(),
        };
        
        log.log_record_change(zone_hash, 1, operation).await;
        
        let stats = log.get_statistics();
        assert_eq!(stats.total_entries, 1);
    }

    #[tokio::test]
    async fn test_zone_delta_generation() {
        let log = AtomicVersionLog::new();
        
        let zone_hash = hash_domain_name("example.com");
        
        // Log multiple changes
        log.log_zone_update(zone_hash, 1, 2, 1024).await;
        log.log_zone_update(zone_hash, 2, 3, 2048).await;
        
        // Get delta
        let delta_result = log.get_zone_delta(zone_hash, 1, 3).await;
        assert!(delta_result.is_ok());
        
        let delta_bytes = delta_result.unwrap();
        assert!(!delta_bytes.is_empty());
    }

    #[tokio::test]
    async fn test_changes_since_version() {
        let log = AtomicVersionLog::new();
        
        let zone_hash = hash_domain_name("example.com");
        
        // Log changes with different versions
        log.log_zone_update(zone_hash, 1, 2, 1024).await;
        log.log_zone_update(zone_hash, 2, 3, 2048).await;
        log.log_zone_update(zone_hash, 3, 4, 4096).await;
        
        // Get changes since version 2
        let changes = log.get_changes_since(2).await;
        
        // Should get changes for versions 3 and 4
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().all(|c| c.to_version > 2));
    }

    #[tokio::test]
    async fn test_log_compaction() {
        let mut log = AtomicVersionLog::new();
        log.compaction_threshold = 5; // Low threshold for testing
        
        let zone_hash = hash_domain_name("example.com");
        
        // Add enough entries to trigger compaction
        for i in 1..=10 {
            log.log_zone_update(zone_hash, i, i + 1, 1024).await;
        }
        
        // Check that compaction is needed
        let stats_before = log.get_statistics();
        assert!(stats_before.needs_compaction);
        
        // Run compaction
        let removed = log.compact().await;
        
        // Verify some entries were removed
        let stats_after = log.get_statistics();
        assert!(stats_after.total_entries < stats_before.total_entries);
    }
}