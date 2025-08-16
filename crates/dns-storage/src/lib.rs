//! Zero-copy storage engine with FlatBuffers and memory mapping
//!
//! This crate provides the storage layer for DNS zones and records,
//! optimized for zero-copy operations and high performance.

pub mod cache;
pub mod disk;
pub mod index;
pub mod memory;
pub mod zone;
pub mod storage_engine;
pub mod version_log;
pub mod backup;

pub use cache::{ZeroCopyCache, AtomicCacheEntry, AtomicCacheStats, AtomicZeroCopyCache};
pub use disk::{MmapDiskStorage, MappedZoneFile, MmapWriter, MmapStorageStatistics};
pub use index::{HashDomainIndex, ZoneIndexEntry, WildcardEntry, IndexStatistics};
pub use memory::MemoryStorage;
pub use zone::{ZoneManager, ZoneHandle, ZoneCreateParams, ZoneRecord, ZoneStatistics, ZoneManagerStatistics};
pub use storage_engine::{ZeroCopyStorageEngine, AtomicZoneMetadata, MappedZone, ZoneUpdateResult, StorageEngineStatistics};
pub use version_log::{AtomicVersionLog, AtomicChangeEntry, ChangeOperation, ZoneDelta, VersionLogStatistics};
pub use backup::{BackupManager, BackupMetadata, BackupType, BackupStatistics};