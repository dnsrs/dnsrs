//! Zero-copy storage engine with FlatBuffers and memory mapping
//!
//! This crate provides the storage layer for DNS zones and records,
//! optimized for zero-copy operations and high performance.

pub mod cache;
pub mod disk;
pub mod index;
pub mod memory;
pub mod zone;

pub use cache::*;
pub use disk::*;
pub use index::*;
pub use memory::*;
pub use zone::*;