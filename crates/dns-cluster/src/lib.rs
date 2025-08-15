//! Planet-scale clustering and replication
//!
//! This crate implements the clustering functionality for distributed
//! DNS operations across unlimited nodes.

pub mod discovery;
pub mod hash_ring;
pub mod replication;
pub mod consensus;

pub use discovery::*;
pub use hash_ring::*;
pub use replication::*;
pub use consensus::*;