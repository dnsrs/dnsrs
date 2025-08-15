//! DNS protocol implementation with zero-copy parsing
//!
//! This crate provides high-performance DNS protocol handling using
//! FlatBuffers for zero-copy serialization and parsing.

pub mod packet;

pub use packet::*;