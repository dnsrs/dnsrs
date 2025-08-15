//! Core DNS types, error handling, and utilities for the Planet Scale DNS Server
//!
//! This crate provides the foundational types and error handling patterns used
//! throughout the DNS server implementation.

pub mod error;
pub mod types;
pub mod hash;
pub mod metrics;
pub mod atomic;

pub use error::{DnsError, DnsResult};
pub use types::*;
pub use hash::*;
pub use metrics::*;
pub use atomic::*;