//! Core DNS types, error handling, and utilities for the Planet Scale DNS Server
//!
//! This crate provides the foundational types and error handling patterns used
//! throughout the DNS server implementation.

pub mod error;
pub mod types;
pub mod hash;
pub mod metrics;
pub mod atomic;
pub mod query;
pub mod resolver;
pub mod router;
pub mod blocklist;

#[cfg(test)]
mod tests;

pub use error::{DnsError, DnsResult};
pub use types::*;
pub use hash::*;
pub use metrics::*;
pub use atomic::*;
pub use query::*;
pub use resolver::*;
pub use router::*;
pub use blocklist::*;