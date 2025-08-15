//! Main DNS server library
//!
//! This crate ties together all the other crates to provide the
//! complete DNS server functionality.

pub mod config;
pub mod server;

pub use config::*;
pub use server::*;