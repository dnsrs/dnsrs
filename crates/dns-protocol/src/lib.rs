//! DNS protocol implementation with FlatBuffers support
//!
//! This crate provides high-performance DNS protocol handlers for UDP, TCP,
//! DNS over HTTPS (DoH), DNS over TLS (DoT), and DNS over QUIC (DoQ).

pub mod handlers;
pub mod packet;
pub mod parser;

pub use handlers::*;
pub use packet::*;
pub use parser::*;