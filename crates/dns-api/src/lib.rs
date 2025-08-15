//! REST API server for DNS management
//!
//! This crate provides the HTTP API for managing DNS zones, records,
//! and server configuration.

pub mod handlers;
pub mod routes;
pub mod auth;
pub mod metrics;

pub use handlers::*;
pub use routes::*;
pub use auth::*;