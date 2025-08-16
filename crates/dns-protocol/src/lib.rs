//! DNS protocol implementation with zero-copy parsing
//!
//! This crate provides high-performance DNS protocol handling using
//! FlatBuffers for zero-copy serialization and parsing.

pub mod packet;
pub mod parser;
pub mod response;
pub mod records;
pub mod validation;
pub mod handlers;

#[cfg(test)]
mod tests;

pub use packet::{ZeroCopyDnsParser, DnsRecordData, RecordDataType};
pub use parser::DnsPacketParser;
pub use response::{DnsResponseBuilder, PrebuiltResponse};
pub use records::{ParsedDnsRecord, ParsedRecordData, DnsHeader, ParsedDnsPacket};
pub use validation::DnsPacketValidator;

// Export protocol handlers
pub use handlers::{
    DnsProtocolHandler, ProtocolType, QueryRouter, ZoneManager,
    UdpDnsHandler, TcpDnsHandler, BufferPool,
    ZoneSyncRequest, ZoneSyncResponse, DynamicUpdate, UpdateOperation,
    ZoneNotify, ChangeSummary, CompressionType, AuthToken,
    UpdateResponse, NotifyResponse, ZoneData, UpdateResult,
};

#[cfg(feature = "doh")]
pub use handlers::DohHandler;

#[cfg(feature = "dot")]
pub use handlers::DotHandler;

#[cfg(feature = "doq")]
pub use handlers::DoqHandler;