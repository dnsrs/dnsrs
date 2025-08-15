//! Core DNS types and constants

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};
use bytes::Bytes;

/// DNS record types as defined in RFCs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RecordType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    NAPTR = 35,
    DS = 43,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    TLSA = 52,
    SMIMEA = 53,
    CDS = 59,
    CDNSKEY = 60,
    OPENPGPKEY = 61,
    CSYNC = 62,
    ZONEMD = 63,
    SVCB = 64,
    HTTPS = 65,
    CAA = 257,
}

impl RecordType {
    /// Convert from u16
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::A),
            2 => Some(Self::NS),
            5 => Some(Self::CNAME),
            6 => Some(Self::SOA),
            12 => Some(Self::PTR),
            15 => Some(Self::MX),
            16 => Some(Self::TXT),
            28 => Some(Self::AAAA),
            33 => Some(Self::SRV),
            35 => Some(Self::NAPTR),
            43 => Some(Self::DS),
            46 => Some(Self::RRSIG),
            47 => Some(Self::NSEC),
            48 => Some(Self::DNSKEY),
            50 => Some(Self::NSEC3),
            51 => Some(Self::NSEC3PARAM),
            52 => Some(Self::TLSA),
            53 => Some(Self::SMIMEA),
            59 => Some(Self::CDS),
            60 => Some(Self::CDNSKEY),
            61 => Some(Self::OPENPGPKEY),
            62 => Some(Self::CSYNC),
            63 => Some(Self::ZONEMD),
            64 => Some(Self::SVCB),
            65 => Some(Self::HTTPS),
            257 => Some(Self::CAA),
            _ => None,
        }
    }
    
    /// Convert to u16
    pub fn to_u16(self) -> u16 {
        self as u16
    }
    
    /// Check if this record type supports DNSSEC
    pub fn supports_dnssec(self) -> bool {
        matches!(self, 
            Self::DS | Self::RRSIG | Self::NSEC | Self::DNSKEY | 
            Self::NSEC3 | Self::NSEC3PARAM | Self::CDS | Self::CDNSKEY
        )
    }
}

/// DNS class (usually IN for Internet)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsClass {
    IN = 1,    // Internet
    CS = 2,    // CSNET (obsolete)
    CH = 3,    // Chaos
    HS = 4,    // Hesiod
}

impl DnsClass {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::IN),
            2 => Some(Self::CS),
            3 => Some(Self::CH),
            4 => Some(Self::HS),
            _ => None,
        }
    }
    
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// DNS response codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ResponseCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
}

impl ResponseCode {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::NoError),
            1 => Some(Self::FormErr),
            2 => Some(Self::ServFail),
            3 => Some(Self::NXDomain),
            4 => Some(Self::NotImp),
            5 => Some(Self::Refused),
            6 => Some(Self::YXDomain),
            7 => Some(Self::YXRRSet),
            8 => Some(Self::NXRRSet),
            9 => Some(Self::NotAuth),
            10 => Some(Self::NotZone),
            _ => None,
        }
    }
    
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// DNS query structure for atomic processing
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub id: u16,
    pub name: String,
    pub name_hash: u64,
    pub record_type: RecordType,
    pub class: DnsClass,
    pub recursion_desired: bool,
    pub dnssec_ok: bool,
    pub client_addr: IpAddr,
    pub timestamp: u64,
}

impl DnsQuery {
    /// Create a new DNS query
    pub fn new(
        id: u16,
        name: String,
        record_type: RecordType,
        class: DnsClass,
        client_addr: IpAddr,
    ) -> Self {
        let name_hash = crate::hash::hash_domain_name(&name);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Self {
            id,
            name,
            name_hash,
            record_type,
            class,
            recursion_desired: false,
            dnssec_ok: false,
            client_addr,
            timestamp,
        }
    }
    
    /// Calculate query hash for caching
    pub fn query_hash(&self) -> u64 {
        crate::hash::hash_query(self.name_hash, self.record_type.to_u16(), self.class.to_u16())
    }
}

/// DNS response structure
#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub id: u16,
    pub response_code: ResponseCode,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_available: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authority: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}

/// DNS question structure
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub record_type: RecordType,
    pub class: DnsClass,
}

/// DNS record structure
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: RecordType,
    pub class: DnsClass,
    pub ttl: u32,
    pub data: RecordData,
}

/// DNS record data variants
#[derive(Debug, Clone)]
pub enum RecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    MX { priority: u16, exchange: String },
    NS(String),
    PTR(String),
    TXT(Vec<String>),
    SRV { priority: u16, weight: u16, port: u16, target: String },
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    // DNSSEC records
    DNSKEY { flags: u16, protocol: u8, algorithm: u8, public_key: Bytes },
    DS { key_tag: u16, algorithm: u8, digest_type: u8, digest: Bytes },
    RRSIG {
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        signature_expiration: u32,
        signature_inception: u32,
        key_tag: u16,
        signer_name: String,
        signature: Bytes,
    },
    // Modern records
    CAA { flags: u8, tag: String, value: Bytes },
    TLSA { cert_usage: u8, selector: u8, matching_type: u8, cert_data: Bytes },
    HTTPS { priority: u16, target: String, params: Vec<(u16, Bytes)> },
    SVCB { priority: u16, target: String, params: Vec<(u16, Bytes)> },
    // Raw data for unknown types
    Unknown { data: Bytes },
}

/// Protocol type for different DNS transports
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolType {
    Udp,
    Tcp,
    DoH,  // DNS over HTTPS
    DoT,  // DNS over TLS
    DoQ,  // DNS over QUIC
}

/// Node information for clustering
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub node_id: u64,
    pub address: String,
    pub region: String,
    pub datacenter: String,
    pub capabilities: Vec<String>,
    pub load_factor: f32,
    pub last_seen: u64,
    pub is_healthy: bool,
}

/// Zone metadata
#[derive(Debug, Clone)]
pub struct ZoneMetadata {
    pub name: String,
    pub name_hash: u64,
    pub serial: u32,
    pub version: u64,
    pub last_modified: u64,
    pub record_count: u32,
    pub size_bytes: u64,
    pub is_authoritative: bool,
    pub dnssec_enabled: bool,
}

/// Constants
pub const MAX_DNS_PACKET_SIZE: usize = 65535;
pub const MAX_UDP_PACKET_SIZE: usize = 512;
pub const MAX_DOMAIN_NAME_LENGTH: usize = 253;
pub const MAX_LABEL_LENGTH: usize = 63;
pub const DEFAULT_TTL: u32 = 300;
pub const MIN_TTL: u32 = 1;
pub const MAX_TTL: u32 = 2147483647; // 2^31 - 1