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
    
    /// Parse DNS query from bytes
    pub fn from_bytes(data: &[u8]) -> crate::DnsResult<Self> {
        // Basic DNS packet parsing
        if data.len() < 12 {
            return Err(crate::DnsError::invalid_packet("Packet too short"));
        }
        
        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        
        if qdcount != 1 {
            return Err(crate::DnsError::invalid_packet("Expected exactly one question"));
        }
        
        // Parse question section (simplified)
        let mut offset = 12;
        let mut name = String::new();
        
        // Parse domain name
        while offset < data.len() {
            let len = data[offset] as usize;
            if len == 0 {
                offset += 1;
                break;
            }
            
            if len > 63 {
                return Err(crate::DnsError::invalid_packet("Label too long"));
            }
            
            if offset + 1 + len >= data.len() {
                return Err(crate::DnsError::invalid_packet("Truncated name"));
            }
            
            if !name.is_empty() {
                name.push('.');
            }
            
            let label = std::str::from_utf8(&data[offset + 1..offset + 1 + len])
                .map_err(|_| crate::DnsError::invalid_packet("Invalid UTF-8 in name"))?;
            name.push_str(label);
            
            offset += 1 + len;
        }
        
        if offset + 4 > data.len() {
            return Err(crate::DnsError::invalid_packet("Truncated question"));
        }
        
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        
        let record_type = RecordType::from_u16(qtype)
            .ok_or_else(|| crate::DnsError::UnsupportedRecordType { record_type: qtype })?;
        let class = DnsClass::from_u16(qclass)
            .ok_or_else(|| crate::DnsError::invalid_packet("Invalid DNS class"))?;
        
        Ok(Self {
            id,
            name: name.clone(),
            name_hash: crate::hash::hash_domain_name(&name),
            record_type,
            class,
            recursion_desired: (flags & 0x0100) != 0,
            dnssec_ok: false, // Would need to parse EDNS0 for this
            client_addr: "0.0.0.0".parse().unwrap(), // Will be set by caller
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        })
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

impl DnsResponse {
    /// Convert DNS response to bytes
    pub fn to_bytes(&self) -> crate::DnsResult<Vec<u8>> {
        let mut buffer = Vec::new();
        
        // DNS header (12 bytes)
        buffer.extend_from_slice(&self.id.to_be_bytes());
        
        // Flags
        let mut flags = 0u16;
        flags |= 0x8000; // QR bit (response)
        if self.authoritative { flags |= 0x0400; }
        if self.truncated { flags |= 0x0200; }
        if self.recursion_available { flags |= 0x0080; }
        if self.authenticated_data { flags |= 0x0020; }
        if self.checking_disabled { flags |= 0x0010; }
        flags |= self.response_code.to_u16();
        
        buffer.extend_from_slice(&flags.to_be_bytes());
        buffer.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        buffer.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        buffer.extend_from_slice(&(self.authority.len() as u16).to_be_bytes());
        buffer.extend_from_slice(&(self.additional.len() as u16).to_be_bytes());
        
        // Questions section
        for question in &self.questions {
            Self::encode_name(&mut buffer, &question.name)?;
            buffer.extend_from_slice(&question.record_type.to_u16().to_be_bytes());
            buffer.extend_from_slice(&question.class.to_u16().to_be_bytes());
        }
        
        // Answer section
        for record in &self.answers {
            Self::encode_record(&mut buffer, record)?;
        }
        
        // Authority section
        for record in &self.authority {
            Self::encode_record(&mut buffer, record)?;
        }
        
        // Additional section
        for record in &self.additional {
            Self::encode_record(&mut buffer, record)?;
        }
        
        Ok(buffer)
    }
    
    /// Encode a domain name
    fn encode_name(buffer: &mut Vec<u8>, name: &str) -> crate::DnsResult<()> {
        if name.is_empty() || name == "." {
            buffer.push(0);
            return Ok(());
        }
        
        for label in name.split('.') {
            if label.len() > 63 {
                return Err(crate::DnsError::invalid_packet("Label too long"));
            }
            buffer.push(label.len() as u8);
            buffer.extend_from_slice(label.as_bytes());
        }
        buffer.push(0); // Root label
        Ok(())
    }
    
    /// Encode a DNS record
    fn encode_record(buffer: &mut Vec<u8>, record: &DnsRecord) -> crate::DnsResult<()> {
        // Name
        Self::encode_name(buffer, &record.name)?;
        
        // Type, Class, TTL
        buffer.extend_from_slice(&record.record_type.to_u16().to_be_bytes());
        buffer.extend_from_slice(&record.class.to_u16().to_be_bytes());
        buffer.extend_from_slice(&record.ttl.to_be_bytes());
        
        // Data
        let data = Self::encode_record_data(&record.data)?;
        buffer.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buffer.extend_from_slice(&data);
        
        Ok(())
    }
    
    /// Encode record data
    fn encode_record_data(data: &RecordData) -> crate::DnsResult<Vec<u8>> {
        let mut buffer = Vec::new();
        
        match data {
            RecordData::A(addr) => {
                buffer.extend_from_slice(&addr.octets());
            }
            RecordData::AAAA(addr) => {
                buffer.extend_from_slice(&addr.octets());
            }
            RecordData::CNAME(name) => {
                Self::encode_name(&mut buffer, name)?;
            }
            RecordData::MX { priority, exchange } => {
                buffer.extend_from_slice(&priority.to_be_bytes());
                Self::encode_name(&mut buffer, exchange)?;
            }
            RecordData::NS(name) => {
                Self::encode_name(&mut buffer, name)?;
            }
            RecordData::PTR(name) => {
                Self::encode_name(&mut buffer, name)?;
            }
            RecordData::TXT(strings) => {
                for s in strings {
                    let bytes = s.as_bytes();
                    if bytes.len() > 255 {
                        return Err(crate::DnsError::invalid_packet("TXT string too long"));
                    }
                    buffer.push(bytes.len() as u8);
                    buffer.extend_from_slice(bytes);
                }
            }
            _ => {
                // For other record types, return empty data for now
                // In a full implementation, these would be properly encoded
            }
        }
        
        Ok(buffer)
    }
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
    // Additional DNSSEC records
    NSEC3PARAM { hash_algorithm: u8, flags: u8, iterations: u16, salt: Bytes },
    CDS { key_tag: u16, algorithm: u8, digest_type: u8, digest: Bytes },
    CDNSKEY { flags: u16, protocol: u8, algorithm: u8, public_key: Bytes },
    // Modern records
    CAA { flags: u8, tag: String, value: Bytes },
    TLSA { cert_usage: u8, selector: u8, matching_type: u8, cert_data: Bytes },
    HTTPS { priority: u16, target: String, params: Vec<(u16, Bytes)> },
    SVCB { priority: u16, target: String, params: Vec<(u16, Bytes)> },
    SMIMEA { cert_usage: u8, selector: u8, matching_type: u8, cert_data: Bytes },
    NAPTR { order: u16, preference: u16, flags: String, services: String, regexp: String, replacement: String },
    OPENPGPKEY { key_data: Bytes },
    CSYNC { serial: u32, flags: u16, type_bit_maps: Bytes },
    ZONEMD { serial: u32, scheme: u8, hash_algorithm: u8, digest: Bytes },
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