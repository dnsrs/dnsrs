//! DNS record data structures for parsed packets
//!
//! This module defines the structures used to represent parsed DNS records
//! with full type safety and validation.

use dns_core::{RecordType, DnsClass, DnsQuestion};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use bytes::Bytes;

/// Complete parsed DNS packet
#[derive(Debug, Clone)]
pub struct ParsedDnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<ParsedDnsRecord>,
    pub authority: Vec<ParsedDnsRecord>,
    pub additional: Vec<ParsedDnsRecord>,
    pub raw_data: Vec<u8>,
    pub client_addr: IpAddr,
    pub parsed_at: u64,
}

/// DNS packet header
#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    /// Check if this is a response packet
    pub fn is_response(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    /// Check if this is an authoritative response
    pub fn is_authoritative(&self) -> bool {
        (self.flags & 0x0400) != 0
    }

    /// Check if the packet is truncated
    pub fn is_truncated(&self) -> bool {
        (self.flags & 0x0200) != 0
    }

    /// Check if recursion is desired
    pub fn recursion_desired(&self) -> bool {
        (self.flags & 0x0100) != 0
    }

    /// Check if recursion is available
    pub fn recursion_available(&self) -> bool {
        (self.flags & 0x0080) != 0
    }

    /// Check if authenticated data flag is set
    pub fn authenticated_data(&self) -> bool {
        (self.flags & 0x0020) != 0
    }

    /// Check if checking disabled flag is set
    pub fn checking_disabled(&self) -> bool {
        (self.flags & 0x0010) != 0
    }

    /// Get the opcode
    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0x0F) as u8
    }

    /// Get the response code
    pub fn response_code(&self) -> u8 {
        (self.flags & 0x0F) as u8
    }
}

/// Parsed DNS resource record
#[derive(Debug, Clone)]
pub struct ParsedDnsRecord {
    pub name: String,
    pub record_type: RecordType,
    pub class: DnsClass,
    pub ttl: u32,
    pub data: ParsedRecordData,
    pub raw_rdata: Vec<u8>,
}

/// Parsed DNS record data for all supported record types
#[derive(Debug, Clone)]
pub enum ParsedRecordData {
    // Standard records
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
    DNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Bytes,
    },
    DS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Bytes,
    },
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
    NSEC {
        next_domain_name: String,
        type_bit_maps: Bytes,
    },
    NSEC3 {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Bytes,
        next_hashed_owner_name: Bytes,
        type_bit_maps: Bytes,
    },

    // Modern records
    CAA {
        flags: u8,
        tag: String,
        value: Bytes,
    },
    TLSA {
        cert_usage: u8,
        selector: u8,
        matching_type: u8,
        cert_data: Bytes,
    },
    HTTPS {
        priority: u16,
        target: String,
        params: Vec<(u16, Bytes)>,
    },
    SVCB {
        priority: u16,
        target: String,
        params: Vec<(u16, Bytes)>,
    },

    // Additional DNSSEC records
    NSEC3PARAM {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Bytes,
    },
    CDS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Bytes,
    },
    CDNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Bytes,
    },

    // Additional modern records
    SMIMEA {
        cert_usage: u8,
        selector: u8,
        matching_type: u8,
        cert_data: Bytes,
    },
    NAPTR {
        order: u16,
        preference: u16,
        flags: String,
        services: String,
        regexp: String,
        replacement: String,
    },
    OPENPGPKEY {
        key_data: Bytes,
    },
    CSYNC {
        serial: u32,
        flags: u16,
        type_bit_maps: Bytes,
    },
    ZONEMD {
        serial: u32,
        scheme: u8,
        hash_algorithm: u8,
        digest: Bytes,
    },

    // Fallback for unknown record types
    Unknown { data: Bytes },
}

impl ParsedRecordData {
    /// Get the wire format size of this record data
    pub fn wire_size(&self) -> usize {
        match self {
            Self::A(_) => 4,
            Self::AAAA(_) => 16,
            Self::CNAME(name) => self.domain_name_wire_size(name),
            Self::MX { exchange, .. } => 2 + self.domain_name_wire_size(exchange),
            Self::NS(name) => self.domain_name_wire_size(name),
            Self::PTR(name) => self.domain_name_wire_size(name),
            Self::TXT(strings) => strings.iter().map(|s| 1 + s.len()).sum(),
            Self::SRV { target, .. } => 6 + self.domain_name_wire_size(target),
            Self::SOA { mname, rname, .. } => {
                self.domain_name_wire_size(mname) + self.domain_name_wire_size(rname) + 20
            }
            Self::DNSKEY { public_key, .. } => 4 + public_key.len(),
            Self::DS { digest, .. } => 4 + digest.len(),
            Self::RRSIG { signer_name, signature, .. } => {
                18 + self.domain_name_wire_size(signer_name) + signature.len()
            }
            Self::NSEC { next_domain_name, type_bit_maps } => {
                self.domain_name_wire_size(next_domain_name) + type_bit_maps.len()
            }
            Self::NSEC3 { salt, next_hashed_owner_name, type_bit_maps, .. } => {
                5 + salt.len() + 1 + next_hashed_owner_name.len() + type_bit_maps.len()
            }
            Self::CAA { tag, value, .. } => 2 + tag.len() + value.len(),
            Self::TLSA { cert_data, .. } => 3 + cert_data.len(),
            Self::HTTPS { target, params, .. } => {
                2 + self.domain_name_wire_size(target) + self.svc_params_wire_size(params)
            }
            Self::SVCB { target, params, .. } => {
                2 + self.domain_name_wire_size(target) + self.svc_params_wire_size(params)
            }
            Self::NSEC3PARAM { salt, .. } => 5 + salt.len(),
            Self::CDS { digest, .. } => 4 + digest.len(),
            Self::CDNSKEY { public_key, .. } => 4 + public_key.len(),
            Self::SMIMEA { cert_data, .. } => 3 + cert_data.len(),
            Self::NAPTR { flags, services, regexp, replacement, .. } => {
                4 + 1 + flags.len() + 1 + services.len() + 1 + regexp.len() + self.domain_name_wire_size(replacement)
            }
            Self::OPENPGPKEY { key_data } => key_data.len(),
            Self::CSYNC { type_bit_maps, .. } => 6 + type_bit_maps.len(),
            Self::ZONEMD { digest, .. } => 6 + digest.len(),
            Self::Unknown { data } => data.len(),
        }
    }

    /// Calculate wire size for a domain name
    fn domain_name_wire_size(&self, name: &str) -> usize {
        if name.is_empty() {
            return 1; // Root domain
        }
        
        // Simple calculation: each label has 1 byte length + content + 1 byte for root
        name.len() + name.split('.').count() + 1
    }

    /// Calculate wire size for service parameters
    fn svc_params_wire_size(&self, params: &[(u16, Bytes)]) -> usize {
        params.iter().map(|(_, value)| 4 + value.len()).sum()
    }

    /// Check if this record type supports DNSSEC validation
    pub fn supports_dnssec(&self) -> bool {
        matches!(self,
            Self::DNSKEY { .. } |
            Self::DS { .. } |
            Self::RRSIG { .. } |
            Self::NSEC { .. } |
            Self::NSEC3 { .. } |
            Self::NSEC3PARAM { .. } |
            Self::CDS { .. } |
            Self::CDNSKEY { .. } |
            Self::CSYNC { .. }
        )
    }

    /// Get a human-readable description of the record data
    pub fn description(&self) -> String {
        match self {
            Self::A(addr) => addr.to_string(),
            Self::AAAA(addr) => addr.to_string(),
            Self::CNAME(name) => name.clone(),
            Self::MX { priority, exchange } => format!("{} {}", priority, exchange),
            Self::NS(name) => name.clone(),
            Self::PTR(name) => name.clone(),
            Self::TXT(strings) => strings.join(" "),
            Self::SRV { priority, weight, port, target } => {
                format!("{} {} {} {}", priority, weight, port, target)
            }
            Self::SOA { mname, rname, serial, .. } => {
                format!("{} {} {}", mname, rname, serial)
            }
            Self::DNSKEY { flags, algorithm, .. } => {
                format!("flags={} algorithm={}", flags, algorithm)
            }
            Self::DS { key_tag, algorithm, digest_type, .. } => {
                format!("key_tag={} algorithm={} digest_type={}", key_tag, algorithm, digest_type)
            }
            Self::CAA { flags, tag, .. } => {
                format!("flags={} tag={}", flags, tag)
            }
            Self::TLSA { cert_usage, selector, matching_type, .. } => {
                format!("usage={} selector={} matching_type={}", cert_usage, selector, matching_type)
            }
            Self::HTTPS { priority, target, .. } => {
                format!("priority={} target={}", priority, target)
            }
            Self::SVCB { priority, target, .. } => {
                format!("priority={} target={}", priority, target)
            }
            Self::SMIMEA { cert_usage, selector, matching_type, .. } => {
                format!("usage={} selector={} matching_type={}", cert_usage, selector, matching_type)
            }
            Self::NAPTR { order, preference, flags, services, .. } => {
                format!("order={} preference={} flags={} services={}", order, preference, flags, services)
            }
            Self::OPENPGPKEY { .. } => "OpenPGP public key".to_string(),
            Self::CSYNC { serial, flags, .. } => {
                format!("serial={} flags={}", serial, flags)
            }
            Self::ZONEMD { serial, scheme, hash_algorithm, .. } => {
                format!("serial={} scheme={} hash_algorithm={}", serial, scheme, hash_algorithm)
            }
            Self::NSEC3PARAM { hash_algorithm, flags, iterations, .. } => {
                format!("hash_algorithm={} flags={} iterations={}", hash_algorithm, flags, iterations)
            }
            Self::CDS { key_tag, algorithm, digest_type, .. } => {
                format!("key_tag={} algorithm={} digest_type={}", key_tag, algorithm, digest_type)
            }
            Self::CDNSKEY { flags, algorithm, .. } => {
                format!("flags={} algorithm={}", flags, algorithm)
            }
            _ => "Complex record data".to_string(),
        }
    }
}

/// DNS opcode constants
pub mod opcodes {
    pub const QUERY: u8 = 0;
    pub const IQUERY: u8 = 1;
    pub const STATUS: u8 = 2;
    pub const NOTIFY: u8 = 4;
    pub const UPDATE: u8 = 5;
}

/// DNS response code constants
pub mod response_codes {
    pub const NO_ERROR: u8 = 0;
    pub const FORMAT_ERROR: u8 = 1;
    pub const SERVER_FAILURE: u8 = 2;
    pub const NAME_ERROR: u8 = 3;
    pub const NOT_IMPLEMENTED: u8 = 4;
    pub const REFUSED: u8 = 5;
    pub const YX_DOMAIN: u8 = 6;
    pub const YX_RR_SET: u8 = 7;
    pub const NX_RR_SET: u8 = 8;
    pub const NOT_AUTH: u8 = 9;
    pub const NOT_ZONE: u8 = 10;
}

/// DNS flag bit positions
pub mod flags {
    pub const QR: u16 = 0x8000;      // Query/Response
    pub const AA: u16 = 0x0400;      // Authoritative Answer
    pub const TC: u16 = 0x0200;      // Truncated
    pub const RD: u16 = 0x0100;      // Recursion Desired
    pub const RA: u16 = 0x0080;      // Recursion Available
    pub const AD: u16 = 0x0020;      // Authenticated Data
    pub const CD: u16 = 0x0010;      // Checking Disabled
}

/// DNSSEC algorithm constants
pub mod dnssec_algorithms {
    pub const RSAMD5: u8 = 1;
    pub const DH: u8 = 2;
    pub const DSA: u8 = 3;
    pub const RSASHA1: u8 = 5;
    pub const DSA_NSEC3_SHA1: u8 = 6;
    pub const RSASHA1_NSEC3_SHA1: u8 = 7;
    pub const RSASHA256: u8 = 8;
    pub const RSASHA512: u8 = 10;
    pub const ECC_GOST: u8 = 12;
    pub const ECDSAP256SHA256: u8 = 13;
    pub const ECDSAP384SHA384: u8 = 14;
    pub const ED25519: u8 = 15;
    pub const ED448: u8 = 16;
}

/// DNSSEC digest type constants
pub mod digest_types {
    pub const SHA1: u8 = 1;
    pub const SHA256: u8 = 2;
    pub const GOST_R_34_11_94: u8 = 3;
    pub const SHA384: u8 = 4;
}

/// TLSA certificate usage constants
pub mod tlsa_usage {
    pub const CA_CONSTRAINT: u8 = 0;
    pub const SERVICE_CERTIFICATE_CONSTRAINT: u8 = 1;
    pub const TRUST_ANCHOR_ASSERTION: u8 = 2;
    pub const DOMAIN_ISSUED_CERTIFICATE: u8 = 3;
}

/// TLSA selector constants
pub mod tlsa_selector {
    pub const FULL_CERTIFICATE: u8 = 0;
    pub const SUBJECT_PUBLIC_KEY_INFO: u8 = 1;
}

/// TLSA matching type constants
pub mod tlsa_matching {
    pub const EXACT_MATCH: u8 = 0;
    pub const SHA256_HASH: u8 = 1;
    pub const SHA512_HASH: u8 = 2;
}

/// CAA property tags
pub mod caa_tags {
    pub const ISSUE: &str = "issue";
    pub const ISSUEWILD: &str = "issuewild";
    pub const IODEF: &str = "iodef";
}

/// SVCB/HTTPS service parameter keys
pub mod svc_param_keys {
    pub const MANDATORY: u16 = 0;
    pub const ALPN: u16 = 1;
    pub const NO_DEFAULT_ALPN: u16 = 2;
    pub const PORT: u16 = 3;
    pub const IPV4HINT: u16 = 4;
    pub const ECH: u16 = 5;
    pub const IPV6HINT: u16 = 6;
}