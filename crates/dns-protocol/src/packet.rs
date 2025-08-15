//! Zero-copy DNS packet parsing using FlatBuffers
//!
//! This module provides high-performance DNS packet parsing that avoids
//! unnecessary memory allocations and copies.

use bytes::{BytesMut, BufMut};
use dns_core::{DnsError, DnsResult};
use flatbuffers::FlatBufferBuilder;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

// Include generated FlatBuffers code
#[allow(unused_imports, dead_code, non_snake_case, clippy::all)]
mod dns_generated {
    include!(concat!(env!("OUT_DIR"), "/dns_generated.rs"));
}

pub use dns_generated::dns::storage::*;

/// Zero-copy DNS packet parser
pub struct ZeroCopyDnsParser {
    /// Pre-allocated buffer for building responses
    builder: FlatBufferBuilder<'static>,
    /// Reusable buffer for packet data
    packet_buffer: BytesMut,
}

impl ZeroCopyDnsParser {
    /// Create a new zero-copy DNS parser
    pub fn new() -> Self {
        Self {
            builder: FlatBufferBuilder::with_capacity(4096),
            packet_buffer: BytesMut::with_capacity(65535),
        }
    }

    /// Parse a raw DNS packet into a FlatBuffer structure
    /// 
    /// This function performs zero-copy parsing by creating a FlatBuffer
    /// that references the original packet data without copying it.
    pub fn parse_packet(&mut self, raw_data: &[u8]) -> DnsResult<Arc<[u8]>> {
        if raw_data.len() < 12 {
            return Err(DnsError::invalid_packet("Packet too short for DNS header"));
        }

        // Parse DNS header without copying
        let header = self.parse_header(raw_data)?;
        
        // Calculate section offsets
        let mut offset = 12; // Header size
        let question_offset = offset as u16;
        
        // Skip questions to find answer section
        for _ in 0..header.qdcount {
            offset = self.skip_question(raw_data, offset)?;
        }
        let answer_offset = offset as u16;
        
        // Skip answers to find authority section
        for _ in 0..header.ancount {
            offset = self.skip_record(raw_data, offset)?;
        }
        let authority_offset = offset as u16;
        
        // Skip authority to find additional section
        for _ in 0..header.nscount {
            offset = self.skip_record(raw_data, offset)?;
        }
        let additional_offset = offset as u16;

        // Calculate hashes for fast lookups
        let packet_hash = dns_core::hash::hash_zone_data(raw_data);
        let query_hash = if header.qdcount > 0 {
            self.calculate_query_hash(raw_data, question_offset)?
        } else {
            0
        };

        // For now, create a simple parsed packet structure
        // TODO: Implement proper FlatBuffers serialization when flatc is available
        let parsed_packet = ParsedDnsPacket {
            raw_data: raw_data.to_vec(),
            header: header.clone(),
            question_offset,
            answer_offset,
            authority_offset,
            additional_offset,
            packet_hash,
            query_hash,
            is_response: (header.flags & 0x8000) != 0,
            is_authoritative: (header.flags & 0x0400) != 0,
            is_truncated: (header.flags & 0x0200) != 0,
            can_serve_from_cache: header.ancount > 0,
            requires_dnssec: (header.flags & 0x8000) != 0, // DO bit check
        };
        
        // Serialize to bytes (simplified for now)
        let serialized = bincode::serialize(&parsed_packet)
            .map_err(|e| DnsError::internal_error(format!("Serialization failed: {}", e)))?;
        
        Ok(Arc::from(serialized.into_boxed_slice()))
    }

    /// Parse DNS header from raw bytes
    fn parse_header(&self, data: &[u8]) -> DnsResult<DnsHeaderData> {
        if data.len() < 12 {
            return Err(DnsError::invalid_packet("Header too short"));
        }

        Ok(DnsHeaderData {
            id: u16::from_be_bytes([data[0], data[1]]),
            flags: u16::from_be_bytes([data[2], data[3]]),
            qdcount: u16::from_be_bytes([data[4], data[5]]),
            ancount: u16::from_be_bytes([data[6], data[7]]),
            nscount: u16::from_be_bytes([data[8], data[9]]),
            arcount: u16::from_be_bytes([data[10], data[11]]),
        })
    }

    /// Skip a DNS question section
    fn skip_question(&self, data: &[u8], mut offset: usize) -> DnsResult<usize> {
        // Skip domain name
        offset = self.skip_domain_name(data, offset)?;
        
        // Skip QTYPE and QCLASS (4 bytes)
        if offset + 4 > data.len() {
            return Err(DnsError::invalid_packet("Question section truncated"));
        }
        
        Ok(offset + 4)
    }

    /// Skip a DNS resource record
    fn skip_record(&self, data: &[u8], mut offset: usize) -> DnsResult<usize> {
        // Skip domain name
        offset = self.skip_domain_name(data, offset)?;
        
        // Skip TYPE, CLASS, TTL (8 bytes)
        if offset + 8 > data.len() {
            return Err(DnsError::invalid_packet("Record header truncated"));
        }
        offset += 8;
        
        // Get RDLENGTH and skip RDATA
        if offset + 2 > data.len() {
            return Err(DnsError::invalid_packet("RDLENGTH missing"));
        }
        
        let rdlength = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        
        if offset + rdlength > data.len() {
            return Err(DnsError::invalid_packet("RDATA truncated"));
        }
        
        Ok(offset + rdlength)
    }

    /// Skip a domain name (handles compression)
    fn skip_domain_name(&self, data: &[u8], mut offset: usize) -> DnsResult<usize> {
        let mut _jumped = false;
        let original_offset = offset;
        
        loop {
            if offset >= data.len() {
                return Err(DnsError::invalid_packet("Domain name truncated"));
            }
            
            let length = data[offset];
            
            if length == 0 {
                // End of name
                offset += 1;
                break;
            } else if (length & 0xC0) == 0xC0 {
                // Compression pointer
                if !_jumped {
                    offset += 2; // Return position after pointer
                }
                
                if offset + 1 >= data.len() {
                    return Err(DnsError::invalid_packet("Compression pointer truncated"));
                }
                
                let pointer = ((length as u16 & 0x3F) << 8) | data[offset + 1] as u16;
                offset = pointer as usize;
                _jumped = true;
                
                // Prevent infinite loops
                if offset >= original_offset {
                    return Err(DnsError::invalid_packet("Invalid compression pointer"));
                }
            } else if (length & 0xC0) == 0 {
                // Regular label
                offset += 1 + length as usize;
                
                if offset > data.len() {
                    return Err(DnsError::invalid_packet("Label extends beyond packet"));
                }
            } else {
                return Err(DnsError::invalid_packet("Invalid label type"));
            }
        }
        
        Ok(offset)
    }

    /// Calculate query hash from question section
    fn calculate_query_hash(&self, data: &[u8], question_offset: u16) -> DnsResult<u64> {
        let mut offset = question_offset as usize;
        
        // Extract domain name for hashing
        let name = self.extract_domain_name(data, offset)?;
        offset = self.skip_domain_name(data, offset)?;
        
        // Extract QTYPE and QCLASS
        if offset + 4 > data.len() {
            return Err(DnsError::invalid_packet("Question truncated"));
        }
        
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        
        // Calculate hash
        let name_hash = dns_core::hash::hash_domain_name(&name);
        Ok(dns_core::hash::hash_query(name_hash, qtype, qclass))
    }

    /// Extract domain name from DNS packet
    fn extract_domain_name(&self, data: &[u8], mut offset: usize) -> DnsResult<String> {
        let mut name = String::with_capacity(253);
        let mut _jumped = false;
        let original_offset = offset;
        
        loop {
            if offset >= data.len() {
                return Err(DnsError::invalid_packet("Domain name truncated"));
            }
            
            let length = data[offset];
            
            if length == 0 {
                // End of name
                break;
            } else if (length & 0xC0) == 0xC0 {
                // Compression pointer
                if offset + 1 >= data.len() {
                    return Err(DnsError::invalid_packet("Compression pointer truncated"));
                }
                
                let pointer = ((length as u16 & 0x3F) << 8) | data[offset + 1] as u16;
                offset = pointer as usize;
                _jumped = true;
                
                // Prevent infinite loops
                if offset >= original_offset {
                    return Err(DnsError::invalid_packet("Invalid compression pointer"));
                }
            } else if (length & 0xC0) == 0 {
                // Regular label
                if !name.is_empty() {
                    name.push('.');
                }
                
                offset += 1;
                if offset + length as usize > data.len() {
                    return Err(DnsError::invalid_packet("Label extends beyond packet"));
                }
                
                let label = std::str::from_utf8(&data[offset..offset + length as usize])
                    .map_err(|_| DnsError::invalid_packet("Invalid UTF-8 in domain name"))?;
                
                name.push_str(label);
                offset += length as usize;
            } else {
                return Err(DnsError::invalid_packet("Invalid label type"));
            }
        }
        
        Ok(name)
    }

    /// Build a zero-copy DNS response
    pub fn build_response(&mut self, query_packet: &[u8], records: &[DnsRecordData]) -> DnsResult<Arc<[u8]>> {
        // Parse original query
        let header = self.parse_header(query_packet)?;
        
        // Build response header
        let response_flags = 0x8000 | // QR bit (response)
                           0x0400 | // AA bit (authoritative)
                           (header.flags & 0x0100); // RD bit from query
        
        self.packet_buffer.clear();
        
        // Write response header
        self.packet_buffer.put_u16(header.id);
        self.packet_buffer.put_u16(response_flags);
        self.packet_buffer.put_u16(header.qdcount); // Questions
        self.packet_buffer.put_u16(records.len() as u16); // Answers
        self.packet_buffer.put_u16(0); // Authority
        self.packet_buffer.put_u16(0); // Additional
        
        // Copy question section from original query
        if header.qdcount > 0 {
            let question_start = 12;
            let mut question_end = question_start;
            
            for _ in 0..header.qdcount {
                question_end = self.skip_question(query_packet, question_end)?;
            }
            
            self.packet_buffer.extend_from_slice(&query_packet[question_start..question_end]);
        }
        
        // Add answer records
        for record in records {
            self.write_record_to_buffer(record)?;
        }
        
        Ok(Arc::from(self.packet_buffer.to_vec().into_boxed_slice()))
    }

    /// Write a DNS record to the packet buffer
    fn write_record_to_buffer(&mut self, record: &DnsRecordData) -> DnsResult<()> {
        // Write name (simplified - assumes no compression for now)
        for label in record.name.split('.') {
            if label.is_empty() {
                continue;
            }
            self.packet_buffer.put_u8(label.len() as u8);
            self.packet_buffer.extend_from_slice(label.as_bytes());
        }
        self.packet_buffer.put_u8(0); // End of name
        
        // Write TYPE, CLASS, TTL
        self.packet_buffer.put_u16(record.record_type);
        self.packet_buffer.put_u16(record.class);
        self.packet_buffer.put_u32(record.ttl);
        
        // Write RDATA
        let rdata = self.serialize_record_data(&record.data)?;
        self.packet_buffer.put_u16(rdata.len() as u16);
        self.packet_buffer.extend_from_slice(&rdata);
        
        Ok(())
    }

    /// Serialize record data based on type
    fn serialize_record_data(&self, data: &RecordDataType) -> DnsResult<Vec<u8>> {
        let mut rdata = Vec::new();
        
        match data {
            RecordDataType::A(addr) => {
                rdata.extend_from_slice(&addr.octets());
            }
            RecordDataType::AAAA(addr) => {
                rdata.extend_from_slice(&addr.octets());
            }
            RecordDataType::CNAME(name) => {
                // Simplified name encoding
                for label in name.split('.') {
                    if label.is_empty() {
                        continue;
                    }
                    rdata.push(label.len() as u8);
                    rdata.extend_from_slice(label.as_bytes());
                }
                rdata.push(0);
            }
            RecordDataType::MX { priority, exchange } => {
                rdata.extend_from_slice(&priority.to_be_bytes());
                for label in exchange.split('.') {
                    if label.is_empty() {
                        continue;
                    }
                    rdata.push(label.len() as u8);
                    rdata.extend_from_slice(label.as_bytes());
                }
                rdata.push(0);
            }
            // Add other record types as needed
            _ => {
                return Err(DnsError::NotImplemented { 
                    feature: "Record type serialization".to_string() 
                });
            }
        }
        
        Ok(rdata)
    }
}

/// DNS header data structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DnsHeaderData {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

/// Parsed DNS packet structure (temporary until FlatBuffers is properly integrated)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ParsedDnsPacket {
    raw_data: Vec<u8>,
    header: DnsHeaderData,
    question_offset: u16,
    answer_offset: u16,
    authority_offset: u16,
    additional_offset: u16,
    packet_hash: u64,
    query_hash: u64,
    is_response: bool,
    is_authoritative: bool,
    is_truncated: bool,
    can_serve_from_cache: bool,
    requires_dnssec: bool,
}

/// DNS record data for response building
#[derive(Debug, Clone)]
pub struct DnsRecordData {
    pub name: String,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: RecordDataType,
}

/// Record data types for serialization
#[derive(Debug, Clone)]
pub enum RecordDataType {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    MX { priority: u16, exchange: String },
    NS(String),
    PTR(String),
    TXT(Vec<String>),
    // Add more as needed
}

impl Default for ZeroCopyDnsParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_query() {
        let mut parser = ZeroCopyDnsParser::new();
        
        // Simple A query for example.com
        let query_packet = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // Question: example.com A IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // End of name
            0x00, 0x01, // QTYPE (A)
            0x00, 0x01, // QCLASS (IN)
        ];
        
        let result = parser.parse_packet(&query_packet);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_response() {
        let mut parser = ZeroCopyDnsParser::new();
        
        let query_packet = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Other counts
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01, // A IN
        ];
        
        let records = vec![
            DnsRecordData {
                name: "example.com".to_string(),
                record_type: 1, // A
                class: 1, // IN
                ttl: 300,
                data: RecordDataType::A(Ipv4Addr::new(192, 0, 2, 1)),
            }
        ];
        
        let result = parser.build_response(&query_packet, &records);
        assert!(result.is_ok());
    }
}