//! DNS response builder using FlatBuffers for zero-copy responses
//!
//! This module provides high-performance DNS response building that minimizes
//! memory allocations and enables zero-copy operations.

use crate::records::*;
use dns_core::{DnsError, DnsResult, RecordType, DnsClass, DnsRecord, RecordData};
use bytes::{BytesMut, BufMut, Bytes};
use std::collections::HashMap;
use std::sync::Arc;

/// Zero-copy DNS response builder
pub struct DnsResponseBuilder {
    /// Pre-allocated buffer for building responses
    buffer: BytesMut,
    /// Compression table for domain names
    compression_table: HashMap<String, u16>,
    /// Maximum response size (for UDP: 512, for TCP: 65535)
    max_size: usize,
    /// Whether to use compression
    use_compression: bool,
}

impl DnsResponseBuilder {
    /// Create a new response builder
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(4096),
            compression_table: HashMap::new(),
            max_size: 512, // Default UDP size
            use_compression: true,
        }
    }

    /// Create a response builder with custom limits
    pub fn with_limits(max_size: usize, use_compression: bool) -> Self {
        Self {
            buffer: BytesMut::with_capacity(max_size.min(65535)),
            compression_table: HashMap::new(),
            max_size,
            use_compression,
        }
    }

    /// Build a DNS response from a query and answer records
    pub fn build_response(
        &mut self,
        query_packet: &ParsedDnsPacket,
        answers: &[DnsRecord],
        authority: &[DnsRecord],
        additional: &[DnsRecord],
        response_code: u8,
    ) -> DnsResult<Arc<[u8]>> {
        self.buffer.clear();
        self.compression_table.clear();

        // Build response header
        self.write_header(
            query_packet.header.id,
            response_code,
            query_packet.questions.len() as u16,
            answers.len() as u16,
            authority.len() as u16,
            additional.len() as u16,
            query_packet.header.recursion_desired(),
        )?;

        // Copy questions from original query
        for question in &query_packet.questions {
            self.write_question(question)?;
        }

        // Write answer records
        for record in answers {
            self.write_resource_record(record)?;
        }

        // Write authority records
        for record in authority {
            self.write_resource_record(record)?;
        }

        // Write additional records
        for record in additional {
            self.write_resource_record(record)?;
        }

        // Check size limits
        if self.buffer.len() > self.max_size {
            // If response is too large, truncate and set TC bit
            return self.build_truncated_response(query_packet, response_code);
        }

        Ok(Arc::from(self.buffer.to_vec().into_boxed_slice()))
    }

    /// Build a simple error response
    pub fn build_error_response(
        &mut self,
        query_packet: &ParsedDnsPacket,
        response_code: u8,
    ) -> DnsResult<Arc<[u8]>> {
        self.buffer.clear();
        self.compression_table.clear();

        // Build error response header
        self.write_header(
            query_packet.header.id,
            response_code,
            query_packet.questions.len() as u16,
            0, // No answers
            0, // No authority
            0, // No additional
            query_packet.header.recursion_desired(),
        )?;

        // Copy questions from original query
        for question in &query_packet.questions {
            self.write_question(question)?;
        }

        Ok(Arc::from(self.buffer.to_vec().into_boxed_slice()))
    }

    /// Build a pre-built response for caching
    pub fn build_prebuilt_response(
        &mut self,
        query_id: u16,
        questions: &[dns_core::DnsQuestion],
        answers: &[DnsRecord],
        authority: &[DnsRecord],
        additional: &[DnsRecord],
        authoritative: bool,
        recursion_desired: bool,
    ) -> DnsResult<Arc<[u8]>> {
        self.buffer.clear();
        self.compression_table.clear();

        let mut flags = 0x8000; // QR bit (response)
        if authoritative {
            flags |= 0x0400; // AA bit
        }
        if recursion_desired {
            flags |= 0x0100; // RD bit
        }
        flags |= 0x0080; // RA bit (recursion available)

        // Write header
        self.buffer.put_u16(query_id);
        self.buffer.put_u16(flags);
        self.buffer.put_u16(questions.len() as u16);
        self.buffer.put_u16(answers.len() as u16);
        self.buffer.put_u16(authority.len() as u16);
        self.buffer.put_u16(additional.len() as u16);

        // Write questions
        for question in questions {
            self.write_question(question)?;
        }

        // Write records
        for record in answers {
            self.write_resource_record(record)?;
        }
        for record in authority {
            self.write_resource_record(record)?;
        }
        for record in additional {
            self.write_resource_record(record)?;
        }

        Ok(Arc::from(self.buffer.to_vec().into_boxed_slice()))
    }

    /// Update response ID in a pre-built response (zero-copy operation)
    pub fn update_response_id(response_data: &[u8], new_id: u16) -> Arc<[u8]> {
        if response_data.len() < 2 {
            return Arc::from(response_data);
        }

        let mut updated = response_data.to_vec();
        updated[0..2].copy_from_slice(&new_id.to_be_bytes());
        Arc::from(updated.into_boxed_slice())
    }

    /// Write DNS header
    fn write_header(
        &mut self,
        id: u16,
        response_code: u8,
        qdcount: u16,
        ancount: u16,
        nscount: u16,
        arcount: u16,
        recursion_desired: bool,
    ) -> DnsResult<()> {
        let mut flags = 0x8000; // QR bit (response)
        flags |= 0x0400; // AA bit (authoritative)
        
        if recursion_desired {
            flags |= 0x0100; // RD bit
        }
        flags |= 0x0080; // RA bit (recursion available)
        flags |= response_code as u16; // RCODE

        self.buffer.put_u16(id);
        self.buffer.put_u16(flags);
        self.buffer.put_u16(qdcount);
        self.buffer.put_u16(ancount);
        self.buffer.put_u16(nscount);
        self.buffer.put_u16(arcount);

        Ok(())
    }

    /// Write a DNS question
    fn write_question(&mut self, question: &dns_core::DnsQuestion) -> DnsResult<()> {
        self.write_domain_name(&question.name)?;
        self.buffer.put_u16(question.record_type.to_u16());
        self.buffer.put_u16(question.class.to_u16());
        Ok(())
    }

    /// Write a DNS resource record
    fn write_resource_record(&mut self, record: &DnsRecord) -> DnsResult<()> {
        // Write name
        self.write_domain_name(&record.name)?;
        
        // Write TYPE, CLASS, TTL
        self.buffer.put_u16(record.record_type.to_u16());
        self.buffer.put_u16(record.class.to_u16());
        self.buffer.put_u32(record.ttl);
        
        // Serialize RDATA
        let rdata = self.serialize_record_data(&record.data)?;
        
        // Write RDLENGTH and RDATA
        self.buffer.put_u16(rdata.len() as u16);
        self.buffer.extend_from_slice(&rdata);
        
        Ok(())
    }

    /// Write a domain name with optional compression
    fn write_domain_name(&mut self, name: &str) -> DnsResult<()> {
        if name.is_empty() || name == "." {
            // Root domain
            self.buffer.put_u8(0);
            return Ok(());
        }

        // Check for compression opportunity
        if self.use_compression {
            if let Some(&offset) = self.compression_table.get(name) {
                // Use compression pointer
                let pointer = 0xC000 | offset;
                self.buffer.put_u16(pointer);
                return Ok(());
            }

            // Record this name for future compression
            if self.buffer.len() < 0x3FFF {
                self.compression_table.insert(name.to_string(), self.buffer.len() as u16);
            }
        }

        // Write labels
        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            
            if label.len() > 63 {
                return Err(DnsError::invalid_packet(
                    format!("Label too long: {} bytes", label.len())
                ));
            }
            
            self.buffer.put_u8(label.len() as u8);
            self.buffer.extend_from_slice(label.as_bytes());
        }
        
        // End of name
        self.buffer.put_u8(0);
        
        Ok(())
    }

    /// Serialize record data based on type
    fn serialize_record_data(&self, data: &RecordData) -> DnsResult<Vec<u8>> {
        let mut rdata = Vec::new();
        
        match data {
            RecordData::A(addr) => {
                rdata.extend_from_slice(&addr.octets());
            }
            RecordData::AAAA(addr) => {
                rdata.extend_from_slice(&addr.octets());
            }
            RecordData::CNAME(name) => {
                rdata.extend_from_slice(&self.encode_domain_name(name)?);
            }
            RecordData::MX { priority, exchange } => {
                rdata.extend_from_slice(&priority.to_be_bytes());
                rdata.extend_from_slice(&self.encode_domain_name(exchange)?);
            }
            RecordData::NS(name) => {
                rdata.extend_from_slice(&self.encode_domain_name(name)?);
            }
            RecordData::PTR(name) => {
                rdata.extend_from_slice(&self.encode_domain_name(name)?);
            }
            RecordData::TXT(strings) => {
                for string in strings {
                    if string.len() > 255 {
                        return Err(DnsError::invalid_packet("TXT string too long"));
                    }
                    rdata.push(string.len() as u8);
                    rdata.extend_from_slice(string.as_bytes());
                }
            }
            RecordData::SRV { priority, weight, port, target } => {
                rdata.extend_from_slice(&priority.to_be_bytes());
                rdata.extend_from_slice(&weight.to_be_bytes());
                rdata.extend_from_slice(&port.to_be_bytes());
                rdata.extend_from_slice(&self.encode_domain_name(target)?);
            }
            RecordData::SOA { mname, rname, serial, refresh, retry, expire, minimum } => {
                rdata.extend_from_slice(&self.encode_domain_name(mname)?);
                rdata.extend_from_slice(&self.encode_domain_name(rname)?);
                rdata.extend_from_slice(&serial.to_be_bytes());
                rdata.extend_from_slice(&refresh.to_be_bytes());
                rdata.extend_from_slice(&retry.to_be_bytes());
                rdata.extend_from_slice(&expire.to_be_bytes());
                rdata.extend_from_slice(&minimum.to_be_bytes());
            }
            RecordData::DNSKEY { flags, protocol, algorithm, public_key } => {
                rdata.extend_from_slice(&flags.to_be_bytes());
                rdata.push(*protocol);
                rdata.push(*algorithm);
                rdata.extend_from_slice(public_key);
            }
            RecordData::DS { key_tag, algorithm, digest_type, digest } => {
                rdata.extend_from_slice(&key_tag.to_be_bytes());
                rdata.push(*algorithm);
                rdata.push(*digest_type);
                rdata.extend_from_slice(digest);
            }
            RecordData::RRSIG { 
                type_covered, algorithm, labels, original_ttl,
                signature_expiration, signature_inception, key_tag,
                signer_name, signature 
            } => {
                rdata.extend_from_slice(&type_covered.to_be_bytes());
                rdata.push(*algorithm);
                rdata.push(*labels);
                rdata.extend_from_slice(&original_ttl.to_be_bytes());
                rdata.extend_from_slice(&signature_expiration.to_be_bytes());
                rdata.extend_from_slice(&signature_inception.to_be_bytes());
                rdata.extend_from_slice(&key_tag.to_be_bytes());
                rdata.extend_from_slice(&self.encode_domain_name(signer_name)?);
                rdata.extend_from_slice(signature);
            }
            RecordData::CAA { flags, tag, value } => {
                rdata.push(*flags);
                rdata.push(tag.len() as u8);
                rdata.extend_from_slice(tag.as_bytes());
                rdata.extend_from_slice(value);
            }
            RecordData::TLSA { cert_usage, selector, matching_type, cert_data } => {
                rdata.push(*cert_usage);
                rdata.push(*selector);
                rdata.push(*matching_type);
                rdata.extend_from_slice(cert_data);
            }
            RecordData::HTTPS { priority, target, params } => {
                rdata.extend_from_slice(&priority.to_be_bytes());
                rdata.extend_from_slice(&self.encode_domain_name(target)?);
                for (key, value) in params {
                    rdata.extend_from_slice(&key.to_be_bytes());
                    rdata.extend_from_slice(&(value.len() as u16).to_be_bytes());
                    rdata.extend_from_slice(value);
                }
            }
            RecordData::SVCB { priority, target, params } => {
                rdata.extend_from_slice(&priority.to_be_bytes());
                rdata.extend_from_slice(&self.encode_domain_name(target)?);
                for (key, value) in params {
                    rdata.extend_from_slice(&key.to_be_bytes());
                    rdata.extend_from_slice(&(value.len() as u16).to_be_bytes());
                    rdata.extend_from_slice(value);
                }
            }
            RecordData::NSEC3PARAM { hash_algorithm, flags, iterations, salt } => {
                rdata.push(*hash_algorithm);
                rdata.push(*flags);
                rdata.extend_from_slice(&iterations.to_be_bytes());
                rdata.push(salt.len() as u8);
                rdata.extend_from_slice(salt);
            }
            RecordData::CDS { key_tag, algorithm, digest_type, digest } => {
                rdata.extend_from_slice(&key_tag.to_be_bytes());
                rdata.push(*algorithm);
                rdata.push(*digest_type);
                rdata.extend_from_slice(digest);
            }
            RecordData::CDNSKEY { flags, protocol, algorithm, public_key } => {
                rdata.extend_from_slice(&flags.to_be_bytes());
                rdata.push(*protocol);
                rdata.push(*algorithm);
                rdata.extend_from_slice(public_key);
            }
            RecordData::SMIMEA { cert_usage, selector, matching_type, cert_data } => {
                rdata.push(*cert_usage);
                rdata.push(*selector);
                rdata.push(*matching_type);
                rdata.extend_from_slice(cert_data);
            }
            RecordData::NAPTR { order, preference, flags, services, regexp, replacement } => {
                rdata.extend_from_slice(&order.to_be_bytes());
                rdata.extend_from_slice(&preference.to_be_bytes());
                rdata.push(flags.len() as u8);
                rdata.extend_from_slice(flags.as_bytes());
                rdata.push(services.len() as u8);
                rdata.extend_from_slice(services.as_bytes());
                rdata.push(regexp.len() as u8);
                rdata.extend_from_slice(regexp.as_bytes());
                rdata.extend_from_slice(&self.encode_domain_name(replacement)?);
            }
            RecordData::OPENPGPKEY { key_data } => {
                rdata.extend_from_slice(key_data);
            }
            RecordData::CSYNC { serial, flags, type_bit_maps } => {
                rdata.extend_from_slice(&serial.to_be_bytes());
                rdata.extend_from_slice(&flags.to_be_bytes());
                rdata.extend_from_slice(type_bit_maps);
            }
            RecordData::ZONEMD { serial, scheme, hash_algorithm, digest } => {
                rdata.extend_from_slice(&serial.to_be_bytes());
                rdata.push(*scheme);
                rdata.push(*hash_algorithm);
                rdata.extend_from_slice(digest);
            }
            RecordData::Unknown { data } => {
                rdata.extend_from_slice(data);
            }
        }
        
        Ok(rdata)
    }

    /// Encode domain name without compression (for RDATA)
    fn encode_domain_name(&self, name: &str) -> DnsResult<Vec<u8>> {
        let mut encoded = Vec::new();
        
        if name.is_empty() || name == "." {
            encoded.push(0);
            return Ok(encoded);
        }
        
        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            
            if label.len() > 63 {
                return Err(DnsError::invalid_packet(
                    format!("Label too long: {} bytes", label.len())
                ));
            }
            
            encoded.push(label.len() as u8);
            encoded.extend_from_slice(label.as_bytes());
        }
        
        encoded.push(0);
        Ok(encoded)
    }

    /// Build a truncated response when the full response is too large
    fn build_truncated_response(
        &mut self,
        query_packet: &ParsedDnsPacket,
        response_code: u8,
    ) -> DnsResult<Arc<[u8]>> {
        self.buffer.clear();
        self.compression_table.clear();

        // Build truncated response header with TC bit set
        let mut flags = 0x8000 | 0x0200; // QR + TC bits
        flags |= 0x0400; // AA bit (authoritative)
        if query_packet.header.recursion_desired() {
            flags |= 0x0100; // RD bit
        }
        flags |= 0x0080; // RA bit
        flags |= response_code as u16; // RCODE

        self.buffer.put_u16(query_packet.header.id);
        self.buffer.put_u16(flags);
        self.buffer.put_u16(query_packet.questions.len() as u16);
        self.buffer.put_u16(0); // No answers in truncated response
        self.buffer.put_u16(0); // No authority
        self.buffer.put_u16(0); // No additional

        // Copy questions
        for question in &query_packet.questions {
            self.write_question(question)?;
        }

        Ok(Arc::from(self.buffer.to_vec().into_boxed_slice()))
    }
}

impl Default for DnsResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Pre-built response cache entry
#[derive(Debug)]
pub struct PrebuiltResponse {
    pub query_hash: u64,
    pub response_data: Arc<[u8]>,
    pub expires_at: u64,
    pub hit_count: std::sync::atomic::AtomicU64,
    pub last_accessed: std::sync::atomic::AtomicU64,
}

impl PrebuiltResponse {
    /// Create a new pre-built response
    pub fn new(query_hash: u64, response_data: Arc<[u8]>, ttl: u32) -> Self {
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + ttl as u64;

        Self {
            query_hash,
            response_data,
            expires_at,
            hit_count: std::sync::atomic::AtomicU64::new(0),
            last_accessed: std::sync::atomic::AtomicU64::new(expires_at),
        }
    }

    /// Check if this response has expired
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expires_at
    }

    /// Get response data with updated ID
    pub fn get_response_with_id(&self, query_id: u16) -> Arc<[u8]> {
        self.hit_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.last_accessed.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );

        DnsResponseBuilder::update_response_id(&self.response_data, query_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_core::{RecordType, DnsClass, DnsQuestion, DnsRecord, RecordData};
    use std::net::Ipv4Addr;

    #[test]
    fn test_build_simple_response() {
        let mut builder = DnsResponseBuilder::new();
        
        // Create a mock query packet
        let query_packet = ParsedDnsPacket {
            header: DnsHeader {
                id: 0x1234,
                flags: 0x0100, // RD bit set
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![DnsQuestion {
                name: "example.com".to_string(),
                record_type: RecordType::A,
                class: DnsClass::IN,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
            raw_data: vec![],
            client_addr: "127.0.0.1".parse().unwrap(),
            parsed_at: 0,
        };

        let answers = vec![DnsRecord {
            name: "example.com".to_string(),
            record_type: RecordType::A,
            class: DnsClass::IN,
            ttl: 300,
            data: RecordData::A(Ipv4Addr::new(192, 0, 2, 1)),
        }];

        let result = builder.build_response(&query_packet, &answers, &[], &[], 0);
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert!(response.len() >= 12); // At least header size
    }

    #[test]
    fn test_update_response_id() {
        let original_response = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01];
        let updated = DnsResponseBuilder::update_response_id(&original_response, 0x5678);
        
        assert_eq!(updated[0], 0x56);
        assert_eq!(updated[1], 0x78);
        assert_eq!(updated[2], 0x81); // Rest should be unchanged
    }
}