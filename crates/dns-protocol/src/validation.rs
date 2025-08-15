//! DNS packet validation with comprehensive bounds checking
//!
//! This module provides security-focused validation for DNS packets to prevent
//! buffer overflows, DoS attacks, and other security vulnerabilities.

use crate::records::*;
use dns_core::{DnsError, DnsResult, RecordType, DnsClass};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// DNS packet validator with configurable security limits
pub struct DnsPacketValidator {
    /// Maximum packet size to prevent DoS attacks
    max_packet_size: usize,
    /// Maximum domain name length (RFC 1035: 253 bytes)
    max_name_length: usize,
    /// Maximum label length (RFC 1035: 63 bytes)
    max_label_length: usize,
    /// Maximum number of compression pointers to follow
    max_compression_depth: usize,
    /// Maximum number of records per section
    max_records_per_section: usize,
    /// Maximum RDATA length
    max_rdata_length: usize,
    /// Maximum TXT record string length
    max_txt_string_length: usize,
}

impl DnsPacketValidator {
    /// Create a new validator with default security limits
    pub fn new() -> Self {
        Self {
            max_packet_size: 65535,
            max_name_length: 253,
            max_label_length: 63,
            max_compression_depth: 16,
            max_records_per_section: 1000,
            max_rdata_length: 65535,
            max_txt_string_length: 255,
        }
    }

    /// Create a validator with custom limits
    pub fn with_limits(
        max_packet_size: usize,
        max_name_length: usize,
        max_label_length: usize,
        max_compression_depth: usize,
        max_records_per_section: usize,
        max_rdata_length: usize,
        max_txt_string_length: usize,
    ) -> Self {
        Self {
            max_packet_size,
            max_name_length,
            max_label_length,
            max_compression_depth,
            max_records_per_section,
            max_rdata_length,
            max_txt_string_length,
        }
    }

    /// Validate complete DNS packet structure and content
    pub fn validate_packet(&self, packet: &ParsedDnsPacket) -> DnsResult<()> {
        // Validate packet size
        if packet.raw_data.len() > self.max_packet_size {
            return Err(DnsError::PacketTooLarge {
                size: packet.raw_data.len(),
                max_size: self.max_packet_size,
            });
        }

        // Validate header
        self.validate_header(&packet.header)?;

        // Validate record counts
        self.validate_record_counts(&packet.header)?;

        // Validate questions
        for question in &packet.questions {
            self.validate_question(question)?;
        }

        // Validate answer records
        for record in &packet.answers {
            self.validate_record(record)?;
        }

        // Validate authority records
        for record in &packet.authority {
            self.validate_record(record)?;
        }

        // Validate additional records
        for record in &packet.additional {
            self.validate_record(record)?;
        }

        Ok(())
    }

    /// Validate DNS header fields
    pub fn validate_header(&self, header: &DnsHeader) -> DnsResult<()> {
        // Validate opcode (0-5 are defined)
        let opcode = header.opcode();
        if opcode > 5 {
            return Err(DnsError::invalid_packet(
                format!("Invalid opcode: {}", opcode)
            ));
        }

        // Validate response code (0-10 are defined in basic DNS)
        let rcode = header.response_code();
        if rcode > 10 {
            return Err(DnsError::invalid_packet(
                format!("Invalid response code: {}", rcode)
            ));
        }

        // Validate reserved bits are zero
        if (header.flags & 0x0040) != 0 {
            return Err(DnsError::invalid_packet("Reserved bit Z must be zero"));
        }

        Ok(())
    }

    /// Validate record counts to prevent DoS attacks
    pub fn validate_record_counts(&self, header: &DnsHeader) -> DnsResult<()> {
        // Check individual section limits
        if header.qdcount as usize > self.max_records_per_section {
            return Err(DnsError::invalid_packet(
                format!("Too many questions: {}", header.qdcount)
            ));
        }

        if header.ancount as usize > self.max_records_per_section {
            return Err(DnsError::invalid_packet(
                format!("Too many answers: {}", header.ancount)
            ));
        }

        if header.nscount as usize > self.max_records_per_section {
            return Err(DnsError::invalid_packet(
                format!("Too many authority records: {}", header.nscount)
            ));
        }

        if header.arcount as usize > self.max_records_per_section {
            return Err(DnsError::invalid_packet(
                format!("Too many additional records: {}", header.arcount)
            ));
        }

        // Check total record count
        let total_records = header.qdcount as u32 + 
                           header.ancount as u32 + 
                           header.nscount as u32 + 
                           header.arcount as u32;

        if total_records > (self.max_records_per_section * 4) as u32 {
            return Err(DnsError::invalid_packet(
                format!("Too many total records: {}", total_records)
            ));
        }

        Ok(())
    }

    /// Validate DNS question
    pub fn validate_question(&self, question: &dns_core::DnsQuestion) -> DnsResult<()> {
        // Validate domain name
        self.validate_domain_name(&question.name)?;

        // Validate record type is known
        RecordType::from_u16(question.record_type.to_u16())
            .ok_or_else(|| DnsError::UnsupportedRecordType { 
                record_type: question.record_type.to_u16() 
            })?;

        // Validate class is known
        DnsClass::from_u16(question.class.to_u16())
            .ok_or_else(|| DnsError::invalid_packet(
                format!("Invalid DNS class: {}", question.class.to_u16())
            ))?;

        Ok(())
    }

    /// Validate DNS resource record
    pub fn validate_record(&self, record: &ParsedDnsRecord) -> DnsResult<()> {
        // Validate domain name
        self.validate_domain_name(&record.name)?;

        // Validate record type is known
        RecordType::from_u16(record.record_type.to_u16())
            .ok_or_else(|| DnsError::UnsupportedRecordType { 
                record_type: record.record_type.to_u16() 
            })?;

        // Validate class is known
        DnsClass::from_u16(record.class.to_u16())
            .ok_or_else(|| DnsError::invalid_packet(
                format!("Invalid DNS class: {}", record.class.to_u16())
            ))?;

        // Validate TTL is reasonable
        if record.ttl > dns_core::types::MAX_TTL {
            return Err(DnsError::invalid_packet(
                format!("TTL too large: {}", record.ttl)
            ));
        }

        // Validate RDATA length
        if record.raw_rdata.len() > self.max_rdata_length {
            return Err(DnsError::invalid_packet(
                format!("RDATA too large: {} bytes", record.raw_rdata.len())
            ));
        }

        // Validate record data based on type
        self.validate_record_data(&record.data, record.record_type)?;

        Ok(())
    }

    /// Validate domain name format and length
    pub fn validate_domain_name(&self, name: &str) -> DnsResult<()> {
        // Check total length
        if name.len() > self.max_name_length {
            return Err(DnsError::InvalidDnsName {
                name: format!("Name too long: {} bytes", name.len())
            });
        }

        // Empty name or root domain is valid
        if name.is_empty() || name == "." {
            return Ok(());
        }

        // Validate each label
        for label in name.split('.') {
            if label.is_empty() {
                continue; // Skip empty labels (trailing dots)
            }

            // Check label length
            if label.len() > self.max_label_length {
                return Err(DnsError::InvalidDnsName {
                    name: format!("Label too long: '{}' ({} bytes)", label, label.len())
                });
            }

            // Validate label characters
            self.validate_label(label)?;
        }

        Ok(())
    }

    /// Validate individual domain name label
    fn validate_label(&self, label: &str) -> DnsResult<()> {
        if label.is_empty() {
            return Err(DnsError::InvalidDnsName {
                name: "Empty label".to_string()
            });
        }

        // First and last characters cannot be hyphens
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DnsError::InvalidDnsName {
                name: format!("Label cannot start or end with hyphen: '{}'", label)
            });
        }

        // Validate characters (letters, digits, hyphens, underscores)
        for ch in label.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
                return Err(DnsError::InvalidDnsName {
                    name: format!("Invalid character '{}' in label '{}'", ch, label)
                });
            }
        }

        Ok(())
    }

    /// Validate record data based on record type
    pub fn validate_record_data(&self, data: &ParsedRecordData, record_type: RecordType) -> DnsResult<()> {
        match (data, record_type) {
            (ParsedRecordData::A(addr), RecordType::A) => {
                self.validate_ipv4_address(*addr)
            }
            (ParsedRecordData::AAAA(addr), RecordType::AAAA) => {
                self.validate_ipv6_address(*addr)
            }
            (ParsedRecordData::CNAME(name), RecordType::CNAME) => {
                self.validate_domain_name(name)
            }
            (ParsedRecordData::MX { priority: _, exchange }, RecordType::MX) => {
                self.validate_domain_name(exchange)
            }
            (ParsedRecordData::NS(name), RecordType::NS) => {
                self.validate_domain_name(name)
            }
            (ParsedRecordData::PTR(name), RecordType::PTR) => {
                self.validate_domain_name(name)
            }
            (ParsedRecordData::TXT(strings), RecordType::TXT) => {
                self.validate_txt_record(strings)
            }
            (ParsedRecordData::SRV { priority: _, weight: _, port, target }, RecordType::SRV) => {
                if *port == 0 {
                    return Err(DnsError::invalid_packet("SRV port cannot be zero"));
                }
                self.validate_domain_name(target)
            }
            (ParsedRecordData::SOA { mname, rname, serial: _, refresh, retry, expire, minimum }, RecordType::SOA) => {
                self.validate_domain_name(mname)?;
                self.validate_domain_name(rname)?;
                self.validate_soa_timers(*refresh, *retry, *expire, *minimum)
            }
            (ParsedRecordData::DNSKEY { flags, protocol, algorithm, public_key }, RecordType::DNSKEY) => {
                self.validate_dnskey_record(*flags, *protocol, *algorithm, public_key)
            }
            (ParsedRecordData::DS { key_tag: _, algorithm, digest_type, digest }, RecordType::DS) => {
                self.validate_ds_record(*algorithm, *digest_type, digest)
            }
            (ParsedRecordData::RRSIG { 
                type_covered, algorithm, labels: _, original_ttl: _,
                signature_expiration, signature_inception, key_tag: _,
                signer_name, signature 
            }, RecordType::RRSIG) => {
                // Validate covered type exists
                RecordType::from_u16(*type_covered)
                    .ok_or_else(|| DnsError::invalid_packet(
                        format!("Invalid RRSIG type covered: {}", type_covered)
                    ))?;
                
                // Validate time ordering
                if signature_inception >= signature_expiration {
                    return Err(DnsError::invalid_packet("RRSIG inception must be before expiration"));
                }
                
                self.validate_domain_name(signer_name)?;
                self.validate_dnssec_algorithm(*algorithm)?;
                self.validate_signature(signature)
            }
            (ParsedRecordData::NSEC { next_domain_name, type_bit_maps }, RecordType::NSEC) => {
                self.validate_domain_name(next_domain_name)?;
                self.validate_type_bit_maps(type_bit_maps)
            }
            (ParsedRecordData::NSEC3 { 
                hash_algorithm, flags: _, iterations, salt,
                next_hashed_owner_name, type_bit_maps 
            }, RecordType::NSEC3) => {
                self.validate_nsec3_record(*hash_algorithm, *iterations, salt, next_hashed_owner_name)?;
                self.validate_type_bit_maps(type_bit_maps)
            }
            (ParsedRecordData::CAA { flags: _, tag, value }, RecordType::CAA) => {
                self.validate_caa_record(tag, value)
            }
            (ParsedRecordData::TLSA { cert_usage, selector, matching_type, cert_data }, RecordType::TLSA) => {
                self.validate_tlsa_record(*cert_usage, *selector, *matching_type, cert_data)
            }
            (ParsedRecordData::HTTPS { priority: _, target, params }, RecordType::HTTPS) => {
                self.validate_domain_name(target)?;
                self.validate_svc_params(params)
            }
            (ParsedRecordData::SVCB { priority: _, target, params }, RecordType::SVCB) => {
                self.validate_domain_name(target)?;
                self.validate_svc_params(params)
            }
            (ParsedRecordData::Unknown { data }, _) => {
                // Basic validation for unknown record types
                if data.len() > self.max_rdata_length {
                    return Err(DnsError::invalid_packet(
                        format!("Unknown record data too large: {} bytes", data.len())
                    ));
                }
                Ok(())
            }
            // Type mismatch
            _ => {
                Err(DnsError::invalid_packet(
                    format!("Record data type mismatch for record type: {:?}", record_type)
                ))
            }
        }
    }

    /// Validate IPv4 address
    fn validate_ipv4_address(&self, addr: Ipv4Addr) -> DnsResult<()> {
        // Basic validation - IPv4 addresses are always valid if parsed
        // Could add additional checks for reserved ranges if needed
        let _ = addr;
        Ok(())
    }

    /// Validate IPv6 address
    fn validate_ipv6_address(&self, addr: Ipv6Addr) -> DnsResult<()> {
        // Basic validation - IPv6 addresses are always valid if parsed
        // Could add additional checks for reserved ranges if needed
        let _ = addr;
        Ok(())
    }

    /// Validate TXT record strings
    fn validate_txt_record(&self, strings: &[String]) -> DnsResult<()> {
        if strings.is_empty() {
            return Err(DnsError::invalid_packet("TXT record cannot be empty"));
        }

        for string in strings {
            if string.len() > self.max_txt_string_length {
                return Err(DnsError::invalid_packet(
                    format!("TXT string too long: {} bytes", string.len())
                ));
            }
        }

        Ok(())
    }

    /// Validate SOA record timers
    fn validate_soa_timers(&self, refresh: u32, retry: u32, expire: u32, minimum: u32) -> DnsResult<()> {
        // Basic sanity checks for SOA timers
        if retry >= refresh {
            return Err(DnsError::invalid_packet("SOA retry must be less than refresh"));
        }

        if expire <= refresh {
            return Err(DnsError::invalid_packet("SOA expire must be greater than refresh"));
        }

        if minimum > dns_core::types::MAX_TTL {
            return Err(DnsError::invalid_packet("SOA minimum TTL too large"));
        }

        Ok(())
    }

    /// Validate DNSKEY record
    fn validate_dnskey_record(&self, flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> DnsResult<()> {
        // Protocol must be 3 for DNSSEC
        if protocol != 3 {
            return Err(DnsError::invalid_packet(
                format!("DNSKEY protocol must be 3, got {}", protocol)
            ));
        }

        // Validate algorithm
        self.validate_dnssec_algorithm(algorithm)?;

        // Validate key length based on algorithm
        self.validate_public_key_length(algorithm, public_key)?;

        // Validate flags
        if (flags & 0x8000) != 0 {
            return Err(DnsError::invalid_packet("DNSKEY reserved flag bit must be zero"));
        }

        Ok(())
    }

    /// Validate DS record
    fn validate_ds_record(&self, algorithm: u8, digest_type: u8, digest: &[u8]) -> DnsResult<()> {
        // Validate algorithm
        self.validate_dnssec_algorithm(algorithm)?;

        // Validate digest type and length
        match digest_type {
            1 => { // SHA-1
                if digest.len() != 20 {
                    return Err(DnsError::invalid_packet("DS SHA-1 digest must be 20 bytes"));
                }
            }
            2 => { // SHA-256
                if digest.len() != 32 {
                    return Err(DnsError::invalid_packet("DS SHA-256 digest must be 32 bytes"));
                }
            }
            4 => { // SHA-384
                if digest.len() != 48 {
                    return Err(DnsError::invalid_packet("DS SHA-384 digest must be 48 bytes"));
                }
            }
            _ => {
                return Err(DnsError::invalid_packet(
                    format!("Unknown DS digest type: {}", digest_type)
                ));
            }
        }

        Ok(())
    }

    /// Validate DNSSEC algorithm
    fn validate_dnssec_algorithm(&self, algorithm: u8) -> DnsResult<()> {
        match algorithm {
            1 | 3 | 5 | 6 | 7 | 8 | 10 | 12 | 13 | 14 | 15 | 16 => Ok(()),
            _ => Err(DnsError::invalid_packet(
                format!("Unknown DNSSEC algorithm: {}", algorithm)
            ))
        }
    }

    /// Validate public key length for algorithm
    fn validate_public_key_length(&self, algorithm: u8, public_key: &[u8]) -> DnsResult<()> {
        match algorithm {
            5 | 7 => { // RSA/SHA-1, RSA/SHA-1-NSEC3
                if public_key.len() < 64 {
                    return Err(DnsError::invalid_packet("RSA public key too short"));
                }
            }
            8 => { // RSA/SHA-256
                if public_key.len() < 64 {
                    return Err(DnsError::invalid_packet("RSA/SHA-256 public key too short"));
                }
            }
            10 => { // RSA/SHA-512
                if public_key.len() < 64 {
                    return Err(DnsError::invalid_packet("RSA/SHA-512 public key too short"));
                }
            }
            13 => { // ECDSA P-256/SHA-256
                if public_key.len() != 64 {
                    return Err(DnsError::invalid_packet("ECDSA P-256 public key must be 64 bytes"));
                }
            }
            14 => { // ECDSA P-384/SHA-384
                if public_key.len() != 96 {
                    return Err(DnsError::invalid_packet("ECDSA P-384 public key must be 96 bytes"));
                }
            }
            15 => { // Ed25519
                if public_key.len() != 32 {
                    return Err(DnsError::invalid_packet("Ed25519 public key must be 32 bytes"));
                }
            }
            16 => { // Ed448
                if public_key.len() != 57 {
                    return Err(DnsError::invalid_packet("Ed448 public key must be 57 bytes"));
                }
            }
            _ => {
                // For unknown algorithms, just check it's not empty
                if public_key.is_empty() {
                    return Err(DnsError::invalid_packet("Public key cannot be empty"));
                }
            }
        }

        Ok(())
    }

    /// Validate signature data
    fn validate_signature(&self, signature: &[u8]) -> DnsResult<()> {
        if signature.is_empty() {
            return Err(DnsError::invalid_packet("RRSIG signature cannot be empty"));
        }

        if signature.len() > 1024 {
            return Err(DnsError::invalid_packet("RRSIG signature too large"));
        }

        Ok(())
    }

    /// Validate type bit maps for NSEC/NSEC3
    fn validate_type_bit_maps(&self, type_bit_maps: &[u8]) -> DnsResult<()> {
        if type_bit_maps.is_empty() {
            return Err(DnsError::invalid_packet("Type bit maps cannot be empty"));
        }

        // Basic validation - should be properly formatted bit maps
        // Full validation would require parsing the bit map format
        Ok(())
    }

    /// Validate NSEC3 record
    fn validate_nsec3_record(&self, hash_algorithm: u8, iterations: u16, salt: &[u8], next_hash: &[u8]) -> DnsResult<()> {
        // Validate hash algorithm (1 = SHA-1)
        if hash_algorithm != 1 {
            return Err(DnsError::invalid_packet(
                format!("Unknown NSEC3 hash algorithm: {}", hash_algorithm)
            ));
        }

        // Validate iterations (should be reasonable to prevent DoS)
        if iterations > 2500 {
            return Err(DnsError::invalid_packet(
                format!("NSEC3 iterations too high: {}", iterations)
            ));
        }

        // Validate salt length
        if salt.len() > 255 {
            return Err(DnsError::invalid_packet("NSEC3 salt too long"));
        }

        // Validate next hash length (SHA-1 = 20 bytes)
        if next_hash.len() != 20 {
            return Err(DnsError::invalid_packet("NSEC3 next hash must be 20 bytes"));
        }

        Ok(())
    }

    /// Validate CAA record
    fn validate_caa_record(&self, tag: &str, value: &[u8]) -> DnsResult<()> {
        // Validate tag
        if tag.is_empty() {
            return Err(DnsError::invalid_packet("CAA tag cannot be empty"));
        }

        if tag.len() > 255 {
            return Err(DnsError::invalid_packet("CAA tag too long"));
        }

        // Validate tag characters (ASCII letters and digits)
        for ch in tag.chars() {
            if !ch.is_ascii_alphanumeric() {
                return Err(DnsError::invalid_packet(
                    format!("Invalid character '{}' in CAA tag", ch)
                ));
            }
        }

        // Validate value length
        if value.len() > 65535 {
            return Err(DnsError::invalid_packet("CAA value too long"));
        }

        Ok(())
    }

    /// Validate TLSA record
    fn validate_tlsa_record(&self, cert_usage: u8, selector: u8, matching_type: u8, cert_data: &[u8]) -> DnsResult<()> {
        // Validate cert usage (0-3 are defined)
        if cert_usage > 3 {
            return Err(DnsError::invalid_packet(
                format!("Invalid TLSA cert usage: {}", cert_usage)
            ));
        }

        // Validate selector (0-1 are defined)
        if selector > 1 {
            return Err(DnsError::invalid_packet(
                format!("Invalid TLSA selector: {}", selector)
            ));
        }

        // Validate matching type (0-2 are defined)
        if matching_type > 2 {
            return Err(DnsError::invalid_packet(
                format!("Invalid TLSA matching type: {}", matching_type)
            ));
        }

        // Validate cert data length based on matching type
        match matching_type {
            0 => {
                // Full certificate/key - no specific length requirement
                if cert_data.is_empty() {
                    return Err(DnsError::invalid_packet("TLSA cert data cannot be empty"));
                }
            }
            1 => {
                // SHA-256 hash
                if cert_data.len() != 32 {
                    return Err(DnsError::invalid_packet("TLSA SHA-256 hash must be 32 bytes"));
                }
            }
            2 => {
                // SHA-512 hash
                if cert_data.len() != 64 {
                    return Err(DnsError::invalid_packet("TLSA SHA-512 hash must be 64 bytes"));
                }
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    /// Validate service parameters for SVCB/HTTPS
    fn validate_svc_params(&self, params: &[(u16, bytes::Bytes)]) -> DnsResult<()> {
        for (key, value) in params {
            // Validate known parameter keys
            match *key {
                0 => { // mandatory
                    if value.len() % 2 != 0 {
                        return Err(DnsError::invalid_packet("SVCB mandatory param must have even length"));
                    }
                }
                1 => { // alpn
                    if value.is_empty() {
                        return Err(DnsError::invalid_packet("SVCB alpn param cannot be empty"));
                    }
                }
                3 => { // port
                    if value.len() != 2 {
                        return Err(DnsError::invalid_packet("SVCB port param must be 2 bytes"));
                    }
                }
                4 => { // ipv4hint
                    if value.len() % 4 != 0 {
                        return Err(DnsError::invalid_packet("SVCB ipv4hint param length must be multiple of 4"));
                    }
                }
                6 => { // ipv6hint
                    if value.len() % 16 != 0 {
                        return Err(DnsError::invalid_packet("SVCB ipv6hint param length must be multiple of 16"));
                    }
                }
                _ => {
                    // Unknown parameter - basic validation
                    if value.len() > 65535 {
                        return Err(DnsError::invalid_packet("SVCB param value too long"));
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for DnsPacketValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_core::{RecordType, DnsClass, DnsQuestion};
    use std::net::Ipv4Addr;

    #[test]
    fn test_validate_domain_name() {
        let validator = DnsPacketValidator::new();

        // Valid names
        assert!(validator.validate_domain_name("example.com").is_ok());
        assert!(validator.validate_domain_name("sub.example.com").is_ok());
        assert!(validator.validate_domain_name("a.b.c.d.e.f.g.h").is_ok());
        assert!(validator.validate_domain_name("").is_ok()); // Root
        assert!(validator.validate_domain_name(".").is_ok()); // Root

        // Invalid names
        assert!(validator.validate_domain_name(&"a".repeat(254)).is_err()); // Too long
        assert!(validator.validate_domain_name(&format!("{}.com", "a".repeat(64))).is_err()); // Label too long
        assert!(validator.validate_domain_name("-example.com").is_err()); // Starts with hyphen
        assert!(validator.validate_domain_name("example-.com").is_err()); // Ends with hyphen
    }

    #[test]
    fn test_validate_record_data() {
        let validator = DnsPacketValidator::new();

        // Valid A record
        let a_data = ParsedRecordData::A(Ipv4Addr::new(192, 0, 2, 1));
        assert!(validator.validate_record_data(&a_data, RecordType::A).is_ok());

        // Type mismatch
        assert!(validator.validate_record_data(&a_data, RecordType::AAAA).is_err());

        // Valid TXT record
        let txt_data = ParsedRecordData::TXT(vec!["hello".to_string(), "world".to_string()]);
        assert!(validator.validate_record_data(&txt_data, RecordType::TXT).is_ok());

        // Empty TXT record (invalid)
        let empty_txt = ParsedRecordData::TXT(vec![]);
        assert!(validator.validate_record_data(&empty_txt, RecordType::TXT).is_err());
    }

    #[test]
    fn test_validate_header() {
        let validator = DnsPacketValidator::new();

        // Valid header
        let header = DnsHeader {
            id: 0x1234,
            flags: 0x0100, // Standard query with RD bit
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        assert!(validator.validate_header(&header).is_ok());

        // Invalid opcode
        let bad_header = DnsHeader {
            id: 0x1234,
            flags: 0x7800, // Opcode 15 (invalid)
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        assert!(validator.validate_header(&bad_header).is_err());
    }
}