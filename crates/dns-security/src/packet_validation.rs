//! DNS packet validation and bounds checking
//! 
//! Implements comprehensive validation of DNS packets to prevent:
//! - Buffer overflow attacks
//! - Malformed packet exploits
//! - Protocol violations
//! - Resource exhaustion attacks

use crate::{SecurityError, SecurityResult, current_timestamp_ms};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use serde::{Deserialize, Serialize};

/// Packet validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    /// Maximum DNS packet size
    pub max_packet_size: usize,
    /// Maximum number of questions in a packet
    pub max_questions: u16,
    /// Maximum number of answers in a packet
    pub max_answers: u16,
    /// Maximum number of authority records
    pub max_authority: u16,
    /// Maximum number of additional records
    pub max_additional: u16,
    /// Maximum domain name length
    pub max_domain_length: usize,
    /// Maximum label length in domain name
    pub max_label_length: usize,
    /// Enable strict RFC compliance checking
    pub strict_rfc_compliance: bool,
    /// Maximum compression pointer depth
    pub max_compression_depth: u8,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            max_packet_size: 4096,
            max_questions: 100,
            max_answers: 1000,
            max_authority: 100,
            max_additional: 1000,
            max_domain_length: 253,
            max_label_length: 63,
            strict_rfc_compliance: true,
            max_compression_depth: 10,
        }
    }
}

/// DNS packet header structure
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
    /// Parse DNS header from packet bytes
    pub fn parse(packet: &[u8]) -> SecurityResult<Self> {
        if packet.len() < 12 {
            return Err(SecurityError::invalid_packet("Packet too short for DNS header"));
        }

        Ok(Self {
            id: u16::from_be_bytes([packet[0], packet[1]]),
            flags: u16::from_be_bytes([packet[2], packet[3]]),
            qdcount: u16::from_be_bytes([packet[4], packet[5]]),
            ancount: u16::from_be_bytes([packet[6], packet[7]]),
            nscount: u16::from_be_bytes([packet[8], packet[9]]),
            arcount: u16::from_be_bytes([packet[10], packet[11]]),
        })
    }

    /// Check if this is a query packet
    pub fn is_query(&self) -> bool {
        (self.flags & 0x8000) == 0
    }

    /// Check if this is a response packet
    pub fn is_response(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    /// Get opcode
    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0x0F) as u8
    }

    /// Check if recursion desired
    pub fn recursion_desired(&self) -> bool {
        (self.flags & 0x0100) != 0
    }
}

/// DNS packet validator
pub struct PacketValidator {
    config: ValidationConfig,
    stats: Arc<ValidationStats>,
}

impl PacketValidator {
    pub fn new(config: ValidationConfig) -> SecurityResult<Self> {
        Ok(Self {
            config,
            stats: Arc::new(ValidationStats::new()),
        })
    }

    /// Validate a DNS query packet
    pub async fn validate_query_packet(&self, packet: &[u8]) -> SecurityResult<bool> {
        self.stats.total_validations.fetch_add(1, Ordering::Relaxed);

        // Basic size check
        if packet.len() > self.config.max_packet_size {
            self.stats.oversized_packets.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        if packet.len() < 12 {
            self.stats.undersized_packets.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        // Parse and validate header
        let header = match DnsHeader::parse(packet) {
            Ok(h) => h,
            Err(_) => {
                self.stats.invalid_headers.fetch_add(1, Ordering::Relaxed);
                return Ok(false);
            }
        };

        // Validate header fields
        if !self.validate_header(&header).await? {
            return Ok(false);
        }

        // Validate packet structure
        if !self.validate_packet_structure(packet, &header).await? {
            return Ok(false);
        }

        self.stats.valid_packets.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    /// Validate DNS response packet
    pub async fn validate_response_packet(&self, packet: &[u8]) -> SecurityResult<bool> {
        self.stats.total_validations.fetch_add(1, Ordering::Relaxed);

        // Basic size check
        if packet.len() > self.config.max_packet_size {
            self.stats.oversized_packets.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        if packet.len() < 12 {
            self.stats.undersized_packets.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        // Parse header
        let header = match DnsHeader::parse(packet) {
            Ok(h) => h,
            Err(_) => {
                self.stats.invalid_headers.fetch_add(1, Ordering::Relaxed);
                return Ok(false);
            }
        };

        // Must be a response
        if !header.is_response() {
            self.stats.invalid_headers.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        // Validate response-specific fields
        if !self.validate_response_header(&header).await? {
            return Ok(false);
        }

        // Validate packet structure
        if !self.validate_packet_structure(packet, &header).await? {
            return Ok(false);
        }

        self.stats.valid_packets.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    /// Validate DNS header fields
    async fn validate_header(&self, header: &DnsHeader) -> SecurityResult<bool> {
        // Check record counts against limits
        if header.qdcount > self.config.max_questions {
            self.stats.excessive_questions.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        if header.ancount > self.config.max_answers {
            self.stats.excessive_answers.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        if header.nscount > self.config.max_authority {
            self.stats.excessive_authority.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        if header.arcount > self.config.max_additional {
            self.stats.excessive_additional.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        // Validate opcode
        let opcode = header.opcode();
        if self.config.strict_rfc_compliance && opcode > 5 {
            self.stats.invalid_opcodes.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        // For queries, should have at least one question
        if header.is_query() && header.qdcount == 0 {
            self.stats.invalid_headers.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        Ok(true)
    }

    /// Validate response-specific header fields
    async fn validate_response_header(&self, header: &DnsHeader) -> SecurityResult<bool> {
        // Response code validation
        let rcode = header.flags & 0x000F;
        if self.config.strict_rfc_compliance && rcode > 5 {
            self.stats.invalid_rcodes.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        Ok(true)
    }

    /// Validate packet structure and content
    async fn validate_packet_structure(&self, packet: &[u8], header: &DnsHeader) -> SecurityResult<bool> {
        let mut offset = 12; // Skip header

        // Validate questions section
        for _ in 0..header.qdcount {
            match self.validate_question(packet, &mut offset).await {
                Ok(true) => continue,
                Ok(false) => {
                    self.stats.invalid_questions.fetch_add(1, Ordering::Relaxed);
                    return Ok(false);
                }
                Err(_) => {
                    self.stats.malformed_questions.fetch_add(1, Ordering::Relaxed);
                    return Ok(false);
                }
            }
        }

        // Validate answer section
        for _ in 0..header.ancount {
            match self.validate_resource_record(packet, &mut offset).await {
                Ok(true) => continue,
                Ok(false) => {
                    self.stats.invalid_answers.fetch_add(1, Ordering::Relaxed);
                    return Ok(false);
                }
                Err(_) => {
                    self.stats.malformed_answers.fetch_add(1, Ordering::Relaxed);
                    return Ok(false);
                }
            }
        }

        // Validate authority section
        for _ in 0..header.nscount {
            match self.validate_resource_record(packet, &mut offset).await {
                Ok(true) => continue,
                Ok(false) => {
                    self.stats.invalid_authority.fetch_add(1, Ordering::Relaxed);
                    return Ok(false);
                }
                Err(_) => {
                    self.stats.malformed_authority.fetch_add(1, Ordering::Relaxed);
                    return Ok(false);
                }
            }
        }

        // Validate additional section
        for _ in 0..header.arcount {
            match self.validate_resource_record(packet, &mut offset).await {
                Ok(true) => continue,
                Ok(false) => {
                    self.stats.invalid_additional.fetch_add(1, Ordering::Relaxed);
                    return Ok(false);
                }
                Err(_) => {
                    self.stats.malformed_additional.fetch_add(1, Ordering::Relaxed);
                    return Ok(false);
                }
            }
        }

        // Check if we consumed the entire packet
        if offset != packet.len() {
            self.stats.trailing_data.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        Ok(true)
    }

    /// Validate a DNS question
    async fn validate_question(&self, packet: &[u8], offset: &mut usize) -> SecurityResult<bool> {
        // Validate domain name
        if !self.validate_domain_name(packet, offset, 0).await? {
            return Ok(false);
        }

        // Check remaining space for QTYPE and QCLASS
        if *offset + 4 > packet.len() {
            return Err(SecurityError::invalid_packet("Question truncated"));
        }

        let qtype = u16::from_be_bytes([packet[*offset], packet[*offset + 1]]);
        let qclass = u16::from_be_bytes([packet[*offset + 2], packet[*offset + 3]]);
        *offset += 4;

        // Validate QTYPE and QCLASS
        if self.config.strict_rfc_compliance {
            if qclass != 1 && qclass != 255 { // IN or ANY
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Validate a DNS resource record
    async fn validate_resource_record(&self, packet: &[u8], offset: &mut usize) -> SecurityResult<bool> {
        // Validate domain name
        if !self.validate_domain_name(packet, offset, 0).await? {
            return Ok(false);
        }

        // Check remaining space for TYPE, CLASS, TTL, RDLENGTH
        if *offset + 10 > packet.len() {
            return Err(SecurityError::invalid_packet("Resource record truncated"));
        }

        let rtype = u16::from_be_bytes([packet[*offset], packet[*offset + 1]]);
        let rclass = u16::from_be_bytes([packet[*offset + 2], packet[*offset + 3]]);
        let ttl = u32::from_be_bytes([
            packet[*offset + 4],
            packet[*offset + 5],
            packet[*offset + 6],
            packet[*offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([packet[*offset + 8], packet[*offset + 9]]);
        *offset += 10;

        // Validate RDATA length
        if *offset + rdlength as usize > packet.len() {
            return Err(SecurityError::invalid_packet("RDATA extends beyond packet"));
        }

        // Validate RDATA content based on type
        if !self.validate_rdata(packet, *offset, rtype, rdlength).await? {
            return Ok(false);
        }

        *offset += rdlength as usize;
        Ok(true)
    }

    /// Validate domain name with compression pointer handling
    async fn validate_domain_name(
        &self,
        packet: &[u8],
        offset: &mut usize,
        compression_depth: u8,
    ) -> SecurityResult<bool> {
        if compression_depth > self.config.max_compression_depth {
            return Ok(false);
        }

        let mut total_length = 0;
        let mut current_offset = *offset;

        loop {
            if current_offset >= packet.len() {
                return Err(SecurityError::invalid_packet("Domain name extends beyond packet"));
            }

            let length = packet[current_offset];

            if length == 0 {
                // End of domain name
                current_offset += 1;
                if compression_depth == 0 {
                    *offset = current_offset;
                }
                break;
            } else if (length & 0xC0) == 0xC0 {
                // Compression pointer
                if current_offset + 1 >= packet.len() {
                    return Err(SecurityError::invalid_packet("Compression pointer truncated"));
                }

                let pointer = ((length as u16 & 0x3F) << 8) | packet[current_offset + 1] as u16;
                
                if pointer as usize >= packet.len() {
                    return Ok(false);
                }

                if compression_depth == 0 {
                    *offset = current_offset + 2;
                }

                // Follow compression pointer recursively
                let mut pointer_offset = pointer as usize;
                return Box::pin(self.validate_domain_name(packet, &mut pointer_offset, compression_depth + 1)).await;
            } else {
                // Regular label
                if length > self.config.max_label_length as u8 {
                    return Ok(false);
                }

                current_offset += 1;
                
                if current_offset + length as usize > packet.len() {
                    return Err(SecurityError::invalid_packet("Label extends beyond packet"));
                }

                // Validate label characters
                for i in 0..length as usize {
                    let ch = packet[current_offset + i];
                    if self.config.strict_rfc_compliance && !self.is_valid_label_char(ch) {
                        return Ok(false);
                    }
                }

                current_offset += length as usize;
                total_length += length as usize + 1;

                if total_length > self.config.max_domain_length {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Validate RDATA content based on record type
    async fn validate_rdata(&self, packet: &[u8], offset: usize, rtype: u16, rdlength: u16) -> SecurityResult<bool> {
        match rtype {
            1 => {
                // A record - must be 4 bytes
                if rdlength != 4 {
                    return Ok(false);
                }
            }
            28 => {
                // AAAA record - must be 16 bytes
                if rdlength != 16 {
                    return Ok(false);
                }
            }
            2 | 5 | 12 => {
                // NS, CNAME, PTR - must contain valid domain name
                let mut rdata_offset = offset;
                if !self.validate_domain_name(packet, &mut rdata_offset, 0).await? {
                    return Ok(false);
                }
                if rdata_offset != offset + rdlength as usize {
                    return Ok(false);
                }
            }
            15 => {
                // MX record - 2 bytes preference + domain name
                if rdlength < 3 {
                    return Ok(false);
                }
                let mut rdata_offset = offset + 2;
                if !self.validate_domain_name(packet, &mut rdata_offset, 0).await? {
                    return Ok(false);
                }
                if rdata_offset != offset + rdlength as usize {
                    return Ok(false);
                }
            }
            6 => {
                // SOA record - complex structure
                if rdlength < 20 {
                    return Ok(false);
                }
                // TODO: Implement full SOA validation
            }
            _ => {
                // Unknown record type - just check length is reasonable
                if rdlength > 65535 {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Check if character is valid in DNS label
    fn is_valid_label_char(&self, ch: u8) -> bool {
        ch.is_ascii_alphanumeric() || ch == b'-' || ch == b'_'
    }

    /// Get current validation statistics
    pub async fn get_stats(&self) -> SecurityResult<ValidationStats> {
        Ok(self.stats.snapshot())
    }
}

/// Packet validation statistics
#[derive(Debug)]
pub struct ValidationStats {
    pub total_validations: AtomicU64,
    pub valid_packets: AtomicU64,
    pub oversized_packets: AtomicU64,
    pub undersized_packets: AtomicU64,
    pub invalid_headers: AtomicU64,
    pub invalid_opcodes: AtomicU64,
    pub invalid_rcodes: AtomicU64,
    pub excessive_questions: AtomicU64,
    pub excessive_answers: AtomicU64,
    pub excessive_authority: AtomicU64,
    pub excessive_additional: AtomicU64,
    pub invalid_questions: AtomicU64,
    pub malformed_questions: AtomicU64,
    pub invalid_answers: AtomicU64,
    pub malformed_answers: AtomicU64,
    pub invalid_authority: AtomicU64,
    pub malformed_authority: AtomicU64,
    pub invalid_additional: AtomicU64,
    pub malformed_additional: AtomicU64,
    pub trailing_data: AtomicU64,
    pub created_at: AtomicU64,
}

impl ValidationStats {
    pub fn new() -> Self {
        Self {
            total_validations: AtomicU64::new(0),
            valid_packets: AtomicU64::new(0),
            oversized_packets: AtomicU64::new(0),
            undersized_packets: AtomicU64::new(0),
            invalid_headers: AtomicU64::new(0),
            invalid_opcodes: AtomicU64::new(0),
            invalid_rcodes: AtomicU64::new(0),
            excessive_questions: AtomicU64::new(0),
            excessive_answers: AtomicU64::new(0),
            excessive_authority: AtomicU64::new(0),
            excessive_additional: AtomicU64::new(0),
            invalid_questions: AtomicU64::new(0),
            malformed_questions: AtomicU64::new(0),
            invalid_answers: AtomicU64::new(0),
            malformed_answers: AtomicU64::new(0),
            invalid_authority: AtomicU64::new(0),
            malformed_authority: AtomicU64::new(0),
            invalid_additional: AtomicU64::new(0),
            malformed_additional: AtomicU64::new(0),
            trailing_data: AtomicU64::new(0),
            created_at: AtomicU64::new(current_timestamp_ms()),
        }
    }

    pub fn snapshot(&self) -> Self {
        Self {
            total_validations: AtomicU64::new(self.total_validations.load(Ordering::Relaxed)),
            valid_packets: AtomicU64::new(self.valid_packets.load(Ordering::Relaxed)),
            oversized_packets: AtomicU64::new(self.oversized_packets.load(Ordering::Relaxed)),
            undersized_packets: AtomicU64::new(self.undersized_packets.load(Ordering::Relaxed)),
            invalid_headers: AtomicU64::new(self.invalid_headers.load(Ordering::Relaxed)),
            invalid_opcodes: AtomicU64::new(self.invalid_opcodes.load(Ordering::Relaxed)),
            invalid_rcodes: AtomicU64::new(self.invalid_rcodes.load(Ordering::Relaxed)),
            excessive_questions: AtomicU64::new(self.excessive_questions.load(Ordering::Relaxed)),
            excessive_answers: AtomicU64::new(self.excessive_answers.load(Ordering::Relaxed)),
            excessive_authority: AtomicU64::new(self.excessive_authority.load(Ordering::Relaxed)),
            excessive_additional: AtomicU64::new(self.excessive_additional.load(Ordering::Relaxed)),
            invalid_questions: AtomicU64::new(self.invalid_questions.load(Ordering::Relaxed)),
            malformed_questions: AtomicU64::new(self.malformed_questions.load(Ordering::Relaxed)),
            invalid_answers: AtomicU64::new(self.invalid_answers.load(Ordering::Relaxed)),
            malformed_answers: AtomicU64::new(self.malformed_answers.load(Ordering::Relaxed)),
            invalid_authority: AtomicU64::new(self.invalid_authority.load(Ordering::Relaxed)),
            malformed_authority: AtomicU64::new(self.malformed_authority.load(Ordering::Relaxed)),
            invalid_additional: AtomicU64::new(self.invalid_additional.load(Ordering::Relaxed)),
            malformed_additional: AtomicU64::new(self.malformed_additional.load(Ordering::Relaxed)),
            trailing_data: AtomicU64::new(self.trailing_data.load(Ordering::Relaxed)),
            created_at: AtomicU64::new(self.created_at.load(Ordering::Relaxed)),
        }
    }

    /// Calculate validation success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.total_validations.load(Ordering::Relaxed);
        let valid = self.valid_packets.load(Ordering::Relaxed);
        
        if total == 0 {
            0.0
        } else {
            valid as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_valid_query_packet() {
        let config = ValidationConfig::default();
        let validator = PacketValidator::new(config).unwrap();

        // Simple A record query for "example.com"
        let packet = vec![
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

        assert!(validator.validate_query_packet(&packet).await.unwrap());
    }

    #[tokio::test]
    async fn test_oversized_packet() {
        let config = ValidationConfig {
            max_packet_size: 100,
            ..Default::default()
        };
        let validator = PacketValidator::new(config).unwrap();

        let packet = vec![0; 200]; // Oversized packet
        assert!(!validator.validate_query_packet(&packet).await.unwrap());
    }

    #[tokio::test]
    async fn test_undersized_packet() {
        let config = ValidationConfig::default();
        let validator = PacketValidator::new(config).unwrap();

        let packet = vec![0; 5]; // Too small for DNS header
        assert!(!validator.validate_query_packet(&packet).await.unwrap());
    }

    #[tokio::test]
    async fn test_excessive_questions() {
        let config = ValidationConfig {
            max_questions: 1,
            ..Default::default()
        };
        let validator = PacketValidator::new(config).unwrap();

        let mut packet = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags
            0x00, 0x02, // QDCOUNT (2 questions)
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];

        // Add two questions
        for _ in 0..2 {
            packet.extend_from_slice(&[
                0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
                0x03, b'c', b'o', b'm',
                0x00, // End of name
                0x00, 0x01, // QTYPE (A)
                0x00, 0x01, // QCLASS (IN)
            ]);
        }

        assert!(!validator.validate_query_packet(&packet).await.unwrap());
    }
}