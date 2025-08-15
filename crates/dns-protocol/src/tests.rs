//! Comprehensive tests for DNS protocol implementation
//!
//! This module tests all supported DNS record types and validation logic.

#[cfg(test)]
mod tests {
    use crate::parser::DnsPacketParser;
    use crate::response::DnsResponseBuilder;
    use crate::validation::DnsPacketValidator;
    use crate::records::{ParsedDnsPacket, DnsHeader, ParsedRecordData};
    use dns_core::{RecordType, DnsClass, DnsRecord, RecordData};
    use std::net::Ipv4Addr;
    use bytes::Bytes;

    /// Test parsing of simple DNS packets
    #[test]
    fn test_parse_simple_packet() {
        let parser = DnsPacketParser::new();
        
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
        
        let result = parser.parse_packet(&query_packet, "127.0.0.1".parse().unwrap());
        assert!(result.is_ok());
        
        let parsed = result.unwrap();
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "example.com");
        assert_eq!(parsed.questions[0].record_type, RecordType::A);
    }

    /// Test parsing of DNS response packets
    #[test]
    fn test_parse_response_packet() {
        let parser = DnsPacketParser::new();
        
        // Simple A response for example.com
        let response_packet = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Flags (response, authoritative)
            0x00, 0x01, // QDCOUNT
            0x00, 0x01, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // Question: example.com A IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // End of name
            0x00, 0x01, // QTYPE (A)
            0x00, 0x01, // QCLASS (IN)
            // Answer: example.com A 192.0.2.1
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // End of name
            0x00, 0x01, // TYPE (A)
            0x00, 0x01, // CLASS (IN)
            0x00, 0x00, 0x01, 0x2c, // TTL (300)
            0x00, 0x04, // RDLENGTH
            192, 0, 2, 1, // RDATA (IP address)
        ];
        
        let result = parser.parse_packet(&response_packet, "127.0.0.1".parse().unwrap());
        assert!(result.is_ok());
        
        let parsed = result.unwrap();
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].name, "example.com");
        assert_eq!(parsed.answers[0].record_type, RecordType::A);
        
        // Check the parsed A record data
        if let ParsedRecordData::A(addr) = &parsed.answers[0].data {
            assert_eq!(*addr, Ipv4Addr::new(192, 0, 2, 1));
        } else {
            panic!("Expected A record");
        }
    }

    /// Test DNS response building with various record types
    #[test]
    fn test_build_responses() {
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
            questions: vec![dns_core::DnsQuestion {
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

        // Test building response with A record
        let answers = vec![DnsRecord {
            name: "example.com".to_string(),
            record_type: RecordType::A,
            class: DnsClass::IN,
            ttl: 300,
            data: RecordData::A(Ipv4Addr::new(192, 0, 2, 1)),
        }];

        let result = builder.build_response(&query_packet, &answers, &[], &[], 0);
        assert!(result.is_ok());

        // Test building response with AAAA record
        let aaaa_answers = vec![DnsRecord {
            name: "example.com".to_string(),
            record_type: RecordType::AAAA,
            class: DnsClass::IN,
            ttl: 300,
            data: RecordData::AAAA("2001:db8::1".parse().unwrap()),
        }];

        let result = builder.build_response(&query_packet, &aaaa_answers, &[], &[], 0);
        assert!(result.is_ok());

        // Test building response with TXT record
        let txt_answers = vec![DnsRecord {
            name: "example.com".to_string(),
            record_type: RecordType::TXT,
            class: DnsClass::IN,
            ttl: 300,
            data: RecordData::TXT(vec!["hello".to_string(), "world".to_string()]),
        }];

        let result = builder.build_response(&query_packet, &txt_answers, &[], &[], 0);
        assert!(result.is_ok());
    }

    /// Test DNS packet validation
    #[test]
    fn test_packet_validation() {
        let validator = DnsPacketValidator::new();

        // Test valid domain name validation
        assert!(validator.validate_domain_name("example.com").is_ok());
        assert!(validator.validate_domain_name("sub.example.com").is_ok());
        assert!(validator.validate_domain_name("").is_ok()); // Root domain

        // Test invalid domain names
        assert!(validator.validate_domain_name(&"a".repeat(254)).is_err()); // Too long
        assert!(validator.validate_domain_name("-example.com").is_err()); // Invalid start
        assert!(validator.validate_domain_name("example-.com").is_err()); // Invalid end

        // Test header validation
        let valid_header = DnsHeader {
            id: 0x1234,
            flags: 0x0100, // Standard query
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        assert!(validator.validate_header(&valid_header).is_ok());

        // Test invalid header
        let invalid_header = DnsHeader {
            id: 0x1234,
            flags: 0x7800, // Invalid opcode
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        assert!(validator.validate_header(&invalid_header).is_err());
    }

    /// Test bounds checking in packet parsing
    #[test]
    fn test_bounds_checking() {
        let parser = DnsPacketParser::new();

        // Test packet too short
        let short_packet = vec![0x12, 0x34]; // Only 2 bytes
        let result = parser.parse_packet(&short_packet, "127.0.0.1".parse().unwrap());
        assert!(result.is_err());

        // Test malformed packet with invalid record count
        let malformed_packet = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Flags
            0x00, 0x01, // QDCOUNT
            0xFF, 0xFF, // ANCOUNT (too many)
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // Truncated - no actual records
        ];
        let result = parser.parse_packet(&malformed_packet, "127.0.0.1".parse().unwrap());
        assert!(result.is_err());
    }

    /// Test DNSSEC record validation
    #[test]
    fn test_dnssec_validation() {
        let validator = DnsPacketValidator::new();

        // Test valid DNSKEY validation
        let valid_dnskey = ParsedRecordData::DNSKEY {
            flags: 0x0100,
            protocol: 3,
            algorithm: 8, // RSA/SHA-256
            public_key: Bytes::from(vec![0u8; 64]), // Minimum RSA key size
        };
        assert!(validator.validate_record_data(&valid_dnskey, RecordType::DNSKEY).is_ok());

        // Test invalid DNSKEY protocol
        let invalid_dnskey = ParsedRecordData::DNSKEY {
            flags: 0x0100,
            protocol: 2, // Invalid protocol
            algorithm: 8,
            public_key: Bytes::from(vec![0u8; 64]),
        };
        assert!(validator.validate_record_data(&invalid_dnskey, RecordType::DNSKEY).is_err());

        // Test valid DS record
        let valid_ds = ParsedRecordData::DS {
            key_tag: 0x1234,
            algorithm: 8,
            digest_type: 2, // SHA-256
            digest: Bytes::from(vec![0u8; 32]), // SHA-256 digest length
        };
        assert!(validator.validate_record_data(&valid_ds, RecordType::DS).is_ok());

        // Test invalid DS digest length
        let invalid_ds = ParsedRecordData::DS {
            key_tag: 0x1234,
            algorithm: 8,
            digest_type: 2, // SHA-256
            digest: Bytes::from(vec![0u8; 20]), // Wrong length for SHA-256
        };
        assert!(validator.validate_record_data(&invalid_ds, RecordType::DS).is_err());
    }

    /// Test modern record validation
    #[test]
    fn test_modern_record_validation() {
        let validator = DnsPacketValidator::new();

        // Test valid CAA record
        let valid_caa = ParsedRecordData::CAA {
            flags: 0,
            tag: "issue".to_string(),
            value: Bytes::from("ca.example.com"),
        };
        assert!(validator.validate_record_data(&valid_caa, RecordType::CAA).is_ok());

        // Test invalid CAA tag (empty)
        let invalid_caa = ParsedRecordData::CAA {
            flags: 0,
            tag: "".to_string(),
            value: Bytes::from("ca.example.com"),
        };
        assert!(validator.validate_record_data(&invalid_caa, RecordType::CAA).is_err());

        // Test valid TLSA record
        let valid_tlsa = ParsedRecordData::TLSA {
            cert_usage: 3,
            selector: 1,
            matching_type: 1, // SHA-256
            cert_data: Bytes::from(vec![0u8; 32]), // SHA-256 hash length
        };
        assert!(validator.validate_record_data(&valid_tlsa, RecordType::TLSA).is_ok());

        // Test invalid TLSA matching type
        let invalid_tlsa = ParsedRecordData::TLSA {
            cert_usage: 3,
            selector: 1,
            matching_type: 5, // Invalid matching type
            cert_data: Bytes::from(vec![0u8; 32]),
        };
        assert!(validator.validate_record_data(&invalid_tlsa, RecordType::TLSA).is_err());
    }

    /// Test error response building
    #[test]
    fn test_error_responses() {
        let mut builder = DnsResponseBuilder::new();

        let query_packet = ParsedDnsPacket {
            header: DnsHeader {
                id: 0x1234,
                flags: 0x0100,
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![dns_core::DnsQuestion {
                name: "nonexistent.example".to_string(),
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

        // Test NXDOMAIN response
        let result = builder.build_error_response(&query_packet, 3); // NXDOMAIN
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.len() >= 12); // At least header size

        // Verify response header
        assert_eq!(response[0], 0x12); // ID high byte
        assert_eq!(response[1], 0x34); // ID low byte
        assert_eq!(response[2] & 0x80, 0x80); // QR bit set (response)
        assert_eq!(response[3] & 0x0F, 3); // RCODE = NXDOMAIN
    }

    /// Test response ID updating (zero-copy optimization)
    #[test]
    fn test_response_id_update() {
        let original_response = vec![
            0x12, 0x34, // Original ID
            0x81, 0x80, // Flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x01, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];

        let updated = DnsResponseBuilder::update_response_id(&original_response, 0x5678);

        assert_eq!(updated[0], 0x56); // New ID high byte
        assert_eq!(updated[1], 0x78); // New ID low byte
        assert_eq!(updated[2], 0x81); // Flags unchanged
        assert_eq!(updated[3], 0x80); // Flags unchanged
    }

    /// Test comprehensive packet parsing with all sections
    #[test]
    fn test_comprehensive_packet_parsing() {
        let parser = DnsPacketParser::new();

        // Create a simpler but valid DNS packet with multiple sections
        let complex_packet = vec![
            // Header
            0x12, 0x34, // ID
            0x84, 0x00, // Flags (response, authoritative)
            0x00, 0x01, // QDCOUNT
            0x00, 0x01, // ANCOUNT
            0x00, 0x01, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            
            // Question: example.com A IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // End of name
            0x00, 0x01, // QTYPE (A)
            0x00, 0x01, // QCLASS (IN)
            
            // Answer: example.com A 192.0.2.1
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // End of name
            0x00, 0x01, // TYPE (A)
            0x00, 0x01, // CLASS (IN)
            0x00, 0x00, 0x01, 0x2c, // TTL (300)
            0x00, 0x04, // RDLENGTH
            192, 0, 2, 1, // RDATA (IP address)
            
            // Authority: example.com NS ns.example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // End of name
            0x00, 0x02, // TYPE (NS)
            0x00, 0x01, // CLASS (IN)
            0x00, 0x00, 0x0e, 0x10, // TTL (3600)
            0x00, 0x10, // RDLENGTH (16 bytes for "ns.example.com")
            0x02, b'n', b's',
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // End of name
        ];

        let result = parser.parse_packet(&complex_packet, "127.0.0.1".parse().unwrap());
        if let Err(ref e) = result {
            println!("Parse error: {}", e);
        }
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.authority.len(), 1);
        assert_eq!(parsed.additional.len(), 0);

        // Verify question
        assert_eq!(parsed.questions[0].name, "example.com");
        assert_eq!(parsed.questions[0].record_type, RecordType::A);

        // Verify answer
        assert_eq!(parsed.answers[0].name, "example.com");
        assert_eq!(parsed.answers[0].record_type, RecordType::A);
        
        // Verify authority
        assert_eq!(parsed.authority[0].name, "example.com");
        assert_eq!(parsed.authority[0].record_type, RecordType::NS);
    }
}