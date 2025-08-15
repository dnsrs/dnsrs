//! Comprehensive DNS packet parsing with bounds checking
//!
//! This module provides robust DNS packet parsing that validates all input
//! and prevents buffer overflows and other security issues.

use crate::records::*;
use dns_core::{DnsError, DnsResult, RecordType, DnsClass, DnsQuery, DnsQuestion, ResponseCode};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use bytes::Bytes;

/// Comprehensive DNS packet parser with security validation
pub struct DnsPacketParser {
    /// Maximum packet size to prevent DoS attacks
    max_packet_size: usize,
    /// Maximum domain name length
    max_name_length: usize,
    /// Maximum number of compression pointers to follow
    max_compression_depth: usize,
}

impl DnsPacketParser {
    /// Create a new DNS packet parser with security limits
    pub fn new() -> Self {
        Self {
            max_packet_size: 65535,
            max_name_length: 253,
            max_compression_depth: 16,
        }
    }

    /// Create a parser with custom limits
    pub fn with_limits(max_packet_size: usize, max_name_length: usize, max_compression_depth: usize) -> Self {
        Self {
            max_packet_size,
            max_name_length,
            max_compression_depth,
        }
    }

    /// Parse a complete DNS packet with full validation
    pub fn parse_packet(&self, data: &[u8], client_addr: IpAddr) -> DnsResult<ParsedDnsPacket> {
        // Validate packet size
        if data.len() > self.max_packet_size {
            return Err(DnsError::PacketTooLarge { 
                size: data.len(), 
                max_size: self.max_packet_size 
            });
        }

        if data.len() < 12 {
            return Err(DnsError::invalid_packet("Packet too short for DNS header"));
        }

        // Parse header with validation
        let header = self.parse_header(data)?;
        
        // Validate header fields
        self.validate_header(&header)?;

        let mut offset = 12;
        let mut questions = Vec::new();
        let mut answers = Vec::new();
        let mut authority = Vec::new();
        let mut additional = Vec::new();

        // Parse questions section
        for _ in 0..header.qdcount {
            let (question, new_offset) = self.parse_question(data, offset)?;
            questions.push(question);
            offset = new_offset;
        }

        // Parse answers section
        for _ in 0..header.ancount {
            let (record, new_offset) = self.parse_resource_record(data, offset)?;
            answers.push(record);
            offset = new_offset;
        }

        // Parse authority section
        for _ in 0..header.nscount {
            let (record, new_offset) = self.parse_resource_record(data, offset)?;
            authority.push(record);
            offset = new_offset;
        }

        // Parse additional section
        for _ in 0..header.arcount {
            let (record, new_offset) = self.parse_resource_record(data, offset)?;
            additional.push(record);
            offset = new_offset;
        }

        // Validate we consumed the entire packet
        if offset != data.len() {
            return Err(DnsError::invalid_packet(
                format!("Packet has {} trailing bytes", data.len() - offset)
            ));
        }

        Ok(ParsedDnsPacket {
            header,
            questions,
            answers,
            authority,
            additional,
            raw_data: data.to_vec(),
            client_addr,
            parsed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Parse DNS header with validation
    fn parse_header(&self, data: &[u8]) -> DnsResult<DnsHeader> {
        if data.len() < 12 {
            return Err(DnsError::invalid_packet("Header too short"));
        }

        let header = DnsHeader {
            id: u16::from_be_bytes([data[0], data[1]]),
            flags: u16::from_be_bytes([data[2], data[3]]),
            qdcount: u16::from_be_bytes([data[4], data[5]]),
            ancount: u16::from_be_bytes([data[6], data[7]]),
            nscount: u16::from_be_bytes([data[8], data[9]]),
            arcount: u16::from_be_bytes([data[10], data[11]]),
        };

        Ok(header)
    }

    /// Validate DNS header fields
    fn validate_header(&self, header: &DnsHeader) -> DnsResult<()> {
        // Check for reasonable limits to prevent DoS
        let total_records = header.qdcount as u32 + 
                           header.ancount as u32 + 
                           header.nscount as u32 + 
                           header.arcount as u32;

        if total_records > 1000 {
            return Err(DnsError::invalid_packet(
                format!("Too many records: {}", total_records)
            ));
        }

        // Validate opcode
        let opcode = (header.flags >> 11) & 0x0F;
        if opcode > 5 {
            return Err(DnsError::invalid_packet(
                format!("Invalid opcode: {}", opcode)
            ));
        }

        // Validate response code
        let rcode = header.flags & 0x0F;
        if rcode > 10 {
            return Err(DnsError::invalid_packet(
                format!("Invalid response code: {}", rcode)
            ));
        }

        Ok(())
    }

    /// Parse a DNS question with validation
    fn parse_question(&self, data: &[u8], offset: usize) -> DnsResult<(DnsQuestion, usize)> {
        // Parse domain name
        let (name, new_offset) = self.parse_domain_name(data, offset)?;
        
        // Validate we have enough bytes for QTYPE and QCLASS
        if new_offset + 4 > data.len() {
            return Err(DnsError::invalid_packet("Question section truncated"));
        }

        let qtype = u16::from_be_bytes([data[new_offset], data[new_offset + 1]]);
        let qclass = u16::from_be_bytes([data[new_offset + 2], data[new_offset + 3]]);

        // Validate record type and class
        let record_type = RecordType::from_u16(qtype)
            .ok_or_else(|| DnsError::UnsupportedRecordType { record_type: qtype })?;
        
        let class = DnsClass::from_u16(qclass)
            .ok_or_else(|| DnsError::invalid_packet(format!("Invalid DNS class: {}", qclass)))?;

        Ok((DnsQuestion {
            name,
            record_type,
            class,
        }, new_offset + 4))
    }

    /// Parse a DNS resource record with full validation
    fn parse_resource_record(&self, data: &[u8], offset: usize) -> DnsResult<(ParsedDnsRecord, usize)> {
        // Parse domain name
        let (name, mut new_offset) = self.parse_domain_name(data, offset)?;
        
        // Validate we have enough bytes for TYPE, CLASS, TTL, RDLENGTH
        if new_offset + 10 > data.len() {
            return Err(DnsError::invalid_packet("Resource record header truncated"));
        }

        let record_type_num = u16::from_be_bytes([data[new_offset], data[new_offset + 1]]);
        let class_num = u16::from_be_bytes([data[new_offset + 2], data[new_offset + 3]]);
        let ttl = u32::from_be_bytes([
            data[new_offset + 4], data[new_offset + 5], 
            data[new_offset + 6], data[new_offset + 7]
        ]);
        let rdlength = u16::from_be_bytes([data[new_offset + 8], data[new_offset + 9]]) as usize;
        
        new_offset += 10;

        // Validate RDATA length
        if new_offset + rdlength > data.len() {
            return Err(DnsError::invalid_packet("RDATA extends beyond packet"));
        }

        // Validate TTL
        if ttl > dns_core::types::MAX_TTL {
            return Err(DnsError::invalid_packet(format!("TTL too large: {}", ttl)));
        }

        // Parse record type and class
        let record_type = RecordType::from_u16(record_type_num)
            .ok_or_else(|| DnsError::UnsupportedRecordType { record_type: record_type_num })?;
        
        let class = DnsClass::from_u16(class_num)
            .ok_or_else(|| DnsError::invalid_packet(format!("Invalid DNS class: {}", class_num)))?;

        // Parse RDATA based on record type
        let rdata = &data[new_offset..new_offset + rdlength];
        let parsed_data = self.parse_record_data(record_type, rdata, data)?;

        Ok((ParsedDnsRecord {
            name,
            record_type,
            class,
            ttl,
            data: parsed_data,
            raw_rdata: rdata.to_vec(),
        }, new_offset + rdlength))
    }

    /// Parse domain name with compression support and validation
    fn parse_domain_name(&self, data: &[u8], offset: usize) -> DnsResult<(String, usize)> {
        let mut name = String::with_capacity(self.max_name_length);
        let mut current_offset = offset;
        let mut jumped = false;
        let mut compression_depth = 0;
        let original_offset = offset;

        loop {
            if current_offset >= data.len() {
                return Err(DnsError::invalid_packet("Domain name extends beyond packet"));
            }

            let length = data[current_offset];

            if length == 0 {
                // End of name
                if !jumped {
                    current_offset += 1;
                }
                break;
            } else if (length & 0xC0) == 0xC0 {
                // Compression pointer
                if current_offset + 1 >= data.len() {
                    return Err(DnsError::invalid_packet("Compression pointer truncated"));
                }

                compression_depth += 1;
                if compression_depth > self.max_compression_depth {
                    return Err(DnsError::invalid_packet("Too many compression pointers"));
                }

                let pointer = ((length as u16 & 0x3F) << 8) | data[current_offset + 1] as u16;
                
                // Validate pointer doesn't point forward (prevents loops)
                if pointer as usize >= original_offset {
                    return Err(DnsError::invalid_packet("Invalid compression pointer"));
                }

                if !jumped {
                    current_offset += 2; // This will be our return offset
                    jumped = true;
                }

                current_offset = pointer as usize;
            } else if (length & 0xC0) == 0 {
                // Regular label
                if length as usize > dns_core::types::MAX_LABEL_LENGTH {
                    return Err(DnsError::invalid_packet(
                        format!("Label too long: {} bytes", length)
                    ));
                }

                current_offset += 1;
                if current_offset + length as usize > data.len() {
                    return Err(DnsError::invalid_packet("Label extends beyond packet"));
                }

                // Add dot separator if not first label
                if !name.is_empty() {
                    name.push('.');
                }

                // Validate label contains valid characters
                let label_bytes = &data[current_offset..current_offset + length as usize];
                let label = std::str::from_utf8(label_bytes)
                    .map_err(|_| DnsError::invalid_packet("Invalid UTF-8 in domain name"))?;

                // Validate label characters (basic validation)
                if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                    return Err(DnsError::invalid_packet("Invalid characters in domain name"));
                }

                name.push_str(label);
                current_offset += length as usize;

                // Check total name length
                if name.len() > self.max_name_length {
                    return Err(DnsError::invalid_packet(
                        format!("Domain name too long: {} bytes", name.len())
                    ));
                }
            } else {
                return Err(DnsError::invalid_packet("Invalid label type"));
            }
        }

        let final_offset = if jumped { current_offset } else { current_offset };
        Ok((name, final_offset))
    }

    /// Parse record data based on record type
    fn parse_record_data(&self, record_type: RecordType, rdata: &[u8], full_packet: &[u8]) -> DnsResult<ParsedRecordData> {
        match record_type {
            RecordType::A => self.parse_a_record(rdata),
            RecordType::AAAA => self.parse_aaaa_record(rdata),
            RecordType::CNAME => self.parse_cname_record(rdata, full_packet),
            RecordType::MX => self.parse_mx_record(rdata, full_packet),
            RecordType::NS => self.parse_ns_record(rdata, full_packet),
            RecordType::PTR => self.parse_ptr_record(rdata, full_packet),
            RecordType::TXT => self.parse_txt_record(rdata),
            RecordType::SRV => self.parse_srv_record(rdata, full_packet),
            RecordType::SOA => self.parse_soa_record(rdata, full_packet),
            // DNSSEC records
            RecordType::DNSKEY => self.parse_dnskey_record(rdata),
            RecordType::DS => self.parse_ds_record(rdata),
            RecordType::RRSIG => self.parse_rrsig_record(rdata, full_packet),
            RecordType::NSEC => self.parse_nsec_record(rdata, full_packet),
            RecordType::NSEC3 => self.parse_nsec3_record(rdata),
            RecordType::NSEC3PARAM => self.parse_nsec3param_record(rdata),
            RecordType::CDS => self.parse_cds_record(rdata),
            RecordType::CDNSKEY => self.parse_cdnskey_record(rdata),
            // Modern records
            RecordType::CAA => self.parse_caa_record(rdata),
            RecordType::TLSA => self.parse_tlsa_record(rdata),
            RecordType::HTTPS => self.parse_https_record(rdata, full_packet),
            RecordType::SVCB => self.parse_svcb_record(rdata, full_packet),
            RecordType::SMIMEA => self.parse_smimea_record(rdata),
            // Additional record types
            RecordType::NAPTR => self.parse_naptr_record(rdata, full_packet),
            RecordType::OPENPGPKEY => self.parse_openpgpkey_record(rdata),
            RecordType::CSYNC => self.parse_csync_record(rdata),
            RecordType::ZONEMD => self.parse_zonemd_record(rdata),
        }
    }

    /// Parse A record (IPv4 address)
    fn parse_a_record(&self, rdata: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() != 4 {
            return Err(DnsError::invalid_packet(
                format!("A record must be 4 bytes, got {}", rdata.len())
            ));
        }

        let addr = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
        Ok(ParsedRecordData::A(addr))
    }

    /// Parse AAAA record (IPv6 address)
    fn parse_aaaa_record(&self, rdata: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() != 16 {
            return Err(DnsError::invalid_packet(
                format!("AAAA record must be 16 bytes, got {}", rdata.len())
            ));
        }

        let mut addr_bytes = [0u8; 16];
        addr_bytes.copy_from_slice(rdata);
        let addr = Ipv6Addr::from(addr_bytes);
        Ok(ParsedRecordData::AAAA(addr))
    }

    /// Parse CNAME record
    fn parse_cname_record(&self, rdata: &[u8], full_packet: &[u8]) -> DnsResult<ParsedRecordData> {
        let (cname, _) = self.parse_domain_name_from_rdata(rdata, full_packet)?;
        Ok(ParsedRecordData::CNAME(cname))
    }

    /// Parse MX record
    fn parse_mx_record(&self, rdata: &[u8], full_packet: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() < 3 {
            return Err(DnsError::invalid_packet("MX record too short"));
        }

        let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
        let (exchange, _) = self.parse_domain_name_from_rdata(&rdata[2..], full_packet)?;

        Ok(ParsedRecordData::MX { priority, exchange })
    }

    /// Parse NS record
    fn parse_ns_record(&self, rdata: &[u8], full_packet: &[u8]) -> DnsResult<ParsedRecordData> {
        let (nsdname, _) = self.parse_domain_name_from_rdata(rdata, full_packet)?;
        Ok(ParsedRecordData::NS(nsdname))
    }

    /// Parse PTR record
    fn parse_ptr_record(&self, rdata: &[u8], full_packet: &[u8]) -> DnsResult<ParsedRecordData> {
        let (ptrdname, _) = self.parse_domain_name_from_rdata(rdata, full_packet)?;
        Ok(ParsedRecordData::PTR(ptrdname))
    }

    /// Parse TXT record
    fn parse_txt_record(&self, rdata: &[u8]) -> DnsResult<ParsedRecordData> {
        let mut strings = Vec::new();
        let mut offset = 0;

        while offset < rdata.len() {
            if offset >= rdata.len() {
                break;
            }

            let length = rdata[offset] as usize;
            offset += 1;

            if offset + length > rdata.len() {
                return Err(DnsError::invalid_packet("TXT record string extends beyond RDATA"));
            }

            let string_bytes = &rdata[offset..offset + length];
            let string = String::from_utf8_lossy(string_bytes).into_owned();
            strings.push(string);
            offset += length;
        }

        Ok(ParsedRecordData::TXT(strings))
    }

    /// Parse SRV record
    fn parse_srv_record(&self, rdata: &[u8], full_packet: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() < 7 {
            return Err(DnsError::invalid_packet("SRV record too short"));
        }

        let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
        let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
        let port = u16::from_be_bytes([rdata[4], rdata[5]]);
        let (target, _) = self.parse_domain_name_from_rdata(&rdata[6..], full_packet)?;

        Ok(ParsedRecordData::SRV { priority, weight, port, target })
    }

    /// Parse SOA record
    fn parse_soa_record(&self, rdata: &[u8], full_packet: &[u8]) -> DnsResult<ParsedRecordData> {
        let (mname, offset1) = self.parse_domain_name_from_rdata(rdata, full_packet)?;
        let (rname, offset2) = self.parse_domain_name_from_rdata(&rdata[offset1..], full_packet)?;
        
        let values_offset = offset1 + offset2;
        if values_offset + 20 > rdata.len() {
            return Err(DnsError::invalid_packet("SOA record values truncated"));
        }

        let values = &rdata[values_offset..];
        let serial = u32::from_be_bytes([values[0], values[1], values[2], values[3]]);
        let refresh = u32::from_be_bytes([values[4], values[5], values[6], values[7]]);
        let retry = u32::from_be_bytes([values[8], values[9], values[10], values[11]]);
        let expire = u32::from_be_bytes([values[12], values[13], values[14], values[15]]);
        let minimum = u32::from_be_bytes([values[16], values[17], values[18], values[19]]);

        Ok(ParsedRecordData::SOA {
            mname, rname, serial, refresh, retry, expire, minimum
        })
    }

    /// Parse DNSKEY record
    fn parse_dnskey_record(&self, rdata: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() < 4 {
            return Err(DnsError::invalid_packet("DNSKEY record too short"));
        }

        let flags = u16::from_be_bytes([rdata[0], rdata[1]]);
        let protocol = rdata[2];
        let algorithm = rdata[3];
        let public_key = Bytes::copy_from_slice(&rdata[4..]);

        Ok(ParsedRecordData::DNSKEY { flags, protocol, algorithm, public_key })
    }

    /// Parse DS record
    fn parse_ds_record(&self, rdata: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() < 4 {
            return Err(DnsError::invalid_packet("DS record too short"));
        }

        let key_tag = u16::from_be_bytes([rdata[0], rdata[1]]);
        let algorithm = rdata[2];
        let digest_type = rdata[3];
        let digest = Bytes::copy_from_slice(&rdata[4..]);

        Ok(ParsedRecordData::DS { key_tag, algorithm, digest_type, digest })
    }

    /// Parse RRSIG record
    fn parse_rrsig_record(&self, rdata: &[u8], full_packet: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() < 18 {
            return Err(DnsError::invalid_packet("RRSIG record too short"));
        }

        let type_covered = u16::from_be_bytes([rdata[0], rdata[1]]);
        let algorithm = rdata[2];
        let labels = rdata[3];
        let original_ttl = u32::from_be_bytes([rdata[4], rdata[5], rdata[6], rdata[7]]);
        let signature_expiration = u32::from_be_bytes([rdata[8], rdata[9], rdata[10], rdata[11]]);
        let signature_inception = u32::from_be_bytes([rdata[12], rdata[13], rdata[14], rdata[15]]);
        let key_tag = u16::from_be_bytes([rdata[16], rdata[17]]);
        
        let (signer_name, name_len) = self.parse_domain_name_from_rdata(&rdata[18..], full_packet)?;
        let signature = Bytes::copy_from_slice(&rdata[18 + name_len..]);

        Ok(ParsedRecordData::RRSIG {
            type_covered, algorithm, labels, original_ttl,
            signature_expiration, signature_inception, key_tag,
            signer_name, signature
        })
    }

    /// Parse NSEC record
    fn parse_nsec_record(&self, rdata: &[u8], full_packet: &[u8]) -> DnsResult<ParsedRecordData> {
        let (next_domain_name, name_len) = self.parse_domain_name_from_rdata(rdata, full_packet)?;
        let type_bit_maps = Bytes::copy_from_slice(&rdata[name_len..]);

        Ok(ParsedRecordData::NSEC { next_domain_name, type_bit_maps })
    }

    /// Parse NSEC3 record
    fn parse_nsec3_record(&self, rdata: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() < 5 {
            return Err(DnsError::invalid_packet("NSEC3 record too short"));
        }

        let hash_algorithm = rdata[0];
        let flags = rdata[1];
        let iterations = u16::from_be_bytes([rdata[2], rdata[3]]);
        let salt_length = rdata[4] as usize;

        if 5 + salt_length >= rdata.len() {
            return Err(DnsError::invalid_packet("NSEC3 salt extends beyond RDATA"));
        }

        let salt = Bytes::copy_from_slice(&rdata[5..5 + salt_length]);
        let hash_length = rdata[5 + salt_length] as usize;

        if 6 + salt_length + hash_length > rdata.len() {
            return Err(DnsError::invalid_packet("NSEC3 hash extends beyond RDATA"));
        }

        let next_hashed_owner_name = Bytes::copy_from_slice(&rdata[6 + salt_length..6 + salt_length + hash_length]);
        let type_bit_maps = Bytes::copy_from_slice(&rdata[6 + salt_length + hash_length..]);

        Ok(ParsedRecordData::NSEC3 {
            hash_algorithm, flags, iterations, salt,
            next_hashed_owner_name, type_bit_maps
        })
    }

    /// Parse CAA record
    fn parse_caa_record(&self, rdata: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() < 2 {
            return Err(DnsError::invalid_packet("CAA record too short"));
        }

        let flags = rdata[0];
        let tag_length = rdata[1] as usize;

        if 2 + tag_length > rdata.len() {
            return Err(DnsError::invalid_packet("CAA tag extends beyond RDATA"));
        }

        let tag = String::from_utf8_lossy(&rdata[2..2 + tag_length]).into_owned();
        let value = Bytes::copy_from_slice(&rdata[2 + tag_length..]);

        Ok(ParsedRecordData::CAA { flags, tag, value })
    }

    /// Parse TLSA record
    fn parse_tlsa_record(&self, rdata: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() < 3 {
            return Err(DnsError::invalid_packet("TLSA record too short"));
        }

        let cert_usage = rdata[0];
        let selector = rdata[1];
        let matching_type = rdata[2];
        let cert_data = Bytes::copy_from_slice(&rdata[3..]);

        Ok(ParsedRecordData::TLSA { cert_usage, selector, matching_type, cert_data })
    }

    /// Parse HTTPS record
    fn parse_https_record(&self, rdata: &[u8], full_packet: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() < 2 {
            return Err(DnsError::invalid_packet("HTTPS record too short"));
        }

        let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
        let (target, name_len) = self.parse_domain_name_from_rdata(&rdata[2..], full_packet)?;
        
        let params = self.parse_svc_params(&rdata[2 + name_len..])?;

        Ok(ParsedRecordData::HTTPS { priority, target, params })
    }

    /// Parse SVCB record
    fn parse_svcb_record(&self, rdata: &[u8], full_packet: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() < 2 {
            return Err(DnsError::invalid_packet("SVCB record too short"));
        }

        let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
        let (target, name_len) = self.parse_domain_name_from_rdata(&rdata[2..], full_packet)?;
        
        let params = self.parse_svc_params(&rdata[2 + name_len..])?;

        Ok(ParsedRecordData::SVCB { priority, target, params })
    }

    /// Parse service parameters for SVCB/HTTPS records
    fn parse_svc_params(&self, data: &[u8]) -> DnsResult<Vec<(u16, Bytes)>> {
        let mut params = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            if offset + 4 > data.len() {
                break; // Not enough data for key + length
            }

            let key = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + length > data.len() {
                return Err(DnsError::invalid_packet("SVC param value extends beyond RDATA"));
            }

            let value = Bytes::copy_from_slice(&data[offset..offset + length]);
            params.push((key, value));
            offset += length;
        }

        Ok(params)
    }

    /// Parse NSEC3PARAM record
    fn parse_nsec3param_record(&self, rdata: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() < 5 {
            return Err(DnsError::invalid_packet("NSEC3PARAM record too short"));
        }

        let hash_algorithm = rdata[0];
        let flags = rdata[1];
        let iterations = u16::from_be_bytes([rdata[2], rdata[3]]);
        let salt_length = rdata[4] as usize;

        if 5 + salt_length > rdata.len() {
            return Err(DnsError::invalid_packet("NSEC3PARAM salt extends beyond RDATA"));
        }

        let salt = Bytes::copy_from_slice(&rdata[5..5 + salt_length]);

        Ok(ParsedRecordData::NSEC3PARAM {
            hash_algorithm, flags, iterations, salt
        })
    }

    /// Parse CDS record (same format as DS)
    fn parse_cds_record(&self, rdata: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() < 4 {
            return Err(DnsError::invalid_packet("CDS record too short"));
        }

        let key_tag = u16::from_be_bytes([rdata[0], rdata[1]]);
        let algorithm = rdata[2];
        let digest_type = rdata[3];
        let digest = Bytes::copy_from_slice(&rdata[4..]);

        Ok(ParsedRecordData::CDS { key_tag, algorithm, digest_type, digest })
    }

    /// Parse CDNSKEY record (same format as DNSKEY)
    fn parse_cdnskey_record(&self, rdata: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() < 4 {
            return Err(DnsError::invalid_packet("CDNSKEY record too short"));
        }

        let flags = u16::from_be_bytes([rdata[0], rdata[1]]);
        let protocol = rdata[2];
        let algorithm = rdata[3];
        let public_key = Bytes::copy_from_slice(&rdata[4..]);

        Ok(ParsedRecordData::CDNSKEY { flags, protocol, algorithm, public_key })
    }

    /// Parse SMIMEA record (same format as TLSA)
    fn parse_smimea_record(&self, rdata: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() < 3 {
            return Err(DnsError::invalid_packet("SMIMEA record too short"));
        }

        let cert_usage = rdata[0];
        let selector = rdata[1];
        let matching_type = rdata[2];
        let cert_data = Bytes::copy_from_slice(&rdata[3..]);

        Ok(ParsedRecordData::SMIMEA { cert_usage, selector, matching_type, cert_data })
    }

    /// Parse NAPTR record
    fn parse_naptr_record(&self, rdata: &[u8], full_packet: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() < 7 {
            return Err(DnsError::invalid_packet("NAPTR record too short"));
        }

        let order = u16::from_be_bytes([rdata[0], rdata[1]]);
        let preference = u16::from_be_bytes([rdata[2], rdata[3]]);
        
        let mut offset = 4;
        
        // Parse flags string
        if offset >= rdata.len() {
            return Err(DnsError::invalid_packet("NAPTR flags missing"));
        }
        let flags_len = rdata[offset] as usize;
        offset += 1;
        
        if offset + flags_len > rdata.len() {
            return Err(DnsError::invalid_packet("NAPTR flags extend beyond RDATA"));
        }
        let flags = String::from_utf8_lossy(&rdata[offset..offset + flags_len]).into_owned();
        offset += flags_len;

        // Parse services string
        if offset >= rdata.len() {
            return Err(DnsError::invalid_packet("NAPTR services missing"));
        }
        let services_len = rdata[offset] as usize;
        offset += 1;
        
        if offset + services_len > rdata.len() {
            return Err(DnsError::invalid_packet("NAPTR services extend beyond RDATA"));
        }
        let services = String::from_utf8_lossy(&rdata[offset..offset + services_len]).into_owned();
        offset += services_len;

        // Parse regexp string
        if offset >= rdata.len() {
            return Err(DnsError::invalid_packet("NAPTR regexp missing"));
        }
        let regexp_len = rdata[offset] as usize;
        offset += 1;
        
        if offset + regexp_len > rdata.len() {
            return Err(DnsError::invalid_packet("NAPTR regexp extends beyond RDATA"));
        }
        let regexp = String::from_utf8_lossy(&rdata[offset..offset + regexp_len]).into_owned();
        offset += regexp_len;

        // Parse replacement domain name
        let (replacement, _) = self.parse_domain_name_from_rdata(&rdata[offset..], full_packet)?;

        Ok(ParsedRecordData::NAPTR {
            order, preference, flags, services, regexp, replacement
        })
    }

    /// Parse OPENPGPKEY record
    fn parse_openpgpkey_record(&self, rdata: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.is_empty() {
            return Err(DnsError::invalid_packet("OPENPGPKEY record cannot be empty"));
        }

        let key_data = Bytes::copy_from_slice(rdata);
        Ok(ParsedRecordData::OPENPGPKEY { key_data })
    }

    /// Parse CSYNC record
    fn parse_csync_record(&self, rdata: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() < 6 {
            return Err(DnsError::invalid_packet("CSYNC record too short"));
        }

        let serial = u32::from_be_bytes([rdata[0], rdata[1], rdata[2], rdata[3]]);
        let flags = u16::from_be_bytes([rdata[4], rdata[5]]);
        let type_bit_maps = Bytes::copy_from_slice(&rdata[6..]);

        Ok(ParsedRecordData::CSYNC { serial, flags, type_bit_maps })
    }

    /// Parse ZONEMD record
    fn parse_zonemd_record(&self, rdata: &[u8]) -> DnsResult<ParsedRecordData> {
        if rdata.len() < 6 {
            return Err(DnsError::invalid_packet("ZONEMD record too short"));
        }

        let serial = u32::from_be_bytes([rdata[0], rdata[1], rdata[2], rdata[3]]);
        let scheme = rdata[4];
        let hash_algorithm = rdata[5];
        let digest = Bytes::copy_from_slice(&rdata[6..]);

        Ok(ParsedRecordData::ZONEMD { serial, scheme, hash_algorithm, digest })
    }

    /// Parse domain name from RDATA (handles compression relative to full packet)
    fn parse_domain_name_from_rdata(&self, rdata: &[u8], _full_packet: &[u8]) -> DnsResult<(String, usize)> {
        // For now, assume no compression in RDATA (simplified)
        // In a full implementation, we'd need to handle compression pointers
        // that reference the full packet
        self.parse_domain_name(rdata, 0)
    }
}

impl Default for DnsPacketParser {
    fn default() -> Self {
        Self::new()
    }
}