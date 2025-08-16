//! DNSSEC-Aware Query Processor
//!
//! This module provides DNSSEC-aware query processing including:
//! - CD (Checking Disabled) bit support
//! - DO (DNSSEC OK) bit handling in EDNS
//! - Automatic RRSIG inclusion for signed zones
//! - Denial of existence proof generation
//! - DNSSEC validation chain construction

use crate::dnssec::{DnssecValidator, DnssecSigner, ValidationResult, RrsigRecord, DnskeyRecord};
use crate::nsec_chain::{DenialProofGenerator, DenialProof, NsecChainManager};
use crate::{SecurityError, SecurityResult};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// DNSSEC query processing flags
#[derive(Debug, Clone, Copy)]
pub struct DnssecQueryFlags {
    pub checking_disabled: bool,  // CD bit
    pub dnssec_ok: bool,         // DO bit in EDNS
    pub authenticated_data: bool, // AD bit (for responses)
}

impl DnssecQueryFlags {
    pub fn from_dns_flags(flags: u16, edns_flags: Option<u16>) -> Self {
        let checking_disabled = (flags & 0x0010) != 0; // CD bit
        let authenticated_data = (flags & 0x0020) != 0; // AD bit
        let dnssec_ok = edns_flags.map_or(false, |f| (f & 0x8000) != 0); // DO bit in EDNS

        Self {
            checking_disabled,
            dnssec_ok,
            authenticated_data,
        }
    }

    pub fn to_dns_flags(&self) -> u16 {
        let mut flags = 0u16;
        if self.checking_disabled {
            flags |= 0x0010; // CD bit
        }
        if self.authenticated_data {
            flags |= 0x0020; // AD bit
        }
        flags
    }
}

/// DNSSEC query context
#[derive(Debug, Clone)]
pub struct DnssecQueryContext {
    pub query_name: String,
    pub query_type: u16,
    pub query_class: u16,
    pub flags: DnssecQueryFlags,
    pub client_ip: IpAddr,
    pub zone_name: String,
    pub is_authoritative: bool,
}

/// DNSSEC response data
#[derive(Debug, Clone)]
pub struct DnssecResponse {
    pub answer_records: Vec<DnsRecordWithSig>,
    pub authority_records: Vec<DnsRecordWithSig>,
    pub additional_records: Vec<DnsRecordWithSig>,
    pub denial_proof: Option<DenialProof>,
    pub validation_results: Vec<ValidationResult>,
    pub flags: DnssecQueryFlags,
}

/// DNS record with optional RRSIG
#[derive(Debug, Clone)]
pub struct DnsRecordWithSig {
    pub record_data: Bytes,
    pub record_type: u16,
    pub record_class: u16,
    pub ttl: u32,
    pub name: String,
    pub rrsig: Option<RrsigRecord>,
}

/// DNSSEC-aware query processor
pub struct DnssecQueryProcessor {
    /// DNSSEC validator for signature verification
    validator: Arc<DnssecValidator>,
    /// DNSSEC signer for authoritative responses
    signer: Arc<DnssecSigner>,
    /// Denial proof generator
    denial_generator: Arc<DenialProofGenerator>,
    /// Zone configurations
    zone_configs: Arc<RwLock<HashMap<String, ZoneDnssecConfig>>>,
    /// Processing statistics
    stats: Arc<DnssecProcessingStats>,
}

/// DNSSEC configuration per zone
#[derive(Debug, Clone)]
pub struct ZoneDnssecConfig {
    pub is_signed: bool,
    pub auto_sign: bool,
    pub validation_required: bool,
    pub nsec3_enabled: bool,
    pub trust_anchors: Vec<DnskeyRecord>,
}

impl Default for ZoneDnssecConfig {
    fn default() -> Self {
        Self {
            is_signed: false,
            auto_sign: false,
            validation_required: false,
            nsec3_enabled: true,
            trust_anchors: Vec::new(),
        }
    }
}

/// DNSSEC processing statistics
#[derive(Debug)]
pub struct DnssecProcessingStats {
    pub queries_processed: AtomicU64,
    pub dnssec_queries: AtomicU64,
    pub signatures_generated: AtomicU64,
    pub signatures_validated: AtomicU64,
    pub denial_proofs_generated: AtomicU64,
    pub validation_failures: AtomicU64,
    pub cd_bit_queries: AtomicU64,
    pub do_bit_queries: AtomicU64,
}

impl DnssecProcessingStats {
    pub fn new() -> Self {
        Self {
            queries_processed: AtomicU64::new(0),
            dnssec_queries: AtomicU64::new(0),
            signatures_generated: AtomicU64::new(0),
            signatures_validated: AtomicU64::new(0),
            denial_proofs_generated: AtomicU64::new(0),
            validation_failures: AtomicU64::new(0),
            cd_bit_queries: AtomicU64::new(0),
            do_bit_queries: AtomicU64::new(0),
        }
    }
}

impl DnssecQueryProcessor {
    pub fn new(
        validator: Arc<DnssecValidator>,
        signer: Arc<DnssecSigner>,
        denial_generator: Arc<DenialProofGenerator>,
    ) -> Self {
        Self {
            validator,
            signer,
            denial_generator,
            zone_configs: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(DnssecProcessingStats::new()),
        }
    }

    /// Process a DNSSEC-aware query
    pub async fn process_query(
        &self,
        context: DnssecQueryContext,
        base_response: Vec<DnsRecordWithSig>,
    ) -> SecurityResult<DnssecResponse> {
        self.stats.queries_processed.fetch_add(1, Ordering::Relaxed);

        // Track DNSSEC-specific flags
        if context.flags.checking_disabled {
            self.stats.cd_bit_queries.fetch_add(1, Ordering::Relaxed);
        }
        if context.flags.dnssec_ok {
            self.stats.do_bit_queries.fetch_add(1, Ordering::Relaxed);
            self.stats.dnssec_queries.fetch_add(1, Ordering::Relaxed);
        }

        let zone_config = {
            let configs = self.zone_configs.read().await;
            configs.get(&context.zone_name).cloned().unwrap_or_default()
        };

        let mut response = DnssecResponse {
            answer_records: base_response,
            authority_records: Vec::new(),
            additional_records: Vec::new(),
            denial_proof: None,
            validation_results: Vec::new(),
            flags: context.flags,
        };

        // If no records found, generate denial of existence proof
        if response.answer_records.is_empty() && zone_config.is_signed {
            response.denial_proof = self.generate_denial_proof(&context).await?;
        }

        // Add DNSSEC records if DO bit is set
        if context.flags.dnssec_ok {
            self.add_dnssec_records(&context, &zone_config, &mut response).await?;
        }

        // Validate signatures if required and CD bit is not set
        if !context.flags.checking_disabled && zone_config.validation_required {
            response.validation_results = self.validate_response_signatures(&response).await?;
        }

        // Set AD bit if all signatures are valid
        if !response.validation_results.is_empty() {
            let all_valid = response.validation_results.iter().all(|r| r.valid);
            response.flags.authenticated_data = all_valid;
        }

        Ok(response)
    }

    /// Generate denial of existence proof
    async fn generate_denial_proof(&self, context: &DnssecQueryContext) -> SecurityResult<Option<DenialProof>> {
        match self.denial_generator.generate_denial_proof(
            &context.zone_name,
            &context.query_name,
            context.query_type,
        ).await {
            Ok(proof) => {
                self.stats.denial_proofs_generated.fetch_add(1, Ordering::Relaxed);
                info!("Generated denial proof for {} in zone {}", context.query_name, context.zone_name);
                Ok(Some(proof))
            }
            Err(SecurityError::ProofGenerationFailed(_)) => {
                // No proof available, not an error
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Add DNSSEC records to response
    async fn add_dnssec_records(
        &self,
        context: &DnssecQueryContext,
        zone_config: &ZoneDnssecConfig,
        response: &mut DnssecResponse,
    ) -> SecurityResult<()> {
        if !zone_config.is_signed {
            return Ok(());
        }

        // Add RRSIG records for answer records
        for record in &mut response.answer_records {
            if record.rrsig.is_none() && zone_config.auto_sign {
                record.rrsig = self.sign_record(context, record).await?;
            }
        }

        // Add DNSKEY records if queried
        if context.query_type == 48 { // DNSKEY
            let dnskey_records = self.signer.get_dnskey_records(&context.zone_name).await?;
            for dnskey in dnskey_records {
                let dnskey_record = self.dnskey_to_record(&dnskey, &context.zone_name)?;
                
                // Sign DNSKEY record
                let mut signed_record = dnskey_record;
                if zone_config.auto_sign {
                    signed_record.rrsig = self.sign_record(context, &signed_record).await?;
                }
                
                response.answer_records.push(signed_record);
            }
        }

        // Add DS records if queried (for child zones)
        if context.query_type == 43 { // DS
            let ds_records = self.signer.generate_ds_records(
                &context.zone_name,
                &[crate::dnssec::DigestType::Sha256, crate::dnssec::DigestType::Sha384],
            ).await?;
            
            for ds in ds_records {
                let ds_record = self.ds_to_record(&ds, &context.zone_name)?;
                
                // Sign DS record
                let mut signed_record = ds_record;
                if zone_config.auto_sign {
                    signed_record.rrsig = self.sign_record(context, &signed_record).await?;
                }
                
                response.answer_records.push(signed_record);
            }
        }

        // Add denial proof records
        if let Some(ref denial_proof) = response.denial_proof {
            match denial_proof {
                DenialProof::Nsec { nsec_record } => {
                    let nsec_dns_record = self.nsec_to_record(nsec_record, &context.zone_name)?;
                    
                    let mut signed_record = nsec_dns_record;
                    if zone_config.auto_sign {
                        signed_record.rrsig = self.sign_record(context, &signed_record).await?;
                    }
                    
                    response.authority_records.push(signed_record);
                }
                DenialProof::Nsec3 { nsec3_record, nsec3_params } => {
                    // Add NSEC3 record
                    let nsec3_dns_record = self.nsec3_to_record(nsec3_record, &context.zone_name)?;
                    
                    let mut signed_nsec3 = nsec3_dns_record;
                    if zone_config.auto_sign {
                        signed_nsec3.rrsig = self.sign_record(context, &signed_nsec3).await?;
                    }
                    
                    response.authority_records.push(signed_nsec3);
                    
                    // Add NSEC3PARAM record
                    let nsec3param_record = self.nsec3param_to_record(nsec3_params, &context.zone_name)?;
                    response.authority_records.push(nsec3param_record);
                }
            }
        }

        Ok(())
    }

    /// Sign a DNS record
    async fn sign_record(
        &self,
        context: &DnssecQueryContext,
        record: &DnsRecordWithSig,
    ) -> SecurityResult<Option<RrsigRecord>> {
        let rrsig = self.signer.sign_rrset(
            &context.zone_name,
            &record.name,
            record.record_type,
            record.record_class,
            record.ttl,
            &record.record_data,
        ).await?;

        self.stats.signatures_generated.fetch_add(1, Ordering::Relaxed);
        Ok(Some(rrsig))
    }

    /// Validate signatures in response
    async fn validate_response_signatures(
        &self,
        response: &DnssecResponse,
    ) -> SecurityResult<Vec<ValidationResult>> {
        let mut validation_results = Vec::new();

        // Validate answer records
        for record in &response.answer_records {
            if let Some(ref rrsig) = record.rrsig {
                let result = self.validator.validate_rrsig(
                    rrsig,
                    &record.record_data,
                    &record.name,
                    record.record_type,
                    record.record_class,
                    record.ttl,
                ).await?;

                if result.valid {
                    self.stats.signatures_validated.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.stats.validation_failures.fetch_add(1, Ordering::Relaxed);
                }

                validation_results.push(result);
            }
        }

        // Validate authority records
        for record in &response.authority_records {
            if let Some(ref rrsig) = record.rrsig {
                let result = self.validator.validate_rrsig(
                    rrsig,
                    &record.record_data,
                    &record.name,
                    record.record_type,
                    record.record_class,
                    record.ttl,
                ).await?;

                if result.valid {
                    self.stats.signatures_validated.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.stats.validation_failures.fetch_add(1, Ordering::Relaxed);
                }

                validation_results.push(result);
            }
        }

        Ok(validation_results)
    }

    /// Convert DNSKEY to DNS record
    fn dnskey_to_record(&self, dnskey: &DnskeyRecord, zone_name: &str) -> SecurityResult<DnsRecordWithSig> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&dnskey.flags.to_u16().to_be_bytes());
        rdata.push(dnskey.protocol);
        rdata.push(dnskey.algorithm as u8);
        rdata.extend_from_slice(&dnskey.public_key);

        Ok(DnsRecordWithSig {
            record_data: Bytes::from(rdata),
            record_type: 48, // DNSKEY
            record_class: 1, // IN
            ttl: 3600,
            name: zone_name.to_string(),
            rrsig: None,
        })
    }

    /// Convert DS to DNS record
    fn ds_to_record(&self, ds: &crate::dnssec::DsRecord, zone_name: &str) -> SecurityResult<DnsRecordWithSig> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&ds.key_tag.to_be_bytes());
        rdata.push(ds.algorithm as u8);
        rdata.push(ds.digest_type as u8);
        rdata.extend_from_slice(&ds.digest);

        Ok(DnsRecordWithSig {
            record_data: Bytes::from(rdata),
            record_type: 43, // DS
            record_class: 1, // IN
            ttl: 3600,
            name: zone_name.to_string(),
            rrsig: None,
        })
    }

    /// Convert NSEC to DNS record
    fn nsec_to_record(&self, nsec: &crate::nsec_chain::NsecRecord, _zone_name: &str) -> SecurityResult<DnsRecordWithSig> {
        let mut rdata = Vec::new();
        
        // Next domain name in wire format
        for label in nsec.next_domain_name.split('.') {
            if !label.is_empty() {
                rdata.push(label.len() as u8);
                rdata.extend_from_slice(label.as_bytes());
            }
        }
        rdata.push(0); // Root label
        
        // Type bit maps
        rdata.extend_from_slice(&nsec.type_bit_maps);

        Ok(DnsRecordWithSig {
            record_data: Bytes::from(rdata),
            record_type: 47, // NSEC
            record_class: 1, // IN
            ttl: nsec.ttl,
            name: nsec.owner_name.clone(),
            rrsig: None,
        })
    }

    /// Convert NSEC3 to DNS record
    fn nsec3_to_record(&self, nsec3: &crate::nsec_chain::Nsec3Record, _zone_name: &str) -> SecurityResult<DnsRecordWithSig> {
        let mut rdata = Vec::new();
        
        rdata.push(nsec3.hash_algorithm);
        rdata.push(nsec3.flags);
        rdata.extend_from_slice(&nsec3.iterations.to_be_bytes());
        rdata.push(nsec3.salt.len() as u8);
        rdata.extend_from_slice(&nsec3.salt);
        rdata.push(nsec3.next_hashed_owner_name.len() as u8);
        rdata.extend_from_slice(&nsec3.next_hashed_owner_name);
        rdata.extend_from_slice(&nsec3.type_bit_maps);

        Ok(DnsRecordWithSig {
            record_data: Bytes::from(rdata),
            record_type: 50, // NSEC3
            record_class: 1, // IN
            ttl: nsec3.ttl,
            name: nsec3.owner_name.clone(),
            rrsig: None,
        })
    }

    /// Convert NSEC3PARAM to DNS record
    fn nsec3param_to_record(&self, nsec3param: &crate::nsec_chain::Nsec3ParamRecord, zone_name: &str) -> SecurityResult<DnsRecordWithSig> {
        let mut rdata = Vec::new();
        
        rdata.push(nsec3param.hash_algorithm);
        rdata.push(nsec3param.flags);
        rdata.extend_from_slice(&nsec3param.iterations.to_be_bytes());
        rdata.push(nsec3param.salt.len() as u8);
        rdata.extend_from_slice(&nsec3param.salt);

        Ok(DnsRecordWithSig {
            record_data: Bytes::from(rdata),
            record_type: 51, // NSEC3PARAM
            record_class: 1, // IN
            ttl: nsec3param.ttl,
            name: zone_name.to_string(),
            rrsig: None,
        })
    }

    /// Configure DNSSEC for a zone
    pub async fn configure_zone_dnssec(
        &self,
        zone_name: String,
        config: ZoneDnssecConfig,
    ) -> SecurityResult<()> {
        let mut configs = self.zone_configs.write().await;
        configs.insert(zone_name.clone(), config);
        
        info!("Configured DNSSEC for zone: {}", zone_name);
        Ok(())
    }

    /// Add trust anchor for a zone
    pub async fn add_trust_anchor(
        &self,
        zone_name: String,
        dnskey: DnskeyRecord,
    ) -> SecurityResult<()> {
        // Add to validator
        self.validator.add_trusted_anchor(zone_name.clone(), dnskey.clone()).await?;
        
        // Add to zone config
        let mut configs = self.zone_configs.write().await;
        let config = configs.entry(zone_name.clone()).or_insert_with(ZoneDnssecConfig::default);
        config.trust_anchors.push(dnskey);
        
        info!("Added trust anchor for zone: {}", zone_name);
        Ok(())
    }

    /// Get DNSSEC processing statistics
    pub fn get_stats(&self) -> Arc<DnssecProcessingStats> {
        self.stats.clone()
    }

    /// Check if a zone is DNSSEC-enabled
    pub async fn is_zone_dnssec_enabled(&self, zone_name: &str) -> bool {
        let configs = self.zone_configs.read().await;
        configs.get(zone_name).map_or(false, |config| config.is_signed)
    }

    /// Enable DNSSEC for a zone
    pub async fn enable_zone_dnssec(
        &self,
        zone_name: String,
        auto_sign: bool,
        nsec3_enabled: bool,
    ) -> SecurityResult<()> {
        let config = ZoneDnssecConfig {
            is_signed: true,
            auto_sign,
            validation_required: true,
            nsec3_enabled,
            trust_anchors: Vec::new(),
        };

        self.configure_zone_dnssec(zone_name.clone(), config).await?;
        
        // Initialize signing for the zone
        if auto_sign {
            let signing_policy = crate::dnssec::SigningPolicy::default();
            self.signer.initialize_zone_signing(zone_name.clone(), signing_policy).await?;
        }

        info!("Enabled DNSSEC for zone: {}", zone_name);
        Ok(())
    }

    /// Disable DNSSEC for a zone
    pub async fn disable_zone_dnssec(&self, zone_name: &str) -> SecurityResult<()> {
        let mut configs = self.zone_configs.write().await;
        if let Some(config) = configs.get_mut(zone_name) {
            config.is_signed = false;
            config.auto_sign = false;
        }
        
        info!("Disabled DNSSEC for zone: {}", zone_name);
        Ok(())
    }

    /// Get zone DNSSEC configuration
    pub async fn get_zone_config(&self, zone_name: &str) -> Option<ZoneDnssecConfig> {
        let configs = self.zone_configs.read().await;
        configs.get(zone_name).cloned()
    }
}

impl Default for DnssecQueryProcessor {
    fn default() -> Self {
        Self::new(
            Arc::new(DnssecValidator::new()),
            Arc::new(DnssecSigner::new()),
            Arc::new(DenialProofGenerator::new()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_dnssec_flags_parsing() {
        let flags = DnssecQueryFlags::from_dns_flags(0x0010, Some(0x8000));
        assert!(flags.checking_disabled);
        assert!(flags.dnssec_ok);
        assert!(!flags.authenticated_data);
    }

    #[tokio::test]
    async fn test_query_processing() {
        let processor = DnssecQueryProcessor::default();
        
        let context = DnssecQueryContext {
            query_name: "example.com".to_string(),
            query_type: 1, // A
            query_class: 1, // IN
            flags: DnssecQueryFlags {
                checking_disabled: false,
                dnssec_ok: true,
                authenticated_data: false,
            },
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            zone_name: "example.com".to_string(),
            is_authoritative: true,
        };

        let base_response = vec![
            DnsRecordWithSig {
                record_data: Bytes::from(vec![192, 0, 2, 1]),
                record_type: 1, // A
                record_class: 1, // IN
                ttl: 3600,
                name: "example.com".to_string(),
                rrsig: None,
            }
        ];

        let response = processor.process_query(context, base_response).await.unwrap();
        assert_eq!(response.answer_records.len(), 1);
        assert!(response.flags.dnssec_ok);
    }
}