//! DNS Security Module
//! 
//! Provides comprehensive security features for the DNS server including:
//! - Atomic token bucket rate limiting per client IP
//! - DDoS protection with automatic blacklisting
//! - Input validation and bounds checking for DNS packets
//! - TSIG authentication for zone transfers and updates
//! - Access control lists with atomic IP range checking
//! - Audit logging for administrative actions

pub mod rate_limiter;
pub mod ddos_protection;
pub mod packet_validation;
pub mod tsig_auth;
pub mod access_control;
pub mod audit_log;
pub mod error;
pub mod dnssec;
pub mod key_management;
pub mod nsec_chain;
pub mod dnssec_processor;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod dnssec_tests;

pub use error::{SecurityError, SecurityResult};
pub use rate_limiter::{AtomicRateLimiter, AtomicTokenBucket, RateLimitConfig};
pub use ddos_protection::{DdosProtection, DdosConfig, ThreatLevel};
pub use packet_validation::{PacketValidator, ValidationConfig};
pub use tsig_auth::{TsigAuthenticator, TsigConfig, TsigKey};
pub use access_control::{AccessController, AclConfig, IpRange};
pub use audit_log::{AuditLogger, AuditEvent, AuditConfig};
pub use dnssec::{
    DnssecValidator, DnssecSigner, DnssecKeyPair, DnssecAlgorithm, DnssecKeyFlags,
    ValidationResult, RrsigRecord, DnskeyRecord, DsRecord, SigningPolicy
};
pub use key_management::{
    AtomicKeyManager, HsmInterface, MockHsm, KeyRolloverPolicy, KeyInfo
};
pub use nsec_chain::{
    NsecChainManager, NsecRecord, Nsec3Record, Nsec3ParamRecord, DenialProofGenerator, DenialProof
};
pub use dnssec_processor::{
    DnssecQueryProcessor, DnssecQueryContext, DnssecResponse, DnssecQueryFlags,
    ZoneDnssecConfig, DnsRecordWithSig
};

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Main security manager that coordinates all security components
pub struct SecurityManager {
    rate_limiter: Arc<AtomicRateLimiter>,
    ddos_protection: Arc<DdosProtection>,
    packet_validator: Arc<PacketValidator>,
    tsig_authenticator: Arc<TsigAuthenticator>,
    access_controller: Arc<AccessController>,
    audit_logger: Arc<AuditLogger>,
    dnssec_processor: Arc<DnssecQueryProcessor>,
    key_manager: Arc<AtomicKeyManager>,
}

impl SecurityManager {
    pub fn new(
        rate_limit_config: RateLimitConfig,
        ddos_config: DdosConfig,
        validation_config: ValidationConfig,
        tsig_config: TsigConfig,
        acl_config: AclConfig,
        audit_config: AuditConfig,
        key_storage_dir: std::path::PathBuf,
        hsm: Option<Arc<MockHsm>>,
    ) -> SecurityResult<Self> {
        let validator = Arc::new(DnssecValidator::new());
        let signer = Arc::new(DnssecSigner::new());
        let denial_generator = Arc::new(DenialProofGenerator::new());
        let dnssec_processor = Arc::new(DnssecQueryProcessor::new(
            validator,
            signer,
            denial_generator,
        ));
        let key_manager = Arc::new(AtomicKeyManager::new(key_storage_dir, hsm)?);

        Ok(Self {
            rate_limiter: Arc::new(AtomicRateLimiter::new(rate_limit_config)?),
            ddos_protection: Arc::new(DdosProtection::new(ddos_config)?),
            packet_validator: Arc::new(PacketValidator::new(validation_config)?),
            tsig_authenticator: Arc::new(TsigAuthenticator::new(tsig_config)?),
            access_controller: Arc::new(AccessController::new(acl_config)?),
            audit_logger: Arc::new(AuditLogger::new(audit_config)?),
            dnssec_processor,
            key_manager,
        })
    }

    /// Check if a client IP is allowed to make a DNS query
    pub async fn check_query_allowed(&self, client_ip: IpAddr, packet: &[u8]) -> SecurityResult<bool> {
        // 1. Check access control list
        if !self.access_controller.is_allowed(client_ip).await? {
            self.audit_logger.log_blocked_access(client_ip, "ACL_DENIED").await?;
            return Ok(false);
        }

        // 2. Check DDoS protection
        let threat_level = self.ddos_protection.assess_threat(client_ip, packet.len()).await?;
        if threat_level.is_blocked() {
            self.audit_logger.log_ddos_block(client_ip, threat_level).await?;
            return Ok(false);
        }

        // 3. Validate packet structure
        if !self.packet_validator.validate_query_packet(packet).await? {
            self.audit_logger.log_invalid_packet(client_ip, "MALFORMED_QUERY").await?;
            return Ok(false);
        }

        // 4. Check rate limiting
        if !self.rate_limiter.check_rate_limit(client_ip).await? {
            self.audit_logger.log_rate_limit_exceeded(client_ip).await?;
            return Ok(false);
        }

        Ok(true)
    }

    /// Check if a zone transfer request is authenticated and authorized
    pub async fn check_zone_transfer_allowed(
        &self,
        client_ip: IpAddr,
        zone_name: &str,
        tsig_signature: Option<&[u8]>,
    ) -> SecurityResult<bool> {
        // 1. Check access control for zone transfers
        if !self.access_controller.is_zone_transfer_allowed(client_ip, zone_name).await? {
            self.audit_logger.log_unauthorized_zone_transfer(client_ip, zone_name).await?;
            return Ok(false);
        }

        // 2. Verify TSIG authentication if provided
        if let Some(signature) = tsig_signature {
            if !self.tsig_authenticator.verify_signature(zone_name, signature).await? {
                self.audit_logger.log_tsig_failure(client_ip, zone_name).await?;
                return Ok(false);
            }
        }

        self.audit_logger.log_zone_transfer_authorized(client_ip, zone_name).await?;
        Ok(true)
    }

    /// Get current security statistics
    pub async fn get_security_stats(&self) -> SecurityResult<SecurityStats> {
        Ok(SecurityStats {
            rate_limit_stats: self.rate_limiter.get_stats().await?,
            ddos_stats: self.ddos_protection.get_stats().await?,
            validation_stats: self.packet_validator.get_stats().await?,
            tsig_stats: self.tsig_authenticator.get_stats().await?,
            acl_stats: self.access_controller.get_stats().await?,
        })
    }

    /// Get DNSSEC processor
    pub fn dnssec_processor(&self) -> Arc<DnssecQueryProcessor> {
        self.dnssec_processor.clone()
    }

    /// Get key manager
    pub fn key_manager(&self) -> Arc<AtomicKeyManager> {
        self.key_manager.clone()
    }

    /// Enable DNSSEC for a zone
    pub async fn enable_zone_dnssec(
        &self,
        zone_name: String,
        auto_sign: bool,
        nsec3_enabled: bool,
    ) -> SecurityResult<()> {
        self.dnssec_processor.enable_zone_dnssec(zone_name, auto_sign, nsec3_enabled).await
    }

    /// Process a DNSSEC-aware query
    pub async fn process_dnssec_query(
        &self,
        context: DnssecQueryContext,
        base_response: Vec<DnsRecordWithSig>,
    ) -> SecurityResult<DnssecResponse> {
        self.dnssec_processor.process_query(context, base_response).await
    }
}

#[derive(Debug)]
pub struct SecurityStats {
    pub rate_limit_stats: rate_limiter::RateLimitStats,
    pub ddos_stats: ddos_protection::DdosStats,
    pub validation_stats: packet_validation::ValidationStats,
    pub tsig_stats: tsig_auth::TsigStats,
    pub acl_stats: access_control::AclStats,
}

/// Utility function to get current timestamp in milliseconds
pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

/// Utility function to calculate hash for IP address
pub fn hash_ip_address(ip: IpAddr) -> u64 {
    use ahash::AHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = AHasher::default();
    ip.hash(&mut hasher);
    hasher.finish()
}