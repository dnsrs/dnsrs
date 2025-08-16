//! Security error types and result handling

pub type SecurityResult<T> = Result<T, SecurityError>;

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Rate limit exceeded for client")]
    RateLimitExceeded,

    #[error("DDoS protection triggered: {reason}")]
    DdosProtection { reason: String },

    #[error("Invalid DNS packet: {reason}")]
    InvalidPacket { reason: String },

    #[error("TSIG authentication failed: {reason}")]
    TsigAuthenticationFailed { reason: String },

    #[error("Access denied by ACL: {reason}")]
    AccessDenied { reason: String },

    #[error("Audit logging failed: {reason}")]
    AuditLogFailed { reason: String },

    #[error("Configuration error: {reason}")]
    ConfigurationError { reason: String },

    #[error("Internal security error: {reason}")]
    InternalError { reason: String },

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    // DNSSEC-specific errors
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Zone not found: {0}")]
    ZoneNotFound(String),

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("HSM error: {0}")]
    HsmError(String),
}

impl SecurityError {
    pub fn invalid_packet(reason: impl Into<String>) -> Self {
        Self::InvalidPacket {
            reason: reason.into(),
        }
    }

    pub fn tsig_failed(reason: impl Into<String>) -> Self {
        Self::TsigAuthenticationFailed {
            reason: reason.into(),
        }
    }

    pub fn access_denied(reason: impl Into<String>) -> Self {
        Self::AccessDenied {
            reason: reason.into(),
        }
    }

    pub fn ddos_protection(reason: impl Into<String>) -> Self {
        Self::DdosProtection {
            reason: reason.into(),
        }
    }

    pub fn config_error(reason: impl Into<String>) -> Self {
        Self::ConfigurationError {
            reason: reason.into(),
        }
    }

    pub fn internal_error(reason: impl Into<String>) -> Self {
        Self::InternalError {
            reason: reason.into(),
        }
    }

    pub fn audit_failed(reason: impl Into<String>) -> Self {
        Self::AuditLogFailed {
            reason: reason.into(),
        }
    }
}