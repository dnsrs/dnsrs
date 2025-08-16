//! API error types and handling

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use utoipa::ToSchema;

/// API error types
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Authentication failed: {0}")]
    Authentication(String),
    
    #[error("Authorization failed: {0}")]
    Authorization(String),
    
    #[error("Validation failed: {errors:?}")]
    Validation { errors: HashMap<String, Vec<String>> },
    
    #[error("Zone not found: {zone}")]
    ZoneNotFound { zone: String },
    
    #[error("Record not found: {name} {record_type}")]
    RecordNotFound { name: String, record_type: String },
    
    #[error("Node not found: {node_id}")]
    NodeNotFound { node_id: String },
    
    #[error("Conflict: {message}")]
    Conflict { message: String },
    
    #[error("Rate limit exceeded")]
    RateLimit,
    
    #[error("Internal server error: {0}")]
    Internal(#[from] anyhow::Error),
    
    #[error("DNS core error: {0}")]
    DnsCore(#[from] dns_core::error::DnsError),
    
    #[error("Storage error: {0}")]
    Storage(String),
    
    #[error("Cluster error: {0}")]
    Cluster(String),
}

/// API error response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    /// Error code
    pub error: String,
    /// Human-readable error message
    pub message: String,
    /// Optional error details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// Request ID for tracing
    pub request_id: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_code, message, details) = match self {
            ApiError::Authentication(msg) => (
                StatusCode::UNAUTHORIZED,
                "AUTHENTICATION_FAILED",
                msg,
                None,
            ),
            ApiError::Authorization(msg) => (
                StatusCode::FORBIDDEN,
                "AUTHORIZATION_FAILED",
                msg,
                None,
            ),
            ApiError::Validation { errors } => (
                StatusCode::BAD_REQUEST,
                "VALIDATION_FAILED",
                "Request validation failed".to_string(),
                Some(serde_json::to_value(errors).unwrap_or_default()),
            ),
            ApiError::ZoneNotFound { zone } => (
                StatusCode::NOT_FOUND,
                "ZONE_NOT_FOUND",
                format!("Zone '{}' not found", zone),
                None,
            ),
            ApiError::RecordNotFound { name, record_type } => (
                StatusCode::NOT_FOUND,
                "RECORD_NOT_FOUND",
                format!("Record '{}' of type '{}' not found", name, record_type),
                None,
            ),
            ApiError::NodeNotFound { node_id } => (
                StatusCode::NOT_FOUND,
                "NODE_NOT_FOUND",
                format!("Node '{}' not found", node_id),
                None,
            ),
            ApiError::Conflict { message } => (
                StatusCode::CONFLICT,
                "CONFLICT",
                message,
                None,
            ),
            ApiError::RateLimit => (
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMIT_EXCEEDED",
                "Rate limit exceeded".to_string(),
                None,
            ),
            ApiError::Internal(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Internal server error".to_string(),
                Some(serde_json::json!({ "error": err.to_string() })),
            ),
            ApiError::DnsCore(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "DNS_CORE_ERROR",
                "DNS core error".to_string(),
                Some(serde_json::json!({ "error": err.to_string() })),
            ),
            ApiError::Storage(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORAGE_ERROR",
                "Storage error".to_string(),
                Some(serde_json::json!({ "error": err })),
            ),
            ApiError::Cluster(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "CLUSTER_ERROR",
                "Cluster error".to_string(),
                Some(serde_json::json!({ "error": err })),
            ),
        };

        let error_response = ErrorResponse {
            error: error_code.to_string(),
            message,
            details,
            request_id: uuid::Uuid::new_v4().to_string(),
        };

        (status, Json(error_response)).into_response()
    }
}

/// Result type for API operations
pub type ApiResult<T> = Result<T, ApiError>;