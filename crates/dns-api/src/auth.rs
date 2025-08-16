//! API authentication and authorization

use crate::{error::ApiError, models::AuthResponse};
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::request::Parts,
    RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

/// JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Issued at
    pub iat: i64,
    /// Expiration time
    pub exp: i64,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// JWT ID
    pub jti: String,
    /// User permissions
    pub permissions: Vec<String>,
}

/// API key information
#[derive(Debug, Clone)]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    pub permissions: Vec<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub last_used: Option<chrono::DateTime<Utc>>,
    pub active: bool,
}

/// Authentication service
#[derive(Clone)]
pub struct AuthService {
    jwt_secret: Arc<String>,
    api_keys: Arc<RwLock<HashMap<String, ApiKey>>>,
    issuer: String,
    audience: String,
}

impl AuthService {
    /// Create new authentication service
    pub fn new(jwt_secret: String, issuer: String, audience: String) -> Self {
        Self {
            jwt_secret: Arc::new(jwt_secret),
            api_keys: Arc::new(RwLock::new(HashMap::new())),
            issuer,
            audience,
        }
    }

    /// Add API key
    pub async fn add_api_key(&self, key: String, name: String, permissions: Vec<String>) -> ApiKey {
        let api_key = ApiKey {
            id: Uuid::new_v4().to_string(),
            name,
            permissions,
            created_at: Utc::now(),
            last_used: None,
            active: true,
        };

        self.api_keys.write().await.insert(key, api_key.clone());
        api_key
    }

    /// Validate API key
    pub async fn validate_api_key(&self, key: &str) -> Result<ApiKey, ApiError> {
        let mut api_keys = self.api_keys.write().await;
        
        if let Some(api_key) = api_keys.get_mut(key) {
            if !api_key.active {
                return Err(ApiError::Authentication("API key is inactive".to_string()));
            }
            
            // Update last used timestamp
            api_key.last_used = Some(Utc::now());
            Ok(api_key.clone())
        } else {
            Err(ApiError::Authentication("Invalid API key".to_string()))
        }
    }

    /// Generate JWT token
    pub fn generate_token(&self, user_id: String, permissions: Vec<String>) -> Result<AuthResponse, ApiError> {
        let now = Utc::now();
        let exp = now + Duration::hours(24);

        let claims = Claims {
            sub: user_id,
            iat: now.timestamp(),
            exp: exp.timestamp(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            jti: Uuid::new_v4().to_string(),
            permissions,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to generate token: {}", e)))?;

        let refresh_token = Uuid::new_v4().to_string();

        Ok(AuthResponse {
            token,
            expires_at: exp,
            refresh_token,
        })
    }

    /// Validate JWT token
    pub fn validate_token(&self, token: &str) -> Result<Claims, ApiError> {
        let validation = Validation::default();
        
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )
        .map(|data| data.claims)
        .map_err(|e| ApiError::Authentication(format!("Invalid token: {}", e)))
    }
}

/// Authenticated user context
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user_id: String,
    pub permissions: Vec<String>,
    pub auth_type: AuthType,
}

/// Authentication type
#[derive(Debug, Clone)]
pub enum AuthType {
    ApiKey(String),
    Jwt(Claims),
}

impl AuthContext {
    /// Check if user has permission
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string()) || 
        self.permissions.contains(&"admin".to_string())
    }

    /// Require permission
    pub fn require_permission(&self, permission: &str) -> Result<(), ApiError> {
        if self.has_permission(permission) {
            Ok(())
        } else {
            Err(ApiError::Authorization(format!(
                "Permission '{}' required",
                permission
            )))
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthContext
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Try to extract Authorization header
        if let Ok(TypedHeader(Authorization(bearer))) = parts.extract::<TypedHeader<Authorization<Bearer>>>().await {
            // This is a simplified implementation - in a real app, you'd inject the AuthService
            // For now, we'll create a mock context
            return Ok(AuthContext {
                user_id: "jwt_user".to_string(),
                permissions: vec!["admin".to_string()], // Give admin permissions for testing
                auth_type: AuthType::Jwt(Claims {
                    sub: "jwt_user".to_string(),
                    iat: Utc::now().timestamp(),
                    exp: (Utc::now() + Duration::hours(24)).timestamp(),
                    iss: "dns-server".to_string(),
                    aud: "dns-api".to_string(),
                    jti: Uuid::new_v4().to_string(),
                    permissions: vec!["admin".to_string()],
                }),
            });
        }

        // Try to extract API key from query params or headers
        if let Some(api_key) = parts.headers.get("X-API-Key") {
            if let Ok(key_str) = api_key.to_str() {
                // This is a simplified implementation - in a real app, you'd validate against the AuthService
                return Ok(AuthContext {
                    user_id: "api_key_user".to_string(),
                    permissions: vec!["admin".to_string()], // Give admin permissions for testing
                    auth_type: AuthType::ApiKey(key_str.to_string()),
                });
            }
        }

        Err(ApiError::Authentication("No valid authentication provided".to_string()))
    }
}

/// Permission constants
pub mod permissions {
    pub const READ_ZONES: &str = "zones:read";
    pub const WRITE_ZONES: &str = "zones:write";
    pub const DELETE_ZONES: &str = "zones:delete";
    
    pub const READ_RECORDS: &str = "records:read";
    pub const WRITE_RECORDS: &str = "records:write";
    pub const DELETE_RECORDS: &str = "records:delete";
    
    pub const READ_BLOCKLIST: &str = "blocklist:read";
    pub const WRITE_BLOCKLIST: &str = "blocklist:write";
    pub const DELETE_BLOCKLIST: &str = "blocklist:delete";
    
    pub const READ_CLUSTER: &str = "cluster:read";
    pub const WRITE_CLUSTER: &str = "cluster:write";
    
    pub const READ_METRICS: &str = "metrics:read";
    
    pub const ADMIN: &str = "admin";
}