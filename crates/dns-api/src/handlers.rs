//! API request handlers

use crate::{
    auth::{permissions, AuthContext},
    error::{ApiError, ApiResult, ErrorResponse},
    models::*,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use std::{collections::HashMap, sync::Arc};
use uuid::Uuid;
use validator::Validate;

/// Application state
#[derive(Clone)]
pub struct AppState {
    // In a real implementation, these would be actual service instances
    pub zones: Arc<tokio::sync::RwLock<HashMap<String, DnsZone>>>,
    pub records: Arc<tokio::sync::RwLock<HashMap<Uuid, DnsRecord>>>,
    pub blocklist: Arc<tokio::sync::RwLock<HashMap<Uuid, BlocklistEntry>>>,
    pub nodes: Arc<tokio::sync::RwLock<HashMap<String, ClusterNode>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            zones: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            records: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            blocklist: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            nodes: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }
}

// Zone Management Handlers

/// List all zones
#[utoipa::path(
    get,
    path = "/api/v1/zones",
    responses(
        (status = 200, description = "List of zones", body = PaginatedResponse<DnsZone>),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn list_zones(
    auth: AuthContext,
    Query(pagination): Query<PaginationQuery>,
    State(state): State<AppState>,
) -> ApiResult<Json<PaginatedResponse<DnsZone>>> {
    auth.require_permission(permissions::READ_ZONES)?;

    let zones = state.zones.read().await;
    let zones_vec: Vec<DnsZone> = zones.values().cloned().collect();
    
    let page = pagination.page.unwrap_or(1).max(1);
    let per_page = pagination.per_page.unwrap_or(20).min(100);
    let total = zones_vec.len() as u64;
    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
    
    let start = ((page - 1) * per_page) as usize;
    let end = (start + per_page as usize).min(zones_vec.len());
    let page_data = zones_vec[start..end].to_vec();

    let response = PaginatedResponse {
        data: page_data,
        pagination: PaginationMeta {
            page,
            per_page,
            total,
            total_pages,
            has_next: page < total_pages,
            has_prev: page > 1,
        },
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
    };

    Ok(Json(response))
}

/// Get zone by name
#[utoipa::path(
    get,
    path = "/api/v1/zones/{zone_name}",
    responses(
        (status = 200, description = "Zone details", body = ApiResponse<DnsZone>),
        (status = 404, description = "Zone not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    params(
        ("zone_name" = String, Path, description = "Zone name")
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn get_zone(
    auth: AuthContext,
    Path(zone_name): Path<String>,
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<DnsZone>>> {
    auth.require_permission(permissions::READ_ZONES)?;

    let zones = state.zones.read().await;
    let zone = zones.get(&zone_name)
        .ok_or_else(|| ApiError::ZoneNotFound { zone: zone_name })?;

    let response = ApiResponse {
        data: zone.clone(),
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
    };

    Ok(Json(response))
}

/// Create new zone
#[utoipa::path(
    post,
    path = "/api/v1/zones",
    request_body = CreateZoneRequest,
    responses(
        (status = 201, description = "Zone created", body = ApiResponse<DnsZone>),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 409, description = "Zone already exists", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn create_zone(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(request): Json<CreateZoneRequest>,
) -> ApiResult<(StatusCode, Json<ApiResponse<DnsZone>>)> {
    auth.require_permission(permissions::WRITE_ZONES)?;
    request.validate().map_err(|e| ApiError::Validation { 
        errors: e.field_errors().iter().map(|(k, v)| {
            (k.to_string(), v.iter().map(|e| e.to_string()).collect())
        }).collect()
    })?;

    let mut zones = state.zones.write().await;
    
    if zones.contains_key(&request.name) {
        return Err(ApiError::Conflict { 
            message: format!("Zone '{}' already exists", request.name) 
        });
    }

    let zone = DnsZone {
        id: Uuid::new_v4(),
        name: request.name.clone(),
        serial: 1,
        record_count: 1, // SOA record
        size: 0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        status: ZoneStatus::Active,
    };

    zones.insert(request.name, zone.clone());

    let response = ApiResponse {
        data: zone,
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Delete zone
#[utoipa::path(
    delete,
    path = "/api/v1/zones/{zone_name}",
    responses(
        (status = 204, description = "Zone deleted"),
        (status = 404, description = "Zone not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    params(
        ("zone_name" = String, Path, description = "Zone name")
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn delete_zone(
    auth: AuthContext,
    Path(zone_name): Path<String>,
    State(state): State<AppState>,
) -> ApiResult<StatusCode> {
    auth.require_permission(permissions::DELETE_ZONES)?;

    let mut zones = state.zones.write().await;
    
    if zones.remove(&zone_name).is_none() {
        return Err(ApiError::ZoneNotFound { zone: zone_name });
    }

    Ok(StatusCode::NO_CONTENT)
}

// DNS Record Management Handlers

/// List records in a zone
#[utoipa::path(
    get,
    path = "/api/v1/zones/{zone_name}/records",
    responses(
        (status = 200, description = "List of records", body = PaginatedResponse<DnsRecord>),
        (status = 404, description = "Zone not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    params(
        ("zone_name" = String, Path, description = "Zone name")
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn list_records(
    auth: AuthContext,
    Path(zone_name): Path<String>,
    Query(pagination): Query<PaginationQuery>,
    State(state): State<AppState>,
) -> ApiResult<Json<PaginatedResponse<DnsRecord>>> {
    auth.require_permission(permissions::READ_RECORDS)?;

    // Verify zone exists
    let zones = state.zones.read().await;
    if !zones.contains_key(&zone_name) {
        return Err(ApiError::ZoneNotFound { zone: zone_name });
    }
    drop(zones);

    let records = state.records.read().await;
    let zone_records: Vec<DnsRecord> = records.values()
        .filter(|r| r.name.ends_with(&zone_name))
        .cloned()
        .collect();
    
    let page = pagination.page.unwrap_or(1).max(1);
    let per_page = pagination.per_page.unwrap_or(20).min(100);
    let total = zone_records.len() as u64;
    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
    
    let start = ((page - 1) * per_page) as usize;
    let end = (start + per_page as usize).min(zone_records.len());
    let page_data = zone_records[start..end].to_vec();

    let response = PaginatedResponse {
        data: page_data,
        pagination: PaginationMeta {
            page,
            per_page,
            total,
            total_pages,
            has_next: page < total_pages,
            has_prev: page > 1,
        },
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
    };

    Ok(Json(response))
}

/// Create DNS record
#[utoipa::path(
    post,
    path = "/api/v1/zones/{zone_name}/records",
    request_body = CreateRecordRequest,
    responses(
        (status = 201, description = "Record created", body = ApiResponse<DnsRecord>),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 404, description = "Zone not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    params(
        ("zone_name" = String, Path, description = "Zone name")
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn create_record(
    auth: AuthContext,
    Path(zone_name): Path<String>,
    State(state): State<AppState>,
    Json(request): Json<CreateRecordRequest>,
) -> ApiResult<(StatusCode, Json<ApiResponse<DnsRecord>>)> {
    auth.require_permission(permissions::WRITE_RECORDS)?;
    request.validate().map_err(|e| ApiError::Validation { 
        errors: e.field_errors().iter().map(|(k, v)| {
            (k.to_string(), v.iter().map(|e| e.to_string()).collect())
        }).collect()
    })?;

    // Verify zone exists
    let zones = state.zones.read().await;
    if !zones.contains_key(&zone_name) {
        return Err(ApiError::ZoneNotFound { zone: zone_name });
    }
    drop(zones);

    let record_id = Uuid::new_v4();
    let record = DnsRecord {
        id: record_id,
        name: request.name,
        record_type: request.record_type,
        data: request.data,
        ttl: request.ttl.unwrap_or(300),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let mut records = state.records.write().await;
    records.insert(record_id, record.clone());

    let response = ApiResponse {
        data: record,
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Get DNS record by ID
#[utoipa::path(
    get,
    path = "/api/v1/zones/{zone_name}/records/{record_id}",
    responses(
        (status = 200, description = "Record details", body = ApiResponse<DnsRecord>),
        (status = 404, description = "Record not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    params(
        ("zone_name" = String, Path, description = "Zone name"),
        ("record_id" = String, Path, description = "Record ID")
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn get_record(
    auth: AuthContext,
    Path((zone_name, record_id)): Path<(String, String)>,
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<DnsRecord>>> {
    auth.require_permission(permissions::READ_RECORDS)?;

    let record_uuid = Uuid::parse_str(&record_id)
        .map_err(|_| ApiError::RecordNotFound { 
            name: record_id.clone(), 
            record_type: "unknown".to_string() 
        })?;

    let records = state.records.read().await;
    let record = records.get(&record_uuid)
        .ok_or_else(|| ApiError::RecordNotFound { 
            name: record_id, 
            record_type: "unknown".to_string() 
        })?;

    // Verify record belongs to the zone
    if !record.name.ends_with(&zone_name) {
        return Err(ApiError::RecordNotFound { 
            name: record.name.clone(), 
            record_type: format!("{:?}", record.record_type) 
        });
    }

    let response = ApiResponse {
        data: record.clone(),
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
    };

    Ok(Json(response))
}

/// Update DNS record
#[utoipa::path(
    put,
    path = "/api/v1/zones/{zone_name}/records/{record_id}",
    request_body = UpdateRecordRequest,
    responses(
        (status = 200, description = "Record updated", body = ApiResponse<DnsRecord>),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 404, description = "Record not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    params(
        ("zone_name" = String, Path, description = "Zone name"),
        ("record_id" = String, Path, description = "Record ID")
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn update_record(
    auth: AuthContext,
    Path((zone_name, record_id)): Path<(String, String)>,
    State(state): State<AppState>,
    Json(request): Json<UpdateRecordRequest>,
) -> ApiResult<Json<ApiResponse<DnsRecord>>> {
    auth.require_permission(permissions::WRITE_RECORDS)?;
    request.validate().map_err(|e| ApiError::Validation { 
        errors: e.field_errors().iter().map(|(k, v)| {
            (k.to_string(), v.iter().map(|e| e.to_string()).collect())
        }).collect()
    })?;

    let record_uuid = Uuid::parse_str(&record_id)
        .map_err(|_| ApiError::RecordNotFound { 
            name: record_id.clone(), 
            record_type: "unknown".to_string() 
        })?;

    let mut records = state.records.write().await;
    let record = records.get_mut(&record_uuid)
        .ok_or_else(|| ApiError::RecordNotFound { 
            name: record_id, 
            record_type: "unknown".to_string() 
        })?;

    // Verify record belongs to the zone
    if !record.name.ends_with(&zone_name) {
        return Err(ApiError::RecordNotFound { 
            name: record.name.clone(), 
            record_type: format!("{:?}", record.record_type) 
        });
    }

    // Update fields
    if let Some(data) = request.data {
        record.data = data;
    }
    if let Some(ttl) = request.ttl {
        record.ttl = ttl;
    }
    record.updated_at = Utc::now();

    let response = ApiResponse {
        data: record.clone(),
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
    };

    Ok(Json(response))
}

/// Delete DNS record
#[utoipa::path(
    delete,
    path = "/api/v1/zones/{zone_name}/records/{record_id}",
    responses(
        (status = 204, description = "Record deleted"),
        (status = 404, description = "Record not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    params(
        ("zone_name" = String, Path, description = "Zone name"),
        ("record_id" = String, Path, description = "Record ID")
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn delete_record(
    auth: AuthContext,
    Path((zone_name, record_id)): Path<(String, String)>,
    State(state): State<AppState>,
) -> ApiResult<StatusCode> {
    auth.require_permission(permissions::DELETE_RECORDS)?;

    let record_uuid = Uuid::parse_str(&record_id)
        .map_err(|_| ApiError::RecordNotFound { 
            name: record_id.clone(), 
            record_type: "unknown".to_string() 
        })?;

    let mut records = state.records.write().await;
    
    // Check if record exists and belongs to zone
    if let Some(record) = records.get(&record_uuid) {
        if !record.name.ends_with(&zone_name) {
            return Err(ApiError::RecordNotFound { 
                name: record.name.clone(), 
                record_type: format!("{:?}", record.record_type) 
            });
        }
    } else {
        return Err(ApiError::RecordNotFound { 
            name: record_id, 
            record_type: "unknown".to_string() 
        });
    }

    records.remove(&record_uuid);
    Ok(StatusCode::NO_CONTENT)
}
// Blo
// Blocklist Management Handlers

/// List blocklist entries
#[utoipa::path(
    get,
    path = "/api/v1/blocklist",
    responses(
        (status = 200, description = "List of blocklist entries", body = PaginatedResponse<BlocklistEntry>),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn list_blocklist(
    auth: AuthContext,
    Query(pagination): Query<PaginationQuery>,
    State(state): State<AppState>,
) -> ApiResult<Json<PaginatedResponse<BlocklistEntry>>> {
    auth.require_permission(permissions::READ_BLOCKLIST)?;

    let blocklist = state.blocklist.read().await;
    let entries: Vec<BlocklistEntry> = blocklist.values().cloned().collect();
    
    let page = pagination.page.unwrap_or(1).max(1);
    let per_page = pagination.per_page.unwrap_or(20).min(100);
    let total = entries.len() as u64;
    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
    
    let start = ((page - 1) * per_page) as usize;
    let end = (start + per_page as usize).min(entries.len());
    let page_data = entries[start..end].to_vec();

    let response = PaginatedResponse {
        data: page_data,
        pagination: PaginationMeta {
            page,
            per_page,
            total,
            total_pages,
            has_next: page < total_pages,
            has_prev: page > 1,
        },
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
    };

    Ok(Json(response))
}

/// Create blocklist entry
#[utoipa::path(
    post,
    path = "/api/v1/blocklist",
    request_body = CreateBlocklistRequest,
    responses(
        (status = 201, description = "Blocklist entry created", body = ApiResponse<BlocklistEntry>),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn create_blocklist_entry(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(request): Json<CreateBlocklistRequest>,
) -> ApiResult<(StatusCode, Json<ApiResponse<BlocklistEntry>>)> {
    auth.require_permission(permissions::WRITE_BLOCKLIST)?;
    request.validate().map_err(|e| ApiError::Validation { 
        errors: e.field_errors().iter().map(|(k, v)| {
            (k.to_string(), v.iter().map(|e| e.to_string()).collect())
        }).collect()
    })?;

    let entry_id = Uuid::new_v4();
    let entry = BlocklistEntry {
        id: entry_id,
        domain: request.domain,
        block_type: request.block_type,
        custom_response: request.custom_response,
        source: request.source.unwrap_or_else(|| "manual".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        active: true,
    };

    let mut blocklist = state.blocklist.write().await;
    blocklist.insert(entry_id, entry.clone());

    let response = ApiResponse {
        data: entry,
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Get blocklist entry by ID
#[utoipa::path(
    get,
    path = "/api/v1/blocklist/{entry_id}",
    responses(
        (status = 200, description = "Blocklist entry details", body = ApiResponse<BlocklistEntry>),
        (status = 404, description = "Entry not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    params(
        ("entry_id" = String, Path, description = "Entry ID")
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn get_blocklist_entry(
    auth: AuthContext,
    Path(entry_id): Path<String>,
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<BlocklistEntry>>> {
    auth.require_permission(permissions::READ_BLOCKLIST)?;

    let entry_uuid = Uuid::parse_str(&entry_id)
        .map_err(|_| ApiError::RecordNotFound { 
            name: entry_id.clone(), 
            record_type: "blocklist".to_string() 
        })?;

    let blocklist = state.blocklist.read().await;
    let entry = blocklist.get(&entry_uuid)
        .ok_or_else(|| ApiError::RecordNotFound { 
            name: entry_id, 
            record_type: "blocklist".to_string() 
        })?;

    let response = ApiResponse {
        data: entry.clone(),
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
    };

    Ok(Json(response))
}

/// Update blocklist entry
#[utoipa::path(
    put,
    path = "/api/v1/blocklist/{entry_id}",
    request_body = UpdateBlocklistRequest,
    responses(
        (status = 200, description = "Blocklist entry updated", body = ApiResponse<BlocklistEntry>),
        (status = 404, description = "Entry not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    params(
        ("entry_id" = String, Path, description = "Entry ID")
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn update_blocklist_entry(
    auth: AuthContext,
    Path(entry_id): Path<String>,
    State(state): State<AppState>,
    Json(request): Json<UpdateBlocklistRequest>,
) -> ApiResult<Json<ApiResponse<BlocklistEntry>>> {
    auth.require_permission(permissions::WRITE_BLOCKLIST)?;

    let entry_uuid = Uuid::parse_str(&entry_id)
        .map_err(|_| ApiError::RecordNotFound { 
            name: entry_id.clone(), 
            record_type: "blocklist".to_string() 
        })?;

    let mut blocklist = state.blocklist.write().await;
    let entry = blocklist.get_mut(&entry_uuid)
        .ok_or_else(|| ApiError::RecordNotFound { 
            name: entry_id, 
            record_type: "blocklist".to_string() 
        })?;

    // Update fields
    if let Some(block_type) = request.block_type {
        entry.block_type = block_type;
    }
    if let Some(custom_response) = request.custom_response {
        entry.custom_response = Some(custom_response);
    }
    if let Some(active) = request.active {
        entry.active = active;
    }
    entry.updated_at = Utc::now();

    let response = ApiResponse {
        data: entry.clone(),
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
    };

    Ok(Json(response))
}

/// Delete blocklist entry
#[utoipa::path(
    delete,
    path = "/api/v1/blocklist/{entry_id}",
    responses(
        (status = 204, description = "Blocklist entry deleted"),
        (status = 404, description = "Entry not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    params(
        ("entry_id" = String, Path, description = "Entry ID")
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn delete_blocklist_entry(
    auth: AuthContext,
    Path(entry_id): Path<String>,
    State(state): State<AppState>,
) -> ApiResult<StatusCode> {
    auth.require_permission(permissions::DELETE_BLOCKLIST)?;

    let entry_uuid = Uuid::parse_str(&entry_id)
        .map_err(|_| ApiError::RecordNotFound { 
            name: entry_id.clone(), 
            record_type: "blocklist".to_string() 
        })?;

    let mut blocklist = state.blocklist.write().await;
    
    if blocklist.remove(&entry_uuid).is_none() {
        return Err(ApiError::RecordNotFound { 
            name: entry_id, 
            record_type: "blocklist".to_string() 
        });
    }

    Ok(StatusCode::NO_CONTENT)
}

// Cluster Management Handlers

/// List cluster nodes
#[utoipa::path(
    get,
    path = "/api/v1/cluster/nodes",
    responses(
        (status = 200, description = "List of cluster nodes", body = PaginatedResponse<ClusterNode>),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn list_cluster_nodes(
    auth: AuthContext,
    Query(pagination): Query<PaginationQuery>,
    State(state): State<AppState>,
) -> ApiResult<Json<PaginatedResponse<ClusterNode>>> {
    auth.require_permission(permissions::READ_CLUSTER)?;

    let nodes = state.nodes.read().await;
    let nodes_vec: Vec<ClusterNode> = nodes.values().cloned().collect();
    
    let page = pagination.page.unwrap_or(1).max(1);
    let per_page = pagination.per_page.unwrap_or(20).min(100);
    let total = nodes_vec.len() as u64;
    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
    
    let start = ((page - 1) * per_page) as usize;
    let end = (start + per_page as usize).min(nodes_vec.len());
    let page_data = nodes_vec[start..end].to_vec();

    let response = PaginatedResponse {
        data: page_data,
        pagination: PaginationMeta {
            page,
            per_page,
            total,
            total_pages,
            has_next: page < total_pages,
            has_prev: page > 1,
        },
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
    };

    Ok(Json(response))
}

/// Get cluster node by ID
#[utoipa::path(
    get,
    path = "/api/v1/cluster/nodes/{node_id}",
    responses(
        (status = 200, description = "Cluster node details", body = ApiResponse<ClusterNode>),
        (status = 404, description = "Node not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    params(
        ("node_id" = String, Path, description = "Node ID")
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn get_cluster_node(
    auth: AuthContext,
    Path(node_id): Path<String>,
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<ClusterNode>>> {
    auth.require_permission(permissions::READ_CLUSTER)?;

    let nodes = state.nodes.read().await;
    let node = nodes.get(&node_id)
        .ok_or_else(|| ApiError::NodeNotFound { node_id })?;

    let response = ApiResponse {
        data: node.clone(),
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
    };

    Ok(Json(response))
}

/// Remove node from cluster
#[utoipa::path(
    delete,
    path = "/api/v1/cluster/nodes/{node_id}",
    responses(
        (status = 204, description = "Node removed from cluster"),
        (status = 404, description = "Node not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    params(
        ("node_id" = String, Path, description = "Node ID")
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn remove_cluster_node(
    auth: AuthContext,
    Path(node_id): Path<String>,
    State(state): State<AppState>,
) -> ApiResult<StatusCode> {
    auth.require_permission(permissions::WRITE_CLUSTER)?;

    let mut nodes = state.nodes.write().await;
    
    if nodes.remove(&node_id).is_none() {
        return Err(ApiError::NodeNotFound { node_id });
    }

    Ok(StatusCode::NO_CONTENT)
}

// Metrics and Statistics Handlers

/// Get server statistics
#[utoipa::path(
    get,
    path = "/api/v1/metrics/stats",
    responses(
        (status = 200, description = "Server statistics", body = ApiResponse<ServerStats>),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn get_server_stats(
    auth: AuthContext,
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<ServerStats>>> {
    auth.require_permission(permissions::READ_METRICS)?;

    // Mock statistics - in real implementation, these would come from actual metrics collectors
    let zones = state.zones.read().await;
    let records = state.records.read().await;
    let blocklist = state.blocklist.read().await;

    let stats = ServerStats {
        total_queries: 1_000_000,
        queries_per_second: 1500.0,
        cache_hit_ratio: 0.85,
        cache_miss_ratio: 0.15,
        blocked_queries: 50_000,
        nxdomain_responses: 25_000,
        active_zones: zones.len() as u32,
        total_records: records.len() as u64,
        memory_usage: MemoryStats {
            total: 512 * 1024 * 1024, // 512MB
            cache: 256 * 1024 * 1024, // 256MB
            zones: 128 * 1024 * 1024, // 128MB
            blocklist: 64 * 1024 * 1024, // 64MB
        },
        uptime: 86400, // 1 day
    };

    let response = ApiResponse {
        data: stats,
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
    };

    Ok(Json(response))
}

/// Health check endpoint
#[utoipa::path(
    get,
    path = "/api/v1/health",
    responses(
        (status = 200, description = "Health check", body = HealthResponse)
    )
)]
pub async fn health_check() -> Json<HealthResponse> {
    let mut checks = HashMap::new();
    
    checks.insert("database".to_string(), ComponentHealth {
        status: "healthy".to_string(),
        error: None,
        last_check: Utc::now(),
    });
    
    checks.insert("cache".to_string(), ComponentHealth {
        status: "healthy".to_string(),
        error: None,
        last_check: Utc::now(),
    });
    
    checks.insert("cluster".to_string(), ComponentHealth {
        status: "healthy".to_string(),
        error: None,
        last_check: Utc::now(),
    });

    let health = HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime: 86400, // Mock uptime
        checks,
    };

    Json(health)
}

/// Authentication endpoint
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    request_body = AuthRequest,
    responses(
        (status = 200, description = "Authentication successful", body = AuthResponse),
        (status = 401, description = "Authentication failed", body = ErrorResponse)
    )
)]
pub async fn authenticate(
    Json(request): Json<AuthRequest>,
) -> ApiResult<Json<AuthResponse>> {
    request.validate().map_err(|e| ApiError::Validation { 
        errors: e.field_errors().iter().map(|(k, v)| {
            (k.to_string(), v.iter().map(|e| e.to_string()).collect())
        }).collect()
    })?;

    // Mock authentication - in real implementation, validate against actual auth service
    if request.key == "admin" && request.password.as_deref() == Some("password") {
        let response = AuthResponse {
            token: "mock_jwt_token".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            refresh_token: Uuid::new_v4().to_string(),
        };
        Ok(Json(response))
    } else {
        Err(ApiError::Authentication("Invalid credentials".to_string()))
    }
}