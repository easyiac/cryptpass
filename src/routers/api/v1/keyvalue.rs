use crate::{
    error::CryptPassErrorDetails,
    init::AppState,
    physical::models::KeyValue,
    routers::CryptPassError::{self, BadRequest, InternalServerError, NotFound},
    services,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;
use utoipa::{IntoParams, ToSchema};

#[derive(Deserialize, IntoParams, ToSchema)]
pub(crate) struct VersionQuery {
    version: Option<i32>,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct KeyValueData {
    data: Value,
}

pub(crate) async fn api() -> Router<AppState> {
    Router::new()
        .route("/details/{*key}", get(details))
        .route("/data/{*key}", get(get_data))
        .route("/data/{*key}", put(update_data))
        .route("/data/{*key}", delete(delete_data))
        .route("/list", get(list_all_keys))
        .route("/list/", get(list_all_keys))
        .route("/list/{*key}", get(list_selective_keys))
}

#[utoipa::path(
    get,
    path = "/api/v1/keyvalue/data/{key}",
    tag = "Key-Value",
    summary = "Fetch the value for a specific key.",
    description = "Retrieve the value associated with a given key. Optionally, a specific version can be requested. Returns the value as JSON if found, or an error if the key does not exist or access is unauthorized.",
    params(
        ("key" = String, Path, description = "Key to read the value for."),
        VersionQuery,
    ),
    responses(
        (status = 200, description = "Value found for the key.", body = KeyValueData),
        (status = 401, description = "Unauthorized access.", body = CryptPassErrorDetails),
        (status = 404, description = "Key not found.", body = CryptPassErrorDetails),
        (status = 500, description = "Internal server error.", body = CryptPassErrorDetails),
    ),
    security(
        ("cryptpass_auth_info" = []),
    ),
)]
pub(crate) async fn get_data(
    Path(key): Path<String>,
    Query(version_query): Query<VersionQuery>,
    State(shared_state): State<AppState>,
) -> Result<(StatusCode, Json<KeyValueData>), CryptPassError> {
    info!("Key Value data api request for key: {}", key);
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;
    let version = version_query.version;
    let existing_data = conn
        .interact(move |conn| services::key_value::read(key.as_str(), version, conn))
        .await
        .map_err(|ex| InternalServerError(format!("Error interacting with database: {}", ex)))??;
    if let Some(existing_data) = existing_data {
        Ok((
            StatusCode::OK,
            Json(KeyValueData {
                data: serde_json::from_str::<Value>(&existing_data)
                    .map_err(|ex| InternalServerError(format!("Error parsing JSON: {}", ex)))?,
            }),
        ))
    } else {
        Err(NotFound("Key not found".to_string()))
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/keyvalue/data/{key}",
    tag = "Key-Value",
    summary = "Create or update the value for a key.",
    description = "Create a new value or update the existing value for a given key. Supports versioning: if a version is provided, updates that version; otherwise, creates a new version. Accepts a JSON body with the value.",
    params(
        ("key" = String, Path, description = "Key to write or update."),
        VersionQuery,
    ),
    responses(
        (status = 201, description = "Value written or updated successfully."),
        (status = 401, description = "Unauthorized access.", body = CryptPassErrorDetails),
        (status = 404, description = "Key not found for update.", body = CryptPassErrorDetails),
        (status = 500, description = "Internal server error.", body = CryptPassErrorDetails),
    ),
    request_body(
        content_type = "application/json",
        content = KeyValueData,
        description = "JSON object containing the value to store.",
    ),
    security(
        ("cryptpass_auth_info" = []),
    ),
)]
pub(crate) async fn update_data(
    Path(key): Path<String>,
    Query(version_query): Query<VersionQuery>,
    State(shared_state): State<AppState>,
    body: Json<KeyValueData>,
) -> Result<impl IntoResponse, CryptPassError> {
    info!("Key Value update data api request for key: {}", key);
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;
    let body_str =
        serde_json::to_string(&body.data).map_err(|ex| BadRequest(format!("Unable to parse data: {}", ex)))?;

    let version = version_query.version;
    let new_version = conn
        .interact(move |conn| services::key_value::write(&key, &body_str, version, conn))
        .await
        .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
    Ok((StatusCode::CREATED, Json(serde_json::json!({"version": new_version}))))
}

#[utoipa::path(
    delete,
    path = "/api/v1/keyvalue/data/{key}",
    tag = "Key-Value",
    summary = "Delete a key or a specific version.",
    description = "Delete the value for a given key, or a specific version if provided. If the key or version does not exist, the operation is a no-op. Returns no content on success.",
    params(
        ("key" = String, Path, description = "Key to delete."),
        VersionQuery,
    ),
    responses(
        (status = 204, description = "Key or version deleted (or did not exist)."),
        (status = 401, description = "Unauthorized access.", body = CryptPassErrorDetails),
        (status = 500, description = "Internal server error.", body = CryptPassErrorDetails),
    ),
    security(
        ("cryptpass_auth_info" = []),
    ),
)]
pub(crate) async fn delete_data(
    Path(key): Path<String>,
    Query(version_query): Query<VersionQuery>,
    State(shared_state): State<AppState>,
) -> Result<impl IntoResponse, CryptPassError> {
    info!("Key Value delete data api request for key: {}", key);
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;
    conn.interact(move |conn| services::key_value::mark_version_for_delete(key.as_str(), version_query.version, conn))
        .await
        .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/keyvalue/details/{key}",
    tag = "Key-Value",
    summary = "Get metadata for a key.",
    description = "Retrieve metadata (such as creation time, version, etc.) for a given key. Does not return the value itself. Useful for auditing and management.",
    params(
        ("key" = String, Path, description = "Key to fetch metadata for."),
        VersionQuery,
    ),
    responses(
        (status = 200, description = "Metadata for the key.", body = KeyValue),
        (status = 401, description = "Unauthorized access.", body = CryptPassErrorDetails),
        (status = 404, description = "Key not found.", body = CryptPassErrorDetails),
        (status = 500, description = "Internal server error.", body = CryptPassErrorDetails),
    ),
    security(
        ("cryptpass_auth_info" = []),
    ),
)]
async fn details(
    Path(key): Path<String>,
    Query(version_query): Query<VersionQuery>,
    State(shared_state): State<AppState>,
) -> Result<impl IntoResponse, CryptPassError> {
    info!("Received keyvalue details request for key: {}", key);
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;
    let version = version_query.version;
    let value = conn
        .interact(move |conn| services::key_value::get_details(&key, version, conn))
        .await
        .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
    if let Some(value) = value {
        Ok((StatusCode::OK, Json(value)))
    } else {
        Err(NotFound("Key not found".to_string()))
    }
}

#[derive(Serialize, ToSchema)]
pub(crate) struct KeyValueList {
    data: Vec<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/keyvalue/list/{key}",
    tag = "Key-Value",
    summary = "List nested keys under a prefix.",
    description = "List all keys that are nested under the given key prefix. Useful for browsing hierarchical key structures.",
    params(
        ("key" = String, Path, description = "Key prefix to list nested keys for."),
    ),
    responses(
        (status = 200, description = "List of nested keys.", body = KeyValueList),
        (status = 401, description = "Unauthorized access.", body = CryptPassErrorDetails),
        (status = 404, description = "Key prefix not found.", body = CryptPassErrorDetails),
        (status = 500, description = "Internal server error.", body = CryptPassErrorDetails),
    ),
    security(
        ("cryptpass_auth_info" = []),
    ),
)]
async fn list_selective_keys(
    Path(key): Path<String>,
    State(shared_state): State<AppState>,
) -> Result<(StatusCode, Json<KeyValueList>), CryptPassError> {
    list_keys(key, shared_state).await
}

#[utoipa::path(
    get,
    path = "/api/v1/keyvalue/list",
    tag = "Key-Value",
    summary = "List all keys in the store.",
    description = "Retrieve a flat list of all keys currently stored in the key-value store. Useful for administrative and backup purposes.",
    responses(
        (status = 200, description = "List of all keys.", body = KeyValueList),
        (status = 401, description = "Unauthorized access.", body = CryptPassErrorDetails),
        (status = 404, description = "No keys found.", body = CryptPassErrorDetails),
    ),
    security(
        ("cryptpass_auth_info" = []),
    ),
)]
async fn list_all_keys(
    State(shared_state): State<AppState>,
) -> Result<(StatusCode, Json<KeyValueList>), CryptPassError> {
    list_keys("".to_string(), shared_state).await
}

async fn list_keys(key: String, shared_state: AppState) -> Result<(StatusCode, Json<KeyValueList>), CryptPassError> {
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;
    info!("Listing keys for {}", key);
    let keys = conn
        .interact(move |conn| services::key_value::list_all_keys(&key, conn))
        .await
        .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
    Ok((StatusCode::OK, Json(KeyValueList { data: keys })))
}
