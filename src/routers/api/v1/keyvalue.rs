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
use serde_json::{Map, Value};
use tracing::info;
use utoipa::{IntoParams, ToSchema};

#[derive(Deserialize, IntoParams, ToSchema, Debug, Clone)]
pub(crate) struct VersionQuery {
    version: Option<i32>,
}

#[derive(Deserialize, Serialize, ToSchema, Debug, Clone)]
pub(crate) enum DataValue {
    Object(Map<String, Value>),
    Array(Vec<Value>),
}

#[derive(Deserialize, Serialize, ToSchema, Debug, Clone)]
pub(crate) struct KeyValueData {
    data: DataValue,
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
        .fallback(crate::routers::fallback::fallback_handler)
}

#[utoipa::path(
    get,
    path = "/api/v1/keyvalue/data/{key}",
    tag = "Key-Value",
    summary = "Read a key",
    description = "Read a key",
    params(
        ("key" = String, Path, description = "Key to read"),
        VersionQuery,
    ),
    responses(
        (status = 200, description = "Value found", body = KeyValueData),
        (status = 401, description = "Unauthorized", body = CryptPassErrorDetails),
        (status = 404, description = "Key not found", body = CryptPassErrorDetails),
        (status = 500, description = "Internal server error", body = CryptPassErrorDetails),
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
    let value = conn
        .interact(move |conn| services::key_value::read(key.as_str(), version, conn))
        .await
        .map_err(|ex| InternalServerError(format!("Error interacting with database: {}", ex)))??;
    if let Some(value) = value {
        Ok((
            StatusCode::OK,
            Json(KeyValueData {
                data: serde_json::from_str::<DataValue>(value.clone().as_str())
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
    summary = "Update a key",
    params(
        ("key" = String, Path, description = "Key to write"),
        VersionQuery,
    ),
    description = "Update a key",
    responses(
        (status = 201, description = "Value written"),
        (status = 401, description = "Unauthorized", body = CryptPassErrorDetails),
        (status = 404, description = "Key not found", body = CryptPassErrorDetails),
        (status = 500, description = "Internal server error", body = CryptPassErrorDetails),
    ),
    request_body(
        content_type = "application/json",
        content = KeyValueData,
        description = "Json secret",
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
    info!("Key Value data api request for key: {}", key);
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;
    let body_str =
        serde_json::to_string(&body.data.clone()).map_err(|ex| BadRequest(format!("Unable to parse data: {}", ex)))?;

    let version = version_query.version;
    let new_version = conn
        .interact(move |conn| services::key_value::write(key.as_str(), body_str.as_str(), version, conn))
        .await
        .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
    Ok((StatusCode::CREATED, Json(serde_json::json!({"version": new_version}))))
}

#[utoipa::path(
    delete,
    path = "/api/v1/keyvalue/data/{key}",
    tag = "Key-Value",
    summary = "Delete a key",
    description = "Delete a key",
    params(
        ("key" = String, Path, description = "Key to delete"),
        VersionQuery,
    ),
    responses(
        (status = 204, description = "Key does not exist anymore"),
        (status = 401, description = "Unauthorized", body = CryptPassErrorDetails),
        (status = 500, description = "Internal server error", body = CryptPassErrorDetails),
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
    info!("Key Value data api request for key: {}", key);
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
    summary = "Get key metadata",
    description = "Get key metadata",
    params(
        ("key" = String, Path, description = "Key to read"),
        VersionQuery,
    ),
    responses(
        (status = 200, description = "Key MetaData", body = KeyValue),
        (status = 401, description = "Unauthorized", body = CryptPassErrorDetails),
        (status = 404, description = "Key not found", body = CryptPassErrorDetails),
        (status = 500, description = "Internal server error", body = CryptPassErrorDetails),
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
        .interact(move |conn| services::key_value::get_details(key.as_str(), version, conn))
        .await
        .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
    if let Some(value) = value {
        Ok((StatusCode::OK, Json(value)))
    } else {
        Err(NotFound("Key not found".to_string()))
    }
}

#[derive(Serialize, ToSchema, Debug, Clone, Deserialize)]
pub(crate) struct KeyValueList {
    data: Vec<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/keyvalue/list/{key}",
    tag = "Key-Value",
    summary = "List nested keys",
    description = "List nested keys",
    params(
        ("key" = String, Path, description = "Key to read"),
    ),
    responses(
        (status = 200, description = "List nested of keys", body = KeyValueList),
        (status = 401, description = "Unauthorized", body = CryptPassErrorDetails),
        (status = 404, description = "Key not found", body = CryptPassErrorDetails),
        (status = 500, description = "Internal server error", body = CryptPassErrorDetails),
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
    summary = "List all the keys",
    description = "List all the keys",
    responses(
        (status = 200, description = "List of keys", body = KeyValueList),
        (status = 401, description = "Unauthorized", body = CryptPassErrorDetails),
        (status = 404, description = "Key not found", body = CryptPassErrorDetails),
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
        .interact(move |conn| services::key_value::list_all_keys(key.as_str(), conn))
        .await
        .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
    Ok((StatusCode::OK, Json(KeyValueList { data: keys })))
}
