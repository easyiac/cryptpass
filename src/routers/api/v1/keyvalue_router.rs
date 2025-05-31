use crate::{
    error::UtoipaCryptPassError,
    physical::models::KeyValueModel,
    routers::CryptPassError::{self, InternalServerError, NotFound},
    services, init::AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, put},
    Json,
};
use serde::Deserialize;
use serde_json::Value;
use tracing::info;
use utoipa::IntoParams;
use utoipa_axum::router::OpenApiRouter;

#[derive(Deserialize, IntoParams)]
pub struct VersionQuery {
    version: Option<i32>,
}

pub(crate) async fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
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
    params(
        ("key" = String, Path, description = "Key to read"),
        VersionQuery
    ),
    responses(
        (status = 200, description = "Value found", body = Value),
        (status = 401, description = "Unauthorized", body = UtoipaCryptPassError),
        (status = 404, description = "Key not found", body = UtoipaCryptPassError),
        (status = 500, description = "Internal server error", body = UtoipaCryptPassError)
    ),
    security(
        ("api_key" = [])
    )
)]
pub(crate) async fn get_data(
    Path(key): Path<String>,
    Query(version_query): Query<VersionQuery>,
    State(shared_state): State<AppState>,
) -> Result<impl IntoResponse, CryptPassError> {
    info!("Key Value data api request for key: {}", key);
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;
    let version = version_query.version;
    let value = conn
        .interact(move |conn| services::key_value::read(key.as_str(), version, conn))
        .await
        .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
    if let Some(value) = value {
        let json_body = serde_json::from_str::<Value>(value.clone().as_str())
            .map_err(|e| InternalServerError(format!("Error parsing JSON: {}", e)))?;
        Ok((StatusCode::OK, Json(json_body)))
    } else {
        Err(NotFound("Key not found".to_string()))
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/keyvalue/data/{key}",
    tag = "Key-Value",
    params(
        ("key" = String, Path, description = "Key to write"),
        VersionQuery,
    ),
    responses(
        (status = 201, description = "Value written"),
        (status = 401, description = "Unauthorized", body = UtoipaCryptPassError),
        (status = 404, description = "Key not found", body = UtoipaCryptPassError),
        (status = 500, description = "Internal server error", body = UtoipaCryptPassError),
    ),
    request_body(
        content_type = "application/json",
        content = String,
        description = "User to update"
    ),
    security(
        ("api_key" = [])
    )
)]
pub(crate) async fn update_data(
    Path(key): Path<String>,
    Query(version_query): Query<VersionQuery>,
    State(shared_state): State<AppState>,
    body: Json<Value>,
) -> Result<impl IntoResponse, CryptPassError> {
    info!("Key Value data api request for key: {}", key);
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;
    let body_str = body.to_string();

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
    params(
        ("key" = String, Path, description = "Key to delete"),
        VersionQuery,
    ),
    responses(
        (status = 204, description = "Value deleted"),
        (status = 401, description = "Unauthorized", body = UtoipaCryptPassError),
        (status = 404, description = "Key not found", body = UtoipaCryptPassError),
        (status = 500, description = "Internal server error", body = UtoipaCryptPassError),
    ),
    security(
        ("api_key" = [])
    )
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
    params(
        ("key" = String, Path, description = "Key to read"),
        VersionQuery
    ),
    responses(
        (status = 200, description = "Key MetaData", body = KeyValueModel),
        (status = 401, description = "Unauthorized", body = UtoipaCryptPassError),
        (status = 404, description = "Key not found", body = UtoipaCryptPassError),
        (status = 500, description = "Internal server error", body = UtoipaCryptPassError),
    ),
    security(
        ("api_key" = [])
    )
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

#[utoipa::path(
    get,
    path = "/api/v1/keyvalue/list/{key}",
    tag = "Key-Value",
    params(
        ("key" = String, Path, description = "Key to read"),
    ),
    responses(
        (status = 200, description = "List of keys", body = Vec<String>),
        (status = 401, description = "Unauthorized", body = UtoipaCryptPassError),
        (status = 404, description = "Key not found", body = UtoipaCryptPassError),
        (status = 500, description = "Internal server error", body = UtoipaCryptPassError),
    ),
    security(
        ("api_key" = [])
    )
)]
async fn list_selective_keys(
    Path(key): Path<String>,
    State(shared_state): State<AppState>,
) -> Result<(StatusCode, Json<Vec<String>>), CryptPassError> {
    list_keys(key, shared_state).await
}

#[utoipa::path(
    get,
    path = "/api/v1/keyvalue/list",
    tag = "Key-Value",
    responses(
        (status = 200, description = "List of keys", body = Vec<String>),
        (status = 401, description = "Unauthorized", body = UtoipaCryptPassError),
        (status = 404, description = "Key not found", body = UtoipaCryptPassError),
    ),
    security(
        ("api_key" = [])
    )
)]
async fn list_all_keys(
    State(shared_state): State<AppState>,
) -> Result<(StatusCode, Json<Vec<String>>), CryptPassError> {
    list_keys("".to_string(), shared_state).await
}

async fn list_keys(key: String, shared_state: AppState) -> Result<(StatusCode, Json<Vec<String>>), CryptPassError> {
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;
    info!("Listing keys for {}", key);
    let keys = conn
        .interact(move |conn| services::key_value::list_all_keys(key.as_str(), conn))
        .await
        .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
    Ok((StatusCode::OK, Json(keys)))
}
