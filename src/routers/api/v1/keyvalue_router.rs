use crate::{
    routers::CryptPassError::{self, BadRequest, InternalServerError, MethodNotAllowed, NotFound},
    services, AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::{Method, StatusCode},
    response::IntoResponse,
    routing::{any, get},
    Json, Router,
};
use serde::Deserialize;
use serde_json::Value;
use tracing::info;

#[derive(Deserialize)]
pub struct VersionQuery {
    version: Option<i32>,
}

pub(crate) async fn api() -> Router<AppState> {
    Router::new()
        .route("/details/{*key}", any(details))
        .route("/data/{*key}", any(data))
        .route("/list", get(list_all_keys))
        .route("/list/", get(list_all_keys))
        .route("/list/{*key}", get(list_selective_keys))
}

//#[debug_handler]
async fn data(
    method: Method,
    Path(key): Path<String>,
    Query(version_query): Query<VersionQuery>,
    State(shared_state): State<AppState>,
    body: Option<Json<Value>>,
) -> Result<impl IntoResponse, CryptPassError> {
    info!("Key Value data api request for key: {}", key);
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;
    match method.as_str() {
        "GET" => {
            let version = version_query.version;
            let value = conn
                .interact(move |conn| services::key_value::read(key.as_str(), conn, version))
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
        "PUT" => {
            let body_str = body.ok_or_else(|| BadRequest("Missing request body".to_string()))?.to_string();

            let version = version_query.version;
            let new_version = conn
                .interact(move |conn| services::key_value::write(key.as_str(), body_str.as_str(), conn, version))
                .await
                .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
            Ok((StatusCode::CREATED, Json(serde_json::json!({"version": new_version}))))
        }
        "DELETE" => {
            conn.interact(move |conn| {
                services::key_value::mark_version_for_delete(key.as_str(), conn, version_query.version)
            })
            .await
            .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
            Ok((StatusCode::OK, Json(serde_json::json!({}))))
        }
        _ => Err(MethodNotAllowed("Method not allowed".to_string())),
    }
}

async fn details(
    method: Method,
    Path(key): Path<String>,
    Query(version_query): Query<VersionQuery>,
    State(shared_state): State<AppState>,
) -> Result<impl IntoResponse, CryptPassError> {
    info!("Received keyvalue details request for key: {}", key);
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;
    match method.as_str() {
        "GET" => {
            let version = version_query.version;
            let value = conn
                .interact(move |conn| services::key_value::get_details(key.as_str(), conn, version))
                .await
                .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
            if let Some(value) = value {
                let json_body = serde_json::to_value(value)
                    .map_err(|e| InternalServerError(format!("Error parsing JSON: {}", e)))?;
                Ok((StatusCode::OK, Json(json_body)))
            } else {
                Err(NotFound("Key not found".to_string()))
            }
        }
        _ => Err(MethodNotAllowed("Method not allowed".to_string())),
    }
}

async fn list_selective_keys(
    Path(key): Path<String>,
    State(shared_state): State<AppState>,
) -> Result<(StatusCode, Json<Vec<String>>), CryptPassError> {
    list_keys(key, shared_state).await
}

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
