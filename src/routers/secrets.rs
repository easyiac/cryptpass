use crate::{
    physical,
    routers::ServerError::{self, InternalServerError, MethodNotAllowed, NotFound},
    AppState,
};
use axum::{
    extract::{Path, State},
    http::{Method, StatusCode},
    Json,
};
use serde_json::Value;
use tracing::{debug, info};

//#[debug_handler]
pub(super) async fn api(
    method: Method,
    Path(key): Path<String>,
    State(shared_state): State<AppState>,
    body: Option<Json<Value>>,
) -> Result<(StatusCode, Json<Value>), ServerError> {
    info!("Received request for key: {}", key);
    let pool = shared_state.pool;
    let conn = pool
        .get()
        .await
        .map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;
    match method.as_str() {
        "GET" => {
            let value =
                conn.interact(move |conn| physical::read(key.as_str(), conn)).await.map_err(
                    |e| InternalServerError(format!("Error interacting with database: {}", e)),
                )??;
            debug!("Read value: {:?}", value);
            if let Some(value) = value {
                debug!("Found value: {}", value);
                let json_body = serde_json::from_str::<Value>(value.clone().as_str())
                    .map_err(|e| InternalServerError(format!("Error parsing JSON: {}", e)))?;
                Ok((StatusCode::OK, Json(json_body)))
            } else {
                Err(NotFound("Key not found".to_string()))
            }
        }
        "PUT" => {
            let body_str = body.unwrap().to_string();
            info!("Received body: {}", body_str.to_string());
            conn.interact(move |conn| {
                physical::write(key.as_str(), body_str.as_str(), conn).map_err(|ex| {
                    InternalServerError(format!("Error reading from physical: {}", ex))
                })
            })
            .await
            .map_err(|e| {
                InternalServerError(format!("Error interacting with database: {}", e))
            })??;
            Ok((StatusCode::CREATED, Json(serde_json::json!({}))))
        }
        "DELETE" => {
            conn.interact(move |conn| physical::mark_all_version_for_delete(key.as_str(), conn))
                .await
                .map_err(|e| {
                    InternalServerError(format!("Error interacting with database: {}", e))
                })??;
            Ok((StatusCode::CREATED, Json(serde_json::json!({}))))
        }
        _ => Err(MethodNotAllowed("Method not allowed".to_string())),
    }
}
