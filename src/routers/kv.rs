use crate::{
    routers::ServerError::{self, InternalServerError, MethodNotAllowed, NotFound},
    services, SharedState,
};
use axum::{
    extract::{Path, State},
    http::{Method, Response, StatusCode},
    response::IntoResponse,
};
use tracing::{debug, info};
pub(super) async fn kv(
    method: Method,
    Path(key): Path<String>,
    State(shared_state): State<SharedState>,
    body: String,
) -> Result<impl IntoResponse, ServerError> {
    info!("Received request for key: {}", key);
    match method.as_str() {
        "GET" => {
            let value = services::kv::read(&key, &shared_state)
                .await
                .map_err(|ex| InternalServerError(format!("Error reading key: {}", ex)))?;
            debug!("Read value: {:?}", value);
            if let Some(value) = value {
                debug!("Found value: {}", value);
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "text/plain")
                    .body(value)
                    .map_err(|ex| {
                        InternalServerError(format!("Error creating GET response: {}", ex))
                    })?)
            } else {
                debug!("Key not found: {}", key);
                Err(NotFound(format!("Key not found: {}", key)))
            }
        }
        "POST" => {
            debug!("Received body: {}", body);
            let write_res = services::kv::write(&key, &body, &shared_state).await;

            if let Err(e) = write_res {
                Err(InternalServerError(format!("Error writing key: {}", e)))
            } else {
                Ok(Response::builder()
                    .status(StatusCode::CREATED)
                    .header("Content-Type", "text/plain")
                    .body("".to_string())
                    .map_err(|ex| {
                        InternalServerError(format!("Error creating POST response: {}", ex))
                    })?)
            }
        }
        "DELETE" => {
            if let Err(e) = services::kv::delete(&key, &shared_state).await {
                Err(InternalServerError(format!("Error deleting key: {}", e)))
            } else {
                Ok(Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header("Content-Type", "text/plain")
                    .body("".to_string())
                    .map_err(|ex| {
                        InternalServerError(format!("Error creating DELETE response: {}", ex))
                    })?)
            }
        }
        _ => Err(MethodNotAllowed("Method not allowed".to_string())),
    }
}
