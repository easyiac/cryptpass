use crate::{
    routers::ServerError::{self, InternalServerError, MethodNotAllowed, NotFound},
    services, AppState,
};
use axum::{
    extract::{Path, State},
    http::{Method, Response, StatusCode},
    response::IntoResponse,
};
use tracing::{debug, info};

pub(crate) async fn kv(
    method: Method,
    Path(key): Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Result<impl IntoResponse, ServerError> {
    info!("Received request for key: {}", key.clone());

    match method.as_str() {
        "GET" => {
            let value = services::kv::read(key.clone(), state)
                .await
                .map_err(|e| InternalServerError(format!("Error reading key: {}", e)))?;
            debug!("Read value: {:?}", value);
            if let Some(value) = value {
                debug!("Found value: {}", value);
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "text/plain")
                    .body(value)
                    .map_err(|e| {
                        InternalServerError(format!("Error creating GET response: {}", e))
                    })?)
            } else {
                debug!("Key not found: {}", key);
                Err(NotFound(format!("Key not found: {}", key)))
            }
        }
        "POST" => {
            debug!("Received body: {}", body);
            let write_res = services::kv::write(key, body, state).await;

            if let Err(e) = write_res {
                Err(InternalServerError(format!("Error writing key: {}", e)))
            } else {
                Ok(Response::builder()
                    .status(StatusCode::CREATED)
                    .header("Content-Type", "text/plain")
                    .body("".to_string())
                    .map_err(|e| {
                        InternalServerError(format!("Error creating POST response: {}", e))
                    })?)
            }
        }
        "DELETE" => {
            if let Err(e) = services::kv::delete(key, state).await {
                Err(InternalServerError(format!("Error deleting key: {}", e)))
            } else {
                Ok(Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header("Content-Type", "text/plain")
                    .body("".to_string())
                    .map_err(|e| {
                        InternalServerError(format!("Error creating DELETE response: {}", e))
                    })?)
            }
        }
        _ => Err(MethodNotAllowed("Method not allowed".to_string())),
    }
}
