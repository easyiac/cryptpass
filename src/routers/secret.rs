use crate::{
    routers::ServerError::{self, InternalServerError, MethodNotAllowed, NotFound},
    AppState,
};
use axum::{
    extract::{Path, State},
    http::{Method, Response, StatusCode},
    response::IntoResponse,
};
use tracing::{debug, info};

pub(crate) async fn secret(
    method: Method,
    Path(path): Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Result<impl IntoResponse, ServerError> {
    info!("Received request for key: {}", path);
    let mut storage = state.physical;

    match method.as_str() {
        "GET" => {
            let value = storage
                .read(&path)
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
                debug!("Key not found: {}", path);
                Err(NotFound(format!("Key not found: {}", path)))
            }
        }
        "POST" => {
            debug!("Received body: {}", body);
            let write_res = storage.write(&path, &body).await;

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
            if let Err(e) = storage.delete(&path).await {
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
