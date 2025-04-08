use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::fmt::Display;
use tracing::warn;
use uuid::Uuid;
#[derive(Debug)]
pub(crate) enum ServerError {
    RouterError(String),
    NotFound(String),
    InternalServerError(String),
    Unauthorized(String),
    MethodNotAllowed(String),
    BadRequest(String),
}

impl Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::NotFound(e) => write!(f, "Not Found: {}", e),
            ServerError::InternalServerError(e) => write!(f, "Internal Server Error: {}", e),
            ServerError::Unauthorized(e) => write!(f, "Unauthorized: {}", e),
            ServerError::MethodNotAllowed(e) => write!(f, "Method Not Allowed: {}", e),
            ServerError::RouterError(e) => write!(f, "Router Error: {}", e),
            ServerError::BadRequest(e) => write!(f, "Bad Request: {}", e),
        }
    }
}
impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        match self {
            ServerError::NotFound(e) => {
                let error_body = serde_json::json!({ "error": e });
                (StatusCode::NOT_FOUND, axum::Json(error_body)).into_response()
            }
            ServerError::InternalServerError(e) => {
                let random_uuid = Uuid::new_v4().to_string();
                warn!("Internal Server Error: {} - {}", random_uuid, e);
                let error_body =
                    serde_json::json!({ "error": "Internal Server Error", "uuid": random_uuid });
                (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(error_body)).into_response()
            }
            ServerError::Unauthorized(e) => {
                let error_body = serde_json::json!({ "error": e });
                (StatusCode::UNAUTHORIZED, axum::Json(error_body)).into_response()
            }
            ServerError::MethodNotAllowed(e) => {
                let error_body = serde_json::json!({ "error": e });
                (StatusCode::METHOD_NOT_ALLOWED, axum::Json(error_body)).into_response()
            }
            ServerError::RouterError(e) => {
                panic!("Router Error, RouterErrors are not meant to be returned: {}", e)
            }
            ServerError::BadRequest(e) => {
                let error_body = serde_json::json!({ "error": e });
                (StatusCode::BAD_REQUEST, axum::Json(error_body)).into_response()
            }
        }
    }
}
