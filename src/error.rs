use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use tracing::warn;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct CryptPassErrorDetails {
    pub(crate) error: String,
    pub(crate) correlation_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) enum CryptPassError {
    RouterError(String),
    NotFound(String),
    InternalServerError(String),
    Unauthorized(String),
    MethodNotAllowed(String),
    BadRequest(String),
}

impl Display for CryptPassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptPassError::NotFound(e) => write!(f, "Not Found: {}", e),
            CryptPassError::InternalServerError(e) => write!(f, "Internal Server Error: {}", e),
            CryptPassError::Unauthorized(e) => write!(f, "Unauthorized: {}", e),
            CryptPassError::MethodNotAllowed(e) => write!(f, "Method Not Allowed: {}", e),
            CryptPassError::RouterError(e) => write!(f, "Router Error: {}", e),
            CryptPassError::BadRequest(e) => write!(f, "Bad Request: {}", e),
        }
    }
}
impl IntoResponse for CryptPassError {
    fn into_response(self) -> Response {
        let random_uuid = Uuid::new_v4().to_string();
        match self {
            CryptPassError::NotFound(e) => {
                warn!("Not Found: {} - {}", random_uuid, e);
                let error_body =
                    serde_json::json!(CryptPassErrorDetails { error: e, correlation_id: Some(random_uuid) });
                (StatusCode::NOT_FOUND, axum::Json(error_body)).into_response()
            }
            CryptPassError::InternalServerError(e) => {
                warn!("Internal Server Error: {} - {}", random_uuid, e);
                let error_body = serde_json::json!(CryptPassErrorDetails {
                    error: "Internal Server Error".to_string(),
                    correlation_id: Some(random_uuid)
                });
                (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(error_body)).into_response()
            }
            CryptPassError::Unauthorized(e) => {
                warn!("Unauthorized: {} - {}", random_uuid, e);
                let error_body =
                    serde_json::json!(CryptPassErrorDetails { error: e, correlation_id: Some(random_uuid) });
                (StatusCode::UNAUTHORIZED, axum::Json(error_body)).into_response()
            }
            CryptPassError::MethodNotAllowed(e) => {
                warn!("Method Not Allowed: {} - {}", random_uuid, e);
                let error_body =
                    serde_json::json!(CryptPassErrorDetails { error: e, correlation_id: Some(random_uuid) });
                (StatusCode::METHOD_NOT_ALLOWED, axum::Json(error_body)).into_response()
            }
            CryptPassError::RouterError(e) => {
                warn!("Router Error: {} - {}", random_uuid, e);
                panic!("Router Error, RouterErrors are not meant to be returned: {}", e)
            }
            CryptPassError::BadRequest(e) => {
                warn!("Bad Request: {} - {}", random_uuid, e);
                let error_body =
                    serde_json::json!(CryptPassErrorDetails { error: e, correlation_id: Some(random_uuid) });
                (StatusCode::BAD_REQUEST, axum::Json(error_body)).into_response()
            }
        }
    }
}
