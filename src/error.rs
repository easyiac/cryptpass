use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::fmt::Display;
use tracing::warn;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CryptPassErrorDetails {
    pub(crate) error: String,
    pub(crate) correlation_id: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) enum CryptPassError {
    RouterError(String),
    NotFound(String),
    InternalServerError(String),
    Unauthorized(String),
    BadRequest(String),
    ApplicationNotInitialized(String),
    ApplicationNotUnlocked(String),
}

impl Display for CryptPassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptPassError::NotFound(ex) => write!(f, "Not Found: {}", ex),
            CryptPassError::InternalServerError(ex) => write!(f, "Internal Server Error: {}", ex),
            CryptPassError::Unauthorized(ex) => write!(f, "Unauthorized: {}", ex),
            CryptPassError::RouterError(ex) => write!(f, "Router Error: {}", ex),
            CryptPassError::BadRequest(ex) => write!(f, "Bad Request: {}", ex),
            CryptPassError::ApplicationNotInitialized(ex) => write!(f, "Application Not Initialized: {}", ex),
            CryptPassError::ApplicationNotUnlocked(ex) => write!(f, "Application Not Unlocked: {}", ex),
        }
    }
}
impl IntoResponse for CryptPassError {
    fn into_response(self) -> Response {
        let random_uuid = Uuid::new_v4().to_string();
        match self {
            CryptPassError::NotFound(ex) => {
                warn!("Not Found: {} - {}", random_uuid, ex);
                let error_body =
                    serde_json::json!(CryptPassErrorDetails { error: ex, correlation_id: Some(random_uuid) });
                (StatusCode::NOT_FOUND, axum::Json(error_body)).into_response()
            }
            CryptPassError::InternalServerError(ex) => {
                warn!("Internal Server Error: {} - {}", random_uuid, ex);
                let error_body = serde_json::json!(CryptPassErrorDetails {
                    error: "Internal Server Error".to_string(),
                    correlation_id: Some(random_uuid)
                });
                (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(error_body)).into_response()
            }
            CryptPassError::Unauthorized(ex) => {
                warn!("Unauthorized: {} - {}", random_uuid, ex);
                let error_body =
                    serde_json::json!(CryptPassErrorDetails { error: ex, correlation_id: Some(random_uuid) });
                (StatusCode::UNAUTHORIZED, axum::Json(error_body)).into_response()
            }
            CryptPassError::RouterError(ex) => {
                warn!("Router Error: {} - {}", random_uuid, ex);
                panic!("Router Error, RouterErrors are not meant to be returned: {}", ex)
            }
            CryptPassError::BadRequest(ex) => {
                warn!("Bad Request: {} - {}", random_uuid, ex);
                let error_body =
                    serde_json::json!(CryptPassErrorDetails { error: ex, correlation_id: Some(random_uuid) });
                (StatusCode::BAD_REQUEST, axum::Json(error_body)).into_response()
            }
            CryptPassError::ApplicationNotUnlocked(ex) => {
                warn!("Application Not Unlocked: {} - {}.", random_uuid, ex);
                let error_body = serde_json::json!(CryptPassErrorDetails {
                    error: "Application Not Unlocked".to_string(),
                    correlation_id: Some(random_uuid)
                });
                (StatusCode::FORBIDDEN, axum::Json(error_body)).into_response()
            }
            CryptPassError::ApplicationNotInitialized(ex) => {
                warn!("Application Not Initialized: {} - {}.", random_uuid, ex);
                let error_body = serde_json::json!(CryptPassErrorDetails {
                    error: "Application Not Initialized".to_string(),
                    correlation_id: Some(random_uuid)
                });
                (StatusCode::FORBIDDEN, axum::Json(error_body)).into_response()
            }
        }
    }
}
