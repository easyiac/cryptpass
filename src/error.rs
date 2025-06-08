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
    ApplicationNotInitialized,
    ApplicationNotUnlocked,
}

impl Display for CryptPassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptPassError::NotFound(e) => write!(f, "Not Found: {}", e),
            CryptPassError::InternalServerError(e) => write!(f, "Internal Server Error: {}", e),
            CryptPassError::Unauthorized(e) => write!(f, "Unauthorized: {}", e),
            CryptPassError::RouterError(e) => write!(f, "Router Error: {}", e),
            CryptPassError::BadRequest(e) => write!(f, "Bad Request: {}", e),
            CryptPassError::ApplicationNotInitialized => write!(f, "Application Not Initialized.",),
            CryptPassError::ApplicationNotUnlocked => write!(f, "Application Not Unlocked.",),
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
            CryptPassError::ApplicationNotUnlocked => {
                warn!("Application Not Unlocked: {}.", random_uuid);
                let error_body = serde_json::json!(CryptPassErrorDetails {
                    error: "Application Not Unlocked".to_string(),
                    correlation_id: Some(random_uuid)
                });
                (StatusCode::FORBIDDEN, axum::Json(error_body)).into_response()
            }
            CryptPassError::ApplicationNotInitialized => {
                warn!("Application Not Initialized: {}.", random_uuid,);
                let error_body = serde_json::json!(CryptPassErrorDetails {
                    error: "Application Not Initialized".to_string(),
                    correlation_id: Some(random_uuid)
                });
                (StatusCode::FORBIDDEN, axum::Json(error_body)).into_response()
            }
        }
    }
}
