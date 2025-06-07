use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use tracing::warn;
use utoipa::ToSchema;

// Export the macros module
pub mod macros;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct CryptPassErrorDetails {
    pub(crate) error: String,
    #[serde(rename = "correlation-id")]
    pub(crate) correlation_id: Option<String>,
    #[serde(rename = "caused-by")]
    pub(crate) caused_by: Option<String>,
}

impl Display for CryptPassErrorDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Error: {} - {}, Caused By: {}.",
            self.error,
            self.correlation_id.clone().unwrap_or("No Correlation ID".to_string()),
            self.caused_by.clone().unwrap_or("No Caused By".to_string())
        )
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) enum CryptPassError {
    RouterError(CryptPassErrorDetails),
    NotFound(CryptPassErrorDetails),
    InternalServerError(CryptPassErrorDetails),
    Unauthorized(CryptPassErrorDetails),
    MethodNotAllowed(CryptPassErrorDetails),
    BadRequest(CryptPassErrorDetails),
    ApplicationNotInitialized(CryptPassErrorDetails),
    ApplicationNotUnlocked(CryptPassErrorDetails),
}

impl Display for CryptPassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptPassError::NotFound(e) => write!(f, "Not Found: {}.", e),
            CryptPassError::InternalServerError(e) => write!(f, "Internal Server Error: {}.", e),
            CryptPassError::Unauthorized(e) => write!(f, "Unauthorized: {}.", e),
            CryptPassError::MethodNotAllowed(e) => write!(f, "Method Not Allowed: {}.", e),
            CryptPassError::RouterError(e) => write!(f, "Router Error: {}.", e),
            CryptPassError::BadRequest(e) => write!(f, "Bad Request: {}.", e),
            CryptPassError::ApplicationNotInitialized(e) => write!(f, "Application Not Initialized: {}.", e),
            CryptPassError::ApplicationNotUnlocked(e) => write!(f, "Application Not Unlocked: {}.", e),
        }
    }
}
impl IntoResponse for CryptPassError {
    fn into_response(self) -> Response {
        match self {
            CryptPassError::NotFound(ex) => {
                warn!("Not Found: {}.", ex);
                (StatusCode::NOT_FOUND, axum::Json(ex)).into_response()
            }
            CryptPassError::InternalServerError(ex) => {
                warn!("Internal Server Error: {}.", ex);
                (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(ex)).into_response()
            }
            CryptPassError::Unauthorized(ex) => {
                warn!("Unauthorized: {}.", ex);
                (StatusCode::UNAUTHORIZED, axum::Json(ex)).into_response()
            }
            CryptPassError::MethodNotAllowed(ex) => {
                warn!("Method Not Allowed: {}.", ex);
                (StatusCode::METHOD_NOT_ALLOWED, axum::Json(ex)).into_response()
            }
            CryptPassError::RouterError(ex) => {
                warn!("Router Error: {}.", ex);
                panic!("Router Error, RouterErrors are not meant to be returned: {}.", ex)
            }
            CryptPassError::BadRequest(ex) => {
                warn!("Bad Request: {}.", ex);
                (StatusCode::BAD_REQUEST, axum::Json(ex)).into_response()
            }
            CryptPassError::ApplicationNotUnlocked(ex) => {
                warn!("Application Not Unlocked: {}.", ex);
                (StatusCode::FORBIDDEN, axum::Json(ex)).into_response()
            }
            CryptPassError::ApplicationNotInitialized(ex) => {
                warn!("Application Not Initialized: {}.", ex);
                (StatusCode::FORBIDDEN, axum::Json(ex)).into_response()
            }
        }
    }
}
