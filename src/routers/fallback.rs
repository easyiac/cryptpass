use crate::error::CryptPassError;
use axum::{http::StatusCode, response::IntoResponse};

pub(crate) async fn fallback_handler() -> Result<impl IntoResponse, CryptPassError> {
    Ok(StatusCode::UNAUTHORIZED)
}
