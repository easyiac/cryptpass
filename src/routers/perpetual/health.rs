use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;
use crate::error::{CryptPassError, CryptPassErrorResponse};

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "Perpetual",
    responses(
        (status = 200, description = "Health Response", body = HealthResponse),
        (status = 500, description = "Internal server error", body = CryptPassErrorResponse)
    ),
    security()
)]
pub(crate) async fn health_handler() -> Result<Json<HealthResponse>, CryptPassError> {
    Ok(Json(HealthResponse { status: "OK" }))
}
