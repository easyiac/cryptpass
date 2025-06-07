use crate::error::{CryptPassError, CryptPassErrorDetails};
use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub(crate) struct Health {
    pub(crate) status: &'static str,
}

#[utoipa::path(
    get,
    path = "/perpetual/health",
    tag = "Perpetual",
    summary = "Check application health status.",
    description = "Returns the health status of the CryptPass application. Useful for monitoring and readiness checks. Responds with a simple status message.",
    responses(
        (status = 200, description = "Health check successful.", body = Health),
        (status = 500, description = "Internal server error.", body = CryptPassErrorDetails),
    ),
    security(),
)]
pub(crate) async fn health_handler() -> Result<Json<Health>, CryptPassError> {
    Ok(Json(Health { status: "OK" }))
}
