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
    summary = "Application health check",
    description = "Application health check results",
    responses(
        (status = 200, description = "Health Response", body = Health),
        (status = 500, description = "Internal server error", body = CryptPassErrorDetails),
    ),
    security(),
)]
pub(crate) async fn health_handler() -> Result<Json<Health>, CryptPassError> {
    Ok(Json(Health { status: "OK" }))
}
