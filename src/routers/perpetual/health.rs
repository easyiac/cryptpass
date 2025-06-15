use crate::{
    error::CryptPassErrorDetails,
    services::{encryption::get_internal_encryption_key, get_settings},
};
use axum::{extract::State, http::StatusCode, Json};
use diesel::SqliteConnection;
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub(crate) struct Health {
    pub(crate) up: bool,
    pub(crate) initialized: bool,
    pub(crate) unlocked: bool,
    pub(crate) error: Option<String>,
}

#[utoipa::path(
    get,
    path = "/perpetual/health",
    tag = "Perpetual",
    summary = "Check application health status.",
    description = "Returns the health status of the CryptPass application, including whether it's running, initialized, and unlocked. Useful for monitoring, readiness checks, and troubleshooting. The response includes detailed status flags and any error messages.",
    responses(
        (status = 200, description = "Health check successful. Application status details returned.", body = Health),
        (status = 500, description = "Internal server error.", body = CryptPassErrorDetails),
    ),
    security(),
)]
pub(crate) async fn health_handler(State(shared_state): State<crate::init::AppState>) -> (StatusCode, Json<Health>) {
    let pool = shared_state.pool;
    let conn = match pool.get().await {
        Ok(conn) => conn,
        Err(ex) => {
            return (
                StatusCode::OK,
                Json(Health { up: false, initialized: false, unlocked: false, error: Option::from(ex.to_string()) }),
            )
        }
    };

    let health = match conn.interact(move |conn| get_health_status(conn)).await {
        Ok(health) => health,
        Err(ex) => {
            return (
                StatusCode::OK,
                Json(Health { up: false, initialized: false, unlocked: false, error: Option::from(ex.to_string()) }),
            )
        }
    };
    return (StatusCode::OK, Json(health));
}

fn get_health_status(conn: &mut SqliteConnection) -> Health {
    let is_initialized = match get_settings("INTERNAL_ENCRYPTION_KEY_ENCRYPTED", conn) {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(ex) => {
            return Health { up: false, initialized: false, unlocked: false, error: Option::from(ex.to_string()) }
        }
    };
    let is_unlocked = match get_internal_encryption_key(conn) {
        Ok(_) => true,
        Err(ex) => {
            return Health { up: false, initialized: true, unlocked: false, error: Option::from(ex.to_string()) }
        }
    };
    Health { up: true, initialized: is_initialized, unlocked: is_unlocked, error: None }
}
