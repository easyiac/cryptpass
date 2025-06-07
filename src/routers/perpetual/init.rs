use crate::{
    error::{
        CryptPassError::{self, InternalServerError},
        CryptPassErrorDetails,
    },
    init::ApplicationInitializationDetails,
};
use axum::{extract::State, http::StatusCode, Json};

#[utoipa::path(
    post,
    path = "/perpetual/initialize",
    tag = "Perpetual",
    summary = "Initialize the application",
    description = "Initialize the application",
    responses(
        (
            status = 201,
            description = "Internal encryption key details, Not the actual key",
            body = ApplicationInitializationDetails,
        ),
        (status = 400, description = "Bad request", body = CryptPassErrorDetails),
        (status = 500, description = "Internal server error", body = CryptPassErrorDetails),
    ),
    security(),
)]
pub(crate) async fn init_app_handler(
    State(shared_state): State<crate::init::AppState>,
) -> Result<(StatusCode, Json<ApplicationInitializationDetails>), CryptPassError> {
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|ex| InternalServerError(format!("Error getting connection from pool: {}", ex)))?;

    let master_key = conn
        .interact(move |conn| crate::init::init_app(conn))
        .await
        .map_err(|ex| InternalServerError(format!("Error interacting with database: {}", ex)))??;

    Ok((StatusCode::CREATED, Json(master_key)))
}
