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
    summary = "Initialize the application and generate master key.",
    description = "Initializes the CryptPass application, generating and storing the master encryption key. This endpoint should be called once during setup. Returns details about the generated key.",
    responses(
        (
            status = 201,
            description = "Application initialized. Master key details returned.",
            body = ApplicationInitializationDetails,
        ),
        (status = 400, description = "Bad request: initialization failed.", body = CryptPassErrorDetails),
        (status = 500, description = "Internal server error.", body = CryptPassErrorDetails),
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
