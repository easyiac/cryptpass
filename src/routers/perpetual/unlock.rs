use crate::{
    error::{
        CryptPassError::{self, InternalServerError},
        CryptPassErrorDetails,
    },
    init::{InternalEncryptionKeyDetails, UnlockDetails},
};
use axum::{extract::State, http::StatusCode, Json};

#[utoipa::path(
    post,
    path = "/perpetual/unlock",
    tag = "Perpetual",
    summary = "Unlock the application with a master key.",
    description = "Unlocks the CryptPass application by providing the master encryption key. This endpoint is required to enable access to encrypted data after startup. Returns internal encryption key details (not the actual key).",
    responses(
        (
            status = 200,
            description = "Application unlocked. Internal encryption key details returned.",
            body = InternalEncryptionKeyDetails,
        ),
        (status = 500, description = "Internal server error.", body = CryptPassErrorDetails),
    ),
    security(),
)]
pub(crate) async fn unlock_handler(
    State(shared_state): State<crate::init::AppState>,
    body: Json<UnlockDetails>,
) -> Result<(StatusCode, Json<InternalEncryptionKeyDetails>), CryptPassError> {
    let unlock_details = body.0;
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|ex| InternalServerError(format!("Error getting connection from pool: {}", ex)))?;

    let set_key = conn
        .interact(move |conn| crate::init::unlock_app(unlock_details, conn))
        .await
        .map_err(|ex| InternalServerError(format!("Error interacting with database: {}", ex)))??;

    Ok((StatusCode::OK, Json(set_key)))
}
