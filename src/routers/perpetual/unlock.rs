use crate::{
    error::{
        CryptPassError::{self, InternalServerError},
        CryptPassErrorResponse,
    },
    routers::api::v1::users::UnlockRequestBody,
    services::InternalEncryptionKeySettings,
};
use axum::{extract::State, http::StatusCode, Json};

#[utoipa::path(
    post,
    path = "/unlock",
    tag = "Perpetual",
    responses(
        (
            status = 200,
            description = "Internal encryption key details, Not the actual key",
            body = InternalEncryptionKeySettings
        ),
        (status = 500, description = "Internal server error", body = CryptPassErrorResponse)
    ),
    security()
)]
pub(crate) async fn unlock_handler(
    State(shared_state): State<crate::init::AppState>,
    body: Json<UnlockRequestBody>,
) -> Result<(StatusCode, Json<InternalEncryptionKeySettings>), CryptPassError> {
    let master_key = body.token.clone();
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;

    let set_key = conn
        .interact(move |conn| crate::init::init_unlock(master_key, conn))
        .await
        .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;

    Ok((StatusCode::OK, Json(set_key)))
}
