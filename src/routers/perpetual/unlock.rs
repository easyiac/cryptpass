use crate::{
    error::{
        CryptPassError::{self, InternalServerError},
        CryptPassErrorDetails,
    },
    init::InternalEncryptionKeyDetails,
};
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub(crate) struct UnlockRequest {
    pub(crate) token: String,
}

#[utoipa::path(
    post,
    path = "/unlock",
    tag = "Perpetual",
    responses(
        (
            status = 200,
            description = "Internal encryption key details, Not the actual key",
            body = InternalEncryptionKeyDetails,
        ),
        (status = 500, description = "Internal server error", body = CryptPassErrorDetails),
    ),
    security(),
)]
pub(crate) async fn unlock_handler(
    State(shared_state): State<crate::init::AppState>,
    body: Json<UnlockRequest>,
) -> Result<(StatusCode, Json<InternalEncryptionKeyDetails>), CryptPassError> {
    let master_key = body.token.clone();
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|ex| InternalServerError(format!("Error getting connection from pool: {}", ex)))?;

    let set_key = conn
        .interact(move |conn| crate::init::init_unlock(master_key, conn))
        .await
        .map_err(|ex| InternalServerError(format!("Error interacting with database: {}", ex)))??;

    Ok((StatusCode::OK, Json(set_key)))
}
