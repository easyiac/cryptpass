use crate::{
    auth::{is_authorized, username_password_login, LoginRequestBody, LoginResponseBody},
    error::{
        CryptPassError::{self, InternalServerError},
        CryptPassErrorResponse,
    },
    init::{AppState, CRYPTPASS_CONFIG_INSTANCE},
};
use axum::{
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::IntoResponse,
    Json,
};
use std::net::SocketAddr;

#[utoipa::path(
    post,
    path = "/login",
    tag = "Perpetual",
    responses(
        (status = 200, description = "Create login token", body = LoginResponseBody),
        (status = 401, description = "Unauthorized", body = CryptPassErrorResponse),
        (status = 500, description = "Internal server error", body = CryptPassErrorResponse)
    ),
    security()
)]
pub(crate) async fn login_handler(
    State(shared_state): State<AppState>,
    body: Json<LoginRequestBody>,
) -> Result<Json<LoginResponseBody>, CryptPassError> {
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;

    let result = conn
        .interact(move |conn| username_password_login(&body, conn))
        .await
        .map_err(|e| InternalServerError(format!("Error interacting with connection: {}", e)))??;
    Ok(Json(result))
}

pub(super) async fn auth_layer(
    State(shared_state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, CryptPassError> {
    let configuration = CRYPTPASS_CONFIG_INSTANCE.get().expect("Configuration not initialized");

    let uri = request.uri().path().to_string().clone();

    let method = request.method().to_string().clone();

    let mut auth_token: Option<String> = None;

    for (key, value) in request.headers().clone() {
        if key.is_some()
            && (key
                .as_ref()
                .ok_or_else(|| CryptPassError::BadRequest("Bad auth header key".to_string()))?
                .to_string()
                .to_lowercase()
                == configuration.server.auth_header_key.to_lowercase())
        {
            let val_str =
                value.to_str().map_err(|_| CryptPassError::BadRequest("Bad auth header value".to_string()))?;
            auth_token = Some(val_str.to_string());
            break;
        }
    }

    let pool = shared_state.pool;
    let conn = pool.get().await.map_err(|ex| InternalServerError(format!("Error getting connection: {}", ex)))?;
    conn.interact(move |conn| is_authorized(auth_token, uri, method, addr, conn))
        .await
        .map_err(|ex| InternalServerError(format!("Error interacting with connection: {}", ex)))??;

    Ok(next.run(request).await.into_response())
}
