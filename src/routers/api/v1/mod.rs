mod admin_router;
mod keyvalue_router;

use crate::{
    auth,
    error::CryptPassError::{self, InternalServerError},
    AppState, CRYPTPASS_CONFIG_INSTANCE,
};
use axum::{
    extract::{ConnectInfo, Request, State},
    middleware,
    middleware::Next,
    response::IntoResponse,
    Router,
};
use std::net::SocketAddr;

pub(super) async fn api(shared_state: AppState) -> Router<AppState> {
    Router::new()
        .nest("/admin", admin_router::api())
        .nest("/keyvalue", keyvalue_router::api())
        .layer(middleware::from_fn_with_state(shared_state.clone(), auth_layer))
}

async fn auth_layer(
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
            && (key.as_ref().unwrap().to_string().to_lowercase()
                == configuration.server.auth_header_key.to_lowercase())
        {
            let val_str = value
                .to_str()
                .map_err(|_| CryptPassError::BadRequest("Bad auth header value".to_string()))?;
            auth_token = Some(val_str.to_string());
            break;
        }
    }

    let pool = shared_state.pool;
    let conn = pool
        .get()
        .await
        .map_err(|ex| InternalServerError(format!("Error getting connection: {}", ex)))?;
    conn.interact(move |conn| auth::is_authorized(auth_token, uri, method, addr, conn))
        .await
        .map_err(|ex| {
            InternalServerError(format!("Error interacting with connection: {}", ex))
        })??;

    Ok(next.run(request).await.into_response())
}
