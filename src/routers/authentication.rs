use crate::{auth, config, routers::ServerError, AppState};
use axum::{
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::IntoResponse,
};
use std::net::SocketAddr;

pub(super) async fn auth_layer(
    State(shared_state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, ServerError> {
    let configuration = config::INSTANCE.get().expect("Configuration not initialized");

    let uri = request.uri().path().to_string().clone();

    let method = request.method().to_string().clone();

    let mut auth_token: Option<String> = None;
    if let Some(header) = request.headers().clone().get(&configuration.server.auth_header_key) {
        auth_token = header.to_str().ok().map(|s| s.to_string());
    }

    let pool = shared_state.pool;
    let conn = pool
        .get()
        .await
        .map_err(|ex| ServerError::Unauthorized(format!("Error getting connection: {}", ex)))?;
    let auth = conn
        .interact(move |conn| {
            auth::is_authorized(auth_token, uri, method, addr, conn)
                .map_err(|ex| ServerError::Unauthorized(format!("Error authorizing: {}", ex)))
        })
        .await
        .map_err(|ex| {
            ServerError::Unauthorized(format!("Error interacting with connection: {}", ex))
        })?
        .map_err(|ex| ServerError::Unauthorized(format!("Error authorizing: {}", ex)))?;

    if auth.0 {
        Ok(next.run(request).await.into_response())
    } else {
        Err(ServerError::Unauthorized(auth.1))
    }
}
