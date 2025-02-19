use crate::{routers::ServerError, SharedState};
use axum::{
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::IntoResponse,
};
use std::net::SocketAddr;
use tracing::info;

pub(crate) async fn auth_layer(
    State(shared_state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, ServerError> {
    let uri = request.uri().path();
    let method = request.method().as_str();
    let mut auth_token: Option<String> = None;
    if let Some(header) = request.headers().get("Authorization") {
        auth_token = Some(
            header
                .to_str()
                .map_err(|ex| {
                    ServerError::InternalServerError(format!("Error parsing token: {}", ex))
                })?
                .to_string(),
        );
    }
    let authentication = shared_state
        .write()
        .map_err(|ex| {
            ServerError::InternalServerError(format!("Error getting shared state: {}", ex))
        })?
        .authentication
        .clone();
    let is_authorized = authentication
        .is_authorized(auth_token, method.to_string(), uri.to_string())
        .await
        .map_err(|ex| ServerError::InternalServerError(format!("Error authorizing: {}", ex)))?;
    if is_authorized {
        Ok(next.run(request).await.into_response())
    } else {
        info!("Unauthorized request from: {:?}", addr.to_string());
        Err(ServerError::Unauthorized("Invalid or Missing token".to_string()))
    }
}
