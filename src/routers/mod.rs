mod authentication;
mod kv;
mod logging;

use crate::{
    configuration::Server,
    routers::{authentication::auth_layer, kv::kv},
    SharedState,
};
use axum::{
    extract::State,
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::{any, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use std::{fmt::Display, net::SocketAddr, sync::Arc};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug)]
pub(crate) enum ServerError {
    RouterError(String),
    NotFound(String),
    InternalServerError(String),
    Unauthorized(String),
    MethodNotAllowed(String),
}
impl Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::NotFound(e) => write!(f, "Not Found: {}", e),
            ServerError::InternalServerError(e) => write!(f, "Internal Server Error: {}", e),
            ServerError::Unauthorized(e) => write!(f, "Unauthorized: {}", e),
            ServerError::MethodNotAllowed(e) => write!(f, "Method Not Allowed: {}", e),
            ServerError::RouterError(e) => write!(f, "Router Error: {}", e),
        }
    }
}
impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        match self {
            ServerError::NotFound(e) => {
                (StatusCode::NOT_FOUND, format!("Resource Not Found: {}", e)).into_response()
            }
            ServerError::InternalServerError(e) => {
                let random_uuid = Uuid::new_v4().to_string();
                warn!("Internal Server Error: {} - {}", random_uuid, e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Internal Server Error: Check logs for {}", random_uuid),
                )
                    .into_response()
            }
            ServerError::Unauthorized(e) => {
                (StatusCode::UNAUTHORIZED, format!("Unauthorized: {}", e)).into_response()
            }
            ServerError::MethodNotAllowed(e) => {
                (StatusCode::METHOD_NOT_ALLOWED, format!("Method Not Allowed: {}", e))
                    .into_response()
            }
            ServerError::RouterError(e) => {
                panic!("Router Error, RouterErrors are not meant to be returned: {}", e)
            }
        }
    }
}

async fn handle_any() -> Result<impl IntoResponse, ServerError> {
    Err::<Response, ServerError>(ServerError::MethodNotAllowed("Unknown Resource".to_string()))
        as Result<_, ServerError>
}

async fn unlock(
    State(shared_state): State<SharedState>,
    body: String,
) -> Result<impl IntoResponse, ServerError> {
    let master_key = &shared_state
        .write()
        .map_err(|e| {
            ServerError::InternalServerError(format!("Error getting shared state: {}", e))
        })?
        .master_key;

    if let Some(_) = master_key.get() {
        Err(ServerError::InternalServerError("Master key is already set".to_string()))
    } else {
        master_key.get_or_init(|| body);
        Response::builder()
            .status(200)
            .header("Content-Type", "text/plain")
            .body("xx".to_string())
            .map_err(|e| {
                ServerError::InternalServerError(format!("Error creating response: {}", e))
            })
    }
}
async fn handle_health() -> Result<impl IntoResponse, ServerError> {
    Response::builder()
        .status(200)
        .header("Content-Type", "text/plain")
        .body("OK".to_string())
        .map_err(|e| ServerError::InternalServerError(format!("Error creating response: {}", e)))
}

//noinspection HttpUrlsUsage
pub(crate) async fn axum_server(
    server: Server,
    shared_state: SharedState,
) -> Result<(), ServerError> {
    let addr: SocketAddr = server.socket_addr.parse().map_err(|e| {
        ServerError::RouterError(format!(
            "Unable to parse address: {}, error: {}",
            server.socket_addr, e
        ))
    })?;
    let kv_router = Router::new().route("/{*key}", any(kv));
    let app = Router::new()
        .nest("/kv", kv_router)
        .route("/unlock", post(unlock))
        .route("/{*key}", any(handle_any))
        .route("/health", any(handle_health))
        .layer(middleware::from_fn_with_state(Arc::clone(&shared_state), auth_layer))
        .with_state(Arc::clone(&shared_state))
        .layer(middleware::from_fn(logging::print_request_response));

    if let Some(server_tls) = server.tls {
        let config =
            RustlsConfig::from_pem(server_tls.cert.into_bytes(), server_tls.key.into_bytes())
                .await
                .map_err(|e| {
                    ServerError::RouterError(format!("Error creating rustls TLS config: {}", e))
                })?;
        info!("Starting server with https://{}", addr);
        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|e| {
                ServerError::RouterError(format!("Error serving without rustls: {}", e.to_string()))
            })
    } else {
        info!("Starting server on http://{}", addr);
        axum_server::bind(addr)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|e| {
                ServerError::RouterError(format!("Error serving without rustls: {}", e.to_string()))
            })
    }
}
