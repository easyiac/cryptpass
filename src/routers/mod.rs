mod admin;
mod authentication;
mod logging;
mod secrets;

use crate::{
    routers::{authentication::auth_layer, logging::print_request_response},
    AppState,
};
use axum::{
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use std::{fmt::Display, net::SocketAddr};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug)]
pub(crate) enum ServerError {
    RouterError(String),
    NotFound(String),
    InternalServerError(String),
    Unauthorized(String),
    MethodNotAllowed(String),
    BadRequest(String),
}

impl Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::NotFound(e) => write!(f, "Not Found: {}", e),
            ServerError::InternalServerError(e) => write!(f, "Internal Server Error: {}", e),
            ServerError::Unauthorized(e) => write!(f, "Unauthorized: {}", e),
            ServerError::MethodNotAllowed(e) => write!(f, "Method Not Allowed: {}", e),
            ServerError::RouterError(e) => write!(f, "Router Error: {}", e),
            ServerError::BadRequest(e) => write!(f, "Bad Request: {}", e),
        }
    }
}
impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        match self {
            ServerError::NotFound(e) => {
                let error_body = serde_json::json!({ "error": e });
                (StatusCode::NOT_FOUND, axum::Json(error_body)).into_response()
            }
            ServerError::InternalServerError(e) => {
                let random_uuid = Uuid::new_v4().to_string();
                warn!("Internal Server Error: {} - {}", random_uuid, e);
                let error_body =
                    serde_json::json!({ "error": "Internal Server Error", "uuid": random_uuid });
                (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(error_body)).into_response()
            }
            ServerError::Unauthorized(e) => {
                let error_body = serde_json::json!({ "error": e });
                (StatusCode::UNAUTHORIZED, axum::Json(error_body)).into_response()
            }
            ServerError::MethodNotAllowed(e) => {
                let error_body = serde_json::json!({ "error": e });
                (StatusCode::METHOD_NOT_ALLOWED, axum::Json(error_body)).into_response()
            }
            ServerError::RouterError(e) => {
                panic!("Router Error, RouterErrors are not meant to be returned: {}", e)
            }
            ServerError::BadRequest(e) => {
                let error_body = serde_json::json!({ "error": e });
                (StatusCode::BAD_REQUEST, axum::Json(error_body)).into_response()
            }
        }
    }
}

async fn handle_any() -> Result<impl IntoResponse, ServerError> {
    Err::<Response, ServerError>(ServerError::MethodNotAllowed("Unknown Resource".to_string()))
        as Result<_, ServerError>
}

async fn handle_health() -> Result<impl IntoResponse, ServerError> {
    Response::builder()
        .status(200)
        .header("Content-Type", "text/plain")
        .body("OK".to_string())
        .map_err(|ex| ServerError::InternalServerError(format!("Error creating response: {}", ex)))
}

pub(crate) async fn axum_server(shared_state: AppState) -> Result<(), ServerError> {
    let configuration = crate::config::INSTANCE.get().expect("Configuration not initialized.");
    let server = &configuration.server.clone();
    let socket_addr = format!("0.0.0.0:{}", server.port.to_string().as_str());
    let addr: SocketAddr = socket_addr.parse().map_err(|ex| {
        ServerError::RouterError(format!("Unable to parse address: {}, error: {}", socket_addr, ex))
    })?;
    let app = Router::new()
        .nest("/api/v1/admin", admin::api())
        .route("/api/v1/secrets/{*key}", any(secrets::api))
        .route("/{*key}", any(handle_any))
        .route("/health", any(handle_health))
        .layer(middleware::from_fn_with_state(shared_state.clone(), auth_layer))
        .layer(middleware::from_fn(print_request_response))
        .with_state(shared_state);

    if let Some(server_tls) = server.clone().tls {
        let config = RustlsConfig::from_pem(
            server_tls.ssl_cert_pem.into_bytes(),
            server_tls.ssl_key_pem.into_bytes(),
        )
        .await
        .map_err(|ex| {
            ServerError::RouterError(format!("Error creating rustls TLS config: {}", ex))
        })?;
        info!("Starting server with https://{}", addr);
        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|ex| {
                ServerError::RouterError(format!(
                    "Error serving without rustls: {}",
                    ex.to_string()
                ))
            })
    } else {
        info!("Starting server on http://{}", addr);
        axum_server::bind(addr)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|ex| {
                ServerError::RouterError(format!(
                    "Error serving without rustls: {}",
                    ex.to_string()
                ))
            })
    }
}
