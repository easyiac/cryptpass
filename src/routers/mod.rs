mod api;

use crate::{
    error::CryptPassError::{self, RouterError},
    AppState, CRYPTPASS_CONFIG_INSTANCE,
};
use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, Request},
    http::{Method, StatusCode},
    middleware::{from_fn, Next},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use http_body_util::BodyExt;
use serde::Serialize;
use std::net::SocketAddr;
use tracing::{info, trace};

pub(crate) async fn axum_server(shared_state: AppState) -> Result<(), CryptPassError> {
    let configuration = CRYPTPASS_CONFIG_INSTANCE.get().expect("Configuration not initialized.");
    let server = &configuration.server.clone();
    let socket_addr = format!("0.0.0.0:{}", server.port.to_string().as_str());
    let addr: SocketAddr = socket_addr.parse().map_err(|ex| {
        RouterError(format!("Unable to parse address: {}, error: {}", socket_addr, ex))
    })?;
    let app = Router::new()
        .nest("/api", api::api(shared_state.clone()).await)
        .route("/health", any(handle_health))
        .layer(from_fn(print_request_response))
        .with_state(shared_state);

    if let Some(server_tls) = server.clone().tls {
        let config = RustlsConfig::from_pem(
            server_tls.ssl_cert_pem.into_bytes(),
            server_tls.ssl_key_pem.into_bytes(),
        )
        .await
        .map_err(|ex| RouterError(format!("Error creating rustls TLS config: {}", ex)))?;
        info!("Starting server with https://{}", addr);
        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|ex| RouterError(format!("Error serving without rustls: {}", ex.to_string())))
    } else {
        info!("Starting server on http://{}", addr);
        axum_server::bind(addr)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|ex| RouterError(format!("Error serving without rustls: {}", ex.to_string())))
    }
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

pub async fn handle_health() -> Result<Json<HealthResponse>, CryptPassError> {
    Ok(Json(HealthResponse { status: "OK" }))
}

pub(super) async fn print_request_response(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user_agent = request
        .headers()
        .get("user-agent")
        .map(|value| value.to_str().unwrap_or_default())
        .unwrap_or_default()
        .to_string();
    let uri = request.uri().path().to_string();
    let (parts, body) = request.into_parts();
    let req_bytes = buffer_and_print("request", body).await?;
    let req = Request::from_parts(parts, Body::from(req_bytes.clone()));

    let res = next.run(req).await;

    let (parts, body) = res.into_parts();
    let res_bytes = buffer_and_print("response", body).await?;
    let res = Response::from_parts(parts, Body::from(res_bytes.clone()));

    trace!(
        "Request from addr: {addr}, method: {method}, uri: {uri}, user_agent: {user_agent}, status: {status}, \
        \"{req_bytes}\" -> \"{res_bytes}\"",
        addr = addr,
        method = method,
        uri = uri,
        status = res.status().as_u16(),
        user_agent = user_agent,
        req_bytes = std::str::from_utf8(&req_bytes).unwrap_or_default(),
        res_bytes = std::str::from_utf8(&res_bytes).unwrap_or_default(),
    );
    Ok(res)
}

async fn buffer_and_print<B>(direction: &str, body: B) -> Result<Bytes, (StatusCode, String)>
where
    B: axum::body::HttpBody<Data = Bytes>,
    B::Error: std::fmt::Display,
{
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("failed to read {direction} body: {err}"),
            ));
        }
    };
    Ok(bytes)
}
