pub(crate) mod api;

use crate::{
    error::{
        CryptPassError::{self, RouterError},
        UtoipaCryptPassError,
    },
    init::AppState,
    init::CRYPTPASS_CONFIG_INSTANCE,
};
use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, Request},
    http::{Method, StatusCode},
    middleware::{from_fn, Next},
    response::{IntoResponse, Response},
    routing::any,
    Json,
};
use axum_server::tls_rustls::RustlsConfig;
use http_body_util::BodyExt;
use serde::Serialize;
use std::net::SocketAddr;
use tracing::{info, trace};
use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
    Modify, OpenApi, ToSchema,
};
use utoipa_axum::router::OpenApiRouter;
use utoipa_rapidoc::RapiDoc;
use utoipa_redoc::{Redoc, Servable as RedocServable};
use utoipa_scalar::{Scalar, Servable};
use utoipa_swagger_ui::SwaggerUi;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "api_key",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-CRYPTPASS-KEY"))),
            )
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::routers::handle_health,
        crate::routers::api::v1::login,
        crate::routers::api::v1::admin_router::unlock,
        crate::routers::api::v1::admin_router::get_user,
        crate::routers::api::v1::admin_router::create_update_user,
        crate::routers::api::v1::keyvalue_router::get_data,
        crate::routers::api::v1::keyvalue_router::update_data,
        crate::routers::api::v1::keyvalue_router::delete_data,
        crate::routers::api::v1::keyvalue_router::details,
        crate::routers::api::v1::keyvalue_router::list_selective_keys,
        crate::routers::api::v1::keyvalue_router::list_all_keys,
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "Health", description = "Health related endpoints."),
        (name = "Login", description = "Login related endpoints."),
        (name = "Admin", description = "Admin related endpoints."),
        (name = "Key-Value", description = "Key-Value related endpoints.")
    ),
    info(
        description = "CryptPass API.",
        license(name = "MIT", url = "https://opensource.org/licenses/MIT"),
    ),
    servers(
        (url = "https://cryptpass.blr-home.arpanrec.com:8088", description = "Production server"),
        (url = "http://127.0.0.1:8088", description = "Local server")
    )
)]
pub(crate) struct ApiDoc;

pub(crate) async fn axum_server(shared_state: AppState) -> Result<(), CryptPassError> {
    let configuration = CRYPTPASS_CONFIG_INSTANCE.get().expect("Configuration not initialized.");
    let server = &configuration.server.clone();
    let socket_addr = format!("0.0.0.0:{}", server.port.to_string().as_str());
    let addr: SocketAddr = socket_addr
        .parse()
        .map_err(|ex| RouterError(format!("Unable to parse address: {}, error: {}", socket_addr, ex)))?;
    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .nest("/api", api::api(shared_state.clone()).await)
        .route("/health", any(handle_health))
        .layer(from_fn(print_request_response))
        .with_state(shared_state)
        .split_for_parts();
    let router = router
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api.clone()))
        .merge(Redoc::with_url("/redoc", api.clone()))
        // There is no need to create `RapiDoc::with_openapi` because the OpenApi is served
        // via SwaggerUi instead we only make rapidoc to point to the existing doc.
        .merge(RapiDoc::new("/api-docs/openapi.json").path("/rapidoc"))
        // Alternative to above
        // .merge(RapiDoc::with_openapi("/api-docs/openapi2.json", api).path("/rapidoc"))
        .merge(Scalar::with_url("/scalar", api));

    if let Some(server_tls) = server.clone().tls {
        let config = RustlsConfig::from_pem(server_tls.ssl_cert_pem.into_bytes(), server_tls.ssl_key_pem.into_bytes())
            .await
            .map_err(|ex| RouterError(format!("Error creating rustls TLS config: {}", ex)))?;
        info!("Starting server with https://{}", addr);
        axum_server::bind_rustls(addr, config)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|ex| RouterError(format!("Error serving without rustls: {}", ex.to_string())))
    } else {
        info!("Starting server on http://{}", addr);
        axum_server::bind(addr)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|ex| RouterError(format!("Error serving without rustls: {}", ex.to_string())))
    }
}

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    responses(
        (status = 200, description = "Health Response", body = HealthResponse),
        (status = 500, description = "Internal server error", body = UtoipaCryptPassError)
    ),
    security()
)]
pub(crate) async fn handle_health() -> Result<Json<HealthResponse>, CryptPassError> {
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
            return Err((StatusCode::BAD_REQUEST, format!("failed to read {direction} body: {err}")));
        }
    };
    Ok(bytes)
}
