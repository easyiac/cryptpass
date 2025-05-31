pub(crate) mod api;
mod fallback;
mod perpetual;
mod print_request_response;

use crate::{
    error::CryptPassError::{self, RouterError},
    init::AppState,
    init::CRYPTPASS_CONFIG_INSTANCE,
};
use axum::{
    http::Method,
    middleware::{self, from_fn},
    routing::{any, post, put},
};
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;
use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
    Modify, OpenApi,
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
        crate::routers::perpetual::health::health_handler,
        crate::routers::perpetual::login_auth::login_handler,
        crate::routers::perpetual::unlock::unlock_handler,
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
        (name = "Perpetual", description = "Core endpoints."),
        (name = "Admin", description = "Admin related endpoints."),
        (name = "Key-Value", description = "Key-Value related endpoints."),
    ),
    info(
        description = "CryptPass API.",
        license(name = "MIT", url = "https://opensource.org/licenses/MIT"),
    ),
    servers(
        (url = "http://127.0.0.1:8088", description = "Local server"),
        (url = "https://10.8.33.192:8088", description = "Local VPN server"),
    ),
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
        .layer(
            CorsLayer::new()
                .allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::PUT,
                    Method::DELETE,
                    Method::HEAD,
                    Method::CONNECT,
                    Method::PATCH,
                ])
                .allow_origin(Any),
        )
        .route("/login", post(perpetual::login_auth::login_handler))
        .layer(middleware::from_fn_with_state(shared_state.clone(), perpetual::login_auth::auth_layer))
        .nest("/api", api::api(shared_state.clone()).await)
        .route("/health", any(perpetual::health::health_handler))
        .route("/unlock", put(perpetual::unlock::unlock_handler))
        .fallback(fallback::fallback_handler)
        .layer(from_fn(print_request_response::print_request_response))
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
