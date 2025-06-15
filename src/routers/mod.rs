mod api;
mod perpetual;
mod printer;

pub(crate) mod correlation_id;

use crate::{
    error::CryptPassError::{self, RouterError},
    init::AppState,
    init::CRYPTPASS_CONFIG_INSTANCE,
    utils::file_or_string,
};
use axum::{http::StatusCode, middleware};
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
                "cryptpass_auth_info",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-CRYPTPASS-KEY"))),
            )
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::routers::perpetual::health::health_handler,
        crate::routers::perpetual::auth::login::login_handler,
        crate::routers::perpetual::unlock::unlock_handler,
        crate::routers::perpetual::init::init_app_handler,
        crate::routers::api::v1::users::get_user,
        crate::routers::api::v1::users::create_update_user,
        crate::routers::api::v1::keyvalue::get_data,
        crate::routers::api::v1::keyvalue::update_data,
        crate::routers::api::v1::keyvalue::delete_data,
        crate::routers::api::v1::keyvalue::details,
        crate::routers::api::v1::keyvalue::list_selective_keys,
        crate::routers::api::v1::keyvalue::list_all_keys,
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "Perpetual", description = "Core endpoints."),
        (name = "Key-Value", description = "Key-Value related endpoints."),
        (name = "Users", description = "User related endpoints."),
    ),
    info(
        description = "CryptPass API.",
        license(name = "MIT", url = "https://opensource.org/licenses/MIT"),
    ),
    servers(
        // (url = "http://127.0.0.1:8088", description = "Local server"),
    ),
)]
pub(crate) struct ApiDoc;

pub(crate) async fn axum_server(shared_state: AppState) -> Result<(), CryptPassError> {
    let configuration = CRYPTPASS_CONFIG_INSTANCE.get().expect("Configuration not initialized.");
    let socket_addr = format!("0.0.0.0:{}", &configuration.server.port.to_string().as_str());
    let addr: SocketAddr = socket_addr
        .parse()
        .map_err(|ex| RouterError(format!("Unable to parse address: {}, error: {}", socket_addr, ex)))?;

    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi()).split_for_parts();
    let router = router
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api.clone()))
        .merge(Redoc::with_url("/redoc", api.clone()))
        .merge(RapiDoc::new("/api-docs/openapi.json").path("/rapidoc"))
        .merge(Scalar::with_url("/scalar", api))
        .nest("/perpetual", perpetual::api().await)
        .nest("/api", api::api().await)
        .layer(middleware::from_fn_with_state(shared_state.clone(), perpetual::auth::layer::auth_layer))
        .fallback(|| async { StatusCode::NOT_FOUND })
        // .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(middleware::from_fn(printer::print_request_response))
        .layer(middleware::from_fn(correlation_id::set_correlation_id))
        .layer(CorsLayer::new().allow_headers(Any).allow_methods(Any).allow_origin(Any).expose_headers(Any))
        .with_state(shared_state);

    if let Some(server_tls) = &configuration.server.tls {
        let config = RustlsConfig::from_pem(
            file_or_string(server_tls.ssl_cert_pem.as_str())?.into_bytes(),
            file_or_string(server_tls.ssl_key_pem.as_str())?.into_bytes(),
        )
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
