pub(crate) mod v1;

use axum::http::Method;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use utoipa_axum::router::OpenApiRouter;

pub(super) async fn api(shared_state: crate::init::AppState) -> OpenApiRouter<crate::init::AppState> {
    OpenApiRouter::new()
        .nest("/v1", v1::api(shared_state).await)
        // .layer(CorsLayer::permissive())
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
        .layer(TraceLayer::new_for_http())
        .fallback(crate::routers::fallback::fallback_handler)
}
