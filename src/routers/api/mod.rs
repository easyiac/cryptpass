mod v1;

use crate::AppState;
use axum::http::Method;
use axum::Router;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

pub(super) async fn api(shared_state: AppState) -> Router<AppState> {
    Router::new()
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
}
