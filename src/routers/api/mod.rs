pub(crate) mod v1;

use tower_http::trace::TraceLayer;
use utoipa_axum::router::OpenApiRouter;

pub(super) async fn api(shared_state: crate::init::AppState) -> OpenApiRouter<crate::init::AppState> {
    OpenApiRouter::new()
        .nest("/v1", v1::api(shared_state).await)
        // .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .fallback(crate::routers::fallback::fallback_handler)
}
