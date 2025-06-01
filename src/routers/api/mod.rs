pub(crate) mod v1;

use utoipa_axum::router::OpenApiRouter;

pub(super) async fn api(shared_state: crate::init::AppState) -> OpenApiRouter<crate::init::AppState> {
    OpenApiRouter::new()
        .nest("/v1", v1::api(shared_state).await)
        .fallback(crate::routers::fallback::fallback_handler)
}
