pub(crate) mod admin_router;
pub(crate) mod keyvalue_router;

use utoipa_axum::router::OpenApiRouter;

pub(super) async fn api(shared_state: crate::init::AppState) -> OpenApiRouter<crate::init::AppState> {
    OpenApiRouter::new()
        .nest("/admin", admin_router::api().await)
        .nest("/keyvalue", keyvalue_router::api().await)
        .with_state(shared_state)
        .fallback(crate::routers::fallback::fallback_handler)
}
