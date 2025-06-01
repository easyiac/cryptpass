pub(crate) mod users;
pub(crate) mod keyvalue;

use utoipa_axum::router::OpenApiRouter;

pub(super) async fn api(shared_state: crate::init::AppState) -> OpenApiRouter<crate::init::AppState> {
    OpenApiRouter::new()
        .nest("/admin", users::api().await)
        .nest("/keyvalue", keyvalue::api().await)
        .with_state(shared_state)
        .fallback(crate::routers::fallback::fallback_handler)
}
