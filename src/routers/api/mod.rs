pub(crate) mod v1;

use axum::Router;

pub(super) async fn api() -> Router<crate::init::AppState> {
    Router::new().nest("/v1", v1::api().await).fallback(crate::routers::fallback::fallback_handler)
}
