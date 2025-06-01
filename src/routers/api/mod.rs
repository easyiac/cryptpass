pub(crate) mod v1;

use axum::Router;

pub(super) async fn api(shared_state: crate::init::AppState) -> Router<crate::init::AppState> {
    Router::new().nest("/v1", v1::api(shared_state).await).fallback(crate::routers::fallback::fallback_handler)
}
