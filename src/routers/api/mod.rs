mod v1;
use crate::AppState;
use axum::Router;

pub(super) async fn api(shared_state: AppState) -> Router<AppState> {
    Router::new().nest("/v1", v1::api(shared_state).await)
}
