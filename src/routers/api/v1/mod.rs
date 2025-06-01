use axum::Router;

pub(crate) mod keyvalue;
pub(crate) mod users;

pub(super) async fn api(shared_state: crate::init::AppState) -> Router<crate::init::AppState> {
    Router::new()
        .nest("/users", users::api().await)
        .nest("/keyvalue", keyvalue::api().await)
        .with_state(shared_state)
        .fallback(crate::routers::fallback::fallback_handler)
}
