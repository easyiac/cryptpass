use axum::Router;

pub(crate) mod keyvalue;
pub(crate) mod users;

pub(super) async fn api() -> Router<crate::init::AppState> {
    Router::new().nest("/users", users::api().await).nest("/keyvalue", keyvalue::api().await)
}
