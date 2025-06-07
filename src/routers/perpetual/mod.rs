use axum::{
    routing::{any, post},
    Router,
};

pub(crate) mod health;

pub(crate) mod init;

pub(crate) mod unlock;

pub(crate) mod auth;

pub(super) async fn api() -> Router<crate::init::AppState> {
    Router::new()
        .route("/login", post(auth::login::login_handler))
        .route("/health", any(health::health_handler))
        .route("/unlock", post(unlock::unlock_handler))
        .route("/initialize", post(init::init_app_handler))
}
