mod authentication;
mod configuration;
mod enc;
mod physical;
mod routers;
mod services;
use crate::{authentication::Authentication, physical::Physical, routers::axum_server};
use tracing::{debug, info};

#[derive(Clone, Debug)]
struct AppState {
    physical: Physical,
    authentication: Authentication,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Starting Application...");
    let configuration = configuration::load_configuration();
    debug!("Server configuration: {:?}", configuration);
    let server = configuration.server.clone();
    let app_state = AppState {
        physical: Physical::new(configuration.physical.clone()).await,
        authentication: Authentication::new(configuration.authentication.clone()),
    };
    axum_server(server, app_state).await.unwrap_or_else(|e| panic!("Unable to start server: {}", e))
}
