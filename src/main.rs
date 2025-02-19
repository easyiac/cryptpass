mod authentication;
mod configuration;
mod enc;
mod physical;
mod routers;
mod services;

use crate::{authentication::Authentication, physical::Physical, routers::axum_server};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use tracing::{debug, info};

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct AppState {
    physical: Physical,
    authentication: Authentication,
    master_key: OnceLock<String>,
    map: HashMap<String, String>,
}
type SharedState = Arc<RwLock<AppState>>;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Starting Application...");
    let configuration = configuration::load_configuration();
    debug!("Server configuration: {:?}", configuration);
    let server = configuration.server.clone();
    let app_state = AppState {
        physical: Physical::new(configuration.physical.clone()),
        authentication: Authentication::new(configuration.authentication.clone()),
        master_key: OnceLock::new(),
        map: HashMap::new(),
    };

    let shared_state = Arc::new(RwLock::new(app_state));

    axum_server(server, shared_state)
        .await
        .unwrap_or_else(|e| panic!("Unable to start server: {}", e))
}
