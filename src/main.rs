mod auth;
mod config;
mod error;
mod physical;
mod routers;
mod services;
mod utils;

use deadpool_diesel::{sqlite::Pool, Manager, Runtime};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use std::sync::OnceLock;
use tracing::{info, warn};

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
pub(crate) static CRYPTPASS_CONFIG_INSTANCE: OnceLock<config::Configuration> = OnceLock::new();

#[derive(Clone)]
struct AppState {
    pub(crate) pool: Pool,
}

#[tokio::main]
async fn main() {
    println!("{}", config::APP_ASCII_NAME);
    config::initialize_logging();
    CRYPTPASS_CONFIG_INSTANCE.get_or_init(|| config::load_configuration());

    let configuration = CRYPTPASS_CONFIG_INSTANCE.get().expect("Configuration not initialized");


    let manager =
        Manager::new(format!("{}/cryptpass.sqlite3", configuration.physical.config.data_dir), Runtime::Tokio1);

    let pool = Pool::builder(manager).build().expect("Failed to build pool.");
    let conn = pool.get().await.expect("Failed to get connection from pool.");

    {
        conn.interact(|conn| conn.run_pending_migrations(MIGRATIONS).map(|_| ()))
            .await
            .expect("Failed to run pending migrations, Unable to interact with database")
            .expect("Unable to run pending migrations in database");

        info!("Database migrations completed.");
    }

    info!("Authorization header key: {}", configuration.server.auth_header_key);
    if let Some(master_enc_key) = &configuration.physical.master_encryption_key {
        warn!("Setting physical master encryption key from configuration which is not recommended. Use /admin/unlock endpoint instead.");
        conn.interact(|conn| config::init_unlock(master_enc_key.clone(), conn))
            .await
            .expect("Failed to set encryption key, Unable to interact with database")
            .expect("Unable to set encryption key in database");
        info!("Initialized encryption key");
    } else {
        info!("No master encryption key provided in configuration. Use /admin/unlock endpoint to set it.");
    }
    let app_state = AppState { pool };
    routers::axum_server(app_state).await.unwrap_or_else(|ex| panic!("Unable to start server: {}", ex))
}
