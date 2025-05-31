mod auth;
mod error;
mod init;
mod physical;
mod routers;
mod services;
mod utils;

use deadpool_diesel::{sqlite::Pool, Manager, Runtime};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use tracing::{info, warn};

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

#[tokio::main]
async fn main() {
    println!("{}", init::APP_ASCII_NAME);
    init::initialize_logging();
    init::CRYPTPASS_CONFIG_INSTANCE.get_or_init(|| init::load_configuration());

    let configuration = init::CRYPTPASS_CONFIG_INSTANCE.get().expect("Configuration not initialized");

    let manager =
        Manager::new(format!("{}/cryptpass.sqlite3", configuration.server.physical.config.data_dir), Runtime::Tokio1);

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
    if let Some(master_enc_key) = &configuration.server.physical.master_encryption_key {
        warn!("Setting physical master encryption key from configuration which is not recommended. Use /admin/unlock endpoint instead.");
        conn.interact(|conn| init::init_unlock(master_enc_key.clone(), conn))
            .await
            .expect("Failed to set encryption key, Unable to interact with database")
            .expect("Unable to set encryption key in database");
        info!("Initialized encryption key");
    } else {
        info!("No master encryption key provided in configuration. Use /admin/unlock endpoint to set it.");
    }
    let app_state = init::AppState { pool };
    routers::axum_server(app_state).await.unwrap_or_else(|ex| panic!("Unable to start server: {}", ex))
}
