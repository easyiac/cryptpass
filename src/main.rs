mod auth;
mod config;
mod encryption;
mod physical;
mod routers;

use crate::{auth::root::create_root_user, routers::axum_server};
use deadpool_diesel::{sqlite::Pool, Manager, Runtime};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use tracing::{info, warn};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

#[derive(Clone)]
struct AppState {
    pub(crate) pool: Pool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Starting Application...");
    config::load_configuration();
    let configuration = config::INSTANCE.get().expect("Configuration not initialized");

    if let Some(master_enc_key) = &configuration.physical.master_encryption_key {
        physical::MASTER_ENCRYPTION_KEY
            .set({
                warn!("Setting physical master encryption key from configuration which is not recommended. Use /admin/unlock endpoint instead.");
                info!("Encryption key hash: {}", encryption::hash(master_enc_key));
                (master_enc_key.clone(), encryption::hash(master_enc_key))
            })
            .expect("Physical master encryption key set failed");
    } else {
        warn!("No master encryption key provided in configuration. Use /admin/unlock endpoint to set it.");
    }

    let manager = Manager::new(
        format!("{}/cryptpass.sqlite3", configuration.physical.config.data_dir),
        Runtime::Tokio1,
    );

    let pool = Pool::builder(manager).build().expect("Failed to build pool");

    {
        let conn = pool.get().await.unwrap();
        conn.interact(|conn| conn.run_pending_migrations(MIGRATIONS).map(|_| ()))
            .await
            .unwrap()
            .unwrap();
    }

    info!("Migrations completed");

    {
        let conn = pool.get().await.unwrap();
        conn.interact(|conn| create_root_user(conn)).await.unwrap().unwrap();
    }

    let app_state = AppState { pool };
    axum_server(app_state).await.unwrap_or_else(|ex| panic!("Unable to start server: {}", ex))
}
