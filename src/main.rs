mod auth;
mod config;
mod utils;
mod error;
mod physical;
mod routers;
mod services;

use deadpool_diesel::{sqlite::Pool, Manager, Runtime};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use std::{fs, path::Path, sync::OnceLock};
use tracing::{debug, error, info, trace, warn};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
pub(crate) static CRYPTPASS_CONFIG_INSTANCE: OnceLock<config::Configuration> = OnceLock::new();

#[derive(Clone)]
struct AppState {
    pub(crate) pool: Pool,
}

#[tokio::main]
async fn main() {
    println!("{}", config::APP_ASCII_NAME);
    initialize_logging();
    load_configuration();
    let configuration = CRYPTPASS_CONFIG_INSTANCE.get().expect("Configuration not initialized");

    if Path::new(&configuration.physical.config.data_dir).exists()
        && !Path::new(&configuration.physical.config.data_dir).is_dir()
    {
        panic!("Data directory path exists but is not a directory: {}", configuration.physical.config.data_dir);
    }
    if !Path::new(&configuration.physical.config.data_dir).exists() {
        fs::create_dir_all(&configuration.physical.config.data_dir).unwrap_or_else(|ex| {
            panic!(
                "Data directory path does not exist and could not be created: {}, error: {}",
                configuration.physical.config.data_dir, ex
            )
        });
        info!("Data directory created: {}", configuration.physical.config.data_dir);
    }

    let manager =
        Manager::new(format!("{}/cryptpass.sqlite3", configuration.physical.config.data_dir), Runtime::Tokio1);

    let pool = Pool::builder(manager).build().expect("Failed to build pool.");

    let conn = pool.get().await.expect("Failed to get connection from pool.");
    conn.interact(|conn| conn.run_pending_migrations(MIGRATIONS).map(|_| ()))
        .await
        .expect("Failed to run pending migrations, Unable to interact with database")
        .expect("Unable to run pending migrations in database");

    info!("Migrations completed");

    info!("Authorization header key: {}", configuration.server.auth_header_key);
    if let Some(master_enc_key) = &configuration.physical.master_encryption_key {
        warn!("Setting physical master encryption key from configuration which is not recommended. Use /admin/unlock endpoint instead.");
        conn.interact(|conn| services::init_unlock(master_enc_key.clone(), conn))
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

pub fn initialize_logging() {
    println!("Initializing logging...");
    let log_level = std::env::var("CRYPTPASS_LOG_LEVEL").unwrap_or_else(|_| "INFO".to_string()).to_uppercase();

    let log_levels = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];
    if !log_levels.contains(&&*log_level) {
        panic!("Invalid log level: {}, Valid log levels are: {:?}", log_level, log_levels);
    }

    println!("Log level: {}", log_level);
    let log_dir = std::env::var("CRYPTPASS_LOG_DIR").unwrap_or_else(|_| "/var/log/cryptpass".to_string());
    println!("Log directory: {}", log_dir);
    if !Path::new(&log_dir).exists() {
        fs::create_dir_all(&log_dir).unwrap_or_else(|ex| {
            panic!("Log directory path does not exist and could not be created: {}, error: {}", log_dir, ex)
        });
        println!("Log directory created: {}", log_dir);
    }

    let general_file_appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("cryptpass")
        .filename_suffix("log")
        .max_log_files(5)
        .build(&log_dir)
        .expect("Failed to create general log file appender");

    let error_file_appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("cryptpass-error")
        .filename_suffix("log")
        .max_log_files(5)
        .build(&log_dir)
        .expect("Failed to create error log file appender");

    let ist_offset = time::UtcOffset::from_hms(5, 30, 0)
        .expect("Failed to create UTC offset for IST, this is a bug, please report it"); // UTC+05:30

    let console_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_timer(fmt::time::OffsetTime::new(ist_offset, time::format_description::well_known::Rfc3339))
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_file(false)
        .with_line_number(false)
        .compact()
        .with_filter(EnvFilter::new(&log_level));

    let general_file_layer = fmt::layer()
        .with_writer(general_file_appender)
        .with_ansi(false)
        .with_timer(fmt::time::OffsetTime::new(ist_offset, time::format_description::well_known::Rfc3339))
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_file(false)
        .with_line_number(false)
        .compact()
        .with_filter(EnvFilter::new(&log_level));

    let error_file_layer = fmt::layer()
        .with_writer(error_file_appender)
        .with_ansi(false)
        .with_timer(fmt::time::OffsetTime::new(ist_offset, time::format_description::well_known::Rfc3339))
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_file(false)
        .with_line_number(false)
        .compact()
        .with_filter(EnvFilter::new("warn"));

    tracing_subscriber::registry().with(console_layer).with(general_file_layer).with(error_file_layer).init();

    error!("LOGGER TEST: Error logging enabled, this is not a error");
    warn!("LOGGER TEST: Warning logging enabled, this is not warning");
    info!("LOGGER TEST: Info logging enabled");
    debug!("LOGGER TEST: Debug logging enabled");
    trace!("LOGGER TEST: Trace logging enabled");
}

fn load_configuration() {
    let default_file = "/etc/cryptpass/config.json";

    let mut configuration = std::env::var("CRYPTPASS_CONFIG").unwrap_or_else(|ex| {
        info!("Environment variable CRYPTPASS_CONFIG not set, error: {}", ex);
        info!("Using default configuration file: {}", default_file);
        default_file.to_string()
    });

    if Path::new(configuration.clone().as_str()).exists() && !Path::new(configuration.clone().as_str()).is_file() {
        panic!("Configuration path exists but is not a regular file: {}", configuration);
    }

    if Path::new(configuration.clone().as_str()).exists() {
        info!("Reading configuration file: {}", configuration);
        configuration = fs::read_to_string(configuration.clone()).unwrap_or_else(|ex| {
            panic!("Provided configuration {} is a file but could not be read, error: {}", configuration, ex)
        });
    } else {
        info!("Provided configuration is not a file, assuming it is a JSON string");
    }

    if CRYPTPASS_CONFIG_INSTANCE.get().is_some() {
        panic!("Configuration already loaded, do not reload configuration multiple times");
    }

    CRYPTPASS_CONFIG_INSTANCE.get_or_init(|| {
        serde_json::from_str(configuration.as_str())
            .unwrap_or_else(|ex| panic!("Failed to parse configuration file: {}, error: {}", configuration, ex))
    });
}
