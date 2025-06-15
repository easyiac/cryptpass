use crate::{
    error::CryptPassError::{self, ApplicationNotInitialized, BadRequest, InternalServerError},
    physical::models::{Privilege, PrivilegeType, Role, RoleType, Users},
    services::{self, encryption::set_internal_encryption_key, get_settings, set_settings},
};
use base64::{prelude::BASE64_STANDARD, Engine};
use deadpool_diesel::sqlite::Pool;
use diesel::SqliteConnection;
use rand::{distr::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::Path,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{debug, error, info, trace, warn};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};
use utoipa::ToSchema;

pub(crate) static CRYPTPASS_CONFIG_INSTANCE: OnceLock<Configuration> = OnceLock::new();

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) pool: Pool,
}
pub(crate) const APP_ASCII_NAME: &str = r##"

          _____                    _____                _____                    _____                _____                    _____                    _____                    _____                    _____
         /\    \                  /\    \              |\    \                  /\    \              /\    \                  /\    \                  /\    \                  /\    \                  /\    \
        /::\    \                /::\    \             |:\____\                /::\    \            /::\    \                /::\    \                /::\    \                /::\    \                /::\    \
       /::::\    \              /::::\    \            |::|   |               /::::\    \           \:::\    \              /::::\    \              /::::\    \              /::::\    \              /::::\    \
      /::::::\    \            /::::::\    \           |::|   |              /::::::\    \           \:::\    \            /::::::\    \            /::::::\    \            /::::::\    \            /::::::\    \
     /:::/\:::\    \          /:::/\:::\    \          |::|   |             /:::/\:::\    \           \:::\    \          /:::/\:::\    \          /:::/\:::\    \          /:::/\:::\    \          /:::/\:::\    \
    /:::/  \:::\    \        /:::/__\:::\    \         |::|   |            /:::/__\:::\    \           \:::\    \        /:::/__\:::\    \        /:::/__\:::\    \        /:::/__\:::\    \        /:::/__\:::\    \
   /:::/    \:::\    \      /::::\   \:::\    \        |::|   |           /::::\   \:::\    \          /::::\    \      /::::\   \:::\    \      /::::\   \:::\    \       \:::\   \:::\    \       \:::\   \:::\    \
  /:::/    / \:::\    \    /::::::\   \:::\    \       |::|___|______    /::::::\   \:::\    \        /::::::\    \    /::::::\   \:::\    \    /::::::\   \:::\    \    ___\:::\   \:::\    \    ___\:::\   \:::\    \
 /:::/    /   \:::\    \  /:::/\:::\   \:::\____\      /::::::::\    \  /:::/\:::\   \:::\____\      /:::/\:::\    \  /:::/\:::\   \:::\____\  /:::/\:::\   \:::\    \  /\   \:::\   \:::\    \  /\   \:::\   \:::\    \
/:::/____/     \:::\____\/:::/  \:::\   \:::|    |    /::::::::::\____\/:::/  \:::\   \:::|    |    /:::/  \:::\____\/:::/  \:::\   \:::|    |/:::/  \:::\   \:::\____\/::\   \:::\   \:::\____\/::\   \:::\   \:::\____\
\:::\    \      \::/    /\::/   |::::\  /:::|____|   /:::/~~~~/~~      \::/    \:::\  /:::|____|   /:::/    \::/    /\::/    \:::\  /:::|____|\::/    \:::\  /:::/    /\:::\   \:::\   \::/    /\:::\   \:::\   \::/    /
 \:::\    \      \/____/  \/____|:::::\/:::/    /   /:::/    /          \/_____/\:::\/:::/    /   /:::/    / \/____/  \/_____/\:::\/:::/    /  \/____/ \:::\/:::/    /  \:::\   \:::\   \/____/  \:::\   \:::\   \/____/
  \:::\    \                    |:::::::::/    /   /:::/    /                    \::::::/    /   /:::/    /                    \::::::/    /            \::::::/    /    \:::\   \:::\    \       \:::\   \:::\    \
   \:::\    \                   |::|\::::/    /   /:::/    /                      \::::/    /   /:::/    /                      \::::/    /              \::::/    /      \:::\   \:::\____\       \:::\   \:::\____\
    \:::\    \                  |::| \::/____/    \::/    /                        \::/____/    \::/    /                        \::/____/               /:::/    /        \:::\  /:::/    /        \:::\  /:::/    /
     \:::\    \                 |::|  ~|           \/____/                          ~~           \/____/                          ~~                    /:::/    /          \:::\/:::/    /          \:::\/:::/    /
      \:::\    \                |::|   |                                                                                                               /:::/    /            \::::::/    /            \::::::/    /
       \:::\____\               \::|   |                                                                                                              /:::/    /              \::::/    /              \::::/    /
        \::/    /                \:|   |                                                                                                              \::/    /                \::/    /                \::/    /
         \/____/                  \|___|                                                                                                               \/____/                  \/____/                  \/____/

"##;

fn default_data_dir() -> String {
    "/var/lib/cryptpass".to_string()
}

#[derive(Deserialize)]
pub(crate) struct PhysicalConfig {
    #[serde(rename = "data-dir", default = "default_data_dir")]
    pub(crate) data_dir: String,
}

fn default_physical_config() -> PhysicalConfig {
    PhysicalConfig { data_dir: default_data_dir() }
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub(crate) struct UnlockDetails {
    #[serde(rename = "master-encryption-key")]
    pub(crate) master_encryption_key: String,
}

#[derive(Deserialize)]
pub(crate) struct Physical {
    #[serde(rename = "unlock-details")]
    pub(crate) unlock_details: Option<UnlockDetails>,

    #[serde(default = "default_physical_config")]
    pub(crate) config: PhysicalConfig,
}

fn default_port() -> i32 {
    8088
}

fn default_auth_header_key() -> String {
    "X-CRYPTPASS-KEY".to_string()
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct ServerTls {
    #[serde(rename = "key-pem")]
    pub(crate) ssl_key_pem: String,

    #[serde(rename = "cert-pem")]
    pub(crate) ssl_cert_pem: String,
}

#[derive(Deserialize)]
pub(crate) struct Server {
    #[serde(default = "default_port")]
    pub(crate) port: i32,

    #[serde(rename = "root-password")]
    pub(crate) root_password: Option<String>,

    #[serde(rename = "auth-header-key", default = "default_auth_header_key")]
    pub(crate) auth_header_key: String,

    #[serde(rename = "tls")]
    pub(crate) tls: Option<ServerTls>,

    #[serde(default = "default_physical")]
    pub(crate) physical: Physical,
}

fn default_physical() -> Physical {
    Physical { unlock_details: None, config: default_physical_config() }
}

fn default_server() -> Server {
    Server {
        port: default_port(),
        root_password: None,
        auth_header_key: default_auth_header_key(),
        tls: None,
        physical: default_physical(),
    }
}

#[derive(Deserialize)]
pub(crate) struct Configuration {
    #[serde(default = "default_server")]
    pub(crate) server: Server,
}

pub(crate) fn load_configuration() -> Configuration {
    let default_file = "/etc/cryptpass/config.json";

    let configuration: String = std::env::var("CRYPTPASS_CONFIG").unwrap_or_else(|ex| {
        info!("Environment variable CRYPTPASS_CONFIG not set, error: {}", ex);
        info!("Using default configuration file: {}", default_file);
        default_file.to_string()
    });

    let configuration =
        crate::utils::file_or_string(configuration.as_str()).expect("Failed to read configuration file");

    let configuration: Configuration = serde_json::from_str(configuration.as_str())
        .unwrap_or_else(|ex| panic!("Failed to parse configuration file: {}, error: {}", configuration, ex));

    if Path::new(&configuration.server.physical.config.data_dir).exists()
        && !Path::new(&configuration.server.physical.config.data_dir).is_dir()
    {
        panic!("Data directory path exists but is not a directory: {}", configuration.server.physical.config.data_dir);
    }
    if !Path::new(&configuration.server.physical.config.data_dir).exists() {
        fs::create_dir_all(&configuration.server.physical.config.data_dir).unwrap_or_else(|ex| {
            panic!(
                "Data directory path does not exist and could not be created: {}, error: {}",
                configuration.server.physical.config.data_dir, ex
            )
        });
        info!("Data directory created: {}", configuration.server.physical.config.data_dir);
    }
    configuration
}

pub(crate) fn initialize_logging() {
    println!("Initializing logging...");
    let log_level = std::env::var("CRYPTPASS_LOG_LEVEL")
        .unwrap_or_else(|ex| {
            debug!("Environment variable CRYPTPASS_LOG_LEVEL not set, error: {}", ex);
            "INFO".to_string()
        })
        .to_uppercase();

    let log_levels = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];
    if !log_levels.contains(&&*log_level) {
        panic!("Invalid log level: {}, Valid log levels are: {:?}", log_level, log_levels);
    }

    println!("Log level: {}", log_level);
    let log_dir = std::env::var("CRYPTPASS_LOG_DIR").unwrap_or_else(|ex| {
        debug!("Environment variable CRYPTPASS_LOG_DIR not set, error: {}", ex);
        "/var/log/cryptpass".to_string()
    });
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

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub(crate) struct InternalEncryptionKeyDetails {
    pub(crate) encrypted_key: String,
    pub(crate) hash: String,
    pub(crate) encryptor_hash: String,
}

pub(crate) fn unlock_app(
    unlock_details: UnlockDetails,
    conn: &mut SqliteConnection,
) -> Result<InternalEncryptionKeyDetails, CryptPassError> {
    info!("Initializing unlock");
    let master_key = crate::utils::file_or_string(unlock_details.master_encryption_key.as_str())?;
    let master_key_hash = crate::utils::hash(&master_key);
    let existing_internal_encryption_key_encrypted_str = get_settings("INTERNAL_ENCRYPTION_KEY_ENCRYPTED", conn)?;
    let internal_encryption_key = match existing_internal_encryption_key_encrypted_str {
        Some(existing_internal_encryption_key_str) => {
            info!("Internal encryption key exists");
            let existing_internal_encryption_key: InternalEncryptionKeyDetails =
                serde_json::from_str(&existing_internal_encryption_key_str.value)
                    .map_err(|ex| BadRequest(format!("Failed to parse internal encryption key: {}", ex)))?;
            if existing_internal_encryption_key.encryptor_hash != master_key_hash {
                return Err(BadRequest("Internal encryption key is encrypted with a different master key".to_string()));
            }
            let internal_encryption_key =
                crate::utils::decrypt(&master_key, &existing_internal_encryption_key.encrypted_key)?;
            let internal_encryption_key_hash = crate::utils::hash(&internal_encryption_key);
            if internal_encryption_key_hash != existing_internal_encryption_key.hash {
                return Err(BadRequest("Internal encryption key hash does not match existing key hash".to_string()));
            }
            internal_encryption_key
        }
        None => {
            return Err(ApplicationNotInitialized("The application has not been initialized yet".to_string()));
        }
    };
    let internal_enc_key_settings = InternalEncryptionKeyDetails {
        encrypted_key: crate::utils::encrypt(&master_key.clone(), &internal_encryption_key)?,
        hash: crate::utils::hash(&internal_encryption_key),
        encryptor_hash: master_key_hash,
    };

    info!("Setting internal encryption key, hash: {}", internal_enc_key_settings.hash);

    set_internal_encryption_key(internal_encryption_key, internal_enc_key_settings.clone().hash)?;

    create_root_user(conn)?;

    Ok(internal_enc_key_settings)
}

fn create_root_user(conn: &mut SqliteConnection) -> Result<(), CryptPassError> {
    info!("Creating root user");
    let configuration = CRYPTPASS_CONFIG_INSTANCE.get().expect("Configuration not initialized.");
    let is_new_root_user;
    let mut roles = Vec::new();
    let current_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|ex| InternalServerError(format!("Failed to get current epoch: {}", ex)))?
        .as_millis() as i64;
    roles.push(Role { name: RoleType::ADMIN, privileges: vec![Privilege { name: PrivilegeType::SUDO }] });
    let root_user_option = services::users::get_user("root", conn)?;

    let mut root_user = match root_user_option {
        Some(user) => {
            is_new_root_user = false;
            user
        }
        None => {
            is_new_root_user = true;
            info!("Creating root user with API token JWT secret");
            let mut rng = rand::rng();
            let mut api_token_jwt_secret = [0u8; 32];
            rng.fill(&mut api_token_jwt_secret);
            let api_token_jwt_secret_base64 = BASE64_STANDARD.encode(api_token_jwt_secret);
            let api_token_jwt_secret_b64_encrypted =
                services::encryption::encrypt(api_token_jwt_secret_base64.as_ref(), conn)?;
            Users {
                username: "root".to_string(),
                email: None,
                password_hash: None,
                password_last_changed: 0i64,
                last_login: 0i64,
                locked: false,
                roles: roles.clone(),
                enabled: true,
                jwt_secret_b64_encrypted: api_token_jwt_secret_b64_encrypted.encrypted_value,
                encryptor_hash: api_token_jwt_secret_b64_encrypted.encryption_key_hash,
                password: None,
            }
        }
    };

    if let Some(password) = &configuration.server.root_password {
        info!("Adding/Updating root user with password hash from config");
        root_user.password_hash = Some(crate::utils::hash(password));
        root_user.password_last_changed = current_epoch;
    }

    if root_user.password_hash.is_none() && configuration.server.root_password.is_none() {
        let s: String = rand::rng().sample_iter(&Alphanumeric).take(64).map(char::from).collect();
        info!("Creating root user with password: {}", s);
        warn!("Make sure to change the password after first login!");
        root_user.password_hash = Some(crate::utils::hash(&s));
        root_user.password_last_changed = current_epoch;
    };

    root_user.locked = false;
    root_user.enabled = true;
    root_user.roles = roles;
    root_user.last_login = 0i64;

    if is_new_root_user {
        info!("Creating new root user");
        services::users::create_user(root_user, conn)?;
        info!("Root user created");
    } else {
        info!("Updating existing root user");
        services::users::update_user(root_user, conn)?;
        info!("Existing root user updated");
    }

    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub(crate) struct ApplicationInitializationDetails {
    pub(crate) master_key: String,
}

pub(crate) fn init_app(conn: &mut SqliteConnection) -> Result<ApplicationInitializationDetails, CryptPassError> {
    info!("Initializing application");
    let existing_internal_encryption_key_encrypted_str = get_settings("INTERNAL_ENCRYPTION_KEY_ENCRYPTED", conn)?;
    if existing_internal_encryption_key_encrypted_str.is_some() {
        return Err(BadRequest("Application already initialized".to_string()));
    }
    let master_key = crate::utils::generate_key();
    let master_key_hash = crate::utils::hash(&master_key);
    info!("Master key generated, hash: {}", master_key_hash);

    let internal_encryption_key = crate::utils::generate_key();
    let internal_encryption_key_encrypted = crate::utils::encrypt(&master_key.clone(), &internal_encryption_key)?;
    let internal_encryption_key_hash = crate::utils::hash(&internal_encryption_key);
    info!("Internal encryption key generated, hash: {}", internal_encryption_key_hash);

    let internal_enc_key_settings = InternalEncryptionKeyDetails {
        encrypted_key: internal_encryption_key_encrypted,
        hash: internal_encryption_key_hash,
        encryptor_hash: master_key_hash,
    };

    let internal_enc_key_settings_str = serde_json::to_string(&internal_enc_key_settings)
        .map_err(|ex| BadRequest(format!("Failed to serialize internal encryption key: {}", ex)))?;

    set_settings("INTERNAL_ENCRYPTION_KEY_ENCRYPTED", internal_enc_key_settings_str.as_ref(), conn)?;

    Ok(ApplicationInitializationDetails { master_key })
}
