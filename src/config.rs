use crate::{
    auth::roles::{Privilege, PrivilegeType, Role, RoleType},
    error::CryptPassError::{self, BadRequest, InternalServerError},
    physical::models::UserModel,
    services::{encryption::INTERNAL_ENCRYPTION_KEY, get_settings, set_settings, InternalEncryptionKeySettings},
    CRYPTPASS_CONFIG_INSTANCE,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use diesel::SqliteConnection;
use rand::{distr::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{debug, error, info, trace, warn};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct PhysicalConfig {
    #[serde(rename = "data-dir", default = "default_data_dir")]
    pub data_dir: String,
}

fn default_physical_config() -> PhysicalConfig {
    PhysicalConfig { data_dir: default_data_dir() }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct Physical {
    #[serde(rename = "master-encryption-key")]
    pub master_encryption_key: Option<String>,

    #[serde(default = "default_physical_config")]
    pub config: PhysicalConfig,
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
    pub ssl_key_pem: String,

    #[serde(rename = "cert-pem")]
    pub ssl_cert_pem: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct Server {
    #[serde(default = "default_port")]
    pub port: i32,

    #[serde(rename = "root-password")]
    pub root_password: Option<String>,

    #[serde(rename = "auth-header-key", default = "default_auth_header_key")]
    pub auth_header_key: String,

    #[serde(rename = "tls")]
    pub tls: Option<ServerTls>,
}

fn default_physical() -> Physical {
    Physical { master_encryption_key: None, config: default_physical_config() }
}

fn default_server() -> Server {
    Server { port: default_port(), root_password: None, auth_header_key: default_auth_header_key(), tls: None }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct Configuration {
    #[serde(default = "default_server")]
    pub server: Server,
    #[serde(default = "default_physical")]
    pub physical: Physical,
}

pub(crate) fn load_configuration() -> Configuration {
    let default_file = "/etc/cryptpass/config.json";

    let mut configuration: String = std::env::var("CRYPTPASS_CONFIG").unwrap_or_else(|ex| {
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

    let configuration: Configuration = serde_json::from_str(configuration.as_str())
        .unwrap_or_else(|ex| panic!("Failed to parse configuration file: {}, error: {}", configuration, ex));

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
    configuration
}

pub(crate) fn initialize_logging() {
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

pub(crate) fn init_unlock(
    master_key: String,
    conn: &mut SqliteConnection,
) -> Result<InternalEncryptionKeySettings, CryptPassError> {
    info!("Initializing unlock");
    let master_key_hash = crate::utils::hash(&master_key);
    let existing_internal_encryption_key_encrypted_str =
        get_settings("INTERNAL_ENCRYPTION_KEY_ENCRYPTED".to_string(), conn)?;
    let internal_encryption_key = match existing_internal_encryption_key_encrypted_str {
        Some(existing_internal_encryption_key_str) => {
            info!("Internal encryption key exists");
            let existing_internal_encryption_key: InternalEncryptionKeySettings =
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
            info!("Internal encryption key does not exist, generating new key");
            let new_key = crate::utils::generate_key();
            info!("New internal encryption key generated, hash: {}", crate::utils::hash(new_key.as_str()));
            new_key
        }
    };
    let internal_enc_key_settings = InternalEncryptionKeySettings {
        encrypted_key: crate::utils::encrypt(&master_key.clone(), &internal_encryption_key)?,
        hash: crate::utils::hash(&internal_encryption_key),
        encryptor_hash: master_key_hash,
    };

    let internal_enc_key_settings_str = serde_json::to_string(&internal_enc_key_settings)
        .map_err(|ex| BadRequest(format!("Failed to serialize internal encryption key: {}", ex)))?;

    set_settings("INTERNAL_ENCRYPTION_KEY_ENCRYPTED".to_string(), internal_enc_key_settings_str, conn)?;

    info!("Setting internal encryption key, hash: {}", internal_enc_key_settings.hash);
    INTERNAL_ENCRYPTION_KEY
        .set({
            crate::services::encryption::InternalEncryptionKey {
                key: internal_encryption_key,
                hash: internal_enc_key_settings.clone().hash,
            }
        })
        .map_err(|ex| {
            BadRequest(format!("Failed to set internal encryption key, Existing key hash: {}", ex.hash.to_string()))
        })?;

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
        .map_err(|_| InternalServerError("System time before UNIX EPOCH".to_string()))?
        .as_millis() as i64;
    roles.push(Role { name: RoleType::ADMIN, privileges: vec![Privilege { name: PrivilegeType::SUDO }] });
    let root_user_option = crate::services::users::get_user("root", conn)
        .map_err(|ex| InternalServerError(format!("Error getting root user: {}", ex)))?;

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
            UserModel {
                username: "root".to_string(),
                email: None,
                password_hash: None,
                password_last_changed: 0i64,
                last_login: 0i64,
                locked: false,
                roles: serde_json::to_string(&roles)
                    .map_err(|ex| InternalServerError(format!("Failed to serialize roles: {}", ex)))?,
                enabled: true,
                api_token_jwt_secret_b64_encrypted: crate::services::encryption::encrypt(
                    api_token_jwt_secret_base64.as_ref(),
                    conn,
                )?,
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
    root_user.roles = serde_json::to_string(&roles)
        .map_err(|ex| InternalServerError(format!("Failed to serialize roles: {}", ex)))?;
    root_user.last_login = 0i64;

    if is_new_root_user {
        info!("Creating new root user");
        crate::services::users::create_user(root_user, conn)?;
        info!("Root user created");
    } else {
        info!("Updating existing root user");
        crate::services::users::update_user(root_user, conn)?;
        info!("Existing root user updated");
    }

    Ok(())
}
