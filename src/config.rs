use serde::{Deserialize, Serialize};
use std::{fs, path::Path, sync::OnceLock};
use tracing::info;

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
    "Authorization".to_string()
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
    Server {
        port: default_port(),
        root_password: None,
        auth_header_key: default_auth_header_key(),
        tls: None,
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct Configuration {
    #[serde(default = "default_server")]
    pub server: Server,
    #[serde(default = "default_physical")]
    pub physical: Physical,
}
pub(crate) static INSTANCE: OnceLock<Configuration> = OnceLock::new();

pub(crate) fn load_configuration() {
    let default_file = "/etc/cryptpass/config.json";

    let mut configuration = std::env::var("CRYPTPASS_CONFIG").unwrap_or_else(|ex| {
        info!("Environment variable CRYPTPASS_CONFIG not set, error: {}", ex);
        info!("Using default configuration file: {}", default_file);
        default_file.to_string()
    });

    if Path::new(configuration.clone().as_str()).exists()
        && !Path::new(configuration.clone().as_str()).is_file()
    {
        panic!("Configuration file path exists but is not a file: {}", configuration);
    }

    if Path::new(configuration.clone().as_str()).exists() {
        configuration = fs::read_to_string(configuration.clone()).unwrap_or_else(|ex| {
            panic!("Configuration file not found: {}, error: {}", configuration, ex)
        });
    }

    if INSTANCE.get().is_some() {
        panic!("Configuration already loaded, do not reload configuration multiple times");
    }

    INSTANCE.get_or_init(|| {
        serde_json::from_str(configuration.as_str()).unwrap_or_else(|ex| {
            panic!("Failed to parse configuration file: {}, error: {}", configuration, ex)
        })
    });
}
