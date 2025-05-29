use serde::{Deserialize, Serialize};

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
