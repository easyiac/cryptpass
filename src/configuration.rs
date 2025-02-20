use serde::Deserialize;
use serde_json::Value;
use std::{fs, sync::OnceLock};
use tracing::info;

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ServerTls {
    pub(crate) cert: String,
    pub(crate) key: String,
}
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct Server {
    pub(crate) socket_addr: String,
    pub(crate) tls: Option<ServerTls>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct Physical {
    pub(crate) physical_type: String,
    pub(crate) physical_details: Value,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct Authentication {
    pub(crate) authentication_type: String,
    pub(crate) authentication_details: Value,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct Configuration {
    pub(crate) server: Server,
    pub(crate) physical: Physical,
    pub(crate) authentication: Authentication,
    pub(crate) master_key: Option<String>,
}

pub(crate) fn load_configuration() -> &'static Configuration {
    let mut configuration_file =
        std::env::var("CRUSTPASS_CONFIGURATION_FILE").unwrap_or("".to_string());
    let mut configuration_json =
        std::env::var("CRUSTPASS_CONFIGURATION_JSON").unwrap_or("".to_string());
    if configuration_file == "" && configuration_json == "" {
        configuration_file = "/etc/crustpass/configuration.json".to_string();
        info!(
            "CRUSTPASS_CONFIGURATION_FILE and CRUSTPASS_CONFIGURATION_JSON not set, using default file: {}",
            configuration_file
        );
        configuration_json = fs::read_to_string(configuration_file.clone()).unwrap_or_else(|ex| {
            panic!("Unable to read the default file: {}, {}", configuration_file.clone(), ex)
        });
    } else if configuration_file != "" && configuration_json != "" {
        info!(
            "CRUSTPASS_CONFIGURATION_FILE and CRUSTPASS_CONFIGURATION_JSON both set, using CRUSTPASS_CONFIGURATION_FILE file: {}",
            configuration_file
        );
        configuration_json = fs::read_to_string(configuration_file.clone())
            .unwrap_or_else(|ex| panic!("Unable to read the file: {}, {}", configuration_file, ex));
    } else if configuration_file != "" && configuration_json == "" {
        info!("CRUSTPASS_CONFIGURATION_FILE set, using file: {}", configuration_file);
        configuration_json = fs::read_to_string(configuration_file.clone())
            .unwrap_or_else(|ex| panic!("Unable to read the file: {}, {}", configuration_file, ex));
    } else if configuration_json != "" && configuration_file == "" {
        info!("CRUSTPASS_CONFIGURATION_JSON set, using JSON");
    } else {
        panic!("Something went wrong with the settings");
    }

    static INST: OnceLock<Configuration> = OnceLock::new();
    INST.get_or_init(|| {
        serde_json::from_str(configuration_json.as_str())
            .unwrap_or_else(|ex| panic!("Error parsing configuration JSON: {}", ex))
    })
}
