use crate::SharedState;
use tracing::info;

#[derive(Debug)]
pub(crate) struct KvError(String);

impl std::fmt::Display for KvError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            KvError(e) => write!(f, "KVError: {}", e),
        }
    }
}

pub(crate) async fn read(
    path: &str,
    shared_state: &SharedState,
) -> Result<Option<String>, KvError> {
    info!("Reading key: {}", path);

    check_path(&path).await.map_err(|ex| KvError(format!("Error checking path: {}", ex)))?;
    let mut app_state = shared_state
        .write()
        .map_err(|ex| KvError(format!("Error getting shared state: {}", ex)))?
        .clone();

    let master_key =
        app_state.master_key.get().ok_or_else(|| KvError("Master key not set".to_string()))?;
    Ok(app_state
        .physical
        .read(path, (master_key.0.as_str(), master_key.1.as_str()))
        .await
        .map_err(|ex| KvError(format!("Error reading key: {}", ex)))?)
}

pub(crate) async fn write(
    path: &str,
    value: &str,
    shared_state: &SharedState,
) -> Result<(), KvError> {
    info!("Writing key: {} with value: {}", path, value);
    check_path(&path).await?;
    let mut app_state = shared_state
        .write()
        .map_err(|ex| KvError(format!("Error getting shared state: {}", ex)))?
        .clone();

    let master_key =
        app_state.master_key.get().ok_or_else(|| KvError("Master key not set".to_string()))?;
    Ok(app_state
        .physical
        .write(path, value, (master_key.0.as_str(), master_key.1.as_str()) /* &str */)
        .await
        .map_err(|ex| KvError(format!("Error writing key: {}", ex)))?)
}

pub(crate) async fn delete(path: &str, shared_state: &SharedState) -> Result<(), KvError> {
    info!("Deleting key: {}", path);
    check_path(&path).await?;
    let mut physical = shared_state
        .write()
        .map_err(|ex| KvError(format!("Error getting shared state: {}", ex)))?
        .physical
        .clone();

    Ok(physical.delete(path).await.map_err(|ex| KvError(format!("Error deleting key: {}", ex)))?)
}

async fn check_path(path: &str) -> Result<(), KvError> {
    if path.starts_with("/") {
        return Err(KvError("Key cannot start with /".to_string()));
    }

    if path.contains("//") {
        return Err(KvError("Key cannot contain //".to_string()));
    }

    if path.ends_with("/") {
        return Err(KvError("Key cannot end with /".to_string()));
    }

    if path.is_empty() {
        return Err(KvError("Key cannot be empty".to_string()));
    }
    Ok(())
}
