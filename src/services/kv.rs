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
    shared_state: &mut SharedState,
) -> Result<Option<String>, KvError> {
    info!("Reading key: {}", path);

    check_path(&path).await.map_err(|ex| KvError(format!("Error checking path: {}", ex)))?;
    let physical = &mut shared_state
        .write()
        .map_err(|ex| KvError(format!("Error getting shared state: {}", ex)))?
        .physical
        .clone();
    let master_enc_key_lock = shared_state
        .read()
        .map_err(|ex| KvError(format!("Error getting shared state: {}", ex)))?
        .master_key
        .clone();
    let master_enc_key =
        master_enc_key_lock.get().ok_or_else(|| KvError("Master key not set".to_string()))?;
    Ok(physical
        .read(path, (master_enc_key.0.as_str(), master_enc_key.1.as_str()), "")
        .await
        .map_err(|ex| KvError(format!("Error reading key: {}", ex)))?)
}

pub(crate) async fn write(
    path: &str,
    value: &str,
    shared_state: &mut SharedState,
) -> Result<(), KvError> {
    info!("Writing key: {} with value: {}", path, value);
    check_path(&path).await?;
    let physical = &mut shared_state
        .write()
        .map_err(|ex| KvError(format!("Error getting shared state: {}", ex)))?
        .physical
        .clone();
    let master_enc_key_lock = shared_state
        .read()
        .map_err(|ex| KvError(format!("Error getting shared state: {}", ex)))?
        .master_key
        .clone();
    let master_enc_key =
        master_enc_key_lock.get().ok_or_else(|| KvError("Master key not set".to_string()))?;
    Ok(physical
        .write(path, value, (master_enc_key.0.as_str(), master_enc_key.1.as_str()), "")
        .await
        .map_err(|ex| KvError(format!("Error writing key: {}", ex)))?)
}

pub(crate) async fn delete(path: &str, shared_state: &mut SharedState) -> Result<(), KvError> {
    info!("Deleting key: {}", path);
    check_path(&path).await?;
    let physical = &mut shared_state
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
