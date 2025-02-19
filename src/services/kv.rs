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

    check_path(&path).await.map_err(|e| KvError(format!("Error checking path: {}", e)))?;
    let physical = &mut shared_state
        .write()
        .map_err(|e| KvError(format!("Error getting shared state: {}", e)))?
        .physical
        .clone();

    Ok(physical.read(path).await.map_err(|e| KvError(format!("Error reading key: {}", e)))?)
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
        .map_err(|e| KvError(format!("Error getting shared state: {}", e)))?
        .physical
        .clone();

    Ok(physical
        .write(path, value)
        .await
        .map_err(|e| KvError(format!("Error writing key: {}", e)))?)
}

pub(crate) async fn delete(path: &str, shared_state: &mut SharedState) -> Result<(), KvError> {
    info!("Deleting key: {}", path);
    check_path(&path).await?;
    let physical = &mut shared_state
        .write()
        .map_err(|e| KvError(format!("Error getting shared state: {}", e)))?
        .physical
        .clone();

    Ok(physical.delete(path).await.map_err(|e| KvError(format!("Error deleting key: {}", e)))?)
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
