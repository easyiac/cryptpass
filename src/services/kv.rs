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

    check_path(&path).await.expect("Error checking path");

    let physical = &mut shared_state.write().unwrap().physical.clone();

    let value = physical.read(path).await.expect("Error reading key").map(|v| v.to_string());
    Ok(value)
}

pub(crate) async fn write(
    path: &str,
    value: &str,
    shared_state: &mut SharedState,
) -> Result<(), KvError> {
    info!("Writing key: {} with value: {}", path, value);
    check_path(&path).await?;
    let storage = &mut shared_state
        .write()
        .map_err(|e| KvError(format!("Error getting shared state: {}", e)))?
        .physical
        .clone();

    storage.write(path, value).await.map_err(|e| KvError(format!("Error writing key: {}", e)))?;
    Ok(())
}

pub(crate) async fn delete(path: &str, shared_state: &mut SharedState) -> Result<(), KvError> {
    info!("Deleting key: {}", path);
    check_path(&path).await?;
    let storage = &mut shared_state
        .write()
        .map_err(|e| KvError(format!("Error getting shared state: {}", e)))?
        .physical
        .clone();

    storage.delete(path).await.map_err(|e| KvError(format!("Error deleting key: {}", e)))?;
    Ok(())
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
