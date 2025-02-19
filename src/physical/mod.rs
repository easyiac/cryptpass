mod libsql_store;

use crate::physical::libsql_store::LibSQLPhysical;
use std::fmt::Display;
use tracing::warn;

#[derive(Clone, Debug)]
pub(crate) enum Physical {
    LibSQL(LibSQLPhysical),
}

#[derive(Debug)]
pub(crate) struct PhysicalError(String);

impl Display for PhysicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Physical Error: {}", self.0)
    }
}

impl Physical {
    pub(crate) async fn new(physical: crate::configuration::Physical) -> Self {
        match physical.physical_type.as_str() {
            "libsql" => Physical::LibSQL(LibSQLPhysical::new(physical).await),
            _ => panic!("Unsupported storage type"),
        }
    }

    pub(crate) async fn read(&mut self, key: &str) -> Result<Option<String>, PhysicalError> {
        let result = match self {
            Physical::LibSQL(physical_impl) => physical_impl
                .read(key)
                .await
                .map_err(|e| PhysicalError(format!("Error reading from libsql: {}", e)))?,
        };

        if let Some((value, key_hash)) = result {
            warn!("Not using key_hash: {}", key_hash);
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    pub(crate) async fn write(&mut self, key: &str, value: &str) -> Result<(), PhysicalError> {
        match self {
            Physical::LibSQL(physical_impl) => physical_impl
                .write(key, value, "key_hash")
                .await
                .map_err(|e| PhysicalError(format!("Error writing to libsql: {}", e))),
        }
    }

    pub(crate) async fn delete(&mut self, key: &str) -> Result<(), PhysicalError> {
        match self {
            Physical::LibSQL(physical_impl) => physical_impl
                .delete(key)
                .await
                .map_err(|e| PhysicalError(format!("Error deleting from libsql: {}", e))),
        }
    }
}
