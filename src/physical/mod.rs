mod libsql_store;

use crate::physical::libsql_store::LibSQLPhysical;
use std::fmt::Display;

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
    pub(crate) fn new(physical: crate::configuration::Physical) -> Self {
        match physical.physical_type.as_str() {
            "libsql" => Physical::LibSQL(LibSQLPhysical::new(physical)),
            _ => panic!("Unsupported storage type"),
        }
    }

    pub(crate) async fn read(&mut self, key: String) -> Result<Option<String>, PhysicalError> {
        match self {
            Physical::LibSQL(physical_impl) => physical_impl
                .read(key)
                .await
                .map_err(|e| PhysicalError(format!("Error reading from libsql: {}", e))),
        }
    }

    pub(crate) async fn write(&mut self, key: String, value: String) -> Result<(), PhysicalError> {
        match self {
            Physical::LibSQL(physical_impl) => physical_impl
                .write(key, value)
                .await
                .map_err(|e| PhysicalError(format!("Error writing to libsql: {}", e))),
        }
    }

    pub(crate) async fn delete(&mut self, key: String) -> Result<(), PhysicalError> {
        match self {
            Physical::LibSQL(physical_impl) => physical_impl
                .delete(key)
                .await
                .map_err(|e| PhysicalError(format!("Error deleting from libsql: {}", e))),
        }
    }
}
