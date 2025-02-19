use libsql::{Builder, Connection};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
// CREATE TABLE secrets_d (
//     id_d INTEGER PRIMARY KEY AUTOINCREMENT,
//     key_d TEXT NOT NULL,
//     value_d TEXT NOT NULL,
//     version_d INTEGER DEFAULT (1) NOT NULL,
//     updated_at_d INTEGER DEFAULT (-1) NOT NULL,
//     is_deleted_d INTEGER DEFAULT (0) NOT NULL
// );
// CREATE UNIQUE INDEX secrets_d_key_d_IDX ON secrets_d (key_d,version_d);

#[derive(Clone, Debug, Deserialize)]
struct LibSQLDetails {
    table_name: String,
    db_url: String,
    auth_token: String,
}

pub(crate) struct LibSQLError(String);

impl std::fmt::Display for LibSQLError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "LibSQL Error: {}", self.0)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LibSQLPhysical {
    libsql_details: LibSQLDetails,
}

impl LibSQLPhysical {
    pub(crate) fn new(physical: crate::configuration::Physical) -> Self {
        if physical.physical_type != "libsql" {
            panic!("Only sqlite is supported at this time");
        }
        let libsql_details: LibSQLDetails = serde_json::from_value(physical.physical_details)
            .unwrap_or_else(|ex| panic!("Error parsing libsql details: {}", ex));
        LibSQLPhysical { libsql_details }
    }

    async fn get_connection(&mut self) -> Result<Connection, LibSQLError> {
        Builder::new_remote(
            self.libsql_details.db_url.clone(),
            self.libsql_details.auth_token.clone(),
        )
        .build()
        .await
        .map_err(|ex| LibSQLError(format!("Error building libsql connection: {}", ex)))?
        .connect()
        .map_err(|ex| LibSQLError(format!("Error connecting to libsql: {}", ex)))
    }

    async fn get_current_version(&mut self, key: &str) -> Result<i64, LibSQLError> {
        let table_name = self.libsql_details.table_name.clone();
        let sql = &format!(
            "SELECT version_d FROM {table_name} WHERE key_d = ? ORDER BY version_d DESC LIMIT 1;"
        );
        let mut rows =
            self.get_connection().await?.query(sql, libsql::params![key]).await.map_err(|ex| {
                LibSQLError(format!("Error performing libsql get_current_version: {}", ex))
            })?;
        if let Some(row) = rows
            .next()
            .await
            .map_err(|ex| LibSQLError(format!("Error getting next row from libsql: {}", ex)))?
        {
            row.get(0)
                .map_err(|ex| LibSQLError(format!("Error getting version from libsql: {}", ex)))
        } else {
            Ok(0)
        }
    }
    pub(crate) async fn read(&mut self, key: &str) -> Result<Option<String>, LibSQLError> {
        let table_name = self.libsql_details.table_name.to_string();
        let sql =&format!(
            "SELECT value_d FROM {table_name} WHERE key_d = ? AND is_deleted_d = 0 ORDER BY version_d DESC LIMIT 1;"
        );
        let mut rows = self
            .get_connection()
            .await?
            .query(sql, libsql::params![key])
            .await
            .map_err(|ex| LibSQLError(format!("Error performing libsql read: {}", ex)))?;
        if let Some(row) = rows
            .next()
            .await
            .map_err(|ex| LibSQLError(format!("Error getting next row from libsql: {}", ex)))?
        {
            Ok(Some(
                row.get(0).map_err(|ex| {
                    LibSQLError(format!("Error getting value from libsql: {}", ex))
                })?,
            ))
        } else {
            Ok(None)
        }
    }

    pub(crate) async fn write(&mut self, key: &str, value: &str) -> Result<(), LibSQLError> {
        let table_name = self.libsql_details.table_name.to_string();
        let next_version = self.get_current_version(key).await? + 1;
        let current_epoch_time: i64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|ex| LibSQLError(format!("Error getting current epoch time: {}", ex)))?
            .as_secs() as i64;
        let sql = &format!("INSERT INTO {table_name} (key_d, value_d, version_d, updated_at_d) VALUES (?, ?, ?, ?);");
        self.get_connection()
            .await?
            .execute(sql, libsql::params![key, value, next_version, current_epoch_time])
            .await
            .map_err(|ex| LibSQLError(format!("Error performing libsql write: {}", ex)))?;
        Ok(())
    }

    pub(crate) async fn delete(&mut self, key: &str) -> Result<(), LibSQLError> {
        let table_name = self.libsql_details.table_name.to_string();
        let current_epoch_time: i64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|ex| LibSQLError(format!("Error getting current epoch time: {}", ex)))?
            .as_secs() as i64;
        let sql =
            &format!("UPDATE {table_name} SET is_deleted_d = 1, updated_at_d = ? WHERE key_d = ?;");
        self.get_connection()
            .await?
            .execute(sql, libsql::params![current_epoch_time, key])
            .await
            .map_err(|ex| LibSQLError(format!("Error performing libsql delete: {}", ex)))?;
        Ok(())
    }
}
