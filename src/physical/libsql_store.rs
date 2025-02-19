use libsql::{Builder, Connection};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

const CREATE_TABLE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS encryption_keys_d (
    id_d INTEGER PRIMARY KEY AUTOINCREMENT,
    encryption_key_hash_d TEXT NOT NULL,
    encryption_key_d TEXT NOT NULL,
    master_key_hash_d TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS secrets_d (
	id_d INTEGER PRIMARY KEY AUTOINCREMENT,
	key_d TEXT NOT NULL,
	value_d TEXT NOT NULL,
	version_d INTEGER DEFAULT (1) NOT NULL,
	updated_at_d INTEGER DEFAULT (-1) NOT NULL,
	is_deleted_d INTEGER DEFAULT (0) NOT NULL,
    encryption_key_hash_d TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS secrets_d_key_d_IDX ON secrets_d (key_d,version_d);
"#;

#[derive(Clone, Debug, Deserialize)]
struct LibSQLDetails {
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
    pub(crate) async fn new(physical: crate::configuration::Physical) -> Self {
        if physical.physical_type != "libsql" {
            panic!("Only sqlite is supported at this time");
        }
        let libsql_details: LibSQLDetails = serde_json::from_value(physical.physical_details)
            .unwrap_or_else(|ex| panic!("Error parsing libsql details: {}", ex));
        let mut libsql = LibSQLPhysical { libsql_details };
        info!("LibSQLPhysical initialized");
        info!("Creating Table: secrets_d");
        let result = libsql
            .get_connection()
            .await
            .unwrap_or_else(|ex| panic!("Error creating table: secrets_d: {}", ex))
            .execute_batch(CREATE_TABLE_SQL)
            .await
            .unwrap_or_else(|ex| panic!("Error creating table: secrets_d: {}", ex));
        info!("Table: secrets_d created: {:?}", result);

        libsql
    }

    async fn get_connection(&mut self) -> Result<Connection, LibSQLError> {
        Builder::new_remote(
            self.libsql_details.db_url.to_string(),
            self.libsql_details.auth_token.to_string(),
        )
        .build()
        .await
        .map_err(|ex| LibSQLError(format!("Error building libsql connection: {}", ex)))?
        .connect()
        .map_err(|ex| LibSQLError(format!("Error connecting to libsql: {}", ex)))
    }

    async fn get_current_version(&mut self, key: &str) -> Result<i64, LibSQLError> {
        let sql =
            "SELECT version_d FROM secrets_d WHERE key_d = ? ORDER BY version_d DESC LIMIT 1;";
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
    pub(crate) async fn read(
        &mut self,
        key: &str,
    ) -> Result<Option<(String, String)>, LibSQLError> {
        let sql ="SELECT value_d, encryption_key_hash_d FROM secrets_d WHERE key_d = ? AND is_deleted_d = 0 ORDER BY version_d DESC LIMIT 1;";
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
            let value = row
                .get(0)
                .map_err(|ex| LibSQLError(format!("Error getting value from libsql: {}", ex)))?;
            let encryption_key_hash = row.get(1).map_err(|ex| {
                LibSQLError(format!("Error getting encryption_key_hash from libsql: {}", ex))
            })?;
            Ok(Some((value, encryption_key_hash)))
        } else {
            Ok(None)
        }
    }

    pub(crate) async fn write(
        &mut self,
        key: &str,
        value: &str,
        key_hash: &str,
    ) -> Result<(), LibSQLError> {
        let next_version = self.get_current_version(key).await? + 1;
        let current_epoch_time: i64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|ex| LibSQLError(format!("Error getting current epoch time: {}", ex)))?
            .as_secs() as i64;
        let sql =
            "INSERT INTO secrets_d (key_d, value_d, version_d, updated_at_d, encryption_key_hash_d) VALUES (?, ?, ?, ?, ?);";
        self.get_connection()
            .await?
            .execute(sql, libsql::params![key, value, next_version, current_epoch_time, key_hash])
            .await
            .map_err(|ex| LibSQLError(format!("Error performing libsql write: {}", ex)))?;
        Ok(())
    }

    pub(crate) async fn delete(&mut self, key: &str) -> Result<(), LibSQLError> {
        let current_epoch_time: i64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|ex| LibSQLError(format!("Error getting current epoch time: {}", ex)))?
            .as_secs() as i64;
        let sql = "UPDATE secrets_d SET is_deleted_d = 1, updated_at_d = ? WHERE key_d = ?;";
        self.get_connection()
            .await?
            .execute(sql, libsql::params![current_epoch_time, key])
            .await
            .map_err(|ex| LibSQLError(format!("Error performing libsql delete: {}", ex)))?;
        Ok(())
    }
}
