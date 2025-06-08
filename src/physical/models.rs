use crate::error::CryptPassError::{self, InternalServerError};
use diesel::{AsChangeset, Identifiable, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Queryable, Insertable, Selectable)]
#[diesel(primary_key(key_hash, encryptor_hash))]
#[diesel(table_name = crate::physical::schema::encryption_keys_table)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub(crate) struct EncryptionKey {
    pub(crate) encrypted_key: String,
    pub(crate) key_hash: String,
    pub(crate) encryptor_hash: String,
}

#[derive(Queryable, Insertable, Selectable)]
#[diesel(table_name = crate::physical::schema::app_settings_table)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
#[diesel(primary_key(settings))]
pub(crate) struct AppSettings {
    pub(crate) settings: String,
    pub(crate) value: String,
    pub(crate) last_updated_at: i64,
}

#[derive(Queryable, Insertable, Selectable, Clone, Serialize, ToSchema)]
#[diesel(table_name = crate::physical::schema::key_value_table)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
#[diesel(primary_key(key, version))]
pub(crate) struct KeyValue {
    pub(crate) key: String,
    pub(crate) encrypted_value: String,
    pub(crate) version: i32,
    pub(crate) deleted: bool,
    pub(crate) last_updated_at: i64,
    pub(crate) encryptor_hash: String,
}

#[derive(Queryable, Insertable, Selectable, Identifiable, AsChangeset)]
#[diesel(table_name = crate::physical::schema::users_table)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
#[diesel(primary_key(username))]
pub(crate) struct UserTable {
    pub(crate) username: String,
    pub(crate) email: Option<String>,
    pub(crate) password_hash: Option<String>,
    pub(crate) password_last_changed: i64,
    pub(crate) roles: String,
    pub(crate) last_login: i64,
    pub(crate) locked: bool,
    pub(crate) enabled: bool,
    pub(crate) encryptor_hash: String,
    pub(crate) jwt_secret_b64_encrypted: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub(crate) enum PrivilegeType {
    SUDO,
    #[allow(non_camel_case_types)]
    NO_SUDO,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub(crate) struct Privilege {
    pub(crate) name: PrivilegeType,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub(crate) enum RoleType {
    ADMIN,
    USER,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub(crate) struct Role {
    pub(crate) name: RoleType,
    pub(crate) privileges: Vec<Privilege>,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub(crate) struct Users {
    #[serde(skip)]
    pub(crate) username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) email: Option<String>,
    #[serde(skip)]
    pub(crate) password_hash: Option<String>,
    pub(crate) password_last_changed: i64,
    pub(crate) roles: Vec<Role>,
    pub(crate) last_login: i64,
    pub(crate) locked: bool,
    pub(crate) enabled: bool,
    #[serde(skip)]
    pub(crate) encryptor_hash: String,
    #[serde(skip)]
    pub(crate) jwt_secret_b64_encrypted: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) password: Option<String>,
}

impl Users {
    pub(crate) fn to_table(&self) -> Result<UserTable, CryptPassError> {
        let ut = UserTable {
            username: self.username.clone(),
            email: self.email.clone(),
            password_hash: self.password_hash.clone(),
            password_last_changed: self.password_last_changed,
            roles: serde_json::to_string(&self.roles)
                .map_err(|ex| CryptPassError::InternalServerError(format!("Unable to serialize roles: {}", ex)))?,
            last_login: self.last_login,
            locked: self.locked,
            enabled: self.enabled,
            encryptor_hash: self.encryptor_hash.clone(),
            jwt_secret_b64_encrypted: self.jwt_secret_b64_encrypted.clone(),
        };
        Ok(ut)
    }
}

impl UserTable {
    pub(crate) fn to_users(&self) -> Result<Users, CryptPassError> {
        let tu = Users {
            username: self.username.clone(),
            email: self.email.clone(),
            password_hash: self.password_hash.clone(),
            password_last_changed: self.password_last_changed,
            roles: serde_json::from_str(&self.roles)
                .map_err(|ex| InternalServerError(format!("Unable to deserialize roles: {}", ex)))?,
            last_login: self.last_login,
            locked: self.locked,
            enabled: self.enabled,
            encryptor_hash: self.encryptor_hash.clone(),
            jwt_secret_b64_encrypted: self.jwt_secret_b64_encrypted.clone(),
            password: None,
        };
        Ok(tu)
    }
}
