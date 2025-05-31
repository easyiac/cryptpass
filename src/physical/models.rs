use diesel::{AsChangeset, Identifiable, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Queryable, Insertable, Selectable, Debug, Identifiable)]
#[diesel(table_name = crate::physical::schema::app_settings)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
#[diesel(primary_key(settings))]
pub(crate) struct AppSettingsModel {
    pub(crate) settings: String,
    pub(crate) value: String,
    pub(crate) last_updated_at: i64,
}

#[derive(Queryable, Insertable, Selectable, Debug, Identifiable)]
#[diesel(primary_key(encryption_key_hash))]
#[diesel(table_name = crate::physical::schema::encryption_keys)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub(crate) struct EncryptionKeyModel {
    pub(crate) encrypted_encryption_key: String,
    pub(crate) encryption_key_hash: String,
    pub(crate) encryptor_key_hash: String,
}

#[derive(Queryable, Insertable, Selectable, Debug, Identifiable, Clone, Serialize, ToSchema)]
#[diesel(table_name = crate::physical::schema::key_value)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
#[diesel(primary_key(key, version))]
pub(crate) struct KeyValueModel {
    pub(crate) key: String,
    pub(crate) encrypted_value: String,
    pub(crate) version: i32,
    pub(crate) deleted: bool,
    pub(crate) last_updated_at: i64,
}

#[derive(
    Queryable, Insertable, Selectable, Debug, Identifiable, Serialize, Deserialize, Clone, AsChangeset, ToSchema,
)]
#[diesel(table_name = crate::physical::schema::users)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
#[diesel(primary_key(username))]
pub(crate) struct UserModel {
    pub(crate) username: String,
    pub(crate) email: Option<String>,
    #[serde(skip)]
    pub(crate) password_hash: Option<String>,
    pub(crate) password_last_changed: i64,
    pub(crate) roles: String,
    pub(crate) last_login: i64,
    pub(crate) locked: bool,
    pub(crate) enabled: bool,
    #[serde(skip)]
    pub(crate) api_token_jwt_secret_b64_encrypted: String,
}
