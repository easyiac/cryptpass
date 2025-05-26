use diesel::{Identifiable, Insertable, Queryable, Selectable};
use serde::Serialize;

#[derive(Queryable, Selectable, Debug, Identifiable)]
#[diesel(primary_key(encryption_key_hash))]
#[diesel(table_name = crate::physical::schema::encryption_keys)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub(crate) struct EncryptionKeyModel {
    pub(crate) encrypted_encryption_key: String,
    pub(crate) encryption_key_hash: String,
    pub(crate) encryptor_key_hash: String,
}

#[derive(Insertable)]
#[diesel(table_name = crate::physical::schema::encryption_keys)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub(crate) struct NewEncryptionKeyModel<'a> {
    pub(crate) id: Option<&'a i64>,
    pub(crate) encrypted_encryption_key: &'a String,
    pub(crate) encryption_key_hash: &'a String,
    pub(crate) encryptor_key_hash: &'a String,
}

#[derive(Queryable, Selectable, Debug, Identifiable, Clone, Serialize)]
#[diesel(table_name = crate::physical::schema::key_value)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
#[diesel(primary_key(key, version))]
pub(crate) struct KeyValueModel {
    pub(crate) key: String,
    pub(crate) encrypted_value: String,
    pub(crate) version: i32,
    pub(crate) encryptor_key_hash: String,
    pub(crate) deleted: bool,
    pub(crate) last_updated_at: i64,
    pub(crate) id: Option<i64>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::physical::schema::key_value)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub(crate) struct NewKeyValueModel<'a> {
    pub(crate) id: Option<&'a i64>,
    pub(crate) key: &'a String,
    pub(crate) encrypted_value: &'a String,
    pub(crate) deleted: bool,
    pub(crate) version: i32,
    pub(crate) last_updated_at: i64,
    pub(crate) encryptor_key_hash: &'a String,
}

#[derive(Queryable, Selectable, Debug, Identifiable)]
#[diesel(table_name = crate::physical::schema::users)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
#[diesel(primary_key(username))]
pub(crate) struct UserModel {
    pub(crate) id: Option<i64>,
    pub(crate) username: String,
    pub(crate) email: Option<String>,
    pub(crate) password_hash: Option<String>,
    pub(crate) password_last_changed: i64,
    pub(crate) roles: String,
    pub(crate) last_login: i64,
    pub(crate) locked: bool,
    pub(crate) enabled: bool,
}

#[derive(Insertable)]
#[diesel(table_name = crate::physical::schema::users)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub(crate) struct NewUserModel<'a> {
    pub(crate) id: Option<&'a i64>,
    pub(crate) username: &'a String,
    pub(crate) email: Option<&'a String>,
    pub(crate) password_hash: Option<&'a String>,
    pub(crate) password_last_changed: &'a i64,
    pub(crate) roles: &'a String,
    pub(crate) last_login: &'a i64,
    pub(crate) locked: &'a bool,
    pub(crate) enabled: &'a bool,
}
