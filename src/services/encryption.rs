use crate::{
    error::CryptPassError::{
        self, ApplicationNotInitialized, ApplicationNotUnlocked, BadRequest, InternalServerError, NotFound,
    },
    physical::{models::EncryptionKey, schema},
    services::get_settings,
    utils,
};
use diesel::{QueryDsl, RunQueryDsl, SelectableHelper, SqliteConnection};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct InternalEncryptionKey {
    pub(crate) key: String,
    pub(crate) hash: String,
}

static INTERNAL_ENCRYPTION_KEY: OnceLock<InternalEncryptionKey> = OnceLock::new();
fn get_internal_encryption_key(conn: &mut SqliteConnection) -> Result<InternalEncryptionKey, CryptPassError> {
    if let Some(internal_encryption_key) = INTERNAL_ENCRYPTION_KEY.get() {
        return Ok(internal_encryption_key.clone());
    } else {
        let existing_internal_encryption_key_encrypted_str = get_settings("INTERNAL_ENCRYPTION_KEY_ENCRYPTED", conn)?;
        if existing_internal_encryption_key_encrypted_str.is_some() {
            Err(ApplicationNotUnlocked)
        } else {
            Err(ApplicationNotInitialized)
        }
    }
}

pub(crate) fn set_internal_encryption_key(key: String, hash: String) -> Result<(), CryptPassError> {
    Ok(INTERNAL_ENCRYPTION_KEY.set(InternalEncryptionKey { key, hash }).map_err(|ex| {
        BadRequest(format!("Failed to set internal encryption key, Existing key hash: {}", ex.hash.to_string()))
    })?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GeneratedEncryptionKey {
    pub(crate) key: String,
    pub(crate) hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EncryptedValue {
    pub(crate) encrypted_value: String,
    pub(crate) encryption_key_hash: String,
}

pub(crate) fn generate_encryption_key(conn: &mut SqliteConnection) -> Result<GeneratedEncryptionKey, CryptPassError> {
    let internal_encryption_key = get_internal_encryption_key(conn)?;
    let key = utils::generate_key();
    let hash = utils::hash(&key);
    let encrypted_encryption_key = utils::encrypt(&internal_encryption_key.key, &key)?;
    let new_encryption_key = EncryptionKey {
        encrypted_key: encrypted_encryption_key.to_string(),
        key_hash: hash.to_string(),
        encryptor_hash: internal_encryption_key.hash,
    };
    diesel::insert_into(schema::encryption_keys_table::table)
        .values(&new_encryption_key)
        .execute(conn)
        .map_err(|ex| InternalServerError(format!("Error inserting encryption key into db: {}", ex)))?;
    Ok(GeneratedEncryptionKey { key, hash })
}

pub(crate) fn encrypt(plaintext: &str, conn: &mut SqliteConnection) -> Result<EncryptedValue, CryptPassError> {
    let generated_encryption_key = generate_encryption_key(conn)?;
    let encrypted_value = utils::encrypt(generated_encryption_key.key.as_str(), plaintext)?;
    let new_encrypted_value = EncryptedValue {
        encrypted_value: encrypted_value.to_string(),
        encryption_key_hash: generated_encryption_key.hash.to_string(),
    };
    Ok(new_encrypted_value)
}

pub(crate) fn get_encryption_key(
    encryption_key_hash: &str,
    conn: &mut SqliteConnection,
) -> Result<String, CryptPassError> {
    let internal_encryption_key = get_internal_encryption_key(conn)?;
    let encryption_key_encrypted = schema::encryption_keys_table::dsl::encryption_keys_table
        .find((&encryption_key_hash, &internal_encryption_key.hash))
        .select(EncryptionKey::as_select())
        .load(conn)
        .map_err(|ex| InternalServerError(format!("Error reading encryption_key from db: {}", ex)))?;

    let encryption_key_encrypted =
        encryption_key_encrypted.first().ok_or_else(|| NotFound("Encryption key not found".to_string()))?;

    if utils::match_hash(encryption_key_encrypted.encryptor_hash.as_str(), internal_encryption_key.hash.as_str()) {
        return Err(BadRequest("Encryption key hash does not match master encryption key hash.".to_string()));
    };
    Ok(utils::decrypt(&internal_encryption_key.key.clone(), &encryption_key_encrypted.encrypted_key)?)
}

pub(crate) fn decrypt(encrypted_value: EncryptedValue, conn: &mut SqliteConnection) -> Result<String, CryptPassError> {
    let encryption_key = get_encryption_key(&encrypted_value.encryption_key_hash, conn)?;
    utils::decrypt(encryption_key.as_str(), encrypted_value.encrypted_value.as_str())
}
