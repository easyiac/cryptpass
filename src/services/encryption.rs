use crate::{
    error::CryptPassError::{self, BadRequest, InternalServerError, NotFound},
    physical::{models::EncryptionKeyModel, schema::encryption_keys},
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

pub(crate) static INTERNAL_ENCRYPTION_KEY: OnceLock<InternalEncryptionKey> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EncryptedValue {
    pub(crate) encrypted_value: String,
    pub(crate) encryption_key_hash: String,
}

pub(crate) fn encrypt(plaintext: &str, conn: &mut SqliteConnection) -> Result<String, CryptPassError> {
    let internal_encryption_key = get_internal_encryption_key()?;
    let encryption_key = utils::generate_key();
    let encryption_key_hash = utils::hash(&encryption_key);
    let encrypted_value = utils::encrypt(encryption_key.as_str(), plaintext)?;
    let encrypted_encryption_key = utils::encrypt(&internal_encryption_key.key, &encryption_key)?;
    let new_encryption_key = EncryptionKeyModel {
        encrypted_encryption_key: encrypted_encryption_key.to_string(),
        encryption_key_hash: encryption_key_hash.to_string(),
        encryptor_key_hash: internal_encryption_key.hash,
    };
    diesel::insert_into(encryption_keys::table)
        .values(&new_encryption_key)
        .execute(conn)
        .map_err(|ex| InternalServerError(format!("Error inserting encryption key into db: {}", ex)))?;
    let new_encrypted_value = EncryptedValue {
        encrypted_value: encrypted_value.to_string(),
        encryption_key_hash: encryption_key_hash.to_string(),
    };
    let new_encrypted_value_json = serde_json::to_string(&new_encrypted_value)
        .map_err(|ex| InternalServerError(format!("Error serializing encrypted value: {}", ex)))?;
    Ok(new_encrypted_value_json)
}

fn get_internal_encryption_key() -> Result<InternalEncryptionKey, CryptPassError> {
    if let Some(internal_encryption_key) = INTERNAL_ENCRYPTION_KEY.get() {
        return Ok(internal_encryption_key.clone());
    }
    Err(InternalServerError("Internal encryption key not set".to_string()))
}

pub(crate) fn decrypt(encrypted_value_json: String, conn: &mut SqliteConnection) -> Result<String, CryptPassError> {
    let internal_encryption_key = get_internal_encryption_key()?;
    let encrypted_value: EncryptedValue = serde_json::from_str(&encrypted_value_json)
        .map_err(|ex| InternalServerError(format!("Error deserializing encrypted value: {}", ex)))?;
    let encryption_key_encrypted = encryption_keys::dsl::encryption_keys
        .find((&encrypted_value.encryption_key_hash, &internal_encryption_key.hash))
        .select(EncryptionKeyModel::as_select())
        .load(conn)
        .map_err(|ex| InternalServerError(format!("Error reading encryption_key from db: {}", ex)))?;

    let encryption_key_encrypted =
        encryption_key_encrypted.first().ok_or_else(|| NotFound("Encryption key not found".to_string()))?;

    if utils::match_hash(encryption_key_encrypted.encryptor_key_hash.as_str(), internal_encryption_key.hash.as_str()) {
        return Err(BadRequest("Encryption key hash does not match master encryption key hash.".to_string()));
    }

    let encryption_key =
        utils::decrypt(&internal_encryption_key.key.clone(), &encryption_key_encrypted.encrypted_encryption_key)?;

    utils::decrypt(encryption_key.as_str(), encrypted_value.encrypted_value.as_str())
}
