use crate::{
    encryption,
    error::CryptPassError::{self, BadRequest, InternalServerError, NotFound},
    physical::{models::EncryptionKeyModel, schema},
};
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper, SqliteConnection};
use std::sync::OnceLock;

pub(crate) static MASTER_ENCRYPTION_KEY: OnceLock<(String, String)> = OnceLock::new(); // key, hash

#[derive(Debug, Clone)]
pub(crate) struct EncryptedValue {
    pub(crate) encrypted_value: String,
    pub(crate) encryption_key_hash: String,
}

pub(crate) fn enc(
    plaintext: &str,
    conn: &mut SqliteConnection,
) -> Result<EncryptedValue, CryptPassError> {
    let (master_enc_key, master_enc_key_hash) = get_master_key()?;
    let encryption_key = encryption::generate_key();
    let encryption_key_hash = encryption::hash(&encryption_key);
    let encrypted_value = encryption::encrypt(encryption_key.as_str(), plaintext)?;
    let encrypted_encryption_key = encryption::encrypt(&master_enc_key, &encryption_key)?;
    let new_encryption_key = crate::physical::models::NewEncryptionKeyModel {
        id: None,
        encrypted_encryption_key: &encrypted_encryption_key.to_string(),
        encryption_key_hash: &encryption_key_hash.to_string(),
        encryptor_key_hash: &master_enc_key_hash,
    };
    diesel::insert_into(schema::encryption_keys::table)
        .values(&new_encryption_key)
        .execute(conn)
        .map_err(|ex| {
            InternalServerError(format!("Error inserting encryption key into db: {}", ex))
        })?;
    Ok(EncryptedValue { encrypted_value, encryption_key_hash })
}

fn get_master_key() -> Result<(String, String), CryptPassError> {
    if let Some(master_key) = MASTER_ENCRYPTION_KEY.get() {
        return Ok(master_key.clone());
    }
    Err(InternalServerError("Master encryption key not set".to_string()))
}

pub(crate) fn dec(
    encrypted_value: EncryptedValue,
    conn: &mut SqliteConnection,
) -> Result<String, CryptPassError> {
    let encryption_key_encrypted = schema::encryption_keys::table
        .filter(
            schema::encryption_keys::encryption_key_hash.eq(encrypted_value.encryption_key_hash),
        )
        .select(EncryptionKeyModel::as_select())
        .load(conn)
        .map_err(|ex| {
            InternalServerError(format!("Error reading encryption_key from db: {}", ex))
        })?;

    let encryption_key_encrypted = encryption_key_encrypted
        .first()
        .ok_or_else(|| NotFound("Encryption key not found".to_string()))?;

    let (master_enc_key, master_enc_key_hash) = get_master_key()?;
    if encryption::match_hash(
        encryption_key_encrypted.encryptor_key_hash.as_str(),
        master_enc_key_hash.as_str(),
    ) {
        return Err(BadRequest(
            "Encryption key hash does not match master encryption key hash.".to_string(),
        ));
    }

    let encryption_key = encryption::decrypt(
        &master_enc_key.clone(),
        &encryption_key_encrypted.encrypted_encryption_key,
    )?;

    encryption::decrypt(encryption_key.as_str(), encrypted_value.encrypted_value.as_str())
}
