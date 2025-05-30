use crate::{
    auth,
    error::CryptPassError::{self, BadRequest, InternalServerError},
    physical::models::{AppSettingsModel, NewAppSettingsModel},
    services::encryption::INTERNAL_ENCRYPTION_KEY,
};
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper, SqliteConnection};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

pub(crate) mod encryption;
pub(crate) mod key_value;
pub(crate) mod users;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct InternalEncryptionKeySettings {
    pub(crate) encrypted_key: String,
    pub(crate) hash: String,
    pub(crate) encryptor_hash: String,
}

pub(crate) fn init_unlock(
    master_key: String,
    conn: &mut SqliteConnection,
) -> Result<InternalEncryptionKeySettings, CryptPassError> {
    info!("Initializing unlock");
    let master_key_hash = crate::utils::hash(&master_key);
    let existing_internal_encryption_key_encrypted_str =
        get_settings("INTERNAL_ENCRYPTION_KEY_ENCRYPTED".to_string(), conn)?;
    let internal_encryption_key = match existing_internal_encryption_key_encrypted_str {
        Some(existing_internal_encryption_key_str) => {
            info!("Internal encryption key exists");
            let existing_internal_encryption_key: InternalEncryptionKeySettings =
                serde_json::from_str(&existing_internal_encryption_key_str.value)
                    .map_err(|ex| BadRequest(format!("Failed to parse internal encryption key: {}", ex)))?;
            if existing_internal_encryption_key.encryptor_hash != master_key_hash {
                return Err(BadRequest("Internal encryption key is encrypted with a different master key".to_string()));
            }
            let internal_encryption_key =
                crate::utils::decrypt(&master_key, &existing_internal_encryption_key.encrypted_key)?;
            let internal_encryption_key_hash = crate::utils::hash(&internal_encryption_key);
            if internal_encryption_key_hash != existing_internal_encryption_key.hash {
                return Err(BadRequest("Internal encryption key hash does not match existing key hash".to_string()));
            }
            internal_encryption_key
        }
        None => {
            info!("Internal encryption key does not exist, generating new key");
            let new_key = crate::utils::generate_key();
            info!("New internal encryption key generated, hash: {}", crate::utils::hash(new_key.as_str()));
            new_key
        }
    };
    let internal_enc_key_settings = InternalEncryptionKeySettings {
        encrypted_key: crate::utils::encrypt(&master_key.clone(), &internal_encryption_key)?,
        hash: crate::utils::hash(&internal_encryption_key),
        encryptor_hash: master_key_hash,
    };

    let internal_enc_key_settings_str = serde_json::to_string(&internal_enc_key_settings)
        .map_err(|ex| BadRequest(format!("Failed to serialize internal encryption key: {}", ex)))?;

    set_settings("INTERNAL_ENCRYPTION_KEY_ENCRYPTED".to_string(), internal_enc_key_settings_str, conn)?;

    info!("Setting internal encryption key, hash: {}", internal_enc_key_settings.hash);
    INTERNAL_ENCRYPTION_KEY
        .set({
            encryption::InternalEncryptionKey {
                key: internal_encryption_key,
                hash: internal_enc_key_settings.clone().hash,
            }
        })
        .map_err(|ex| {
            BadRequest(format!("Failed to set internal encryption key, Existing key hash: {}", ex.hash.to_string()))
        })?;

    auth::root::create_root_user(conn)?;

    Ok(internal_enc_key_settings)
}

pub(crate) fn get_settings(
    settings_key: String,
    conn: &mut SqliteConnection,
) -> Result<Option<AppSettingsModel>, CryptPassError> {
    let settings_val = crate::physical::schema::app_settings::dsl::app_settings
        .find(&settings_key)
        .select(AppSettingsModel::as_select())
        .load(conn)
        .map_err(|ex| InternalServerError(format!("Error reading settings: {}", ex)))?;

    Ok(settings_val.into_iter().next())
}

pub(crate) fn set_settings(
    settings_key: String,
    settings_value: String,
    conn: &mut SqliteConnection,
) -> Result<(), CryptPassError> {
    let current_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| InternalServerError("System time before UNIX EPOCH".to_string()))?
        .as_millis() as i64;
    let existing_settings = get_settings(settings_key.clone(), conn)?;
    if let Some(existing_settings) = existing_settings {
        if existing_settings.value == settings_value {
            return Ok(());
        }

        info!("Updating settings: {} = {} -> {}", settings_key, existing_settings.value, settings_value);

        diesel::update(crate::physical::schema::app_settings::dsl::app_settings.find(existing_settings.settings))
            .set((
                crate::physical::schema::app_settings::value.eq(&settings_value),
                crate::physical::schema::app_settings::last_updated_at.eq(&current_epoch),
            ))
            .execute(conn)
            .map_err(|ex| InternalServerError(format!("Error updating settings: {}", ex)))?;
        Ok(())
    } else {
        info!("Inserting settings: {} = {}", settings_key, settings_value);
        let new_settings =
            NewAppSettingsModel { settings: &settings_key, value: &settings_value, last_updated_at: &current_epoch };
        diesel::insert_into(crate::physical::schema::app_settings::dsl::app_settings)
            .values(&new_settings)
            .execute(conn)
            .map_err(|ex| InternalServerError(format!("Error inserting settings: {}", ex)))?;
        Ok(())
    }
}
