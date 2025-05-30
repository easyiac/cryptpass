use crate::{
    error::CryptPassError::{self, InternalServerError},
    physical::models::AppSettingsModel,
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
            AppSettingsModel { settings: settings_key, value: settings_value, last_updated_at: current_epoch };
        diesel::insert_into(crate::physical::schema::app_settings::dsl::app_settings)
            .values(&new_settings)
            .execute(conn)
            .map_err(|ex| InternalServerError(format!("Error inserting settings: {}", ex)))?;
        Ok(())
    }
}
