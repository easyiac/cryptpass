pub(crate) mod encryption;
pub(crate) mod key_value;
pub(crate) mod users;

use crate::{
    error::CryptPassError::{self, InternalServerError},
    physical::models::AppSettings,
};
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper, SqliteConnection};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

pub(crate) fn get_settings(
    settings_key: &str,
    conn: &mut SqliteConnection,
) -> Result<Option<AppSettings>, CryptPassError> {
    let settings_val = crate::physical::schema::app_settings_table::dsl::app_settings_table
        .find(&settings_key)
        .select(AppSettings::as_select())
        .load(conn)
        .map_err(|ex| InternalServerError(format!("Error reading settings: {}", ex)))?;

    Ok(settings_val.into_iter().next())
}

pub(crate) fn set_settings(
    settings_key: &str,
    settings_value: &str,
    conn: &mut SqliteConnection,
) -> Result<(), CryptPassError> {
    let current_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|ex| InternalServerError(format!("Error getting current epoch: {}", ex)))?
        .as_millis() as i64;
    let existing_settings = get_settings(settings_key, conn)?;
    if let Some(existing_settings) = existing_settings {
        info!("Updating settings: {}", settings_key);

        diesel::update(
            crate::physical::schema::app_settings_table::dsl::app_settings_table.find(existing_settings.settings),
        )
        .set((
            crate::physical::schema::app_settings_table::value.eq(&settings_value),
            crate::physical::schema::app_settings_table::last_updated_at.eq(&current_epoch),
        ))
        .execute(conn)
        .map_err(|ex| InternalServerError(format!("Error updating settings: {}", ex)))?;
        Ok(())
    } else {
        info!("Inserting settings: {} = {}", settings_key, settings_value);
        let new_settings = AppSettings {
            settings: settings_key.to_string(),
            value: settings_value.to_string(),
            last_updated_at: current_epoch,
        };
        diesel::insert_into(crate::physical::schema::app_settings_table::dsl::app_settings_table)
            .values(&new_settings)
            .execute(conn)
            .map_err(|ex| InternalServerError(format!("Error inserting settings: {}", ex)))?;
        Ok(())
    }
}
