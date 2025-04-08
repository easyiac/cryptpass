mod models;
mod schema;
use crate::{
    auth::roles::User,
    encryption::{decrypt, encrypt, generate_key, hash, match_hash},
    physical::models::{
        EncryptionKeyModel, KeyValueModel, NewEncryptionKeyModel, NewKeyValueModel, NewUserModel,
        UserModel,
    },
};
use diesel::{
    ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper, SqliteConnection,
    TextExpressionMethods,
};
use std::fmt::Display;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

#[derive(Debug)]
pub(crate) struct PhysicalError(String);

impl Display for PhysicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Physical Error: {}", self.0)
    }
}

pub(crate) static MASTER_ENCRYPTION_KEY: OnceLock<(String, String)> = OnceLock::new(); // key, hash

fn get_next_version(key: &str, conn: &mut SqliteConnection) -> i32 {
    let current_max = schema::key_value::table
        .select(schema::key_value::version)
        .filter(schema::key_value::key.eq(key))
        .order(schema::key_value::version.desc())
        .first::<i32>(conn)
        .unwrap_or(0);
    current_max + 1
}

pub(crate) fn write(
    key: &str,
    value: &str,
    conn: &mut SqliteConnection,
) -> Result<(), PhysicalError> {
    validate_keys(key, false)?;
    let (master_enc_key, master_enc_key_hash) =
        if let Some(master_key) = MASTER_ENCRYPTION_KEY.get() {
            (master_key.0.clone(), master_key.1.clone())
        } else {
            return Err(PhysicalError("Master encryption key not set".to_string()));
        };
    let next_version = get_next_version(key, conn);

    let encryption_key = generate_key();
    let encryption_key_hash = hash(&encryption_key);
    let encrypted_value = encrypt(&encryption_key, value)
        .map_err(|ex| PhysicalError(format!("Error encrypting value: {}", ex)))?;
    let encrypted_encryption_key = encrypt(&master_enc_key, &encryption_key)
        .map_err(|ex| PhysicalError(format!("Error encrypting encryption key: {}", ex)))?;
    let new_key_value = NewKeyValueModel {
        id: None,
        key: &key.to_string(),
        encrypted_value: &encrypted_value.to_string(),
        deleted: false,
        version: next_version,
        last_updated_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PhysicalError("System time before UNIX EPOCH".to_string()))?
            .as_millis() as i64,
        encryptor_key_hash: &encryption_key_hash.to_string(),
    };
    let new_encryption_key = NewEncryptionKeyModel {
        id: None,
        encrypted_encryption_key: &encrypted_encryption_key.to_string(),
        encryption_key_hash: &encryption_key_hash.to_string(),
        encryptor_key_hash: &master_enc_key_hash,
    };
    diesel::insert_into(schema::encryption_keys::table)
        .values(&new_encryption_key)
        .execute(conn)
        .map_err(|ex| PhysicalError(format!("Error inserting into db: {}", ex)))?;
    diesel::insert_into(schema::key_value::table)
        .values(&new_key_value)
        .execute(conn)
        .map_err(|ex| PhysicalError(format!("Error inserting into db: {}", ex)))?;
    Ok(())
}

fn get_latest_version(key: &str, conn: &mut SqliteConnection) -> i32 {
    let key = key.to_string();
    schema::key_value::table
        .select(schema::key_value::version)
        .filter(schema::key_value::key.eq(key))
        .filter(schema::key_value::deleted.eq(false))
        .order(schema::key_value::version.desc())
        .first::<i32>(conn)
        .unwrap_or(0)
}

pub(crate) fn read(
    key: &str,
    conn: &mut SqliteConnection,
) -> Result<Option<String>, PhysicalError> {
    validate_keys(key, false)?;
    let (master_enc_key, master_enc_key_hash) =
        if let Some(master_key) = MASTER_ENCRYPTION_KEY.get() {
            (master_key.0.clone(), master_key.1.clone())
        } else {
            return Err(PhysicalError("Master encryption key not set".to_string()));
        };
    let latest_version = get_latest_version(key, conn);
    if latest_version == 0 {
        return Ok(None);
    }
    let result = schema::key_value::dsl::key_value
        .filter(schema::key_value::version.eq(latest_version))
        .filter(schema::key_value::key.eq(key))
        .limit(1)
        .select(KeyValueModel::as_select())
        .load(conn)
        .map_err(|ex| PhysicalError(format!("Error reading from db: {}", ex)))?;
    let key_value = if result.first().is_some() {
        result.first().unwrap()
    } else {
        return Ok(None);
    };
    let encryption_key_hash = key_value.encryptor_key_hash.to_string();
    let encrypted_value = key_value.encrypted_value.to_string();
    let encryption_key_encrypted = schema::encryption_keys::table
        .filter(schema::encryption_keys::encryption_key_hash.eq(encryption_key_hash))
        .select(EncryptionKeyModel::as_select())
        .load(conn)
        .map_err(|ex| PhysicalError(format!("Error reading from db: {}", ex)))?;

    if encryption_key_encrypted.is_empty() {
        return Err(PhysicalError(format!("Encryption key not found for key: {}", key)));
    }

    if match_hash(
        encryption_key_encrypted.first().unwrap().encryptor_key_hash.as_str(),
        master_enc_key_hash.as_str(),
    ) {
        return Err(PhysicalError(format!(
            "Encryption key hash does not match master encryption key hash for key: {}",
            key
        )));
    }

    let encryption_key = decrypt(
        &master_enc_key.clone(),
        &encryption_key_encrypted.first().unwrap().encrypted_encryption_key,
    )
    .map_err(|ex| PhysicalError(format!("Error decrypting encryption key: {}", ex)))?;
    let decrypted_value = decrypt(&encryption_key, &encrypted_value)
        .map_err(|ex| PhysicalError(format!("Error decrypting value: {}", ex)))?;
    Ok(Some(decrypted_value))
}

pub(crate) fn mark_all_version_for_delete(
    key: &str,
    conn: &mut SqliteConnection,
) -> Result<(), PhysicalError> {
    validate_keys(key, false)?;
    diesel::update(schema::key_value::table)
        .filter(schema::key_value::key.eq(key))
        .set(schema::key_value::deleted.eq(true))
        .execute(conn)
        .map_err(|ex| PhysicalError(format!("Error deleting from db: {}", ex)))?;
    Ok(())
}

pub(crate) fn list_all_keys(
    key: &str,
    conn: &mut SqliteConnection,
) -> Result<Vec<String>, PhysicalError> {
    validate_keys(key, true)?;
    let mut find_key = key.to_string();
    if !find_key.is_empty() {
        find_key = format!("{}/", find_key);
    }
    Ok(schema::key_value::dsl::key_value
        .filter(schema::key_value::key.like(format!("{}%", find_key)))
        .filter(schema::key_value::deleted.eq(false))
        .select(schema::key_value::key)
        .distinct()
        .load::<String>(conn)
        .unwrap_or_else(|ex| {
            warn!("Error listing keys from db: {}", ex);
            vec![]
        }))
}

pub(crate) fn get_user(
    username: &str,
    conn: &mut SqliteConnection,
) -> Result<Option<User>, PhysicalError> {
    let result = schema::users::dsl::users
        .filter(schema::users::username.eq(username))
        .limit(1)
        .select(UserModel::as_select())
        .load(conn)
        .map_err(|ex| PhysicalError(format!("Error reading from db: {}", ex)))?;
    if result.first().is_none() {
        return Ok(None);
    };
    let user_model = result.first().unwrap();
    let user = User {
        id: user_model.id,
        username: user_model.username.to_string(),
        email: user_model.email.clone(),
        password_hash: user_model.password_hash.clone(),
        password_last_changed: user_model.password_last_changed,
        roles: serde_json::from_str(user_model.roles.as_str())
            .map_err(|ex| PhysicalError(format!("Error parsing roles: {}", ex)))?,
        last_login: user_model.last_login,
        locked: user_model.locked,
        enabled: user_model.enabled,
    };
    Ok(Some(user))
}

pub(crate) fn create_user(user: User, conn: &mut SqliteConnection) -> Result<(), PhysicalError> {
    let roles_str = serde_json::to_string(&user.roles)
        .map_err(|ex| PhysicalError(format!("Error serializing roles: {}", ex)))?;
    let user_model = NewUserModel {
        id: user.id.as_ref(),
        username: &user.username,
        email: user.email.as_ref(),
        password_hash: user.password_hash.as_ref(),
        password_last_changed: user.password_last_changed.as_ref(),
        roles: &roles_str,
        last_login: user.last_login.as_ref(),
        locked: &user.locked,
        enabled: &user.enabled,
    };
    diesel::insert_into(schema::users::table)
        .values(&user_model)
        .execute(conn)
        .map_err(|ex| PhysicalError(format!("Error inserting into db: {}", ex)))?;
    Ok(())
}

pub(crate) fn update_user(user: User, conn: &mut SqliteConnection) -> Result<(), PhysicalError> {
    let roles_str = serde_json::to_string(&user.roles)
        .map_err(|ex| PhysicalError(format!("Error serializing roles: {}", ex)))?;
    diesel::update(schema::users::table)
        .filter(schema::users::username.eq(user.username))
        .set((
            schema::users::email.eq(user.email),
            schema::users::password_hash.eq(user.password_hash),
            schema::users::password_last_changed.eq(user.password_last_changed),
            schema::users::roles.eq(roles_str),
            schema::users::last_login.eq(user.last_login),
            schema::users::locked.eq(user.locked),
            schema::users::enabled.eq(user.enabled),
        ))
        .execute(conn)
        .map_err(|ex| PhysicalError(format!("Error updating user in db: {}", ex)))?;
    Ok(())
}

fn validate_keys(key: &str, is_listing: bool) -> Result<(), PhysicalError> {
    if key.is_empty() && !is_listing {
        return Err(PhysicalError("Key cannot be empty".to_string()));
    }
    if key.len() > 255 {
        return Err(PhysicalError("Key cannot be longer than 255 characters".to_string()));
    }
    if key.contains(' ') {
        return Err(PhysicalError("Key cannot contain spaces".to_string()));
    }
    if key.contains('\n') {
        return Err(PhysicalError("Key cannot contain newlines".to_string()));
    }
    if key.contains('\r') {
        return Err(PhysicalError("Key cannot contain carriage returns".to_string()));
    }
    if key.contains('\t') {
        return Err(PhysicalError("Key cannot contain tabs".to_string()));
    }
    if key.contains('\0') {
        return Err(PhysicalError("Key cannot contain null characters".to_string()));
    }
    if key.starts_with("/") || key.ends_with("/") {
        return Err(PhysicalError("Key cannot start or end with a slash".to_string()));
    }
    Ok(())
}
