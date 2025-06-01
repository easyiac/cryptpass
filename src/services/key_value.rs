use crate::{
    error::CryptPassError::{self, BadRequest, InternalServerError, NotFound},
    physical::{models::KeyValue, schema},
    services::encryption,
};
use diesel::{
    dsl::count, ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper, SqliteConnection, TextExpressionMethods,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{trace, warn};

fn get_next_version(key: &str, conn: &mut SqliteConnection) -> i32 {
    let current_max = schema::key_value_table::table
        .select(schema::key_value_table::version)
        .filter(schema::key_value_table::key.eq(key))
        .order(schema::key_value_table::version.desc())
        .first::<i32>(conn)
        .unwrap_or(0);
    current_max + 1
}

fn is_version_exists(key: &str, version: i32, conn: &mut SqliteConnection) -> bool {
    let key = key.to_string();
    schema::key_value_table::table
        .select(count(schema::key_value_table::version))
        .filter(schema::key_value_table::key.eq(key))
        .filter(schema::key_value_table::version.eq(version))
        .get_result(conn)
        .unwrap_or(0)
        > 0
}

pub(crate) fn write(
    key: &str,
    value: &str,
    version_asked: Option<i32>,
    conn: &mut SqliteConnection,
) -> Result<i32, CryptPassError> {
    validate_keys(key, false, version_asked)?;

    let next_version = match version_asked {
        Some(v) if v > 0 => {
            if is_version_exists(key, v, conn) {
                return Err(BadRequest(format!("Version {} already exists for key {}", v, key)));
            }
            v
        }
        _ => get_next_version(key, conn),
    };
    let encrypted_value = encryption::encrypt(&value, conn)?;
    let new_key_value = KeyValue {
        key: key.to_string(),
        encrypted_value,
        deleted: false,
        version: next_version,
        last_updated_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|ex| InternalServerError(format!("Error getting current time: {}", ex)))?
            .as_millis() as i64,
    };
    diesel::insert_into(schema::key_value_table::table)
        .values(&new_key_value)
        .execute(conn)
        .map_err(|ex| InternalServerError(format!("Error inserting key value into db: {}", ex)))?;
    Ok(next_version)
}

fn get_latest_version(key: &str, conn: &mut SqliteConnection) -> i32 {
    let key = key.to_string();
    schema::key_value_table::table
        .select(schema::key_value_table::version)
        .filter(schema::key_value_table::key.eq(key))
        .filter(schema::key_value_table::deleted.eq(false))
        .order(schema::key_value_table::version.desc())
        .first::<i32>(conn)
        .unwrap_or(0)
}

pub(crate) fn get_details(
    key: &str,
    version_asked: Option<i32>,
    conn: &mut SqliteConnection,
) -> Result<Option<KeyValue>, CryptPassError> {
    validate_keys(key, false, version_asked)?;
    let latest_version = match version_asked {
        Some(v) if v > 0 => v,
        _ => get_latest_version(key, conn),
    };
    if latest_version == 0 {
        return Ok(None);
    }
    let result = schema::key_value_table::dsl::key_value_table
        .filter(schema::key_value_table::version.eq(latest_version))
        .filter(schema::key_value_table::key.eq(key))
        .filter(schema::key_value_table::deleted.eq(false))
        .limit(1)
        .select(KeyValue::as_select())
        .load(conn)
        .map_err(|ex| InternalServerError(format!("Error reading key_value from db: {}", ex)))?;
    let key_value = if let Some(first) = result.first() {
        first.clone()
    } else {
        return Ok(None);
    };
    Ok(Some(key_value))
}

pub(crate) fn read(
    key: &str,
    version_asked: Option<i32>,
    conn: &mut SqliteConnection,
) -> Result<Option<String>, CryptPassError> {
    let key_value = if let Some(kv) = get_details(key, version_asked, conn)? {
        kv
    } else {
        Err(NotFound("Key not found".to_string()))?
    };
    let encrypted_value = key_value.encrypted_value.to_string();
    let decrypted_value = encryption::decrypt(encrypted_value, conn)?;
    Ok(Some(decrypted_value))
}

pub(crate) fn mark_version_for_delete(
    key: &str,
    version_asked: Option<i32>,
    conn: &mut SqliteConnection,
) -> Result<(), CryptPassError> {
    validate_keys(key, false, version_asked)?;

    if let Some(v) = version_asked {
        diesel::update(schema::key_value_table::table)
            .filter(schema::key_value_table::key.eq(key))
            .filter(schema::key_value_table::version.eq(v))
            .set(schema::key_value_table::deleted.eq(true))
            .execute(conn)
            .map_err(|ex| InternalServerError(format!("Error deleting key {}, version {} from db: {}", key, v, ex)))?;
    } else {
        diesel::update(schema::key_value_table::table)
            .filter(schema::key_value_table::key.eq(key))
            .filter(schema::key_value_table::deleted.eq(false))
            .set(schema::key_value_table::deleted.eq(true))
            .execute(conn)
            .map_err(|ex| InternalServerError(format!("Error deleting all versions for key value from db: {}", ex)))?;
    }

    Ok(())
}

pub(crate) fn list_all_keys(key: &str, conn: &mut SqliteConnection) -> Result<Vec<String>, CryptPassError> {
    validate_keys(key, true, None)?;
    let mut find_key = key.to_string();
    if !find_key.is_empty() {
        find_key = format!("{}/", find_key);
    }
    Ok(schema::key_value_table::dsl::key_value_table
        .filter(schema::key_value_table::key.like(format!("{}%", find_key)))
        .filter(schema::key_value_table::deleted.eq(false))
        .select(schema::key_value_table::key)
        .distinct()
        .load::<String>(conn)
        .unwrap_or_else(|ex| {
            warn!("Error listing keys from db: {}", ex);
            vec![]
        }))
}

fn validate_keys(key: &str, is_listing: bool, version_asked: Option<i32>) -> Result<(), CryptPassError> {
    if key.is_empty() && !is_listing {
        return Err(BadRequest("Key cannot be empty".to_string()));
    }
    if key.len() > 255 {
        return Err(BadRequest("Key cannot be longer than 255 characters".to_string()));
    }
    if key.contains(' ') {
        return Err(BadRequest("Key cannot contain spaces".to_string()));
    }
    if key.contains('\n') {
        return Err(BadRequest("Key cannot contain newlines".to_string()));
    }
    if key.contains('\r') {
        return Err(BadRequest("Key cannot contain carriage returns".to_string()));
    }
    if key.contains('\t') {
        return Err(BadRequest("Key cannot contain tabs".to_string()));
    }
    if key.contains('\0') {
        return Err(BadRequest("Key cannot contain null characters".to_string()));
    }
    if key.starts_with("/") || key.ends_with("/") {
        return Err(BadRequest("Key cannot start or end with a slash".to_string()));
    }
    if let Some(v) = version_asked {
        if v < 1 {
            trace!("Version asked is less than 1, returning error key: {}, version: {}", key, v);
            return Err(BadRequest("Version cannot be less than 1".to_string()));
        }
    }
    Ok(())
}
