use crate::error::CryptPassError::{self, InternalServerError};
use std::path::Path;
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};
use tracing::debug;

pub(crate) mod aes256;
pub(crate) mod sha256;

pub(crate) fn encrypt(key_iv_base64: &str, plaintext: &str) -> Result<String, CryptPassError> {
    aes256::encryption(key_iv_base64, plaintext)
}

pub(crate) fn decrypt(key_iv_base64: &str, encrypted_text_base64: &str) -> Result<String, CryptPassError> {
    aes256::decryption(key_iv_base64, encrypted_text_base64)
}

pub(crate) fn generate_key() -> String {
    aes256::generate_key()
}

pub(crate) fn hash(data: &str) -> String {
    sha256::encode(data)
}

pub(crate) fn match_hash(data: &str, hash: &str) -> bool {
    sha256::match_hash(data, hash)
}

pub(crate) fn epoch_to_ist(epoch_ms: i128) -> Result<String, CryptPassError> {
    // Convert milliseconds to seconds + nanoseconds
    let seconds = epoch_ms / 1000;
    let nanoseconds = ((epoch_ms % 1000) * 1_000_000) as i32;

    // Construct the UTC time
    let utc = OffsetDateTime::from_unix_timestamp(seconds as i64)
        .map_err(|ex| InternalServerError(format!("Failed to convert epoch to UTC: {}", ex)))?
        .replace_nanosecond(nanoseconds as u32)
        .map_err(|ex| InternalServerError(format!("Failed to replace nanoseconds: {}", ex)))?;

    // IST offset is +5:30
    let ist_offset = UtcOffset::from_hms(5, 30, 0)
        .map_err(|ex| InternalServerError(format!("Failed to create IST offset: {}", ex)))?;
    let ist_time = utc.to_offset(ist_offset);

    Ok(ist_time.format(&Rfc3339).map_err(|ex| InternalServerError(format!("Failed to format IST time: {}", ex)))?)
}

pub(crate) fn file_or_string(path: &str) -> Result<String, CryptPassError> {
    if Path::new(path).exists() && Path::new(path).is_file() {
        debug!("Reading file: {}", path);
        return Ok(
            std::fs::read_to_string(path).map_err(|ex| InternalServerError(format!("Failed to read file: {}", ex)))?
        );
    }
    Ok(path.to_string())
}
