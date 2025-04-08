pub(crate) mod roles;
pub(crate) mod root;

use crate::{
    encryption::match_hash,
    error::ServerError::{self, Unauthorized},
    physical::get_user,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use diesel::SqliteConnection;
use std::net::SocketAddr;

pub(crate) fn is_authorized(
    auth_token: Option<String>,
    _uri: String,
    _resource: String,
    _origin: SocketAddr,
    conn: &mut SqliteConnection,
) -> Result<(bool, String), ServerError> {
    if auth_token.is_none() {
        return Ok((false, "Missing token".to_string()));
    }

    let token = auth_token.unwrap().trim_start_matches("Basic ").to_string();

    let decoded_bytes = BASE64_STANDARD
        .decode(token.clone())
        .map_err(|_| Unauthorized("Invalid Base64 token".to_string()))?;
    let decoded_str = String::from_utf8(decoded_bytes)
        .map_err(|_| Unauthorized("Invalid UTF-8 token".to_string()))?;

    let mut parts = decoded_str.splitn(2, ':');
    let username =
        parts.next().ok_or_else(|| Unauthorized("Missing username".to_string()))?.to_string();
    let password =
        parts.next().ok_or_else(|| Unauthorized("Missing password".to_string()))?.to_string();

    let user_option = get_user(username.as_ref(), conn)?;

    if user_option.is_none() {
        return Ok((false, "User not found".to_string()));
    }

    let user = user_option.unwrap();

    if user.password_hash.is_none() {
        return Ok((false, "User has no password".to_string()));
    } else {
        if !match_hash(password.as_ref(), user.password_hash.as_ref().unwrap()) {
            return Ok((false, "Invalid password".to_string()));
        }
    }
    Ok((true, username))
}
