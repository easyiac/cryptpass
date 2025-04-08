pub(crate) mod roles;
pub(crate) mod root;
use crate::encryption::match_hash;
use crate::physical::get_user;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use diesel::SqliteConnection;
use std::fmt::Display;
use std::net::SocketAddr;

#[derive(Debug)]
pub(crate) struct AuthError(String);

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Auth Error: {}", self.0)
    }
}

pub(crate) fn is_authorized(
    auth_token: Option<String>,
    _uri: String,
    _resource: String,
    _origin: SocketAddr,
    conn: &mut SqliteConnection,
) -> Result<(bool, String), AuthError> {
    if auth_token.is_none() {
        return Ok((false, "Missing token".to_string()));
    }

    let token = auth_token.unwrap().trim_start_matches("Basic ").to_string();

    let decoded_bytes = BASE64_STANDARD
        .decode(token.clone())
        .map_err(|_| AuthError("Invalid Base64 token".to_string()))?;
    let decoded_str = String::from_utf8(decoded_bytes)
        .map_err(|_| AuthError("Invalid UTF-8 token".to_string()))?;

    let mut parts = decoded_str.splitn(2, ':');
    let username =
        parts.next().ok_or_else(|| AuthError("Missing username".to_string()))?.to_string();
    let password =
        parts.next().ok_or_else(|| AuthError("Missing password".to_string()))?.to_string();

    let user_option = get_user(username.as_ref(), conn)
        .map_err(|ex| AuthError(format!("Error getting root user: {}", ex)))?;

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
