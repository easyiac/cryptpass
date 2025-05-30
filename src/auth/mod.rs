pub(crate) mod roles;

use crate::{
    error::CryptPassError::{self, InternalServerError, Unauthorized},
    services,
    utils::match_hash,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use diesel::SqliteConnection;
use regex::Regex;
use std::net::SocketAddr;
use tracing::{debug, trace, warn};

pub(crate) fn is_authorized(
    auth_token: Option<String>,
    uri: String,
    method: String,
    origin: SocketAddr,
    conn: &mut SqliteConnection,
) -> Result<(), CryptPassError> {
    trace!(
        "Checking authorization for URI: {}, method: {}, origin: {}, auth_token: {:?}",
        uri,
        method,
        origin,
        auth_token
    );

    let public_uri_patterns =
        vec!["/health*", "/openapi.json", "/openapi.yaml", "/favicon.ico", "/api/v1/unlock", "/api/v1/login"];

    for pattern_str in public_uri_patterns {
        let regex = Regex::new(pattern_str).map_err(|e| {
            InternalServerError(format!("Invalid regex pattern '{}' in configuration: {}", pattern_str, e))
        })?;
        if regex.is_match(&uri) {
            debug!("Access granted for Public URI: {}, method: {}, origin: {}", uri, method, origin);
            return Ok(());
        }
    }

    let token = match auth_token {
        Some(token) => token.trim_start_matches("Basic ").to_string(),
        None => {
            let msg = "Missing authorization token for protected URI";
            warn!("Access denied for URI: {}, method: {}, origin: {}, reason: {}", uri, method, origin, msg);
            return Err(Unauthorized(msg.to_string()));
        }
    };

    let decoded_bytes =
        BASE64_STANDARD.decode(token.clone()).map_err(|_| Unauthorized("Invalid Base64 token".to_string()))?;
    let decoded_str = String::from_utf8(decoded_bytes).map_err(|_| Unauthorized("Invalid UTF-8 token".to_string()))?;

    let mut parts = decoded_str.splitn(2, ':');
    let username = parts.next().ok_or_else(|| Unauthorized("Missing username in token".to_string()))?.to_string();
    let password = parts.next().ok_or_else(|| Unauthorized("Missing password in token".to_string()))?.to_string();

    let user_option = services::users::get_user(username.as_ref(), conn)?;

    let user = match user_option {
        Some(user) => user,
        None => {
            let msg = format!("User not found: {}", username);
            warn!("Access denied for URI: {}, method: {}, origin: {}, reason: {}", uri, method, origin, msg);
            Err(Unauthorized(msg))?
        }
    };

    let user_password_hash = match user.password_hash {
        Some(hash) => hash,
        None => {
            let msg = format!("User account is not configured for password authentication: {}", username);
            warn!("Access denied for URI: {}, method: {}, origin: {}, reason: {}", uri, method, origin, msg);
            Err(Unauthorized(msg))?
        }
    };

    if !match_hash(password.as_ref(), user_password_hash.as_ref()) {
        let msg = format!("Invalid password for user: {}", username);
        warn!("Access denied for URI: {}, method: {}, origin: {}, reason: {}", uri, method, origin, msg);
        Err(Unauthorized(msg))?
    }
    Ok(())
}
