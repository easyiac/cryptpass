pub(crate) mod roles;

use crate::{
    error::CryptPassError::{self, BadRequest, InternalServerError, Unauthorized},
    services,
    utils::match_hash,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use diesel::SqliteConnection;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::{distr::Alphanumeric, Rng};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{debug, trace, warn};
use utoipa::ToSchema;

static JWT_SECRET: OnceLock<String> = OnceLock::new();
static JWT_DURATION: i64 = 3600;

fn get_jwt_secret() -> &'static str {
    JWT_SECRET.get_or_init(|| {
        let secret_jwt = rand::rng().sample_iter(&Alphanumeric).take(64).map(char::from).collect();
        trace!("Initializing JWT secret: {}", secret_jwt);
        secret_jwt
    })
}

#[derive(Serialize, Deserialize)]
struct JWTHeader {
    alg: String,
    typ: String,
}

#[derive(Serialize, Deserialize)]
struct JWTClaims {
    sub: String,
    exp: i64,
    role: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub(crate) struct LoginRequestBody {
    username: Option<String>,
    password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub(crate) struct LoginResponseBody {
    token: Option<String>,
}

pub(crate) fn username_password_login(
    login_request: &LoginRequestBody,
    conn: &mut SqliteConnection,
) -> Result<LoginResponseBody, CryptPassError> {
    trace!("Login request: {:?}", login_request);
    let current_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| InternalServerError("System time before UNIX EPOCH".to_string()))?
        .as_millis() as i64;
    let expiration_epoch = current_epoch + JWT_DURATION;

    let username = login_request.username.as_ref().ok_or(InternalServerError("Missing username".to_string()))?;
    let password = login_request.password.as_ref().ok_or(InternalServerError("Missing password".to_string()))?;
    let user_option = services::users::get_user(username.as_ref(), conn)?;
    let user = match user_option {
        Some(user) => user,
        None => {
            let msg = format!("User not found: {}", username);
            return Err(BadRequest(msg));
        }
    };

    let user_password_hash = match user.password_hash {
        Some(hash) => hash,
        None => {
            let msg = format!("User account is not configured for password authentication: {}", username);
            return Err(BadRequest(msg));
        }
    };

    if !match_hash(password.as_ref(), user_password_hash.as_ref()) {
        let msg = format!("Invalid password for user: {}", username);
        return Err(BadRequest(msg));
    };

    let jwt_secret = get_jwt_secret();

    let token = encode(
        &Header::new(Algorithm::HS512),
        &JWTClaims { sub: username.to_string(), exp: expiration_epoch, role: user.roles },
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|e| InternalServerError(format!("Error generating JWT token: {}", e)))?;
    Ok(LoginResponseBody { token: Some(format!("Bearer {}", token)) })
}

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
        vec!["/health*", "/openapi.json", "/favicon.ico", "/unlock", "/login"];

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
    debug!("Access granted for URI: {}, method: {}, origin: {}", uri, method, origin);
    Ok(())
}

#[tokio::test]
async fn test_is_authorized() {
    let mut header = Header::new(Algorithm::HS512);
    header.kid = Some("blabla".to_owned());
    let mut extras = std::collections::HashMap::with_capacity(1);
    extras.insert("custom".to_string(), "header".to_string());

    let my_claims = JWTClaims { sub: "1234567890".to_string(), exp: 1516239022, role: "admin".to_string() };

    let token =
        encode(&header, &my_claims, &EncodingKey::from_secret("secretrafasfafasfasfasfasfasfasfasfasfasfasf".as_ref()));

    let token = token.unwrap();
    println!("{}", token);
}
