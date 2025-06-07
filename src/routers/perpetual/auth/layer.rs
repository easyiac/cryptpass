use crate::{
    error::CryptPassError::{self, BadRequest, InternalServerError, Unauthorized},
    init::{AppState, CRYPTPASS_CONFIG_INSTANCE},
    routers::perpetual::auth::{get_jwt_secret, JWTClaims},
    services,
    utils::{epoch_to_ist, match_hash},
};
use axum::{
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::IntoResponse,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use diesel::SqliteConnection;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use regex::Regex;
use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{debug, trace, warn};

pub(crate) async fn auth_layer(
    State(shared_state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, CryptPassError> {
    let configuration = CRYPTPASS_CONFIG_INSTANCE.get().expect("Configuration not initialized");

    let uri = request.uri().path().to_string().clone();

    let method = request.method().to_string().clone();

    let mut auth_token: Option<String> = None;

    for (key, value) in request.headers().clone() {
        if key.is_some()
            && (key.as_ref().ok_or_else(|| BadRequest("Bad auth header key".to_string()))?.to_string().to_lowercase()
                == configuration.server.auth_header_key.to_lowercase())
        {
            let val_str = value.to_str().map_err(|ex| BadRequest(format!("Invalid auth header value: {}", ex)))?;
            auth_token = Some(val_str.to_string());
            break;
        }
    }

    let pool = shared_state.pool;
    let conn = pool.get().await.map_err(|ex| InternalServerError(format!("Error getting connection: {}", ex)))?;
    conn.interact(move |conn| is_authorized(auth_token, uri, method, addr, conn))
        .await
        .map_err(|ex| InternalServerError(format!("Error interacting with connection: {}", ex)))??;

    Ok(next.run(request).await.into_response())
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

    // TODO: total fucking disaster, matching regexes is a disaster.
    let public_uri_patterns = vec!["^/api-docs/openapi.json", "^/favicon.ico", "^/swagger-ui", "^/perpetual"];
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
        Some(token) => token.to_string(),
        None => {
            let msg = "Missing authorization token for protected URI";
            warn!("Access denied for URI: {}, method: {}, origin: {}, reason: {}", uri, method, origin, msg);
            return Err(Unauthorized(msg.to_string()));
        }
    };
    match token {
        basic_auth_token if token.starts_with("Basic ") => {
            is_authorized_basic(basic_auth_token.clone(), uri.clone(), method.clone(), origin.clone(), conn)
        }
        bearer_auth_token if token.starts_with("Bearer ") => {
            is_authorized_bearer(bearer_auth_token.clone(), uri.clone(), method.clone(), origin.clone(), conn)
        }
        _ => {
            let msg = "Unsupported authorization token type";
            warn!(
                "Access denied for URI: {}, method: {}, origin: {}, reason: {}",
                uri.clone(),
                method.clone(),
                origin.clone(),
                msg
            );
            Err(Unauthorized(msg.to_string()))?
        }
    }?;
    debug!("Access granted for URI: {}, method: {}, origin: {}", uri, method, origin);
    Ok(())
}

fn is_authorized_bearer(
    bearer_auth_token: String,
    uri: String,
    method: String,
    origin: SocketAddr,
    _: &mut SqliteConnection,
) -> Result<(), CryptPassError> {
    trace!("Checking bearer authorization for URI: {}, method: {}, origin: {}", uri, method, origin);
    let bearer_auth_token = bearer_auth_token.trim_start_matches("Bearer ");
    let token = decode::<JWTClaims>(
        &bearer_auth_token,
        &DecodingKey::from_secret(get_jwt_secret().as_ref()),
        &Validation::new(Algorithm::HS512),
    )
    .map_err(|ex| Unauthorized(format!("Invalid JWT token: {}", ex)))?
    .claims;
    let current_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|ex| InternalServerError(format!("Error getting current epoch: {}", ex)))?
        .as_millis();
    if current_epoch > token.exp {
        let msg = format!("JWT token expired at: {}", epoch_to_ist(token.exp as i128)?);
        warn!("Access denied for URI: {}, method: {}, origin: {}, reason: {}", uri, method, origin, msg);
        Err(Unauthorized(msg))?
    }
    Ok(())
}

fn is_authorized_basic(
    basic_auth_token: String,
    uri: String,
    method: String,
    origin: SocketAddr,
    conn: &mut SqliteConnection,
) -> Result<(), CryptPassError> {
    trace!("Checking basic authorization for URI: {}, method: {}, origin: {}", uri, method, origin);
    let basic_auth_token = basic_auth_token.trim_start_matches("Basic ");
    let decoded_bytes =
        BASE64_STANDARD.decode(basic_auth_token).map_err(|ex| Unauthorized(format!("Invalid base64 token: {}", ex)))?;
    let decoded_str =
        String::from_utf8(decoded_bytes).map_err(|ex| Unauthorized(format!("Invalid UTF-8 token: {}", ex)))?;

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
