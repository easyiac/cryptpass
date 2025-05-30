use crate::{
    auth::roles::{Privilege, PrivilegeType, Role, RoleType, User},
    error::CryptPassError::{self, BadRequest, InternalServerError, NotFound},
    utils::hash,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, put},
    Json, Router,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use rand::Rng;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) async fn api() -> Router<crate::AppState> {
    Router::new()
        .route("/user/{username}", put(create_update_user))
        .route("/user/{username}", get(get_user))
        .route("/unlock", put(unlock))
}

async fn unlock(
    State(shared_state): State<crate::AppState>,
    body: Json<Value>,
) -> Result<(StatusCode, Json<Value>), CryptPassError> {
    let master_key = body
        .get("key")
        .ok_or_else(|| BadRequest("Missing 'key' in request body".to_string()))?
        .as_str()
        .ok_or_else(|| BadRequest("'key' must be a string".to_string()))?
        .to_string();
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;
    let set_key = conn
        .interact(move |conn| crate::config::init_unlock(master_key, conn))
        .await
        .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;

    let value =
        serde_json::to_value(set_key).map_err(|e| InternalServerError(format!("Serialization error: {}", e)))?;

    Ok((StatusCode::OK, Json(value)))
}

async fn get_user(
    Path(username): Path<String>,
    State(shared_state): State<crate::AppState>,
) -> Result<(StatusCode, Json<User>), CryptPassError> {
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;
    let user_err = username.clone();
    let user = conn
        .interact(move |conn| crate::services::users::get_user(username.as_str(), conn))
        .await
        .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??
        .ok_or_else(|| NotFound(format!("User with key {} not found", user_err)))?;
    Ok((StatusCode::OK, Json(user)))
}

// #[debug_handler]
async fn create_update_user(
    Path(username): Path<String>,
    State(shared_state): State<crate::AppState>,
    body: Json<Value>,
) -> Result<(StatusCode, Json<User>), CryptPassError> {
    let current_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| InternalServerError("System time before UNIX EPOCH".to_string()))?
        .as_millis() as i64;
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;
    let user_err = username.clone();
    let is_new_user;
    let user_option = conn
        .interact(move |conn| crate::services::users::get_user(username.as_str(), conn))
        .await
        .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
    let mut default_roles = Vec::new();
    default_roles.push(Role { name: RoleType::USER, privileges: vec![Privilege { name: PrivilegeType::NO_SUDO }] });
    let mut user = match user_option {
        Some(user) => {
            is_new_user = false;
            user
        }
        None => {
            let mut api_token_jwt_secret = [0u8; 32];
            rand::rng().fill(&mut api_token_jwt_secret);
            let api_token_jwt_secret_base64 = BASE64_STANDARD.encode(api_token_jwt_secret);
            let api_token_jwt_secret_b64_encrypted = conn
                .interact(move |conn| {
                    crate::services::encryption::encrypt(api_token_jwt_secret_base64.clone().as_ref(), conn)
                })
                .await
                .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
            is_new_user = true;
            User {
                username: user_err,
                email: None,
                password_hash: None,
                password_last_changed: 0i64,
                roles: default_roles.clone(),
                last_login: 0i64,
                locked: false,
                enabled: true,
                api_token_jwt_secret_b64_encrypted,
            }
        }
    };

    if let Some(password) = body.get("password") {
        let password_str =
            password.as_str().ok_or_else(|| BadRequest("'password' must be a string".to_string()))?.to_string();
        user.password_hash = Some(hash(password_str.as_str()));
        user.password_last_changed = current_epoch;
    };

    if let Some(email) = body.get("email") {
        let email_str = email.as_str().ok_or_else(|| BadRequest("'email' must be a string".to_string()))?.to_string();
        user.email = Some(email_str);
    };

    if let Some(locked) = body.get("locked") {
        let locked_bool = locked.as_bool().ok_or_else(|| BadRequest("'locked' must be a boolean".to_string()))?;
        user.locked = locked_bool;
    };

    if let Some(enabled) = body.get("enabled") {
        let enabled_bool = enabled.as_bool().ok_or_else(|| BadRequest("'enabled' must be a boolean".to_string()))?;
        user.enabled = enabled_bool;
    };

    if let Some(roles) = body.get("roles") {
        let roles_vec: Vec<Role> =
            serde_json::from_value(roles.clone()).map_err(|e| BadRequest(format!("Error parsing roles: {}", e)))?;
        user.roles = roles_vec;
    };
    let user_res = user.clone();
    if is_new_user {
        conn.interact(move |conn| crate::services::users::create_user(user.clone(), conn))
            .await
            .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
    } else {
        conn.interact(move |conn| crate::services::users::update_user(user.clone(), conn))
            .await
            .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
    }

    Ok((StatusCode::OK, Json(user_res)))
}
