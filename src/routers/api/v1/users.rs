use crate::{
    error::{
        CryptPassError::{self, BadRequest, InternalServerError, NotFound},
        CryptPassErrorDetails,
    },
    physical::models::{Privilege, PrivilegeType, Role, RoleType, Users},
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

pub(super) async fn api() -> Router<crate::init::AppState> {
    Router::new().route("/user/{username}", put(create_update_user)).route("/user/{username}", get(get_user))
}

#[utoipa::path(
    get,
    path = "/api/v1/users/user/{username}",
    tag = "Users",
    summary = "Fetch user details by username.",
    description = "Retrieve the user record for a given username. Returns user details if found, or an error if the user does not exist or access is unauthorized.",
    params(
        ("username" = String, Path, description = "Username of the user to fetch."),
    ),
    responses(
        (status = 200, description = "User found.", body = Users),
        (status = 401, description = "Unauthorized access.", body = CryptPassErrorDetails),
        (status = 404, description = "User not found.", body = CryptPassErrorDetails),
        (status = 500, description = "Internal server error.", body = CryptPassErrorDetails),
    ),
    security(
        ("cryptpass_auth_info" = []),
    ),
)]
async fn get_user(
    Path(username): Path<String>,
    State(shared_state): State<crate::init::AppState>,
) -> Result<(StatusCode, Json<Users>), CryptPassError> {
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;
    let user = conn
        .interact(move |conn| crate::services::users::get_user(&username, conn))
        .await
        .map_err(|ex| InternalServerError(format!("Error interacting with database: {}", ex)))??;
    match user {
        Some(user) => Ok((StatusCode::OK, Json(user))),
        None => Err(NotFound("User with not found".to_string())),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/users/user/{username}",
    tag = "Users",
    summary = "Create or update a user by username.",
    description = "Create a new user or update an existing user record for the specified username. Accepts a JSON body with user details. Returns the updated user record.",
    params(
        ("username" = String, Path, description = "Username of the user to create or update."),
    ),
    request_body(
        content_type = "application/json",
        content = Users,
        description = "User object to create or update.",
    ),
    responses(
        (status = 201, description = "User created or updated.", body = Users),
        (status = 401, description = "Unauthorized access.", body = CryptPassErrorDetails),
        (status = 404, description = "User not found for update.", body = CryptPassErrorDetails),
        (status = 500, description = "Internal server error.", body = CryptPassErrorDetails),
    ),
    security(
        ("cryptpass_auth_info" = []),
    ),
)]
async fn create_update_user(
    Path(username): Path<String>,
    State(shared_state): State<crate::init::AppState>,
    body: Json<Value>,
) -> Result<(StatusCode, Json<Users>), CryptPassError> {
    let current_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|ex| InternalServerError(format!("Error getting current epoch: {}", ex)))?
        .as_millis() as i64;
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;
    let username_for_user_option_query = username.clone();
    let is_new_user;
    let user_option = conn
        .interact(move |conn| crate::services::users::get_user(username_for_user_option_query.as_str(), conn))
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
            let jwt_secret_b64_encrypted = conn
                .interact(move |conn| {
                    crate::services::encryption::encrypt(api_token_jwt_secret_base64.clone().as_ref(), conn)
                })
                .await
                .map_err(|ex| InternalServerError(format!("Error interacting with database: {}", ex)))??;
            is_new_user = true;
            Users {
                username,
                email: None,
                password_hash: None,
                password_last_changed: 0i64,
                roles: default_roles,
                last_login: 0i64,
                locked: false,
                enabled: true,
                jwt_secret_b64_encrypted: jwt_secret_b64_encrypted.encrypted_value,
                encryptor_hash: jwt_secret_b64_encrypted.encryption_key_hash,
                password: None,
            }
        }
    };

    if let Some(_) = body.get("password_last_changed") {
        Err(BadRequest("password_last_changed can't be set manually via API, It's handled internally.".to_string()))?
    };
    if let Some(_) = body.get("last_login") {
        Err(BadRequest("last_login can't be set manually via API, It's handled internally.".to_string()))?
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
        user.roles = serde_json::from_value(roles.clone())
            .map_err(|e| BadRequest(format!("'roles' must be a valid JSON array: {}", e)))?;
    };
    let user_for_create_update = user.clone();
    if is_new_user {
        conn.interact(move |conn| crate::services::users::create_user(user_for_create_update, conn))
            .await
            .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
    } else {
        conn.interact(move |conn| crate::services::users::update_user(user_for_create_update, conn))
            .await
            .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;
    }

    Ok((StatusCode::OK, Json(user)))
}
