use crate::{
    auth::roles::{Privilege, PrivilegeType, Role, RoleType, User},
    encryption::hash,
    physical::{self, MASTER_ENCRYPTION_KEY},
    routers::ServerError::{self, BadRequest, NotFound},
    AppState,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, put},
    Json, Router,
};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

pub(crate) fn api() -> Router<AppState> {
    let new_router = Router::new()
        .route("/user/{username}", put(create_update_user))
        .route("/user/{username}", get(get_user))
        .route("/unlock", put(unlock))
        .route("/list/keys", get(list_all_keys))
        .route("/list/keys/", get(list_all_keys))
        .route("/list/keys/{*key}", get(list_selective_keys));
    new_router
}

pub(super) async fn unlock(body: Json<Value>) -> Result<(StatusCode, Json<Value>), ServerError> {
    let master_key = body
        .get("key")
        .ok_or_else(|| BadRequest("Missing 'key' in request body".to_string()))?
        .as_str()
        .ok_or_else(|| BadRequest("'key' must be a string".to_string()))?
        .to_string();

    MASTER_ENCRYPTION_KEY.set((master_key.clone(), hash(master_key.as_str()))).map_err(|ex| {
        BadRequest(format!(
            "Failed to set master encryption key, Existing key hash: {}",
            ex.1.to_string()
        ))
    })?;
    let json_body = serde_json::json!({
        "message": format!("Master encryption key set successfully, Key Hash: {}", hash(master_key.as_str()))
    });

    Ok((StatusCode::OK, Json(json_body)))
}

pub(super) async fn get_user(
    Path(username): Path<String>,
    State(shared_state): State<AppState>,
) -> Result<(StatusCode, Json<User>), ServerError> {
    let pool = shared_state.pool;
    let conn = pool
        .get()
        .await
        .map_err(|e| BadRequest(format!("Error getting connection from pool: {}", e)))?;
    let user_err = username.clone();
    let user = conn
        .interact(move |conn| {
            physical::get_user(username.as_str(), conn)
                .map_err(|ex| BadRequest(format!("Error reading from physical: {}", ex)))
        })
        .await
        .map_err(|e| BadRequest(format!("Error interacting with database: {}", e)))
        .map_err(|e| BadRequest(format!("Error getting reading user: {}", e)))??
        .ok_or_else(|| NotFound(format!("User with key {} not found", user_err)))?;
    Ok((StatusCode::OK, Json(user)))
}

pub(super) async fn create_update_user(
    Path(username): Path<String>,
    State(shared_state): State<AppState>,
    body: Json<Value>,
) -> Result<(StatusCode, Json<User>), ServerError> {
    let current_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BadRequest("System time before UNIX EPOCH".to_string()))?
        .as_millis() as i64;
    let pool = shared_state.pool;
    let conn = pool
        .get()
        .await
        .map_err(|e| BadRequest(format!("Error getting connection from pool: {}", e)))?;
    let user_err = username.clone();
    let is_new_user;
    let user_option = conn
        .interact(move |conn| {
            physical::get_user(username.as_str(), conn)
                .map_err(|ex| BadRequest(format!("Error reading from physical: {}", ex)))
        })
        .await
        .map_err(|e| BadRequest(format!("Error interacting with database: {}", e)))
        .map_err(|e| BadRequest(format!("Error getting reading user: {}", e)))??;
    let mut default_roles = Vec::new();
    default_roles.push(Role {
        name: RoleType::USER,
        privileges: vec![Privilege { name: PrivilegeType::NO_SUDO }],
    });
    let mut user = match user_option {
        Some(user) => {
            is_new_user = false;
            user
        }
        None => {
            is_new_user = true;
            User {
                id: None,
                username: user_err,
                email: None,
                password_hash: None,
                password_last_changed: None,
                roles: default_roles.clone(),
                last_login: None,
                locked: false,
                enabled: true,
            }
        }
    };

    if let Some(password) = body.get("password") {
        let password_str = password
            .as_str()
            .ok_or_else(|| BadRequest("'password' must be a string".to_string()))?
            .to_string();
        user.password_hash = Some(hash(password_str.as_str()));
        user.password_last_changed = Some(current_epoch);
    };

    if let Some(email) = body.get("email") {
        let email_str = email
            .as_str()
            .ok_or_else(|| BadRequest("'email' must be a string".to_string()))?
            .to_string();
        user.email = Some(email_str);
    };

    if let Some(locked) = body.get("locked") {
        let locked_bool =
            locked.as_bool().ok_or_else(|| BadRequest("'locked' must be a boolean".to_string()))?;
        user.locked = locked_bool;
    };

    if let Some(enabled) = body.get("enabled") {
        let enabled_bool = enabled
            .as_bool()
            .ok_or_else(|| BadRequest("'enabled' must be a boolean".to_string()))?;
        user.enabled = enabled_bool;
    };

    if let Some(roles) = body.get("roles") {
        let roles_vec: Vec<Role> = serde_json::from_value(roles.clone())
            .map_err(|e| BadRequest(format!("Error parsing roles: {}", e)))?;
        user.roles = roles_vec;
    };
    let user_res = user.clone();
    if is_new_user {
        conn.interact(move |conn| {
            physical::create_user(user.clone(), conn)
                .map_err(|ex| BadRequest(format!("Error reading from physical: {}", ex)))
        })
        .await
        .map_err(|e| BadRequest(format!("Error interacting with database: {}", e)))
        .map_err(|e| BadRequest(format!("Error getting reading user: {}", e)))??;
    } else {
        conn.interact(move |conn| {
            physical::update_user(user.clone(), conn)
                .map_err(|ex| BadRequest(format!("Error reading from physical: {}", ex)))
        })
        .await
        .map_err(|e| BadRequest(format!("Error interacting with database: {}", e)))
        .map_err(|e| BadRequest(format!("Error getting reading user: {}", e)))??;
    }

    Ok((StatusCode::OK, Json(user_res)))
}

pub(super) async fn list_selective_keys(
    Path(key): Path<String>,
    State(shared_state): State<AppState>,
) -> Result<(StatusCode, Json<Vec<String>>), ServerError> {
    list_keys(key, shared_state).await
}

pub(super) async fn list_all_keys(
    State(shared_state): State<AppState>,
) -> Result<(StatusCode, Json<Vec<String>>), ServerError> {
    list_keys("".to_string(), shared_state).await
}

pub(super) async fn list_keys(
    key: String,
    shared_state: AppState,
) -> Result<(StatusCode, Json<Vec<String>>), ServerError> {
    let pool = shared_state.pool;
    let conn = pool
        .get()
        .await
        .map_err(|e| BadRequest(format!("Error getting connection from pool: {}", e)))?;
    info!("Listing keys for {}", key);
    let keys = conn
        .interact(move |conn| {
            physical::list_all_keys(key.as_str(), conn)
                .map_err(|ex| BadRequest(format!("Error reading from physical: {}", ex)))
        })
        .await
        .map_err(|e| BadRequest(format!("Error interacting with database: {}", e)))
        .map_err(|e| BadRequest(format!("Error getting reading key: {}", e)))??;
    Ok((StatusCode::OK, Json(keys)))
}
