use crate::{
    auth::roles::{Privilege, PrivilegeType, Role, RoleType},
    error::{
        CryptPassError::{self, BadRequest, InternalServerError, NotFound},
        CryptPassErrorResponse,
    },
    physical::models::UserModel,
    services::InternalEncryptionKeySettings,
    utils::hash,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, put},
    Json,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;

pub(super) async fn api() -> OpenApiRouter<crate::init::AppState> {
    OpenApiRouter::new()
        .route("/user/{username}", put(create_update_user))
        .route("/user/{username}", get(get_user))
        .route("/unlock", put(unlock))
        .fallback(crate::routers::fallback::fallback_handler)
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub(crate) struct UnlockRequestBody {
    pub token: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/unlock",
    tag = "Admin",
    responses(
        (status = 200, description = "Application unlocked", body = InternalEncryptionKeySettings),
        (status = 500, description = "Internal server error", body = CryptPassErrorResponse)
    ),
    security()
)]
pub(crate) async fn unlock(
    State(shared_state): State<crate::init::AppState>,
    body: Json<UnlockRequestBody>,
) -> Result<(StatusCode, Json<InternalEncryptionKeySettings>), CryptPassError> {
    let master_key = body.token.clone();
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;

    let set_key = conn
        .interact(move |conn| crate::init::init_unlock(master_key, conn))
        .await
        .map_err(|e| InternalServerError(format!("Error interacting with database: {}", e)))??;

    Ok((StatusCode::OK, Json(set_key)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/user/{username}",
    tag = "Admin",
    params(
        ("username" = String, Path, description = "Username of the user to get")
    ),
    responses(
        (status = 200, description = "User", body = UserModel),
        (status = 401, description = "Unauthorized", body = CryptPassErrorResponse),
        (status = 404, description = "User not found", body = CryptPassErrorResponse),
        (status = 500, description = "Internal server error", body = CryptPassErrorResponse)
    ),
    security(
        ("api_key" = [])
    )
)]
async fn get_user(
    Path(username): Path<String>,
    State(shared_state): State<crate::init::AppState>,
) -> Result<(StatusCode, Json<UserModel>), CryptPassError> {
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

#[utoipa::path(
    put,
    path = "/api/v1/admin/user/{username}",
    tag = "Admin",
    params(
        ("username" = String, Path, description = "Username of the user to update")
    ),
    request_body(
        content_type = "application/json",
        content = UserModel,
        description = "User to update"
    ),
    responses(
        (status = 200, description = "User", body = UserModel),
        (status = 404, description = "User not found", body = CryptPassErrorResponse),
        (status = 401, description = "Unauthorized", body = CryptPassErrorResponse),
        (status = 500, description = "Internal server error", body = CryptPassErrorResponse)
    ),
    security(
        ("api_key" = [])
    )
)]
async fn create_update_user(
    Path(username): Path<String>,
    State(shared_state): State<crate::init::AppState>,
    body: Json<Value>,
) -> Result<(StatusCode, Json<UserModel>), CryptPassError> {
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
            UserModel {
                username: user_err,
                email: None,
                password_hash: None,
                password_last_changed: 0i64,
                roles: serde_json::to_string(&default_roles)
                    .map_err(|_| InternalServerError("Failed to serialize roles for root user".to_string()))?,
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
        user.roles = roles.to_string();
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
