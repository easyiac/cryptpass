use crate::{
    error::{
        CryptPassError::{self, InternalServerError, Unauthorized},
        CryptPassErrorResponse,
    },
    init::AppState,
    routers::perpetual::auth::{get_jwt_secret, JWTClaims, LoginRequestBody, LoginResponseBody, JWT_DURATION},
    services,
    utils::match_hash,
};
use axum::{extract::State, Json};
use diesel::SqliteConnection;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::trace;

#[utoipa::path(
    post,
    path = "/login",
    tag = "Perpetual",
    description = "Login endpoint for username and password authentication",
    responses(
        (status = 200, description = "Create login token", body = LoginResponseBody),
        (status = 401, description = "Unauthorized", body = CryptPassErrorResponse),
        (status = 500, description = "Internal server error", body = CryptPassErrorResponse)
    ),
    security(),
)]
pub(crate) async fn login_handler(
    State(shared_state): State<AppState>,
    body: Json<LoginRequestBody>,
) -> Result<Json<LoginResponseBody>, CryptPassError> {
    let pool = shared_state.pool;
    let conn =
        pool.get().await.map_err(|e| InternalServerError(format!("Error getting connection from pool: {}", e)))?;

    let result = conn
        .interact(move |conn| username_password_login(&body, conn))
        .await
        .map_err(|e| InternalServerError(format!("Error interacting with connection: {}", e)))??;
    Ok(Json(result))
}

pub(crate) fn username_password_login(
    login_request: &LoginRequestBody,
    conn: &mut SqliteConnection,
) -> Result<LoginResponseBody, CryptPassError> {
    trace!("Login request: {:?}", login_request);
    let current_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|ex| InternalServerError(format!("Error getting current epoch: {}", ex)))?
        .as_millis();
    let expiration_epoch = current_epoch + JWT_DURATION;

    let username = login_request.username.as_ref().ok_or(InternalServerError("Missing username".to_string()))?;
    let password = login_request.password.as_ref().ok_or(InternalServerError("Missing password".to_string()))?;
    let user_option = services::users::get_user(username.as_ref(), conn)?;
    let user = match user_option {
        Some(user) => user,
        None => {
            let msg = format!("User not found: {}", username);
            return Err(Unauthorized(msg));
        }
    };

    let user_password_hash = match user.clone().password_hash {
        Some(hash) => hash,
        None => {
            let msg = format!("User account is not configured for password authentication: {}", username);
            return Err(Unauthorized(msg));
        }
    };

    if !match_hash(password.as_ref(), user_password_hash.as_ref()) {
        let msg = format!("Invalid password for user: {}", username);
        return Err(Unauthorized(msg));
    };

    let token = encode(
        &Header::new(Algorithm::HS512),
        &JWTClaims { sub: username.to_string(), exp: expiration_epoch, role: user.clone().to_table()?.roles },
        &EncodingKey::from_secret(get_jwt_secret().as_bytes()),
    )
    .map_err(|e| InternalServerError(format!("Error generating JWT token: {}", e)))?;
    Ok(LoginResponseBody { token: Some(token), token_type: Some("Bearer".to_string()) })
}
