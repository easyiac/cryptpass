use rand::{distr::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use tracing::trace;
use utoipa::ToSchema;

pub(crate) mod layer;
pub(crate) mod login;

static JWT_SECRET: OnceLock<String> = OnceLock::new();
static JWT_DURATION: u128 = 3600000;
pub(crate) fn get_jwt_secret() -> &'static str {
    JWT_SECRET.get_or_init(|| {
        let secret_jwt = rand::rng().sample_iter(&Alphanumeric).take(64).map(char::from).collect();
        trace!("Initializing JWT secret: {}", secret_jwt);
        secret_jwt
    })
}

#[derive(Serialize, Deserialize)]
pub(crate) struct JWTClaims {
    pub(crate) sub: String,
    pub(crate) exp: u128,
    pub(crate) role: String,
}

#[derive(Deserialize, Debug, ToSchema)]
pub(crate) struct LoginRequest {
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct LoginResponse {
    pub(crate) token: Option<String>,
    #[serde(rename = "type")]
    pub(crate) token_type: Option<String>,
}
