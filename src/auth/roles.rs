use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) enum PrivilegeType {
    SUDO,
    #[allow(non_camel_case_types)]
    NO_SUDO,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct Privilege {
    pub(crate) name: PrivilegeType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) enum RoleType {
    ADMIN,
    USER,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct Role {
    pub(crate) name: RoleType,
    pub(crate) privileges: Vec<Privilege>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct User {
    pub(crate) username: String,
    pub(crate) email: Option<String>,
    pub(crate) password_hash: Option<String>,
    pub(crate) password_last_changed: i64,
    pub(crate) roles: Vec<Role>,
    pub(crate) last_login: i64,
    pub(crate) locked: bool,
    pub(crate) enabled: bool,
    pub(crate) api_token_jwt_secret_b64_encrypted: String,
}
