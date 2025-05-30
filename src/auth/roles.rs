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
