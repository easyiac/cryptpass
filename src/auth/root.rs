use crate::{
    auth::roles::{Privilege, PrivilegeType, Role, RoleType, User},
    encryption::hash,
    error::CryptPassError::{self, InternalServerError},
    services, CRYPTPASS_CONFIG_INSTANCE,
};
use diesel::SqliteConnection;
use rand::{distr::Alphanumeric, Rng};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

pub(crate) fn create_root_user(conn: &mut SqliteConnection) -> Result<(), CryptPassError> {
    let configuration = CRYPTPASS_CONFIG_INSTANCE.get().expect("Configuration not initialized.");
    let is_new_root_user;
    let mut roles = Vec::new();
    let current_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| InternalServerError("System time before UNIX EPOCH".to_string()))?
        .as_millis() as i64;
    roles.push(Role {
        name: RoleType::ADMIN,
        privileges: vec![Privilege { name: PrivilegeType::SUDO }],
    });
    let root_user_option = services::users::get_user("root", conn)
        .map_err(|ex| InternalServerError(format!("Error getting root user: {}", ex)))?;

    let mut root_user = match root_user_option {
        Some(user) => {
            is_new_root_user = false;
            user
        }
        None => {
            is_new_root_user = true;
            User {
                id: None,
                username: "root".to_string(),
                email: None,
                password_hash: None,
                password_last_changed: 0i64,
                roles: roles.clone(),
                last_login: 0i64,
                locked: false,
                enabled: true,
            }
        }
    };

    if let Some(password) = &configuration.server.root_password {
        info!("Adding/Updating root user with password hash from config");
        root_user.password_hash = Some(hash(password));
        root_user.password_last_changed = current_epoch;
    }

    if root_user.password_hash.is_none() && configuration.server.root_password.is_none() {
        let s: String = rand::rng().sample_iter(&Alphanumeric).take(10).map(char::from).collect();
        info!("Creating root user with password: {}", s);
        warn!("Make sure to change the password after first login!");
        root_user.password_hash = Some(hash(&s));
        root_user.password_last_changed = current_epoch;
    };

    root_user.locked = false;
    root_user.enabled = true;
    root_user.roles = roles;
    root_user.last_login = 0i64;

    if is_new_root_user {
        info!("Creating new root user");
        services::users::create_user(root_user, conn)?;
        info!("Root user created");
    } else {
        info!("Updating existing root user");
        services::users::update_user(root_user, conn)?;
        info!("Existing root user updated");
    }

    Ok(())
}
