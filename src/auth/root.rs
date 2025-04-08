use crate::{
    auth::{
        roles::{Privilege, PrivilegeType, Role, RoleType, User},
        AuthError,
    },
    encryption::hash,
    physical::{create_user, get_user, update_user},
};
use diesel::SqliteConnection;
use rand::{distr::Alphanumeric, Rng};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

pub(crate) fn create_root_user(conn: &mut SqliteConnection) -> Result<(), AuthError> {
    let configuration = crate::config::INSTANCE.get().expect("Configuration not initialized.");
    let is_new_root_user;
    let mut roles = Vec::new();
    let current_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError("System time before UNIX EPOCH".to_string()))?
        .as_millis() as i64;
    roles.push(Role {
        name: RoleType::ADMIN,
        privileges: vec![Privilege { name: PrivilegeType::SUDO }],
    });
    let root_user_option = get_user("root", conn)
        .map_err(|ex| AuthError(format!("Error getting root user: {}", ex)))?;

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
                password_last_changed: None,
                roles: roles.clone(),
                last_login: None,
                locked: false,
                enabled: true,
            }
        }
    };

    if root_user.password_hash.is_none() && configuration.server.root_password.is_none() {
        let s: String = rand::rng().sample_iter(&Alphanumeric).take(10).map(char::from).collect();
        info!("Creating root user with password hash: {}", s);
        let password_hash = hash(&s);
        root_user.password_hash = Some(password_hash);
        root_user.password_last_changed = Some(current_epoch);
    };

    if let Some(password) = &configuration.server.root_password {
        info!("Adding/Updating root user with password hash from config");
        let password_hash = hash(&password);
        root_user.password_hash = Some(password_hash);
        root_user.password_last_changed = Some(current_epoch);
    }

    root_user.locked = false;
    root_user.enabled = true;
    root_user.roles = roles;

    if is_new_root_user {
        info!("Creating new root user: {}", current_epoch);
        create_user(root_user, conn)
            .map_err(|ex| AuthError(format!("Error creating root user: {}", ex)))?;
    } else {
        info!("Updating existing root user: {}", current_epoch);
        update_user(root_user, conn)
            .map_err(|ex| AuthError(format!("Error updating root user: {}", ex)))?;
    }

    Ok(())
}
