use crate::{
    auth::roles::User,
    error::CryptPassError::{self, BadRequest, InternalServerError},
    physical::{
        models::{NewUserModel, UserModel},
        schema,
    },
};
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper, SqliteConnection};

pub(crate) fn get_user(
    username: &str,
    conn: &mut SqliteConnection,
) -> Result<Option<User>, CryptPassError> {
    let result = schema::users::dsl::users
        .filter(schema::users::username.eq(username))
        .limit(1)
        .select(UserModel::as_select())
        .load(conn)
        .map_err(|ex| InternalServerError(format!("Error reading user from db: {}", ex)))?;

    let user_model = match result.first() {
        Some(user) => user,
        None => return Ok(None),
    };

    let user = User {
        id: user_model.id,
        username: user_model.username.to_string(),
        email: user_model.email.clone(),
        password_hash: user_model.password_hash.clone(),
        password_last_changed: user_model.password_last_changed,
        roles: serde_json::from_str(user_model.roles.as_str())
            .map_err(|ex| InternalServerError(format!("Error parsing roles: {}", ex)))?,
        last_login: user_model.last_login,
        locked: user_model.locked,
        enabled: user_model.enabled,
    };
    Ok(Some(user))
}

pub(crate) fn create_user(user: User, conn: &mut SqliteConnection) -> Result<(), CryptPassError> {
    let roles_str = serde_json::to_string(&user.roles)
        .map_err(|ex| BadRequest(format!("Error serializing roles: {}", ex)))?;
    let user_model = NewUserModel {
        id: user.id.as_ref(),
        username: &user.username,
        email: user.email.as_ref(),
        password_hash: user.password_hash.as_ref(),
        password_last_changed: &user.password_last_changed,
        roles: &roles_str,
        last_login: &user.last_login,
        locked: &user.locked,
        enabled: &user.enabled,
    };
    diesel::insert_into(schema::users::table)
        .values(&user_model)
        .execute(conn)
        .map_err(|ex| InternalServerError(format!("Error inserting user into db: {}", ex)))?;
    Ok(())
}

pub(crate) fn update_user(user: User, conn: &mut SqliteConnection) -> Result<(), CryptPassError> {
    let roles_str = serde_json::to_string(&user.roles)
        .map_err(|ex| BadRequest(format!("Error serializing roles: {}", ex)))?;
    diesel::update(schema::users::table)
        .filter(schema::users::username.eq(user.username))
        .set((
            schema::users::email.eq(user.email),
            schema::users::password_hash.eq(user.password_hash),
            schema::users::password_last_changed.eq(user.password_last_changed),
            schema::users::roles.eq(roles_str),
            schema::users::last_login.eq(user.last_login),
            schema::users::locked.eq(user.locked),
            schema::users::enabled.eq(user.enabled),
        ))
        .execute(conn)
        .map_err(|ex| InternalServerError(format!("Error updating user in db: {}", ex)))?;
    Ok(())
}
