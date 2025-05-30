use crate::{
    error::CryptPassError::{self, InternalServerError},
    physical::{models::UserModel, schema},
};
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper, SqliteConnection};

pub(crate) fn get_user(username: &str, conn: &mut SqliteConnection) -> Result<Option<UserModel>, CryptPassError> {
    let result = schema::users::dsl::users
        .filter(schema::users::username.eq(username))
        .limit(1)
        .select(UserModel::as_select())
        .load(conn)
        .map_err(|ex| InternalServerError(format!("Error reading user from db: {}", ex)))?;

    match result.first() {
        Some(user) => Ok(Some(user.clone())),
        None => Ok(None),
    }
}

pub(crate) fn create_user(user: UserModel, conn: &mut SqliteConnection) -> Result<(), CryptPassError> {
    diesel::insert_into(schema::users::table)
        .values(&user)
        .execute(conn)
        .map_err(|ex| InternalServerError(format!("Error inserting user into db: {}", ex)))?;
    Ok(())
}

pub(crate) fn update_user(user: UserModel, conn: &mut SqliteConnection) -> Result<(), CryptPassError> {
    diesel::update(schema::users::table)
        .filter(schema::users::username.eq(user.username.clone()))
        .set(user)
        .execute(conn)
        .map_err(|ex| InternalServerError(format!("Error updating user in db: {}", ex)))?;
    Ok(())
}
