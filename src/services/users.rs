use crate::{
    error::CryptPassError::{self, InternalServerError},
    physical::{models::UserTable, models::Users, schema},
};
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper, SqliteConnection};

pub(crate) fn get_user<'a>(username: &'a str, conn: &'a mut SqliteConnection) -> Result<Option<Users>, CryptPassError> {
    let result = schema::users_table::dsl::users_table
        .filter(schema::users_table::username.eq(username))
        .limit(1)
        .select(UserTable::as_select())
        .load(conn)
        .map_err(|ex| InternalServerError(format!("Error reading user from db: {}", ex)))?;

    match result.first() {
        Some(user) => Ok(Some(user.to_users()?)),
        None => Ok(None),
    }
}

pub(crate) fn create_user(user: Users, conn: &mut SqliteConnection) -> Result<(), CryptPassError> {
    diesel::insert_into(schema::users_table::table)
        .values(&user.to_table()?)
        .execute(conn)
        .map_err(|ex| InternalServerError(format!("Error inserting user into db: {}", ex)))?;
    Ok(())
}

pub(crate) fn update_user(user: Users, conn: &mut SqliteConnection) -> Result<(), CryptPassError> {
    diesel::update(schema::users_table::table)
        .filter(schema::users_table::username.eq(user.username.clone()))
        .set(user.to_table()?)
        .execute(conn)
        .map_err(|ex| InternalServerError(format!("Error updating user in db: {}", ex)))?;
    Ok(())
}
