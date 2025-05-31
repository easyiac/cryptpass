use std::fs;
use utoipa::OpenApi;

mod auth;
mod error;
mod init;
mod physical;
pub(crate) mod routers;
mod services;
mod utils;
fn main() {
    fs::write("./openapi.json", routers::ApiDoc::openapi().to_pretty_json().expect("Unable to convert to pretty json"))
        .expect("Unable to write to file");
}
