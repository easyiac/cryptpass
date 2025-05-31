mod auth;
mod error;
mod init;
mod physical;
mod routers;
mod services;
mod utils;

use std::{fs, path::Path};
use utoipa::OpenApi;

fn main() {
    let path = "./openapi.json";
    println!("Deleting old openapi.json at {}", path);

    if Path::new(path).exists() {
        if let Err(e) = fs::remove_file(path) {
            eprintln!("Failed to delete file: {}", e);
        } else {
            println!("File deleted.");
        }
    } else {
        println!("File does not exist.");
    }

    println!("Generating openapi.json at {}", path);

    fs::write(path, routers::ApiDoc::openapi().to_pretty_json().expect("Unable to convert to pretty json"))
        .expect("Unable to write to file");
}
