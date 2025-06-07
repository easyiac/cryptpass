mod error;
mod init;
mod physical;
mod routers;
mod services;
mod utils;

use std::{fs, path::Path};
use utoipa::OpenApi;

fn main() {
    let path = "./docs/OpenAPI.yaml";
    println!("Deleting old openapi yaml at {}", path);

    if Path::new(path).exists() {
        if let Err(e) = fs::remove_file(path) {
            eprintln!("Failed to delete file: {}", e);
        } else {
            println!("File deleted. {}", path);
        }
    } else {
        println!("File does not exist. {}", path);
    }

    println!("Generating openapi.json at {}", path);

    fs::write(path, routers::ApiDoc::openapi().to_yaml().expect("Unable to convert to pretty json"))
        .expect("Unable to write to file");
}
