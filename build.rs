use std::fs;

fn main() {
    let app_version = env!("CARGO_PKG_VERSION");
    fs::write("CRYPTPASS_VERSION", app_version).expect("Unable to write file:: CRYPTPASS_VERSION");
}
