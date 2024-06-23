use std::{fs, process::Command};

fn main() {
    // Install Node Dependencies
    Command::new("sh")
        .arg("-c")
        .arg("npm install")
        .output()
        .unwrap();

    // Create Assets directory
    fs::create_dir_all("assets").unwrap();

    // Populate Assets directory
    fs::copy(
        "node_modules/htmx.org/dist/htmx.min.js",
        "assets/htmx.min.js",
    )
    .unwrap();
}
