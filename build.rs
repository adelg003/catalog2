use std::{fs, process::Command};

fn main() {
    // Install Node Dependencies
    let output = Command::new("sh")
        .arg("-c")
        .arg("npm install")
        .output()
        .unwrap();

    // Ensure Node Install worked
    if !output.status.success() {
        panic!(
            "Shell command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Create Assets directory
    fs::create_dir_all("assets/scripts").unwrap();

    // Populate Assets directory
    fs::copy(
        "node_modules/htmx.org/dist/htmx.min.js",
        "assets/scripts/htmx.min.js",
    )
    .unwrap();
}
