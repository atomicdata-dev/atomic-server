use std::time::SystemTime;

use static_files::resource_dir;

const JS_DIST: &str = "../browser/data-browser/dist";
const SRC_BROWSER: &str = "../browser/data-browser/src";

macro_rules! p {
    ($($tokens: tt)*) => {
        println!("cargo:warning={}", format!($($tokens)*))
    }
}

/// Check if any JS files were modified since the last build
fn should_build() -> bool {
    if let Ok(dist) = std::fs::metadata(format!("{}/index.html", JS_DIST)) {
        let dist_time = dist
            .modified()
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        for entry in walkdir::WalkDir::new(SRC_BROWSER)
            .into_iter()
            .filter_map(|e| {
                // ignore ds store
                if let Ok(e) = e {
                    if e.path().to_str().unwrap().contains(".DS_Store") {
                        return None;
                    }
                    Some(e)
                } else {
                    None
                }
            })
        {
            if entry.path().is_file() {
                let src_time = entry
                    .metadata()
                    .unwrap()
                    .modified()
                    .unwrap()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap();
                if src_time >= dist_time {
                    p!("Source file modified: {:?}, rebuilding...", entry.path());
                    return true;
                }
            }
        }

        p!("No changes in JS, skipping build.");
        false
    } else {
        p!("No dist folder found, building...");
        true
    }
}

fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=../browser");

    let pckgmanager = "pnpm";

    if should_build() {
        p!("install js packages...");
        std::process::Command::new(pckgmanager)
            .current_dir("../browser/data-browser")
            .args(["install"])
            .output()
            .expect("failed to install deps");
        p!("build js assets...");
        std::process::Command::new(pckgmanager)
            .current_dir("../browser/data-browser")
            .args(["run", "build"])
            .output()
            .expect("failed to build js bundle");
    }

    resource_dir(JS_DIST)
        .build()
        .unwrap_or_else(|_| panic!("failed to open data browser assets from {}", JS_DIST));

    Ok(())
}
