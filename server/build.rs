use std::time::SystemTime;

use static_files::resource_dir;

const JS_DIST: &str = "../browser/data-browser/dist";
const SRC_BROWSER: &str = "../browser/data-browser/src";

macro_rules! p {
    ($($tokens: tt)*) => {
        println!("cargo:warning={}", format!($($tokens)*))
    }
}

fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=../browser");

    if should_build() {
        build_js()
    }

    resource_dir(JS_DIST)
        .build()
        .unwrap_or_else(|_| panic!("failed to open data browser assets from {}", JS_DIST));

    Ok(())
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

        p!("No changes in JS source files, skipping JS build.");
        false
    } else {
        p!("No JS dist folder found, building...");
        true
    }
}

/// Runs JS package manager to install packages and build the JS bundle
fn build_js() {
    let pkg_manager = "pnpm";
    let browser_path = "../browser/data-browser";

    p!("install js packages...");
    std::process::Command::new(pkg_manager)
        .current_dir(browser_path)
        .args(["install"])
        .output()
        .unwrap_or_else(|_| {
            panic!(
                "Failed to install js packages. Make sure you have {} installed.",
                pkg_manager
            )
        });
    p!("build js assets...");
    let out = std::process::Command::new(pkg_manager)
        .current_dir(browser_path)
        .args(["run", "build"])
        .output()
        .expect("Failed to build js bundle");
    // Check if out contains errors
    if out.status.success() {
        p!("js build successful");
    } else {
        panic!(
            "js build failed: {}",
            String::from_utf8(out.stderr).unwrap()
        );
    }
}
