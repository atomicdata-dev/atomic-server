use std::time::SystemTime;

const JS_DIST_SOURCE: &str = "../browser/data-browser/dist";
const SRC_BROWSER: &str = "../browser/data-browser/src";
const BROWSER_ROOT: &str = "../browser/";
const JS_DIST_TMP: &str = "./assets_tmp";

macro_rules! p {
    ($($tokens: tt)*) => {
        println!("cargo:warning={}", format!($($tokens)*))
    }
}

fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed={}", BROWSER_ROOT);

    if should_build() {
        build_js();
        dircpy::copy_dir(JS_DIST_SOURCE, JS_DIST_TMP)?;
    }

    if !std::path::Path::new(JS_DIST_TMP).exists() {
        p!("Could not find JS_DIST_TMP folder, copying JS_DIST_SOURCE");
        dircpy::copy_dir(JS_DIST_SOURCE, JS_DIST_TMP)?;
    }

    // Makes the static files available for compilation
    static_files::resource_dir(JS_DIST_TMP)
        .build()
        .unwrap_or_else(|e| panic!("failed to open data browser assets from {JS_DIST_TMP}. {e}"));

    Ok(())
}

fn should_build() -> bool {
    if !std::path::Path::new(BROWSER_ROOT).exists() {
        p!("Could not find browser folder, assuming this is a `cargo publish` run. Skipping JS build.");
        return false;
    }
    // Check if any JS files were modified since the last build
    if let Ok(tmp_dist_index_html) = std::fs::metadata(format!("{}/index.html", JS_DIST_TMP)) {
        let dist_time = tmp_dist_index_html
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
    } else if std::path::Path::new(SRC_BROWSER).exists() {
        p!("No JS dist folder found, but did find source folder, building...");
        true
    } else {
        p!("Could not find index.html in JS_DIST_TMP, assuming this is a `cargo publish` run. Skipping JS build.");
        false
    }
}

/// Runs JS package manager to install packages and build the JS bundle
fn build_js() {
    let pkg_manager = "pnpm";

    p!("install js packages...");

    std::process::Command::new(pkg_manager)
        .current_dir(BROWSER_ROOT)
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
        .current_dir(BROWSER_ROOT)
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
