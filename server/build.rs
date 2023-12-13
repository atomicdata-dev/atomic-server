use std::{path::PathBuf, time::SystemTime};

macro_rules! p {
    ($($tokens: tt)*) => {
        println!("cargo:warning={}", format!($($tokens)*))
    }
}

struct Dirs {
    js_dist_source: PathBuf,
    js_dist_tmp: PathBuf,
    src_browser: PathBuf,
    browser_root: PathBuf,
}

fn main() -> std::io::Result<()> {
    const BROWSER_ROOT: &str = "../browser/";
    let dirs: Dirs = {
        Dirs {
            js_dist_source: PathBuf::from("../browser/data-browser/dist"),
            js_dist_tmp: PathBuf::from("./assets_tmp"),
            src_browser: PathBuf::from("../browser/data-browser/src"),
            browser_root: PathBuf::from(BROWSER_ROOT),
        }
    };
    println!("cargo:rerun-if-changed={}", BROWSER_ROOT);

    if should_build(&dirs) {
        build_js(&dirs);
        dircpy::copy_dir(&dirs.js_dist_source, &dirs.js_dist_tmp)?;
    } else if dirs.js_dist_tmp.exists() {
        p!("Found {}, skipping copy", dirs.js_dist_tmp.display());
    } else {
        p!(
            "Could not find {} , copying from {}",
            dirs.js_dist_tmp.display(),
            dirs.js_dist_source.display()
        );
        dircpy::copy_dir(&dirs.js_dist_source, &dirs.js_dist_tmp)?;
    }

    // Makes the static files available for compilation
    static_files::resource_dir(&dirs.js_dist_tmp)
        .build()
        .unwrap_or_else(|_e| {
            panic!(
                "failed to open data browser assets from {}",
                dirs.js_dist_tmp.display()
            )
        });

    Ok(())
}

fn should_build(dirs: &Dirs) -> bool {
    if !dirs.browser_root.exists() {
        p!("Could not find browser folder, assuming this is a `cargo publish` run. Skipping JS build.");
        return false;
    }
    // Check if any JS files were modified since the last build
    if let Ok(tmp_dist_index_html) =
        std::fs::metadata(format!("{}/index.html", dirs.js_dist_tmp.display()))
    {
        let dist_time = tmp_dist_index_html
            .modified()
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        for entry in walkdir::WalkDir::new(&dirs.src_browser)
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
    } else if dirs.src_browser.exists() {
        p!(
            "No JS dist folder found at {}, but did find source folder {}, building...",
            dirs.js_dist_tmp.display(),
            dirs.src_browser.display()
        );
        true
    } else {
        p!(
            "Could not find index.html in {}. Skipping JS build.",
            dirs.js_dist_tmp.display()
        );
        false
    }
}

/// Runs JS package manager to install packages and build the JS bundle
fn build_js(dirs: &Dirs) {
    let pkg_manager = "pnpm";

    p!("install js packages...");

    std::process::Command::new(pkg_manager)
        .current_dir(&dirs.browser_root)
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
        .current_dir(&dirs.browser_root)
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
