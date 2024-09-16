use std::{
    fs::{self, Metadata},
    path::PathBuf,
    time::SystemTime,
};

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
    // Uncomment this line if you want faster builds during development
    return Ok(());
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
        let _ = fs::remove_dir_all(&dirs.js_dist_tmp);
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
        let has_changes = walkdir::WalkDir::new(&dirs.src_browser)
            .into_iter()
            .filter_entry(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .map(|s| !s.starts_with(".DS_Store"))
                    .unwrap_or(false)
            })
            .any(|entry| is_older_than(&entry.unwrap(), &tmp_dist_index_html));

        if has_changes {
            return true;
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
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        panic!("js build failed:\nStdout:\n{}\nStderr:\n{}", stdout, stderr);
    }
}

fn is_older_than(dir_entry: &walkdir::DirEntry, dist_meta: &Metadata) -> bool {
    let dist_time = dist_meta
        .modified()
        .unwrap()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();

    if dir_entry.path().is_file() {
        let src_time = dir_entry
            .metadata()
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        if src_time >= dist_time {
            p!(
                "Source file modified: {:?}, rebuilding...",
                dir_entry.path()
            );
            return true;
        }
    }
    false
}
