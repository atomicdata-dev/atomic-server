use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

macro_rules! p {
    ($($tokens: tt)*) => {
        println!("cargo:warning={}", format!($($tokens)*))
    }
}

struct Dirs {
    js_dist_source: PathBuf,
    js_dist_tmp: PathBuf,
    /// Published-form runtime (`browser/form-app`), embedded as a
    /// `form-assets/` subtree of `js_dist_tmp` alongside the data-browser
    /// dist — see `copy_form_assets`.
    form_app_dist_source: PathBuf,
    /// All source directories to watch for changes
    src_dirs: Vec<PathBuf>,
    browser_root: PathBuf,
}

fn main() -> std::io::Result<()> {
    let start_total = Instant::now();
    // Uncomment this line if you want faster builds during development
    // return Ok(());

    const BROWSER_ROOT: &str = "../browser/";
    let dirs: Dirs = {
        Dirs {
            js_dist_source: PathBuf::from("../browser/data-browser/dist"),
            js_dist_tmp: PathBuf::from("./assets_tmp"),
            form_app_dist_source: PathBuf::from("../browser/form-app/dist"),
            src_dirs: vec![
                PathBuf::from("../browser/data-browser/src"),
                PathBuf::from("../browser/lib/src"),
                PathBuf::from("../browser/react/src"),
                // Not just sources: how the bundle is *built* decides what
                // ends up embedded. A vite.config.ts change (say, turning
                // source maps off) leaves every file under src/ untouched, so
                // without these the mtime check below sees no change, keeps
                // the stale dist, and links assets that don't match the
                // config -- silently, and only in whichever build ran first.
                // WalkDir yields a plain file as a single entry, so listing
                // files here works the same as listing directories.
                PathBuf::from("../browser/data-browser/vite.config.ts"),
                PathBuf::from("../browser/data-browser/package.json"),
                PathBuf::from("../browser/pnpm-lock.yaml"),
                PathBuf::from("../browser/form-renderer/src"),
                PathBuf::from("../browser/form-app/src"),
            ],
            browser_root: PathBuf::from(BROWSER_ROOT),
        }
    };
    println!("cargo:rerun-if-changed={}", BROWSER_ROOT);

    let start_should_build = Instant::now();
    let needs_build = should_build(&dirs);
    p!(
        "should_build() took: {:.3}s",
        start_should_build.elapsed().as_secs_f32()
    );

    if needs_build {
        let start_build_js = Instant::now();
        build_js(&dirs);
        p!(
            "build_js() took: {:.3}s",
            start_build_js.elapsed().as_secs_f32()
        );

        let start_copy = Instant::now();
        let _ = fs::remove_dir_all(&dirs.js_dist_tmp);
        dircpy::copy_dir(&dirs.js_dist_source, &dirs.js_dist_tmp)?;
        copy_form_assets(&dirs)?;
        p!(
            "Copying assets took: {:.3}s",
            start_copy.elapsed().as_secs_f32()
        );
    } else if dirs.js_dist_tmp.exists() && !dist_is_newer_than_tmp(&dirs) {
        p!(
            "{} is current with {}, skipping copy",
            dirs.js_dist_tmp.display(),
            dirs.js_dist_source.display()
        );
        // The main copy is skipped, but that doesn't mean form-assets is
        // there too — `copy_form_assets` reads a different source, so
        // `dist_is_newer_than_tmp` says nothing about it. Backfill it
        // separately so `include_str!("../../assets_tmp/form-assets/index.html")`
        // in handlers/form.rs doesn't fail to compile.
        if !dirs.js_dist_tmp.join("form-assets").exists() {
            copy_form_assets(&dirs)?;
        }
    } else if dirs.js_dist_tmp.exists() {
        // `needs_build` is false and the embedded copy still has to be
        // refreshed: `should_build` answers "are the JS SOURCES newer than
        // `dist`", i.e. "should I run `pnpm build`". Building the frontend by
        // hand — which is what a deploy does, and what the e2e docs tell you to
        // do — makes that false while leaving `dist` newer than the copy we
        // embed. Gating the copy on it meant the binary shipped whatever
        // `assets_tmp` held from some earlier build, silently: the more
        // carefully you prepared the bundle, the more certainly you embedded a
        // stale one.
        p!(
            "{} is newer than {}, refreshing the embedded copy",
            dirs.js_dist_source.display(),
            dirs.js_dist_tmp.display()
        );
        let start_copy = Instant::now();
        let _ = fs::remove_dir_all(&dirs.js_dist_tmp);
        dircpy::copy_dir(&dirs.js_dist_source, &dirs.js_dist_tmp)?;
        copy_form_assets(&dirs)?;
        p!(
            "Copying assets took: {:.3}s",
            start_copy.elapsed().as_secs_f32()
        );
    } else {
        p!(
            "Could not find {} , copying from {}",
            dirs.js_dist_tmp.display(),
            dirs.js_dist_source.display()
        );
        let start_copy = Instant::now();
        dircpy::copy_dir(&dirs.js_dist_source, &dirs.js_dist_tmp)?;
        copy_form_assets(&dirs)?;
        p!(
            "Copying assets took: {:.3}s",
            start_copy.elapsed().as_secs_f32()
        );
    }

    // Pre-compress big, compressible assets with brotli quality 11. The
    // runtime `middleware::Compress` only uses brotli at its default
    // quality (~3), which leaves significant size on the table for big
    // assets (the 5.6 MB Loro WASM is the bulk of the cost). Files are
    // re-used across builds — `precompress_assets` skips when the `.br`
    // sibling is newer than the source.
    //
    // This is a *production-serving* optimization and is pure overhead for
    // local iteration (q11 over the wasm alone is ~100s, and the
    // `rm -rf assets_tmp` above invalidates the `.br` cache on every real
    // build). So only run it for release builds; debug `cargo run` — the dev
    // iteration loop — skips it and lets the runtime middleware compress on
    // the fly. Override with `ATOMICSERVER_PRECOMPRESS=true` if you need to
    // test the precompressed path in debug.
    let want_precompress = std::env::var("PROFILE").as_deref() == Ok("release")
        || std::env::var("ATOMICSERVER_PRECOMPRESS").as_deref() == Ok("true");
    if want_precompress {
        let start_precompress = Instant::now();
        if let Err(e) = precompress_assets(&dirs.js_dist_tmp) {
            p!("Pre-compression failed (continuing without): {}", e);
        }
        p!(
            "Pre-compressing assets took: {:.3}s",
            start_precompress.elapsed().as_secs_f32()
        );
    } else {
        p!("Skipping asset pre-compression (debug build; runtime middleware compresses on the fly). Set ATOMICSERVER_PRECOMPRESS=true to force.");
    }

    // Makes the static files available for compilation
    let start_bundle = Instant::now();
    static_files::resource_dir(&dirs.js_dist_tmp)
        .build()
        .unwrap_or_else(|_e| {
            panic!(
                "failed to open data browser assets from {}",
                dirs.js_dist_tmp.display()
            )
        });
    p!(
        "Bundling static files took: {:.3}s",
        start_bundle.elapsed().as_secs_f32()
    );

    p!(
        "Total build.rs time: {:.3}s",
        start_total.elapsed().as_secs_f32()
    );

    Ok(())
}

fn should_build(dirs: &Dirs) -> bool {
    // If the ATOMICSERVER_SKIP_JS_BUILD environment variable is set, skip the JS build
    if let Ok(env_skip) = std::env::var("ATOMICSERVER_SKIP_JS_BUILD") {
        if env_skip == "true" {
            p!("ATOMICSERVER_SKIP_JS_BUILD is set, skipping JS build.");
            return false;
        }
    }

    if !dirs.browser_root.exists() {
        p!("Could not find browser folder, assuming this is a `cargo publish` run. Skipping JS build.");
        return false;
    }
    // Check if any JS files were modified since the last build
    // Compare against the actual dist output, not the temporary copy
    // Find the newest file in the dist directory to compare against
    let dist_time = find_newest_file_time(&dirs.js_dist_source);

    if let Some(dist_time) = dist_time {
        let has_changes = dirs.src_dirs.iter().any(|src_dir| {
            walkdir::WalkDir::new(src_dir)
                .into_iter()
                .filter_entry(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .map(|s| !s.starts_with(".DS_Store"))
                        .unwrap_or(false)
                        && !is_js_build_output(entry.path())
                })
                .any(|entry| {
                    if let Ok(entry) = entry {
                        is_newer_than_dist(&entry, dist_time)
                    } else {
                        false
                    }
                })
        });

        if has_changes {
            return true;
        }

        p!("No changes in JS source files, skipping JS build.");
        false
    } else if dirs.src_dirs.iter().any(|d| d.exists()) {
        p!(
            "No JS dist folder found at {}, but source folders exist, building...",
            dirs.js_dist_tmp.display(),
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

/// Runs JS package manager to install packages and build the JS bundle.
///
/// Cargo buffers ALL build-script output (`cargo:warning=` lines) until this
/// script returns, and the previous implementation captured the child's
/// stdout/stderr with `.output()` — so while `pnpm` (and the nested
/// `wasm-pack` → `cargo` build it triggers) ran, NOTHING was visible. A stuck
/// build looked like a frozen `atomic-server(build)` with zero feedback. To
/// keep it observable we stream every child's output LIVE to a log file
/// (`server/js-build.log`) that can be `tail -f`'d during the build.
///
/// IMPORTANT (the recursive-cargo deadlock): `pnpm run build` eventually runs
/// `wasm-pack build` in `../../wasm`, which invokes a NESTED `cargo`. If that
/// nested cargo built into the shared workspace `target/`, it would block on
/// the artifact-directory lock the OUTER `cargo run`/`cargo build` (or
/// rust-analyzer's `cargo check`) already holds — a deadlock that hangs here
/// forever ("Blocking waiting for file lock on artifact directory"). The
/// `build:wasm` npm script now sets `CARGO_TARGET_DIR=../target/wasm-pack` so
/// the nested build uses a SEPARATE lock root and can't contend. To skip the JS
/// build entirely (faster backend-only iteration), set
/// `ATOMICSERVER_SKIP_JS_BUILD=true` (assets are reused from `assets_tmp`).
fn build_js(dirs: &Dirs) {
    use std::fs::File;
    use std::process::Stdio;

    let pkg_manager = "pnpm";

    // A log file the child writes to LIVE — the only output visible while the
    // build runs (Cargo hides build-script output until completion). Path is
    // relative to the server crate dir (build.rs's CWD).
    let log_path = PathBuf::from("js-build.log");
    let log_display = std::fs::canonicalize(".")
        .map(|d| d.join(&log_path))
        .unwrap_or_else(|_| log_path.clone());
    p!(
        "Building JS+WASM assets via `{} run build`. This invokes wasm-pack \
         (nested cargo) and can take minutes — live output streams to {}. \
         If it hangs, it is the recursive-cargo lock: re-run with \
         ATOMICSERVER_SKIP_JS_BUILD=true to skip this step.",
        pkg_manager,
        log_display.display(),
    );

    // Open (truncate) the log; stdout+stderr of both child commands go here.
    let open_log = || {
        File::create(&log_path).unwrap_or_else(|e| {
            panic!(
                "Failed to create JS build log {}: {}",
                log_path.display(),
                e
            )
        })
    };

    let run_streamed = |args: &[&str], step: &str| {
        let log = open_log();
        let log_err = log
            .try_clone()
            .expect("Failed to clone JS build log handle");
        let status = std::process::Command::new(pkg_manager)
            .current_dir(&dirs.browser_root)
            .args(args)
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .status()
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to spawn `{} {}` (is {} installed?): {}",
                    pkg_manager,
                    args.join(" "),
                    pkg_manager,
                    e
                )
            });

        if !status.success() {
            // Surface the captured log in the panic — the live stream is gone
            // from the terminal by the time Cargo prints this.
            let tail = std::fs::read_to_string(&log_path).unwrap_or_default();
            panic!("js {} failed (see {}):\n{}", step, log_path.display(), tail);
        }
    };

    p!("install js packages...");
    run_streamed(&["install"], "install");

    p!("build js assets...");
    run_streamed(&["run", "build"], "build");

    p!("js build successful");
}

/// Copies `browser/form-app/dist` into `<js_dist_tmp>/form-assets/`, so the
/// published-form runtime rides along in the same `static_files::generate()`
/// map as the data-browser dist (see `routes.rs`'s `ResourceFiles::new("/",
/// generate())`) — `/form-assets/*` requests are then served automatically,
/// no extra server route needed. Only the HTML shell at `/form/{id}` needs
/// its own handler (`handlers::form::form_page`), which `include_str!`s
/// `form-assets/index.html` from this same copy at compile time.
fn copy_form_assets(dirs: &Dirs) -> std::io::Result<()> {
    if !dirs.form_app_dist_source.exists() {
        p!(
            "Could not find {}, skipping form-app asset embed (form/:id route will 404)",
            dirs.form_app_dist_source.display()
        );
        return Ok(());
    }

    let dest = dirs.js_dist_tmp.join("form-assets");
    dircpy::copy_dir(&dirs.form_app_dist_source, &dest)
}

/// Pre-compress eligible files (`.wasm`, `.js`, `.css`, `.html`, `.svg`,
/// `.json`) with brotli quality 11 and write `<path>.br` siblings. Skips
/// files below `MIN_SIZE` (compression overhead dominates) and reuses
/// existing `.br` outputs when they're newer than the source — so
/// incremental builds don't re-pay the (slow) q11 cost.
fn precompress_assets(root: &Path) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    const COMPRESSIBLE: &[&str] = &["wasm", "js", "css", "html", "svg", "json"];
    const MIN_SIZE: u64 = 4096;
    const QUALITY: u32 = 11;
    const WINDOW: u32 = 22;

    // Pass 1 (serial walk): collect the files that actually need (re)compression
    // as `(source, .br destination, source size)`.
    let mut jobs: Vec<(PathBuf, PathBuf, u64)> = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !COMPRESSIBLE.iter().any(|e| *e == ext) {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.len() < MIN_SIZE {
            continue;
        }

        let mut br_path = path.to_path_buf();
        br_path.set_extension(format!("{}.br", ext));

        // Skip if .br is up-to-date relative to the source.
        if let Ok(br_meta) = fs::metadata(&br_path) {
            if let (Ok(src_t), Ok(br_t)) = (meta.modified(), br_meta.modified()) {
                if br_t >= src_t {
                    continue;
                }
            }
        }

        jobs.push((path.to_path_buf(), br_path, meta.len()));
    }

    if jobs.is_empty() {
        return Ok(());
    }

    // Pass 2 (parallel): each file is independent, so brotli q11 runs on all
    // cores at once. Wall-clock collapses to the slowest single file (the
    // 5.6 MB wasm) instead of the serial sum over every asset. Per-file errors
    // are non-fatal — a file that fails to compress is simply served raw.
    let next = AtomicUsize::new(0);
    let compressed = AtomicUsize::new(0);
    let total_in = AtomicU64::new(0);
    let total_out = AtomicU64::new(0);
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(jobs.len());

    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some((src, br_path, len)) = jobs.get(i) else {
                    break;
                };
                let Ok(data) = fs::read(src) else { continue };
                let mut out: Vec<u8> = Vec::with_capacity(data.len() / 3);
                {
                    let mut w = brotli::CompressorWriter::new(&mut out, 4096, QUALITY, WINDOW);
                    if w.write_all(&data).is_err() || w.flush().is_err() {
                        continue;
                    }
                }
                // Only emit if compression actually paid off — for tiny files
                // brotli sometimes inflates.
                if (out.len() as u64) < *len && fs::write(br_path, &out).is_ok() {
                    compressed.fetch_add(1, Ordering::Relaxed);
                    total_in.fetch_add(*len, Ordering::Relaxed);
                    total_out.fetch_add(out.len() as u64, Ordering::Relaxed);
                }
            });
        }
    });

    let compressed = compressed.into_inner();
    if compressed > 0 {
        let total_in = total_in.into_inner();
        let total_out = total_out.into_inner();
        let saved = total_in.saturating_sub(total_out);
        p!(
            "Pre-compressed {} files: {} KB → {} KB (saved {} KB, {:.1}% ratio)",
            compressed,
            total_in / 1024,
            total_out / 1024,
            saved / 1024,
            (total_out as f64 / total_in.max(1) as f64) * 100.0,
        );
    }
    Ok(())
}

/// Paths under `src/` that the JS build *writes*, so they are output, not
/// input, even though they live among the sources (and `main.loader.js` is
/// committed, unlike its two siblings).
///
/// wuchale rewrites all three on every `pnpm run build` — same bytes, new
/// mtime. Counting them as "a source changed" makes this check
/// self-triggering: one build guarantees the next one rebuilds too, so the
/// ~35s data-browser build is paid every single time and the mtime comparison
/// never gets to do its job. CI feels it hardest, where each job starts from
/// whatever the previous one left behind.
///
/// A genuine wuchale change still forces a rebuild: it arrives as a
/// `pnpm-lock.yaml` bump, which is watched.
fn is_js_build_output(path: &Path) -> bool {
    // Matched on the tail rather than the file name alone: `data.js` is a
    // name plausible enough to exist as real source elsewhere under src/, and
    // silently ignoring *that* would be the opposite bug — a source edit that
    // never triggers a rebuild.
    const GENERATED: &[&str] = &[
        "src/locales/main.loader.js",
        "src/locales/data.js",
        "src/locales/.wuchale",
    ];

    // `.wuchale` needs no contents check: WalkDir consults filter_entry on a
    // directory before descending, so rejecting it here prunes the subtree.
    let path = path.to_string_lossy().replace('\\', "/");
    GENERATED.iter().any(|suffix| path.ends_with(suffix))
}

/// Finds the modification time of the newest file in the dist directory
/// Newest mtime among the files in `dist` that the JS build actually produces.
///
/// Anything else that lands in there is not evidence the bundle is current, and
/// treating it as such is silent: `tsconfig.build.json` sets `outDir: ./dist`,
/// so a plain `pnpm typecheck` drops `tsconfig.build.tsbuildinfo` in beside the
/// bundle. That one file then reads as "dist is newer than every source",
/// `should_build` says there is nothing to do, and the server embeds a bundle
/// from before the sources changed — while a `cargo build` that looks entirely
/// successful scrolls past. Observed exactly that: sources at 14:42, tsbuildinfo
/// at 14:43, actual bundle still 13:47.
/// True when the built bundle is newer than the copy we embed.
///
/// Compares newest-file times both ways rather than trusting `should_build`,
/// which is about whether `pnpm build` needs to run, not about whether the
/// embedded copy is current. The two diverge exactly when someone builds the
/// frontend themselves.
fn dist_is_newer_than_tmp(dirs: &Dirs) -> bool {
    match (
        find_newest_file_time(&dirs.js_dist_source),
        find_newest_file_time(&dirs.js_dist_tmp),
    ) {
        (Some(dist), Some(tmp)) => dist > tmp,
        // No embedded copy yet, or an unreadable one: copy and be sure.
        (Some(_), None) => true,
        // Nothing built to copy from — leave whatever is embedded alone.
        (None, _) => false,
    }
}

fn find_newest_file_time(dist_dir: &PathBuf) -> Option<Duration> {
    let mut newest_time: Option<Duration> = None;

    if let Ok(entries) = walkdir::WalkDir::new(dist_dir)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
    {
        for entry in entries {
            let is_build_metadata = entry
                .path()
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e == "tsbuildinfo")
                .unwrap_or(false);

            if is_build_metadata {
                continue;
            }

            if entry.path().is_file() {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(modified) = meta.modified() {
                        if let Ok(time) = modified.duration_since(SystemTime::UNIX_EPOCH) {
                            newest_time = Some(newest_time.map_or(time, |t| t.max(time)));
                        }
                    }
                }
            }
        }
    }

    newest_time
}

/// Checks if a source file is newer than the dist build time
/// Returns true if the source file is significantly newer (more than 2 seconds)
/// This accounts for filesystem timestamp precision issues
fn is_newer_than_dist(dir_entry: &walkdir::DirEntry, dist_time: Duration) -> bool {
    if !dir_entry.path().is_file() {
        return false;
    }

    let src_modified = match dir_entry.metadata() {
        Ok(meta) => meta.modified().ok(),
        Err(_) => return false,
    };

    let src_modified_time = match src_modified {
        Some(time) => time,
        None => return false,
    };

    // Check if source timestamp is in the future relative to current time
    // This handles files with incorrect future timestamps (like Dec 31 2026)
    let now = SystemTime::now();
    match src_modified_time.duration_since(now) {
        Ok(future_duration) => {
            // Source file is in the future - if more than 1 hour, ignore it
            if future_duration > Duration::from_secs(3600) {
                p!(
                    "Source file {:?} has future timestamp ({}s ahead), ignoring...",
                    dir_entry.path(),
                    future_duration.as_secs()
                );
                return false;
            }
        }
        Err(_) => {
            // Source file is in the past or present, which is normal
        }
    }

    // Convert source time to duration since epoch for comparison
    let src_time = match src_modified_time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(time) => time,
        Err(_) => return false, // Source file has invalid timestamp (before epoch)
    };

    // Add a 2-second tolerance to account for filesystem timestamp precision issues
    // Only rebuild if source is significantly newer (more than 2 seconds)
    let tolerance = Duration::from_secs(2);
    if src_time > dist_time + tolerance {
        p!(
            "Source file modified: {:?}, rebuilding...",
            dir_entry.path()
        );
        return true;
    }

    false
}
