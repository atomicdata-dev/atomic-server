use static_files::resource_dir;

fn main() -> std::io::Result<()> {
    let js_build_path = "../browser/data-browser/dist";

    if std::fs::read_dir(js_build_path).is_err() {
        println!("Running `pnpm run build` in the data-browser folder...");
        std::process::Command::new("pnpm")
            .current_dir("../browser")
            .args(["run", "build"])
            .output()
            .expect("failed to execute process");
    }

    resource_dir(js_build_path)
        .build()
        .unwrap_or_else(|_| panic!("failed to open data browser assets from {}", js_build_path));

    Ok(())
}
