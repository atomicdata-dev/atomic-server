use static_files::resource_dir;

fn main() -> std::io::Result<()> {
    // Imports the static files.
    // These should be regularly updated to reflect the latest changes.
    // Their source is atomic-data-browser's `publish` folder, after running `pmpm build`.
    resource_dir("./app_assets")
        .build()
        .expect("failed to build app_assets");

    Ok(())
}
