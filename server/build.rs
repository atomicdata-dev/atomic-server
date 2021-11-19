use clap::IntoApp;
use clap_generate::{generate_to, generators};

include!("src/cli.rs");

fn main() -> Result<(), std::io::Error> {
    let outdir = match std::env::var_os("OUT_DIR") {
        None => return Ok(()),
        Some(outdir) => outdir,
    };
    let mut app = crate::Opts::into_app();
    let path = generate_to(generators::Bash, &mut app, "atomic-server", &outdir)?;
    let path = generate_to(generators::Fish, &mut app, "atomic-server", &outdir)?;
    println!("cargo:warning=completion file is generated: {:?}", path);
    Ok(())
}
