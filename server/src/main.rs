mod appstate;
mod config;
mod content_types;
mod errors;
mod handlers;
mod helpers;
mod https;
mod jsonerrors;
mod routes;
#[cfg(feature = "desktop")]
mod tray_icon;

use actix_cors::Cors;
use actix_web::{middleware, web, App, HttpServer};
use atomic_lib::{errors::AtomicResult, Storelike};
use clap::{crate_version, AppSettings, Arg, SubCommand};
use std::{fs::File, sync::Mutex};

#[actix_rt::main]
async fn main() -> AtomicResult<()> {
    let matches = clap::App::new("atomic-server")
        .version(crate_version!())
        .author("Joep Meindertsma <joep@ontola.io>")
        .about("Store and share Atomic Data!")
        .after_help("Visit https://atomicdata.dev for more info")
        .setting(AppSettings::ArgRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("run")
                .about("Starts the server")
        )
        .subcommand(
            SubCommand::with_name("export")
                .about("Create a JSON-AD backup of the store.")
                .arg(Arg::with_name("path")
                    .help("Where the file should be saved. Defaults to `~/.config/atomic/backups/{current_date}.jsonld`.")
                    .required(false)
                )
        )
        .subcommand(
            SubCommand::with_name("import")
                .about("Import a JSON-AD backup to the store. Overwrites Resources with same @id.")
                .arg(Arg::with_name("path")
                    .help("where the file should be imported from")
                    .required(true)
                )
        )
        .get_matches();

    // Enable all logging
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    const VERSION: &str = env!("CARGO_PKG_VERSION");
    log::info!("Atomic-server {}. Visit https://atomicdata.dev and https://github.com/joepio/atomic for more information.", VERSION);

    // Read .env vars, https certs
    let config = config::init().expect("Error setting config");
    // Initialize DB and HTML templating engine
    let appstate = match appstate::init(config.clone()) {
        Ok(state) => state,
        Err(e) => {
            panic!("Error during appstate setup. {}", e)
        }
    };

    match matches.subcommand_name() {
        Some("export") => {
            let path = match matches.subcommand_matches("export").unwrap().value_of("path") {
                Some(p) => std::path::Path::new(p).to_path_buf(),
                None => {
                    let date = chrono::Local::now().to_rfc3339();
                    let pathstr = format!("backups/{}.jsonld", date);
                    let mut pt = config.config_dir;
                    pt.push(&pathstr);
                    pt
                },
            };
            let outstr = appstate.store.export(true)?;
            std::fs::create_dir_all(path.parent().unwrap())
                .map_err(|e| format!("Failed to create directory {:?}. {}", path, e))?;
            let mut file = File::create(&path).map_err(|e| format!("Failed to write file to {:?}. {}", path, e))?;
            use std::io::Write;
            write!(file, "{}", outstr)?;
            println!("Succesfully exported data to {}", path.to_str().unwrap());
            std::process::exit(0);
        }
        Some("import") => {
            let pathstr = matches.subcommand_matches("import").unwrap().value_of("path").unwrap();
            let path = std::path::Path::new(pathstr);
            let readstring = std::fs::read_to_string(path)?;

            appstate.store.import(&readstring)?;

            println!("Sucesfully imported {} to store.", pathstr);
            std::process::exit(0);
        }
        Some("run") => {
            // todo!();
        }
        Some(unkown) => {
            panic!(format!("Unkown command: {}", unkown));
        }
        None => println!("Run atomic-server --help for available commands"),
    };

    let server = HttpServer::new(move || {
        let data = web::Data::new(Mutex::new(appstate.clone()));
        // Allow requests from other domains
        let cors = Cors::permissive();

        App::new()
            .app_data(data)
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .configure(routes::config_routes)
            .app_data(
                web::JsonConfig::default()
                    // register error_handler for JSON extractors.
                    .error_handler(jsonerrors::json_error_handler),
            )
    });

    #[cfg(feature = "desktop")]
    tray_icon::tray_icon_process(config.clone());

    if config.https {
        // If there is no certificate file, or the certs are too old, start HTTPS initialization
        if std::fs::File::open(&config.cert_path).is_err() || crate::https::check_expiration_certs()
        {
            https::cert_init_server(&config).await.unwrap();
        }
        let https_config = crate::https::get_https_config(&config)
            .expect("HTTPS TLS Configuration with Let's Encrypt failed.");
        let endpoint = format!("{}:{}", config.ip, config.port_https);
        server
            .bind_rustls(&endpoint, https_config)
            .expect(&*format!("Cannot bind to endpoint {}", &endpoint))
            .run()
            .await?;
        Ok(())
    } else {
        let endpoint = format!("{}:{}", config.ip, config.port);
        server
            .bind(&format!("{}:{}", config.ip, config.port))
            .expect(&*format!("Cannot bind to endpoint {}", &endpoint))
            .run()
            .await?;
        Ok(())
    }
}
