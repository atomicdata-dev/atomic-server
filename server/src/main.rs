mod actor_messages;
mod appstate;
mod commit_monitor;
mod config;
mod content_types;
mod errors;
mod handlers;
mod helpers;
mod https;
mod jsonerrors;
mod process;
mod routes;
#[cfg(feature = "desktop")]
mod tray_icon;

use actix::Actor;
use actix_cors::Cors;
use actix_web::{middleware, web, App, HttpServer};
use atomic_lib::{errors::AtomicResult, Storelike};
use clap::{crate_version, Arg, SubCommand};
use std::{fs::File, sync::Mutex};

#[actix_web::main]
async fn main() -> AtomicResult<()> {
    // We start off by checking the command line arguments and commands
    let matches = clap::App::new("atomic-server")
        .version(crate_version!())
        .author("Joep Meindertsma <joep@ontola.io>")
        .about("Store and share Atomic Data! Visit https://atomicdata.dev for more info. Pass no subcommands to launch the server.")
        .subcommand(
            SubCommand::with_name("export")
                .about("Create a JSON-AD backup of the store.")
                .arg(Arg::with_name("path")
                    .help("Where the file should be saved. Defaults to `~/.config/atomic/backups/{current_date}.json`.")
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
        .arg(
            Arg::with_name("reindex")
            .long("reindex")
            .short("r")
            .help("Rebuilds the index (can take a while for large stores).")
        )
        .arg(
            Arg::with_name("init")
            .long("init")
            .help("Recreates the `/setup` Invite for creating a new Root User. Also re-runs various populate commands, and re-builds the index.")
            .short("i")
        )
        .get_matches();

    // Enable all logging
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    const VERSION: &str = env!("CARGO_PKG_VERSION");
    log::info!("Atomic-server {}. Visit https://atomicdata.dev and https://github.com/joepio/atomic for more information.", VERSION);

    // Read .env vars, https certs
    let config = config::init(&matches).expect("Error setting config");

    // Check if atomic-server is already running somwehere, and try to stop it. It's not a problem if things go wrong here, so errors are simply logged.
    let _ = process::terminate_existing_processes(&config)
        .map_err(|e| log::error!("Could not check for running instance: {}", e));

    // The Appstate contains the actual database
    let appstate = match appstate::init(config.clone()) {
        Ok(state) => state,
        Err(e) => {
            panic!("Error during appstate setup. {}", e)
        }
    };

    // All subcommands (as of now) also require appstate, which is why we have this logic below initial CLI logic.
    match matches.subcommand_name() {
        Some("export") => {
            let path = match matches
                .subcommand_matches("export")
                .unwrap()
                .value_of("path")
            {
                Some(p) => std::path::Path::new(p).to_path_buf(),
                None => {
                    let date = chrono::Local::now().to_rfc3339();
                    let pathstr = format!("backups/{}.json", date);
                    let mut pt = config.config_dir;
                    pt.push(&pathstr);
                    pt
                }
            };
            let outstr = appstate.store.export(true)?;
            std::fs::create_dir_all(path.parent().unwrap())
                .map_err(|e| format!("Failed to create directory {:?}. {}", path, e))?;
            let mut file = File::create(&path)
                .map_err(|e| format!("Failed to write file to {:?}. {}", path, e))?;
            use std::io::Write;
            write!(file, "{}", outstr)?;
            println!("Succesfully exported data to {}", path.to_str().unwrap());
            std::process::exit(0);
        }
        Some("import") => {
            let pathstr = matches
                .subcommand_matches("import")
                .unwrap()
                .value_of("path")
                .unwrap();
            let path = std::path::Path::new(pathstr);
            let readstring = std::fs::read_to_string(path)?;

            appstate.store.import(&readstring)?;

            println!("Sucesfully imported {} to store.", pathstr);
            std::process::exit(0);
        }
        Some("run") => {
            // continue, start server
        }
        Some(unkown) => {
            panic!("Unkown command: {}", unkown);
        }
        None => {
            // Start server if no command is found
        }
    };

    // Start other async processes
    #[cfg(feature = "desktop")]
    tray_icon::tray_icon_process(config.clone());

    if config.rebuild_index {
        let appstate_clone = appstate.clone();

        actix_web::rt::spawn(async move {
            log::warn!("Building index... This could take a while, expect worse performance until 'Building index finished'");
            appstate_clone
                .store
                .clear_index()
                .expect("Failed to clear index");
            appstate_clone
                .store
                .build_index(true)
                .expect("Failed to build index");
            log::info!("Building index finished!");
        });
    }

    // We start the process responsible for keeping track of changes to Resources and notifying subscribers
    let commit_monitor = commit_monitor::CommitMonitor::default().start();
    // TODO: Remove this mock loop!
    {
        let appstate_clone = appstate.clone();
        let config_clone = config.clone();

        actix_web::rt::spawn(async move {
            let mut interval = actix_web::rt::time::interval(std::time::Duration::from_secs(1));
            loop {
                interval.tick().await;
                let mut demo_resource_drive = appstate_clone
                    .store
                    .get_resource(&config_clone.local_base_url)
                    .unwrap();
                demo_resource_drive
                    .set_propval(
                        atomic_lib::urls::NAME.to_string(),
                        atomic_lib::Value::String("NEW NAME".into()),
                        &appstate_clone.store,
                    )
                    .unwrap();
                let commit = demo_resource_drive
                    .get_commit_builder()
                    .clone()
                    .sign(
                        &appstate_clone.store.get_default_agent().unwrap(),
                        &appstate_clone.store,
                    )
                    .unwrap();

                commit_monitor.do_send(crate::actor_messages::CommitMessage { commit });
            }
        });
    }
    let server = HttpServer::new(move || {
        let data = web::Data::new(Mutex::new(appstate.clone()));
        // Allow requests from other domains
        // let cors = Cors::default().allow_any_origin();
        let cors = Cors::permissive();

        App::new()
            .app_data(data)
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .configure(routes::config_routes)
            .default_service(web::to(|| {
                log::error!("Wrong route, should not happen with normal requests");
                actix_web::HttpResponse::NotFound()
            }))
            .app_data(
                web::JsonConfig::default()
                    // register error_handler for JSON extractors.
                    .error_handler(jsonerrors::json_error_handler),
            )
    });

    let message = format!("{}\n\nVisit {}\n\n", BANNER, config.local_base_url);

    if config.https {
        // If there is no certificate file, or the certs are too old, start HTTPS initialization
        if std::fs::File::open(&config.cert_path).is_err() || crate::https::check_expiration_certs()
        {
            https::cert_init_server(&config).await.unwrap();
        }
        let https_config = crate::https::get_https_config(&config)
            .expect("HTTPS TLS Configuration with Let's Encrypt failed.");
        let endpoint = format!("{}:{}", config.ip, config.port_https);
        println!("{}", message);
        server
            .bind_rustls(&endpoint, https_config)
            .expect(&*format!("Cannot bind to endpoint {}", &endpoint))
            .run()
            .await?;
    } else {
        let endpoint = format!("{}:{}", config.ip, config.port);
        println!("{}", message);
        server
            .bind(&format!("{}:{}", config.ip, config.port))
            .expect(&*format!("Cannot bind to endpoint {}", &endpoint))
            .run()
            .await?;
    }
    process::remove_pid(&config)?;

    Ok(())
}

const BANNER: &str = r#"
         __                  _
  ____ _/ /_____  ____ ___  (_)____      ________  ______   _____  _____
 / __ `/ __/ __ \/ __ `__ \/ / ___/_____/ ___/ _ \/ ___/ | / / _ \/ ___/
/ /_/ / /_/ /_/ / / / / / / / /__/_____(__  )  __/ /   | |/ /  __/ /
\__,_/\__/\____/_/ /_/ /_/_/\___/     /____/\___/_/    |___/\___/_/
"#;
