//! Contains routing logic, sends the client to the correct handler.
//! We should try to minimize what happens in here, since most logic should be defined in Atomic Data - not in the server itself.

use crate::{content_types, handlers};
use actix_web::{guard, http::Method, web};
use actix_web_static_files::ResourceFiles;

/// Should match all routes
const ANY: &str = "{tail:.*}";

// Includes the js assets from the `browser` folder,
// used for hosting the front-end JS bundles, service workers,
// css, icons and other static files.
// See build.rs for more info.
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// Set up the Actix server routes. This defines which paths are used.
// Keep in mind that the order of these matters. An early, greedy route will take
// precedence over a later route.
pub fn config_routes(app: &mut actix_web::web::ServiceConfig) {
    app.service(web::resource("/ws").to(handlers::web_sockets::web_socket_handler))
        .service(web::resource("/download/{path:[^{}]+}").to(handlers::download::handle_download))
        .service(web::resource("/export").to(handlers::export::handle_export))
        // This `generate` imports the static files from the `app_assets` folder
        .service(
            ResourceFiles::new("/", generate())
                .skip_handler_when_not_found()
                .do_not_resolve_defaults(),
        )
        // Catch all (non-download) HTML requests and send them to the single page app
        .service(
            web::resource(ANY)
                .guard(guard::Method(Method::GET))
                .guard(guard::fn_guard(|guard_ctx| {
                    content_types::get_accept(guard_ctx.head().headers())
                        == content_types::ContentType::Html
                }))
                .to(handlers::single_page_app::single_page),
        )
        .service(
            web::resource("/upload")
                .guard(guard::Method(Method::POST))
                .to(handlers::upload::upload_handler),
        )
        .service(
            web::resource("/commit")
                .guard(guard::Method(Method::POST))
                .to(handlers::commit::post_commit),
        )
        .service(
            web::resource("/search")
                .guard(guard::Method(Method::GET))
                .to(handlers::search::search_query),
        )
        .service(
            web::resource(ANY)
                .guard(guard::Method(Method::GET))
                .to(handlers::get_resource::handle_get_resource),
        )
        .service(
            web::resource(ANY)
                .guard(guard::Method(Method::POST))
                .to(handlers::post_resource::handle_post_resource),
        )
        // Also allow the home resource (not matched by the previous one)
        .service(web::resource("/").to(handlers::get_resource::handle_get_resource));
}
