//! Contains routing logic, sends the client to the correct handler.
//! We should try to minimize what happens in here, since most logic should be defined in Atomic Data - not in the server itself.

use actix_web::{http::Method, web};

use crate::{config::Config, content_types, handlers};

/// Should match all routes
const ANY: &str = "{tail:.*}";

/// Set up the Actix server routes. This defines which paths are used.
// Keep in mind that the order of these matters. An early, greedy route will take
// precedence over a later route.
pub fn config_routes(app: &mut actix_web::web::ServiceConfig, config: &Config) {
    app.service(web::resource("/ws").to(handlers::web_sockets::web_socket_handler))
        .service(web::resource("/download/{path:[^{}]+}").to(handlers::download::handle_download))
        // Catch all (non-download) HTML requests and send them to the single page app
        .service(
            web::resource(ANY)
                .guard(actix_web::guard::Method(Method::GET))
                .guard(actix_web::guard::fn_guard(|guard_ctx| {
                    content_types::get_accept(guard_ctx.head().headers())
                        == content_types::ContentType::Html
                }))
                .to(handlers::single_page_app::single_page),
        )
        .service(
            web::resource("/upload")
                .guard(actix_web::guard::Method(Method::POST))
                .to(handlers::upload::upload_handler),
        )
        .service(web::resource("/tpf").to(handlers::tpf::tpf))
        .service(
            web::resource("/commit")
                .guard(actix_web::guard::Method(Method::POST))
                .to(handlers::commit::post_commit),
        )
        .service(
            web::resource("/search")
                .guard(actix_web::guard::Method(Method::GET))
                .to(handlers::search::search_query),
        );
    if config.opts.rdf_search {
        app.service(
            web::resource("/search")
                .guard(actix_web::guard::Method(Method::POST))
                .to(handlers::search::search_index_rdf),
        );
    }
    app.service(web::resource(ANY).to(handlers::resource::handle_get_resource))
        // Also allow the home resource (not matched by the previous one)
        .service(web::resource("/").to(handlers::resource::handle_get_resource));
}
