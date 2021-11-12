use actix_web::{http::Method, web};

use crate::{config::Config, content_types, handlers};

/// Set up the Actix server routes. This defines which paths are used.
// Keep in mind that the order of these matters. An early, greedy route will take
// precedence over a later route.
pub fn config_routes(app: &mut actix_web::web::ServiceConfig, config: &Config) {
    app.service(web::resource("/ws").to(handlers::web_sockets::web_socket_handler))
        // Catch all HTML requests and send them to the single page app
        .service(
            web::resource("/*")
                .guard(actix_web::guard::Method(Method::GET))
                .guard(actix_web::guard::fn_guard(|head| {
                    content_types::get_accept(head.headers()) == content_types::ContentType::Html
                }))
                .to(handlers::single_page_app::single_page),
        )
        .service(
            web::scope("/tpf").service(web::resource("").route(web::get().to(handlers::tpf::tpf))),
        )
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
    app.service(
        web::scope("/{path:[^{}]+}")
            .service(web::resource("").route(web::get().to(handlers::resource::get_resource))),
    )
    // Also allow the home resource (not matched by the previous one)
    .service(web::resource("/").to(handlers::resource::get_resource));
}
