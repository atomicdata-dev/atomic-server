use actix_web::{http::Method, web};

use crate::{content_types, handlers};

pub fn config_routes(app: &mut actix_web::web::ServiceConfig) {
    app
        // Catch all HTML requests and send them to the single page app
        .service(
            web::resource("/*")
                .guard(actix_web::guard::Method(Method::GET))
                .guard(actix_web::guard::fn_guard(|head| {
                    content_types::get_accept(&head.headers()) == content_types::ContentType::HTML
                }))
                .to(handlers::single_page_app::single_page),
        )
        .service(actix_files::Files::new("/static", "static/").show_files_listing())
        .service(actix_files::Files::new("/.well-known", "static/well-known/").show_files_listing())
        .service(
            web::scope("/tpf").service(web::resource("").route(web::get().to(handlers::tpf::tpf))),
        )
        .service(
            web::scope("/commit")
                .service(web::resource("").route(web::post().to(handlers::commit::post_commit))),
        )
        .service(
            web::scope("/validate")
                .service(web::resource("").route(web::get().to(handlers::validate::validate))),
        )
        .service(
            web::scope("/{path:[^{}]+}")
                .service(web::resource("").route(web::get().to(handlers::resource::get_resource))),
        );
}
