//! `POST /mcp`: Streamable HTTP transport, answering each JSON-RPC message
//! with one JSON response. No sessions and no server-initiated messages, which
//! the spec allows for a server that only answers requests.

use actix_web::{http::StatusCode, web, HttpRequest, HttpResponse};
use serde_json::{json, Value};

use super::{
    tokens::{self, Grant},
    tools,
};
use crate::appstate::AppState;

const SUPPORTED: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

fn unauthorized(origin: &str, why: &str) -> HttpResponse {
    HttpResponse::Unauthorized()
        .insert_header((
            "WWW-Authenticate",
            format!("Bearer resource_metadata=\"{origin}/.well-known/oauth-protected-resource\""),
        ))
        .json(json!({"error": "unauthorized", "error_description": why}))
}

fn rpc_error(id: &Value, code: i64, message: &str) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message}
    }))
}

pub async fn mcp(
    appstate: web::Data<AppState>,
    body: web::Bytes,
    req: HttpRequest,
) -> HttpResponse {
    let origin = crate::context::RequestContext::new(&req, &appstate).origin;

    let bearer = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let Some(bearer) = bearer else {
        return unauthorized(&origin, "Send a bearer token");
    };
    let grant: Grant = match tokens::verify(&appstate, tokens::ACCESS, bearer) {
        Ok(g) => g,
        Err(e) => return unauthorized(&origin, &e),
    };

    let message: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return rpc_error(&Value::Null, -32700, "Parse error"),
    };
    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");

    // Notifications and responses carry no id and get no answer.
    let Some(id) = id else {
        return HttpResponse::Accepted().finish();
    };

    match method {
        "initialize" => {
            let asked = message
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("");
            let version = SUPPORTED
                .iter()
                .find(|v| **v == asked)
                .unwrap_or(&SUPPORTED[0]);

            HttpResponse::Ok().json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "atomic", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": tools::instructions(grant.write),
                }
            }))
        }
        "ping" => HttpResponse::Ok().json(json!({"jsonrpc": "2.0", "id": id, "result": {}})),
        "tools/list" => HttpResponse::Ok().json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {"tools": tools::list(grant.write)}
        })),
        "tools/call" => {
            let name = message
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let args = message
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let (text, is_error) =
                match tools::call(&appstate, &origin, &req, &grant, name, &args).await {
                    Ok(value) => (
                        serde_json::to_string_pretty(&value).unwrap_or_default(),
                        false,
                    ),
                    Err(e) => (format!("Error: {e}"), true),
                };

            HttpResponse::Ok().json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"content": [{"type": "text", "text": text}], "isError": is_error}
            }))
        }
        _ => rpc_error(&id, -32601, "Method not found"),
    }
}

/// A client may open a GET stream for server messages; there are none.
pub async fn mcp_get() -> HttpResponse {
    HttpResponse::build(StatusCode::METHOD_NOT_ALLOWED)
        .insert_header(("Allow", "POST"))
        .finish()
}
