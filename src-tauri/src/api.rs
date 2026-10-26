//! Локальный HTTP API для расширения Chrome (127.0.0.1, по умолчанию порт 2082).
//!
//! GET  /api/ping        — без токена: проверить, что приложение запущено
//! GET  /api/status      — состояние подключения
//! GET  /api/servers     — подписки и серверы
//! POST /api/connect     — {"server": "<id или auto:<sub>>"} (необязательно)
//! POST /api/disconnect
//! POST /api/select      — {"server": "..."}
//!
//! Все запросы, кроме ping, требуют заголовок `X-Tunnelka-Token`.
//! Запросы со страниц сайтов (Origin не chrome-extension://) отклоняются.

use std::io::Read;
use std::sync::Arc;

use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server};

use crate::engine::Engine;

pub fn spawn(engine: Arc<Engine>) {
    let port = engine.settings().api_port;
    std::thread::spawn(move || {
        let server = match Server::http(("127.0.0.1", port)) {
            Ok(s) => s,
            Err(e) => {
                engine.log(format!("[api] не удалось открыть порт {port}: {e}"));
                return;
            }
        };
        engine.log(format!("[api] API для расширения: http://127.0.0.1:{port}"));
        for req in server.incoming_requests() {
            let engine = engine.clone();
            std::thread::spawn(move || handle(engine, req));
        }
    });
}

fn header(req: &Request, name: &str) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str().to_string())
}

fn reply(req: Request, code: u16, body: Value) {
    let resp = Response::from_string(body.to_string())
        .with_status_code(code)
        .with_header(Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap());
    let _ = req.respond(resp);
}

fn handle(engine: Arc<Engine>, mut req: Request) {
    let path = req.url().split('?').next().unwrap_or("").to_string();
    let method = req.method().clone();

    if let Some(origin) = header(&req, "Origin") {
        if !origin.starts_with("chrome-extension://") && !origin.starts_with("moz-extension://")
        {
            return reply(req, 403, json!({"error": "forbidden origin"}));
        }
    }
    if path == "/api/ping" {
        return reply(
            req,
            200,
            json!({"app": "tunnelka", "version": env!("CARGO_PKG_VERSION")}),
        );
    }
    let token = engine.settings().api_token;
    if header(&req, "X-Tunnelka-Token").as_deref() != Some(token.as_str()) {
        return reply(req, 401, json!({"error": "неверный токен — скопируйте его в настройках приложения"}));
    }

    let mut body = String::new();
    let _ = req.as_reader().take(64 * 1024).read_to_string(&mut body);
    let arg: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let server_arg = arg.get("server").and_then(|v| v.as_str()).map(|s| s.to_string());

    let result: Result<Value, String> = match (method, path.as_str()) {
        (Method::Get, "/api/status") => Ok(status_json(&engine)),
        (Method::Get, "/api/servers") => Ok(servers_json(&engine)),
        (Method::Post, "/api/connect") => tauri::async_runtime::block_on(async {
            if let Some(s) = &server_arg {
                engine.select(s).await?;
            }
            if !engine.is_running() {
                engine.connect().await?;
            }
            Ok(status_json(&engine))
        }),
        (Method::Post, "/api/disconnect") => {
            engine.disconnect();
            Ok(status_json(&engine))
        }
        (Method::Post, "/api/select") => match server_arg {
            Some(s) => tauri::async_runtime::block_on(engine.select(&s)).map(|_| status_json(&engine)),
            None => Err("не указан server".into()),
        },
        _ => return reply(req, 404, json!({"error": "not found"})),
    };
    match result {
        Ok(v) => reply(req, 200, v),
        Err(e) => reply(req, 400, json!({"error": e})),
    }
}

fn status_json(engine: &Engine) -> Value {
    serde_json::to_value(engine.status()).unwrap_or(Value::Null)
}

fn servers_json(engine: &Engine) -> Value {
    let st = engine.snapshot();
    let subs: Vec<Value> = st
        .subscriptions
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "name": s.name,
                "servers": s.servers.iter().filter(|x| x.usable()).map(|x| json!({
                    "id": x.id, "name": x.name, "protocol": x.protocol
                })).collect::<Vec<_>>()
            })
        })
        .collect();
    json!({"selected": st.selected, "subscriptions": subs})
}
