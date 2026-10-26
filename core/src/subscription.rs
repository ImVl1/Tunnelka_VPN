//! Загрузка и разбор подписок: base64/текстовые списки ссылок и JSON sing-box,
//! заголовки profile-title, subscription-userinfo, profile-update-interval и т.п.

use std::collections::HashSet;
use std::time::Duration;

use serde_json::Value;

use crate::links::{b64_decode_str, link_to_server, server_id};
use crate::model::{Server, SubInfo};

/// Результат загрузки подписки.
#[derive(Debug, Clone, Default)]
pub struct Fetched {
    pub title: Option<String>,
    pub info: Option<SubInfo>,
    pub update_interval_h: Option<u32>,
    pub support_url: Option<String>,
    pub web_page_url: Option<String>,
    pub announce: Option<String>,
    pub servers: Vec<Server>,
}

/// Значения заголовков вида `base64:...` декодируются.
fn header_text(v: &str) -> String {
    let v = v.trim();
    match v.strip_prefix("base64:") {
        Some(b) => b64_decode_str(b).unwrap_or_else(|| v.to_string()),
        None => v.to_string(),
    }
}

pub fn parse_userinfo(v: &str) -> SubInfo {
    let mut info = SubInfo::default();
    for part in v.split(';') {
        if let Some((k, val)) = part.split_once('=') {
            let n = val.trim().parse::<f64>().unwrap_or(0.0).max(0.0) as u64;
            match k.trim() {
                "upload" => info.upload = n,
                "download" => info.download = n,
                "total" => info.total = n,
                "expire" => info.expire = n,
                _ => {}
            }
        }
    }
    info
}

/// Применяет заголовок ответа (или строку `#key: value` из тела).
fn apply_header(f: &mut Fetched, key: &str, value: &str) {
    match key.to_ascii_lowercase().as_str() {
        "profile-title" => f.title = Some(header_text(value)).filter(|s| !s.is_empty()),
        "subscription-userinfo" => f.info = Some(parse_userinfo(value)),
        "profile-update-interval" => {
            f.update_interval_h = value.trim().parse::<u32>().ok().filter(|h| *h > 0)
        }
        "support-url" => f.support_url = Some(value.trim().to_string()),
        "profile-web-page-url" => f.web_page_url = Some(value.trim().to_string()),
        "announce" => f.announce = Some(header_text(value)).filter(|s| !s.is_empty()),
        "content-disposition" => {
            if f.title.is_none() {
                if let Some(name) = value.split("filename=").nth(1) {
                    let name = name.trim_matches(|c| c == '"' || c == '\'' || c == ' ');
                    if !name.is_empty() {
                        f.title = Some(name.to_string());
                    }
                }
            }
        }
        _ => {}
    }
}

/// Разбирает тело подписки. `seed` делает id серверов уникальными в пределах подписки.
pub fn parse_body(body: &str, seed: &str) -> Fetched {
    let mut f = Fetched::default();
    parse_body_into(&mut f, body, seed);
    f
}

fn parse_body_into(f: &mut Fetched, body: &str, seed: &str) {
    let body = body.trim_start_matches('\u{feff}').trim();

    // JSON: конфиг sing-box (UA sing-box/Hiddify) или конфиги Xray (UA Happ/v2RayTun).
    if body.starts_with('{') || body.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<Value>(body) {
            f.servers = servers_from_xray_json(&v, seed);
            if f.servers.is_empty() {
                f.servers = servers_from_singbox_json(&v, seed);
            }
            return;
        }
    }

    let text = if body.contains("://") {
        body.to_string()
    } else {
        b64_decode_str(body).unwrap_or_default()
    };

    let mut seen = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(meta) = line.strip_prefix('#') {
            if let Some((k, v)) = meta.split_once(':') {
                apply_header(f, k.trim(), v);
            }
            continue;
        }
        if !seen.insert(line.to_string()) {
            continue;
        }
        if let Some(s) = link_to_server(line, seed) {
            f.servers.push(s);
        }
    }
}

const SUPPORTED: &[&str] = &[
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "hysteria2",
    "tuic",
    "socks",
    "http",
];

fn servers_from_xray_json(v: &Value, seed: &str) -> Vec<Server> {
    let configs: Vec<&Value> = match v {
        Value::Array(a) => a.iter().collect(),
        Value::Object(_) => vec![v],
        _ => vec![],
    };
    let mut out = vec![];
    let mut seen = HashSet::new();
    for cfg in configs {
        // У Xray outbound'ы описаны полем "protocol", у sing-box — "type".
        let Some((name, ob)) = crate::xray::outbound_from_config(cfg) else {
            continue;
        };
        let key = ob.to_string();
        if !seen.insert(key.clone()) {
            continue;
        }
        let (address, port) = crate::xray::outbound_endpoint(&ob);
        out.push(Server {
            id: server_id(&format!("{seed}|xray|{key}")),
            name,
            link: String::new(),
            protocol: ob["protocol"].as_str().unwrap_or("xray").to_string(),
            address,
            port,
            transport: crate::xray::outbound_label(&ob),
            outbound: None,
            xray: Some(ob),
            error: None,
        });
    }
    out
}

fn servers_from_singbox_json(v: &Value, seed: &str) -> Vec<Server> {
    let mut out = vec![];
    let Some(list) = v.get("outbounds").and_then(|o| o.as_array()) else {
        return out;
    };
    for ob in list {
        let Some(kind) = ob.get("type").and_then(|t| t.as_str()) else {
            continue;
        };
        if !SUPPORTED.contains(&kind) || ob.get("server").is_none() {
            continue;
        }
        let mut outbound = ob.clone();
        let name = outbound
            .as_object_mut()
            .and_then(|o| o.remove("tag"))
            .and_then(|t| t.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| kind.to_string());
        if let Some(o) = outbound.as_object_mut() {
            // Эти поля зависят от чужого конфига (детуры, резолверы) — убираем.
            for k in ["detour", "domain_resolver", "domain_strategy", "bind_interface"] {
                o.remove(k);
            }
        }
        let address = ob["server"].as_str().unwrap_or("").to_string();
        let transport = ob
            .get("transport")
            .and_then(|t| t.get("type"))
            .and_then(|t| t.as_str())
            .unwrap_or("tcp")
            .to_string();
        let port = ob["server_port"].as_u64().unwrap_or(0) as u16;
        out.push(Server {
            id: server_id(&format!("{seed}|json|{}", outbound)),
            name,
            link: String::new(),
            protocol: kind.to_string(),
            address,
            port,
            transport,
            outbound: Some(outbound),
            xray: None,
            error: None,
        });
    }
    out
}

/// Скачивает подписку. `via_proxy` — запасной путь через локальный прокси
/// (если прямой доступ к панели заблокирован, а VPN уже подключён).
pub async fn fetch(
    url: &str,
    user_agent: &str,
    seed: &str,
    via_proxy: Option<&str>,
) -> Result<Fetched, String> {
    let mut builder = reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(Duration::from_secs(25))
        .connect_timeout(Duration::from_secs(10));
    if let Some(p) = via_proxy {
        builder = builder.proxy(reqwest::Proxy::all(p).map_err(|e| e.to_string())?);
    } else {
        builder = builder.no_proxy();
    }
    let client = builder.build().map_err(|e| e.to_string())?;
    let resp = client
        .get(url)
        .header("Accept", "*/*")
        .send()
        .await
        .map_err(|e| format!("не удалось загрузить подписку: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("сервер подписки ответил {}", resp.status()));
    }
    let mut f = Fetched::default();
    for (k, v) in resp.headers() {
        if let Ok(v) = v.to_str() {
            apply_header(&mut f, k.as_str(), v);
        }
    }
    let body = resp.text().await.map_err(|e| e.to_string())?;
    parse_body_into(&mut f, &body, seed);
    if f.servers.is_empty() {
        return Err("в подписке не найдено ни одного сервера".into());
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn base64_list_with_meta() {
        let raw = "#profile-title: base64:0JzQvtC5INCS0J/QnQ==\nvless://u@a.com:443?security=tls#A\nvless://u@a.com:443?security=tls#A\ntrojan://p@b.com:443#B\n";
        let body = base64::engine::general_purpose::STANDARD.encode(raw);
        let f = parse_body(&body, "x");
        assert_eq!(f.servers.len(), 2, "дубликаты должны отбрасываться");
        assert_eq!(f.title.as_deref(), Some("Мой ВПН"));
    }

    #[test]
    fn userinfo() {
        let i = parse_userinfo("upload=100; download=200; total=1073741824; expire=1767225600");
        assert_eq!(i.download, 200);
        assert_eq!(i.total, 1073741824);
        assert_eq!(i.expire, 1767225600);
    }

    #[test]
    fn singbox_json() {
        let body = r#"{"outbounds":[{"type":"selector","tag":"proxy","outbounds":["a"]},{"type":"vless","tag":"🇩🇪 DE","server":"de.example.com","server_port":443,"uuid":"u","detour":"x"},{"type":"direct","tag":"direct"}]}"#;
        let f = parse_body(body, "x");
        assert_eq!(f.servers.len(), 1);
        assert_eq!(f.servers[0].name, "🇩🇪 DE");
        let ob = f.servers[0].outbound.as_ref().unwrap();
        assert!(ob.get("tag").is_none() && ob.get("detour").is_none());
    }

    #[test]
    fn xray_json_array() {
        let body = r#"[{"remarks":"NL xhttp","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"address":"nl.example.com","port":443,"id":"u","encryption":"none"},"streamSettings":{"network":"xhttp","security":"reality"}},{"tag":"direct","protocol":"freedom"}]},
                       {"remarks":"DE tcp","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"de.example.com","port":8443,"users":[{"id":"u"}]}]},"streamSettings":{"network":"tcp","security":"reality"}}]}]"#;
        let f = parse_body(body, "x");
        assert_eq!(f.servers.len(), 2);
        assert!(f.servers[0].needs_xray());
        assert_eq!(f.servers[0].transport, "xhttp · reality");
        assert_eq!(f.servers[1].port, 8443);
    }
}
