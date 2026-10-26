//! Разбор ссылок vless:// vmess:// trojan:// ss:// hysteria2:// tuic:// socks:// http://
//! в outbound-объекты sing-box.

use std::collections::HashMap;

use base64::Engine;
use percent_encoding::percent_decode_str;
use serde_json::{json, Map, Value};

use crate::model::Server;

pub type Result<T> = std::result::Result<T, String>;

/// Результат разбора одной ссылки.
#[derive(Debug, Clone)]
pub struct Parsed {
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    /// `tcp · reality`, `ws · tls`, …
    pub transport: String,
    pub outbound: Value,
}

/// Подпись транспорта для интерфейса.
pub fn transport_label(net: &str, security: &str) -> String {
    let net = match net.to_ascii_lowercase().as_str() {
        "" | "raw" | "none" => "tcp".to_string(),
        "splithttp" => "xhttp".to_string(),
        "websocket" => "ws".to_string(),
        other => other.to_string(),
    };
    match security.to_ascii_lowercase().as_str() {
        "" | "none" => net,
        sec => format!("{net} · {sec}"),
    }
}

/// FNV-1a: стабильный хэш для идентификаторов серверов.
pub fn fnv1a(data: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in data.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

pub fn server_id(seed: &str) -> String {
    format!("s{:016x}", fnv1a(seed))
}

/// Превращает ссылку в `Server`. Неподдерживаемые ссылки тоже возвращаются —
/// с заполненным `error`, чтобы пользователь видел, что пришло в подписке.
pub fn link_to_server(link: &str, id_seed: &str) -> Option<Server> {
    let link = link.trim();
    if link.is_empty() || link.starts_with('#') || !link.contains("://") {
        return None;
    }
    let id = server_id(&format!("{id_seed}|{link}"));
    let sb = parse_link(link);
    let xr = crate::xray::parse_link(link);
    let (name, protocol, address, port, transport) = match (&sb, &xr) {
        (Ok(p), _) => (p.name.clone(), p.protocol.clone(), p.address.clone(), p.port, p.transport.clone()),
        (Err(_), Ok(x)) => (x.name.clone(), x.protocol.clone(), x.address.clone(), x.port, x.transport.clone()),
        (Err(e), Err(_)) => {
            let scheme = link.split("://").next().unwrap_or("").to_lowercase();
            let name = link
                .rsplit_once('#')
                .map(|(_, f)| decode(f))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| scheme.clone());
            return Some(Server {
                id,
                name,
                link: link.to_string(),
                protocol: scheme,
                address: String::new(),
                port: 0,
                transport: String::new(),
                outbound: None,
                xray: None,
                error: Some(e.clone()),
            });
        }
    };
    Some(Server {
        id,
        name,
        link: link.to_string(),
        protocol,
        address,
        port,
        transport,
        outbound: sb.ok().map(|p| p.outbound),
        xray: xr.ok().map(|x| x.outbound),
        error: None,
    })
}

pub fn parse_link(link: &str) -> Result<Parsed> {
    let (scheme, rest) = link
        .split_once("://")
        .ok_or_else(|| "не похоже на ссылку".to_string())?;
    match scheme.to_ascii_lowercase().as_str() {
        "vless" => parse_vless(rest),
        "vmess" => parse_vmess(rest),
        "trojan" => parse_trojan(rest),
        "ss" => parse_ss(rest),
        "hysteria2" | "hy2" => parse_hy2(rest),
        "tuic" => parse_tuic(rest),
        "socks" | "socks5" | "socks5h" => parse_socks(rest),
        "http" | "https" => parse_http(scheme, rest),
        "wireguard" | "wg" => Err("WireGuard пока не поддерживается".into()),
        "hysteria" => Err("Hysteria v1 не поддерживается, используйте Hysteria2".into()),
        other => Err(format!("протокол {other}:// не поддерживается")),
    }
}

// ---------------------------------------------------------------------------
// Общий разбор URI: userinfo@host:port?query#fragment
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub(crate) struct Uri {
    pub(crate) user: Option<String>,
    /// Пароль после `user:` (сырой, без декодирования).
    pub(crate) pass: Option<String>,
    pub(crate) host: String,
    /// Строка порта как есть: может быть `443`, `443,20000-30000`.
    pub(crate) port: String,
    pub(crate) params: HashMap<String, String>,
    pub(crate) fragment: String,
}

pub(crate) fn decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

pub(crate) fn split_uri(rest: &str) -> Result<Uri> {
    let mut u = Uri::default();
    let (rest, frag) = match rest.split_once('#') {
        Some((a, b)) => (a, b),
        None => (rest, ""),
    };
    u.fragment = decode(frag).trim().to_string();
    let (rest, query) = match rest.split_once('?') {
        Some((a, b)) => (a, b),
        None => (rest, ""),
    };
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        u.params.insert(decode(k).to_ascii_lowercase(), decode(v));
    }
    let rest = rest.trim_end_matches('/');
    let (userinfo, hostport) = match rest.rsplit_once('@') {
        Some((a, b)) => (Some(a), b),
        None => (None, rest),
    };
    if let Some(ui) = userinfo {
        match ui.split_once(':') {
            Some((a, b)) => {
                u.user = Some(a.to_string());
                u.pass = Some(b.to_string());
            }
            None => u.user = Some(ui.to_string()),
        }
    }
    // [ipv6]:port
    if let Some(stripped) = hostport.strip_prefix('[') {
        let (h, p) = stripped
            .split_once(']')
            .ok_or_else(|| "некорректный IPv6-адрес".to_string())?;
        u.host = h.to_string();
        u.port = p.trim_start_matches(':').to_string();
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => {
                u.host = h.to_string();
                u.port = p.to_string();
            }
            None => u.host = hostport.to_string(),
        }
    }
    if u.host.is_empty() {
        return Err("не указан адрес сервера".into());
    }
    Ok(u)
}

impl Uri {
    pub(crate) fn p(&self, key: &str) -> Option<&str> {
        self.params
            .get(key)
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty())
    }

    pub(crate) fn flag(&self, keys: &[&str]) -> bool {
        keys.iter()
            .any(|k| matches!(self.p(k), Some("1") | Some("true") | Some("True")))
    }

    pub(crate) fn port_u16(&self, default: u16) -> Result<u16> {
        if self.port.is_empty() {
            return Ok(default);
        }
        let first = self
            .port
            .split([',', '-'])
            .next()
            .unwrap_or_default();
        first
            .parse::<u16>()
            .map_err(|_| format!("некорректный порт «{}»", self.port))
    }

    pub(crate) fn name_or(&self, fallback: &str) -> String {
        if self.fragment.is_empty() {
            fallback.to_string()
        } else {
            self.fragment.clone()
        }
    }
}

pub(crate) fn is_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

pub(crate) fn csv(s: &str) -> Vec<Value> {
    s.split(',')
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .map(|x| Value::String(x.to_string()))
        .collect()
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let trimmed = clean.trim_end_matches('=');
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    STANDARD_NO_PAD
        .decode(trimmed)
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .ok()
}

pub fn b64_decode_str(s: &str) -> Option<String> {
    b64_decode(s).and_then(|b| String::from_utf8(b).ok())
}

// ---------------------------------------------------------------------------
// TLS / REALITY / транспорт
// ---------------------------------------------------------------------------

fn tls_object(u: &Uri, security: &str, default_alpn: Option<&[&str]>) -> Option<Value> {
    match security {
        "tls" | "xtls" | "reality" => {}
        _ => return None,
    }
    let mut tls = Map::new();
    tls.insert("enabled".into(), json!(true));
    let sni = u
        .p("sni")
        .or_else(|| u.p("peer"))
        .or_else(|| u.p("servername"))
        .map(|s| s.to_string())
        .or_else(|| u.p("host").map(|h| h.split(',').next().unwrap_or(h).to_string()))
        .or_else(|| (!is_ip(&u.host)).then(|| u.host.clone()));
    if let Some(sni) = sni {
        tls.insert("server_name".into(), json!(sni));
    }
    if u.flag(&["allowinsecure", "insecure", "allow_insecure", "skip-cert-verify"]) {
        tls.insert("insecure".into(), json!(true));
    }
    if let Some(alpn) = u.p("alpn") {
        tls.insert("alpn".into(), Value::Array(csv(alpn)));
    } else if let Some(def) = default_alpn {
        tls.insert("alpn".into(), json!(def));
    }
    let fp = u.p("fp").or_else(|| u.p("fingerprint"));
    let reality = security == "reality";
    if fp.is_some() || reality {
        let fp = match fp.unwrap_or("chrome") {
            // sing-box не знает "random"/"randomized" в каждом билде — берём chrome.
            "random" | "randomized" | "none" => "chrome",
            other => other,
        };
        tls.insert(
            "utls".into(),
            json!({"enabled": true, "fingerprint": fp}),
        );
    }
    if reality {
        let mut r = Map::new();
        r.insert("enabled".into(), json!(true));
        if let Some(pbk) = u.p("pbk").or_else(|| u.p("publickey")) {
            r.insert("public_key".into(), json!(pbk));
        }
        if let Some(sid) = u.p("sid").or_else(|| u.p("shortid")) {
            r.insert("short_id".into(), json!(sid));
        }
        tls.insert("reality".into(), Value::Object(r));
    }
    Some(Value::Object(tls))
}

fn transport_object(
    net: &str,
    path: Option<&str>,
    host: Option<&str>,
    header_type: Option<&str>,
    service_name: Option<&str>,
) -> Result<Option<Value>> {
    match net {
        "" | "tcp" | "raw" | "none" => {
            if header_type == Some("http") {
                let mut t = Map::new();
                t.insert("type".into(), json!("http"));
                if let Some(h) = host {
                    t.insert("host".into(), Value::Array(csv(h)));
                }
                if let Some(p) = path {
                    t.insert("path".into(), json!(p.split(',').next().unwrap_or("/")));
                }
                t.insert("method".into(), json!("GET"));
                Ok(Some(Value::Object(t)))
            } else {
                Ok(None)
            }
        }
        "ws" | "websocket" => {
            let mut t = Map::new();
            t.insert("type".into(), json!("ws"));
            let mut path = path.unwrap_or("/").to_string();
            // ?ed=2048 — early data
            if let Some((p, q)) = path.clone().split_once('?') {
                let mut kept = vec![];
                for kv in q.split('&') {
                    if let Some(v) = kv.strip_prefix("ed=") {
                        if let Ok(n) = v.parse::<u32>() {
                            t.insert("max_early_data".into(), json!(n));
                            t.insert(
                                "early_data_header_name".into(),
                                json!("Sec-WebSocket-Protocol"),
                            );
                            continue;
                        }
                    }
                    kept.push(kv);
                }
                path = if kept.is_empty() {
                    p.to_string()
                } else {
                    format!("{p}?{}", kept.join("&"))
                };
            }
            t.insert("path".into(), json!(path));
            if let Some(h) = host {
                t.insert("headers".into(), json!({ "Host": h }));
            }
            Ok(Some(Value::Object(t)))
        }
        "grpc" | "gun" => {
            let mut t = Map::new();
            t.insert("type".into(), json!("grpc"));
            t.insert(
                "service_name".into(),
                json!(service_name.or(path).unwrap_or("")),
            );
            Ok(Some(Value::Object(t)))
        }
        "http" | "h2" => {
            let mut t = Map::new();
            t.insert("type".into(), json!("http"));
            if let Some(h) = host {
                t.insert("host".into(), Value::Array(csv(h)));
            }
            t.insert("path".into(), json!(path.unwrap_or("/")));
            Ok(Some(Value::Object(t)))
        }
        "httpupgrade" => {
            let mut t = Map::new();
            t.insert("type".into(), json!("httpupgrade"));
            if let Some(h) = host {
                t.insert("host".into(), json!(h));
            }
            t.insert("path".into(), json!(path.unwrap_or("/")));
            Ok(Some(Value::Object(t)))
        }
        "xhttp" | "splithttp" => {
            Err("транспорт XHTTP не поддерживается ядром sing-box".into())
        }
        "kcp" | "mkcp" | "quic" => Err(format!("транспорт {net} не поддерживается")),
        other => Err(format!("неизвестный транспорт «{other}»")),
    }
}

fn base(kind: &str, u: &Uri, port: u16) -> Map<String, Value> {
    let mut o = Map::new();
    o.insert("type".into(), json!(kind));
    o.insert("server".into(), json!(u.host));
    o.insert("server_port".into(), json!(port));
    o
}

fn finish(o: Map<String, Value>, u: &Uri, protocol: &str, port: u16) -> Parsed {
    let net = match o.get("transport").and_then(|t| t.get("type")).and_then(|t| t.as_str()) {
        Some(t) => t.to_string(),
        None if matches!(protocol, "hysteria2" | "tuic") => "udp".to_string(),
        None => "tcp".to_string(),
    };
    let sec = match o.get("tls") {
        Some(t) if t.get("reality").is_some() => "reality",
        Some(_) if !matches!(protocol, "hysteria2" | "tuic") => "tls",
        _ => "",
    };
    Parsed {
        transport: transport_label(&net, sec),
        name: u.name_or(&format!("{}:{}", u.host, port)),
        protocol: protocol.to_string(),
        address: u.host.clone(),
        port,
        outbound: Value::Object(o),
    }
}

// ---------------------------------------------------------------------------
// Протоколы
// ---------------------------------------------------------------------------

fn parse_vless(rest: &str) -> Result<Parsed> {
    let u = split_uri(rest)?;
    let port = u.port_u16(443)?;
    let uuid = decode(u.user.as_deref().ok_or("в ссылке нет UUID")?);
    if let Some(enc) = u.p("encryption") {
        if enc != "none" {
            return Err("VLESS Encryption поддерживается только ядром Xray".into());
        }
    }
    if u.p("pqv").is_some() {
        return Err("REALITY с ML-DSA поддерживается только ядром Xray".into());
    }
    let mut o = base("vless", &u, port);
    o.insert("uuid".into(), json!(uuid));
    let net = u.p("type").unwrap_or("tcp").to_ascii_lowercase();
    if let Some(flow) = u.p("flow") {
        let flow = if flow.starts_with("xtls-rprx-vision") {
            "xtls-rprx-vision"
        } else {
            flow
        };
        o.insert("flow".into(), json!(flow));
    }
    o.insert(
        "packet_encoding".into(),
        json!(u.p("packetencoding").unwrap_or("xudp")),
    );
    let security = u.p("security").unwrap_or("none").to_ascii_lowercase();
    if let Some(tls) = tls_object(&u, &security, None) {
        o.insert("tls".into(), tls);
    }
    if let Some(t) = transport_object(
        &net,
        u.p("path"),
        u.p("host"),
        u.p("headertype"),
        u.p("servicename"),
    )? {
        o.insert("transport".into(), t);
    }
    Ok(finish(o, &u, "vless", port))
}

fn parse_trojan(rest: &str) -> Result<Parsed> {
    let u = split_uri(rest)?;
    let port = u.port_u16(443)?;
    let mut password = decode(u.user.as_deref().ok_or("в ссылке нет пароля")?);
    if let Some(p) = &u.pass {
        password = format!("{password}:{}", decode(p));
    }
    let mut o = base("trojan", &u, port);
    o.insert("password".into(), json!(password));
    // У trojan TLS включён по умолчанию.
    let security = u.p("security").unwrap_or("tls").to_ascii_lowercase();
    if let Some(tls) = tls_object(&u, &security, None) {
        o.insert("tls".into(), tls);
    }
    let net = u.p("type").unwrap_or("tcp").to_ascii_lowercase();
    if let Some(t) = transport_object(
        &net,
        u.p("path"),
        u.p("host"),
        u.p("headertype"),
        u.p("servicename"),
    )? {
        o.insert("transport".into(), t);
    }
    Ok(finish(o, &u, "trojan", port))
}

fn parse_vmess(rest: &str) -> Result<Parsed> {
    let rest = rest.split('#').next().unwrap_or(rest);
    let text = b64_decode_str(rest).ok_or("vmess: не удалось декодировать base64")?;
    let j: Value = serde_json::from_str(&text).map_err(|_| "vmess: некорректный JSON")?;
    let s = |k: &str| -> Option<String> {
        match j.get(k) {
            Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
            Some(Value::Number(n)) => Some(n.to_string()),
            _ => None,
        }
    };
    let host = s("add").ok_or("vmess: нет адреса")?;
    let port: u16 = s("port")
        .and_then(|p| p.parse().ok())
        .ok_or("vmess: некорректный порт")?;
    let uuid = s("id").ok_or("vmess: нет UUID")?;
    let mut u = Uri {
        host: host.clone(),
        port: port.to_string(),
        fragment: s("ps").unwrap_or_default(),
        ..Default::default()
    };
    for (k, key) in [
        ("sni", "sni"),
        ("alpn", "alpn"),
        ("fp", "fp"),
        ("host", "host"),
        ("allowinsecure", "allowInsecure"),
    ] {
        if let Some(v) = s(key) {
            u.params.insert(k.into(), v);
        }
    }
    let mut o = base("vmess", &u, port);
    o.insert("uuid".into(), json!(uuid));
    o.insert(
        "security".into(),
        json!(s("scy").unwrap_or_else(|| "auto".into())),
    );
    o.insert(
        "alter_id".into(),
        json!(s("aid").and_then(|a| a.parse::<u32>().ok()).unwrap_or(0)),
    );
    o.insert("packet_encoding".into(), json!("xudp"));
    let security = s("tls").unwrap_or_default().to_ascii_lowercase();
    if let Some(tls) = tls_object(&u, &security, None) {
        o.insert("tls".into(), tls);
    }
    let net = s("net").unwrap_or_else(|| "tcp".into()).to_ascii_lowercase();
    let path = s("path");
    let hosth = s("host");
    let ht = s("type");
    if let Some(t) = transport_object(
        &net,
        path.as_deref(),
        hosth.as_deref(),
        ht.as_deref(),
        path.as_deref(),
    )? {
        o.insert("transport".into(), t);
    }
    Ok(finish(o, &u, "vmess", port))
}

fn parse_ss(rest: &str) -> Result<Parsed> {
    // Старый формат: ss://base64(method:pass@host:port)#name
    let (body, frag) = rest.split_once('#').unwrap_or((rest, ""));
    let body_no_q = body.split('?').next().unwrap_or(body);
    let normalized = if !body_no_q.contains('@') {
        let dec = b64_decode_str(body_no_q.trim_end_matches('/'))
            .ok_or("ss: не удалось декодировать ссылку")?;
        let q = body.strip_prefix(body_no_q).unwrap_or("");
        format!("{dec}{q}#{frag}")
    } else {
        rest.to_string()
    };
    let u = split_uri(&normalized)?;
    let port = u.port_u16(8388)?;
    // SIP002: userinfo = base64(method:password) или method:password в открытом виде.
    let (method, password) = match (&u.user, &u.pass) {
        (Some(m), Some(p)) => (decode(m), decode(p)),
        (Some(ui), None) => {
            let dec = b64_decode_str(&decode(ui)).ok_or("ss: некорректный userinfo")?;
            let (m, p) = dec.split_once(':').ok_or("ss: нет пароля")?;
            (m.to_string(), p.to_string())
        }
        _ => return Err("ss: нет метода шифрования".into()),
    };
    let mut o = base("shadowsocks", &u, port);
    o.insert("method".into(), json!(method));
    o.insert("password".into(), json!(password));
    if let Some(plugin) = u.p("plugin") {
        let (name, opts) = plugin.split_once(';').unwrap_or((plugin, ""));
        let name = match name {
            "simple-obfs" | "obfs-local" => "obfs-local",
            "v2ray-plugin" => "v2ray-plugin",
            other => return Err(format!("ss: плагин {other} не поддерживается")),
        };
        o.insert("plugin".into(), json!(name));
        o.insert("plugin_opts".into(), json!(opts));
    }
    o.insert("udp_over_tcp".into(), json!(u.flag(&["uot"])));
    Ok(finish(o, &u, "shadowsocks", port))
}

fn port_ranges(port: &str, mport: Option<&str>) -> Vec<Value> {
    let mut out = vec![];
    let mut push = |part: &str| {
        let part = part.trim();
        if let Some((a, b)) = part.split_once('-') {
            if a.parse::<u16>().is_ok() && b.parse::<u16>().is_ok() {
                out.push(json!(format!("{a}:{b}")));
            }
        }
    };
    if port.contains(',') || port.contains('-') {
        port.split(',').for_each(&mut push);
    }
    if let Some(m) = mport {
        m.split(',').for_each(&mut push);
    }
    out
}

fn parse_hy2(rest: &str) -> Result<Parsed> {
    let u = split_uri(rest)?;
    let port = u.port_u16(443)?;
    let mut password = decode(u.user.as_deref().unwrap_or(""));
    if let Some(p) = &u.pass {
        password = format!("{password}:{}", decode(p));
    }
    let mut o = base("hysteria2", &u, port);
    o.insert("password".into(), json!(password));
    let ranges = port_ranges(&u.port, u.p("mport"));
    if !ranges.is_empty() {
        o.insert("server_ports".into(), Value::Array(ranges));
    }
    if let Some(obfs) = u.p("obfs") {
        if obfs != "none" {
            o.insert(
                "obfs".into(),
                json!({"type": obfs, "password": u.p("obfs-password").unwrap_or("")}),
            );
        }
    }
    if let Some(up) = u.p("up").and_then(|v| v.trim_end_matches(char::is_alphabetic).trim().parse::<u32>().ok()) {
        o.insert("up_mbps".into(), json!(up));
    }
    if let Some(down) = u.p("down").and_then(|v| v.trim_end_matches(char::is_alphabetic).trim().parse::<u32>().ok()) {
        o.insert("down_mbps".into(), json!(down));
    }
    let tls = tls_object(&u, "tls", Some(&["h3"])).unwrap_or_default();
    o.insert("tls".into(), tls);
    Ok(finish(o, &u, "hysteria2", port))
}

fn parse_tuic(rest: &str) -> Result<Parsed> {
    let u = split_uri(rest)?;
    let port = u.port_u16(443)?;
    let uuid = decode(u.user.as_deref().ok_or("tuic: нет UUID")?);
    let password = decode(u.pass.as_deref().or(u.p("password")).unwrap_or(""));
    let mut o = base("tuic", &u, port);
    o.insert("uuid".into(), json!(uuid));
    o.insert("password".into(), json!(password));
    if let Some(cc) = u.p("congestion_control").or_else(|| u.p("congestion-control")) {
        o.insert("congestion_control".into(), json!(cc));
    }
    if let Some(m) = u.p("udp_relay_mode").or_else(|| u.p("udp-relay-mode")) {
        o.insert("udp_relay_mode".into(), json!(m));
    }
    let tls = tls_object(&u, "tls", Some(&["h3"])).unwrap_or_default();
    o.insert("tls".into(), tls);
    Ok(finish(o, &u, "tuic", port))
}

fn parse_socks(rest: &str) -> Result<Parsed> {
    let u = split_uri(rest)?;
    let port = u.port_u16(1080)?;
    let mut o = base("socks", &u, port);
    o.insert("version".into(), json!("5"));
    let (user, pass) = match (&u.user, &u.pass) {
        (Some(a), Some(b)) => (Some(decode(a)), Some(decode(b))),
        // socks://base64(user:pass)@host:port
        (Some(a), None) => match b64_decode_str(&decode(a)).and_then(|d| {
            d.split_once(':').map(|(x, y)| (x.to_string(), y.to_string()))
        }) {
            Some((x, y)) => (Some(x), Some(y)),
            None => (Some(decode(a)), None),
        },
        _ => (None, None),
    };
    if let Some(user) = user {
        o.insert("username".into(), json!(user));
    }
    if let Some(pass) = pass {
        o.insert("password".into(), json!(pass));
    }
    Ok(finish(o, &u, "socks", port))
}

fn parse_http(scheme: &str, rest: &str) -> Result<Parsed> {
    let u = split_uri(rest)?;
    let tls = scheme.eq_ignore_ascii_case("https");
    let port = u.port_u16(if tls { 443 } else { 80 })?;
    let mut o = base("http", &u, port);
    if let Some(user) = &u.user {
        o.insert("username".into(), json!(decode(user)));
    }
    if let Some(pass) = &u.pass {
        o.insert("password".into(), json!(decode(pass)));
    }
    if tls {
        o.insert("tls".into(), tls_object(&u, "tls", None).unwrap_or_default());
    }
    Ok(finish(o, &u, if tls { "https" } else { "http" }, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_reality() {
        let l = "vless://0b4d5c3a-1111-2222-3333-444455556666@1.2.3.4:443?type=tcp&security=reality&pbk=AbCdEf&fp=chrome&sni=www.microsoft.com&sid=ab12&flow=xtls-rprx-vision#%F0%9F%87%B3%F0%9F%87%B1%20NL";
        let p = parse_link(l).unwrap();
        assert_eq!(p.name, "🇳🇱 NL");
        let o = p.outbound;
        assert_eq!(o["type"], "vless");
        assert_eq!(o["server_port"], 443);
        assert_eq!(o["flow"], "xtls-rprx-vision");
        assert_eq!(o["tls"]["reality"]["public_key"], "AbCdEf");
        assert_eq!(o["tls"]["reality"]["short_id"], "ab12");
        assert_eq!(o["tls"]["server_name"], "www.microsoft.com");
        assert_eq!(o["tls"]["utls"]["fingerprint"], "chrome");
        assert!(o.get("transport").is_none());
    }

    #[test]
    fn vless_ws_early_data() {
        let l = "vless://uuid@example.com:8443?type=ws&security=tls&path=%2Fws%3Fed%3D2048&host=cdn.example.com#ws";
        let o = parse_link(l).unwrap().outbound;
        assert_eq!(o["transport"]["type"], "ws");
        assert_eq!(o["transport"]["path"], "/ws");
        assert_eq!(o["transport"]["max_early_data"], 2048);
        assert_eq!(o["transport"]["headers"]["Host"], "cdn.example.com");
        assert_eq!(o["tls"]["server_name"], "cdn.example.com");
    }

    #[test]
    fn vless_xhttp_goes_to_xray() {
        let l = "vless://uuid@example.com:443?type=xhttp&security=reality&pbk=k&sid=1#x";
        assert!(parse_link(l).is_err(), "sing-box не умеет XHTTP");
        let s = link_to_server(l, "t").unwrap();
        assert!(s.usable() && s.needs_xray());
        assert_eq!(s.transport, "xhttp · reality");
        assert_eq!(s.name, "x");
        // TCP+REALITY работает в обоих ядрах.
        let s = link_to_server("vless://u@1.2.3.4:443?type=tcp&security=reality&pbk=k&sid=1&flow=xtls-rprx-vision#t", "t").unwrap();
        assert!(s.outbound.is_some() && s.xray.is_some());
        assert_eq!(s.transport, "tcp · reality");
        // Неподдерживаемое никем остаётся с ошибкой.
        let s = link_to_server("wireguard://k@1.2.3.4:51820#wg", "t").unwrap();
        assert!(!s.usable() && s.error.is_some());
    }

    #[test]
    fn vmess() {
        let j = r#"{"v":"2","ps":"VMess test","add":"vm.example.com","port":"443","id":"abc","aid":"0","scy":"auto","net":"grpc","type":"none","host":"","path":"svc","tls":"tls","sni":"vm.example.com"}"#;
        let l = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(j)
        );
        let p = parse_link(&l).unwrap();
        assert_eq!(p.name, "VMess test");
        assert_eq!(p.outbound["transport"]["service_name"], "svc");
        assert_eq!(p.outbound["tls"]["enabled"], true);
    }

    #[test]
    fn shadowsocks_sip002_and_legacy() {
        let ui = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("chacha20-ietf-poly1305:pa:ss");
        let p = parse_link(&format!("ss://{ui}@5.6.7.8:8388#SS")).unwrap();
        assert_eq!(p.outbound["method"], "chacha20-ietf-poly1305");
        assert_eq!(p.outbound["password"], "pa:ss");
        let legacy = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:secret@9.9.9.9:1234");
        let p = parse_link(&format!("ss://{legacy}#Old")).unwrap();
        assert_eq!(p.port, 1234);
        assert_eq!(p.outbound["password"], "secret");
        let p = parse_link("ss://2022-blake3-aes-128-gcm:a2V5:dXNlcg@[2001:db8::1]:443#v6").unwrap();
        assert_eq!(p.address, "2001:db8::1");
        assert_eq!(p.outbound["password"], "a2V5:dXNlcg");
    }

    #[test]
    fn hysteria2_ports() {
        let p = parse_link("hy2://pass@h.example.com:443,20000-30000?obfs=salamander&obfs-password=x&sni=h.example.com&insecure=1#hy").unwrap();
        let o = p.outbound;
        assert_eq!(o["server_port"], 443);
        assert_eq!(o["server_ports"][0], "20000:30000");
        assert_eq!(o["obfs"]["type"], "salamander");
        assert_eq!(o["tls"]["insecure"], true);
        assert_eq!(o["tls"]["alpn"][0], "h3");
    }

    #[test]
    fn tuic_and_trojan_and_socks() {
        let p = parse_link("tuic://uuid:pw@t.example.com:443?congestion_control=bbr&alpn=h3&sni=t.example.com#t").unwrap();
        assert_eq!(p.outbound["password"], "pw");
        assert_eq!(p.outbound["congestion_control"], "bbr");
        let p = parse_link("trojan://secret@tr.example.com:443?sni=tr.example.com#tr").unwrap();
        assert_eq!(p.outbound["tls"]["enabled"], true);
        let p = parse_link("socks5://user:pass@10.0.0.1:1080#s").unwrap();
        assert_eq!(p.outbound["username"], "user");
    }
}
