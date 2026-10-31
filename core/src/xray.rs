//! Xray-core: разбор ссылок VLESS/VMess/Trojan в outbound Xray и генерация конфига.
//!
//! sing-box не поддерживает XHTTP, VLESS Encryption и REALITY с ML-DSA. Такие серверы
//! запускаются в Xray: для каждого сервера Xray открывает локальный SOCKS-вход
//! на 127.0.0.1, а sing-box подключается к нему как к обычному SOCKS-серверу.
//! TUN, раздельное туннелирование и DNS по-прежнему делает sing-box.
//!
//! Формат конфига сверён с Xray-core v26.10 (infra/conf).

use std::collections::HashSet;

use serde_json::{json, Map, Value};

use crate::links::{b64_decode_str, csv, decode, is_ip, split_uri, transport_label, Result, Uri};

#[derive(Debug, Clone)]
pub struct XParsed {
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub transport: String,
    pub outbound: Value,
}

pub fn parse_link(link: &str) -> Result<XParsed> {
    let (scheme, rest) = link.split_once("://").ok_or("не похоже на ссылку")?;
    match scheme.to_ascii_lowercase().as_str() {
        "vless" => vless(rest),
        "trojan" => trojan(rest),
        "vmess" => vmess(rest),
        other => Err(format!("{other}:// в Xray не используется")),
    }
}

fn sni_of(u: &Uri) -> Option<String> {
    u.p("sni")
        .or_else(|| u.p("peer"))
        .or_else(|| u.p("servername"))
        .map(|s| s.to_string())
        .or_else(|| u.p("host").map(|h| h.split(',').next().unwrap_or(h).to_string()))
        .or_else(|| (!is_ip(&u.host)).then(|| u.host.clone()))
}

/// streamSettings Xray из параметров ссылки.
fn stream(u: &Uri, net: &str, security: &str) -> Result<Value> {
    let mut s = Map::new();
    let path = u.p("path");
    let host = u.p("host");
    let net = net.to_ascii_lowercase();
    match net.as_str() {
        "" | "tcp" | "raw" | "none" => {
            s.insert("network".into(), json!("raw"));
            if u.p("headertype") == Some("http") {
                let mut req = Map::new();
                req.insert("path".into(), Value::Array(csv(path.unwrap_or("/"))));
                if let Some(h) = host {
                    req.insert("headers".into(), json!({ "Host": csv(h) }));
                }
                s.insert(
                    "rawSettings".into(),
                    json!({"header": {"type": "http", "request": req}}),
                );
            }
        }
        "xhttp" | "splithttp" => {
            s.insert("network".into(), json!("xhttp"));
            let mut x = Map::new();
            x.insert("path".into(), json!(path.unwrap_or("/")));
            if let Some(h) = host {
                x.insert("host".into(), json!(h));
            }
            x.insert("mode".into(), json!(u.p("mode").unwrap_or("auto")));
            if let Some(extra) = u.p("extra") {
                match serde_json::from_str::<Value>(extra) {
                    Ok(v @ Value::Object(_)) => {
                        x.insert("extra".into(), v);
                    }
                    _ => return Err("XHTTP: параметр extra не является JSON-объектом".into()),
                }
            }
            s.insert("xhttpSettings".into(), Value::Object(x));
        }
        "ws" | "websocket" => {
            s.insert("network".into(), json!("ws"));
            let mut w = Map::new();
            w.insert("path".into(), json!(path.unwrap_or("/")));
            if let Some(h) = host {
                w.insert("host".into(), json!(h));
            }
            s.insert("wsSettings".into(), Value::Object(w));
        }
        "grpc" | "gun" => {
            s.insert("network".into(), json!("grpc"));
            let mut g = Map::new();
            g.insert(
                "serviceName".into(),
                json!(u.p("servicename").or(path).unwrap_or("")),
            );
            if let Some(a) = u.p("authority") {
                g.insert("authority".into(), json!(a));
            }
            g.insert("multiMode".into(), json!(u.p("mode") == Some("multi")));
            s.insert("grpcSettings".into(), Value::Object(g));
        }
        "httpupgrade" => {
            s.insert("network".into(), json!("httpupgrade"));
            let mut h = Map::new();
            h.insert("path".into(), json!(path.unwrap_or("/")));
            if let Some(hh) = host {
                h.insert("host".into(), json!(hh));
            }
            s.insert("httpupgradeSettings".into(), Value::Object(h));
        }
        "kcp" | "mkcp" => {
            s.insert("network".into(), json!("kcp"));
            let mut k = Map::new();
            k.insert(
                "header".into(),
                json!({"type": u.p("headertype").unwrap_or("none")}),
            );
            if let Some(seed) = u.p("seed") {
                k.insert("seed".into(), json!(seed));
            }
            s.insert("kcpSettings".into(), Value::Object(k));
        }
        other => return Err(format!("транспорт «{other}» не поддерживается")),
    }

    let fp = u.p("fp").or_else(|| u.p("fingerprint")).unwrap_or("chrome");
    match security {
        "tls" | "xtls" => {
            s.insert("security".into(), json!("tls"));
            let mut t = Map::new();
            if let Some(sni) = sni_of(u) {
                t.insert("serverName".into(), json!(sni));
            }
            t.insert("fingerprint".into(), json!(fp));
            if let Some(alpn) = u.p("alpn") {
                t.insert("alpn".into(), Value::Array(csv(alpn)));
            }
            if u.flag(&["allowinsecure", "insecure", "allow_insecure"]) {
                t.insert("allowInsecure".into(), json!(true));
            }
            if let Some(ech) = u.p("ech") {
                t.insert("echConfigList".into(), json!(ech));
            }
            s.insert("tlsSettings".into(), Value::Object(t));
        }
        "reality" => {
            s.insert("security".into(), json!("reality"));
            let mut r = Map::new();
            if let Some(sni) = sni_of(u) {
                r.insert("serverName".into(), json!(sni));
            }
            r.insert("fingerprint".into(), json!(fp));
            let pbk = u
                .p("pbk")
                .or_else(|| u.p("publickey"))
                .or_else(|| u.p("password"))
                .ok_or("REALITY: в ссылке нет публичного ключа (pbk)")?;
            r.insert("password".into(), json!(pbk));
            r.insert("shortId".into(), json!(u.p("sid").or_else(|| u.p("shortid")).unwrap_or("")));
            if let Some(spx) = u.p("spx").or_else(|| u.p("spiderx")) {
                r.insert("spiderX".into(), json!(spx));
            }
            if let Some(pqv) = u.p("pqv") {
                r.insert("mldsa65Verify".into(), json!(pqv));
            }
            s.insert("realitySettings".into(), Value::Object(r));
        }
        _ => {
            s.insert("security".into(), json!("none"));
        }
    }
    Ok(Value::Object(s))
}

fn finish(u: &Uri, protocol: &str, port: u16, net: &str, sec: &str, outbound: Value) -> XParsed {
    XParsed {
        name: u.name_or(&format!("{}:{}", u.host, port)),
        protocol: protocol.into(),
        address: u.host.clone(),
        port,
        transport: transport_label(net, if sec == "none" { "" } else { sec }),
        outbound,
    }
}

fn vless(rest: &str) -> Result<XParsed> {
    let u = split_uri(rest)?;
    let port = u.port_u16(443)?;
    let id = decode(u.user.as_deref().ok_or("в ссылке нет UUID")?);
    let net = u.p("type").unwrap_or("tcp").to_string();
    let sec = u.p("security").unwrap_or("none").to_ascii_lowercase();
    let mut settings = Map::new();
    settings.insert("address".into(), json!(u.host));
    settings.insert("port".into(), json!(port));
    settings.insert("id".into(), json!(id));
    settings.insert("encryption".into(), json!(u.p("encryption").unwrap_or("none")));
    if let Some(flow) = u.p("flow") {
        settings.insert("flow".into(), json!(flow));
    }
    let ob = json!({
        "protocol": "vless",
        "settings": settings,
        "streamSettings": stream(&u, &net, &sec)?
    });
    Ok(finish(&u, "vless", port, &net, &sec, ob))
}

fn trojan(rest: &str) -> Result<XParsed> {
    let u = split_uri(rest)?;
    let port = u.port_u16(443)?;
    let mut password = decode(u.user.as_deref().ok_or("в ссылке нет пароля")?);
    if let Some(p) = &u.pass {
        password = format!("{password}:{}", decode(p));
    }
    let net = u.p("type").unwrap_or("tcp").to_string();
    let sec = u.p("security").unwrap_or("tls").to_ascii_lowercase();
    let ob = json!({
        "protocol": "trojan",
        "settings": {"address": u.host, "port": port, "password": password},
        "streamSettings": stream(&u, &net, &sec)?
    });
    Ok(finish(&u, "trojan", port, &net, &sec, ob))
}

fn vmess(rest: &str) -> Result<XParsed> {
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
    let port: u16 = s("port").and_then(|p| p.parse().ok()).ok_or("vmess: некорректный порт")?;
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
        ("path", "path"),
        ("headertype", "type"),
        ("mode", "mode"),
        ("allowinsecure", "allowInsecure"),
    ] {
        if let Some(v) = s(key) {
            u.params.insert(k.into(), v);
        }
    }
    let net = s("net").unwrap_or_else(|| "tcp".into());
    let sec = s("tls").unwrap_or_else(|| "none".into()).to_ascii_lowercase();
    let ob = json!({
        "protocol": "vmess",
        "settings": {
            "address": host,
            "port": port,
            "id": s("id").ok_or("vmess: нет UUID")?,
            "security": s("scy").unwrap_or_else(|| "auto".into())
        },
        "streamSettings": stream(&u, &net, &sec)?
    });
    Ok(finish(&u, "vmess", port, &net, &sec, ob))
}

// ---------------------------------------------------------------------------
// Подписки в формате Xray JSON (так отдают Remnawave/Marzban для Happ, v2RayTun)
// ---------------------------------------------------------------------------

const XRAY_PROTOCOLS: &[&str] = &["vless", "vmess", "trojan", "shadowsocks", "hysteria"];

/// Из одного конфига Xray подписки достаёт то, через что идёт трафик: основной
/// outbound (как выбрал бы сам Xray по правилам маршрутизации) или балансировщик.
///
/// Возвращается «связка»: `{"bundle": true, "main": ..., "outbounds": [...],
/// "balancer": ..., "dns": ...}` — основной outbound вместе со всем, через что он
/// подключается (`dialerProxy`, `proxySettings`: цепочки, «белые списки»,
/// фрагментация), балансировщик и DNS конфига. Xray запускает её так же, как
/// исходный конфиг.
pub fn outbound_from_config(cfg: &Value) -> Option<(String, Value)> {
    let obs: Vec<&Value> = cfg.get("outbounds")?.as_array()?.iter().collect();
    let tag_of = |o: &Value| o.get("tag").and_then(|t| t.as_str()).unwrap_or("").to_string();
    let by_tag = |t: &str| obs.iter().copied().find(|o| !t.is_empty() && tag_of(o) == t);
    let is_proxy = |o: &Value| {
        o.get("protocol")
            .and_then(|p| p.as_str())
            .map(|p| XRAY_PROTOCOLS.contains(&p))
            .unwrap_or(false)
    };

    // Куда Xray отправил бы обычный трафик: первое правило без условий или,
    // если такого нет, первый outbound списка.
    let rules = cfg
        .pointer("/routing/rules")
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();
    let catch_all = rules.iter().find(|r| is_catch_all(r));
    let balancers = cfg
        .pointer("/routing/balancers")
        .and_then(|b| b.as_array())
        .cloned()
        .unwrap_or_default();

    let mut main: Option<&Value> = None;
    let mut balancer: Option<Value> = None;
    match catch_all {
        Some(r) if r.get("balancerTag").is_some() => {
            let bt = r["balancerTag"].as_str().unwrap_or("");
            balancer = balancers.iter().find(|b| b["tag"].as_str() == Some(bt)).cloned();
        }
        Some(r) => main = r["outboundTag"].as_str().and_then(by_tag).filter(|o| is_proxy(o)),
        None => main = obs.first().copied().filter(|o| is_proxy(o)),
    }
    // Балансировщик без подходящих серверов не нужен.
    let members: Vec<&Value> = match &balancer {
        Some(b) => {
            let sel: Vec<&str> = b["selector"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                .unwrap_or_default();
            obs.iter()
                .copied()
                .filter(|o| is_proxy(o) && sel.iter().any(|p| tag_of(o).starts_with(p)))
                .collect()
        }
        None => vec![],
    };
    if members.is_empty() {
        balancer = None;
    }
    if main.is_none() && balancer.is_none() {
        // Нестандартная маршрутизация: берём «proxy» или первый прокси,
        // который сам не служит промежуточным звеном цепочки.
        let deps: HashSet<String> = obs.iter().flat_map(|o| dep_tags(o)).collect();
        main = obs
            .iter()
            .copied()
            .filter(|o| is_proxy(o))
            .find(|o| tag_of(o) == "proxy")
            .or_else(|| obs.iter().copied().filter(|o| is_proxy(o)).find(|o| !deps.contains(&tag_of(o))))
            .or_else(|| obs.iter().copied().find(|o| is_proxy(o)));
    }
    let primary = main.or_else(|| members.first().copied())?;
    let name = cfg
        .get("remarks")
        .and_then(|r| r.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            let t = tag_of(primary);
            if t.is_empty() { "Xray".into() } else { t }
        });

    // Всё, от чего зависит основной outbound (или участники балансировщика).
    let mut need: Vec<String> = vec![];
    let mut queue: Vec<&Value> = match &balancer {
        Some(_) => members.clone(),
        None => vec![primary],
    };
    if let Some(fb) = balancer.as_ref().and_then(|b| b["fallbackTag"].as_str()).and_then(by_tag) {
        queue.push(fb);
    }
    while let Some(o) = queue.pop() {
        let t = tag_of(o);
        if need.contains(&t) {
            continue;
        }
        need.push(t);
        for d in dep_tags(o) {
            if let Some(dep) = by_tag(&d) {
                queue.push(dep);
            }
        }
    }
    // Связка: outbound'ы в исходном порядке, без тех, что не нужны.
    let mut list: Vec<Value> = vec![];
    for (i, o) in obs.iter().enumerate() {
        let t = tag_of(o);
        if !need.contains(&t) {
            continue;
        }
        let mut o = (*o).clone();
        if t.is_empty() {
            o["tag"] = json!(format!("ob{i}"));
        }
        if let Some(m) = o.as_object_mut() {
            m.remove("sendThrough");
        }
        list.push(o);
    }
    let tags: HashSet<String> = list.iter().map(|o| tag_of(o)).collect();
    // Ссылки на outbound'ы, которых нет в конфиге, убираем.
    for o in list.iter_mut() {
        if let Some(sock) = o.pointer_mut("/streamSettings/sockopt").and_then(|s| s.as_object_mut()) {
            if sock.get("dialerProxy").and_then(|d| d.as_str()).map(|d| !tags.contains(d)).unwrap_or(false) {
                sock.remove("dialerProxy");
            }
        }
        if o.pointer("/proxySettings/tag").and_then(|d| d.as_str()).map(|d| !tags.contains(d)).unwrap_or(false) {
            o.as_object_mut().unwrap().remove("proxySettings");
        }
    }
    let mut bundle = json!({
        "bundle": true,
        "main": main.map(|o| tag_of(o)),
        "outbounds": list,
    });
    // DNS из конфига: адреса серверов могут быть закреплены в hosts, а провайдер
    // может рассчитывать на свои DNS-серверы.
    if let Some(d) = dns_of(cfg) {
        bundle["dns"] = d;
    }
    if let Some(b) = balancer {
        bundle["balancer"] = b;
        for key in ["observatory", "burstObservatory"] {
            if let Some(v) = cfg.get(key) {
                bundle[key] = v.clone();
            }
        }
    }
    Some((name, bundle))
}

/// Правило маршрутизации без условий (ловит весь трафик).
fn is_catch_all(r: &Value) -> bool {
    let Some(m) = r.as_object() else { return false };
    if m.get("outboundTag").is_none() && m.get("balancerTag").is_none() {
        return false;
    }
    m.iter().all(|(k, v)| match k.as_str() {
        "type" | "outboundTag" | "balancerTag" | "ruleTag" | "inboundTag" => true,
        "network" => {
            let n = v.as_str().unwrap_or("").replace(' ', "");
            n.contains("tcp") && n.contains("udp")
        }
        "port" => matches!(v.as_str().map(|s| s.trim()), Some("0-65535") | Some("1-65535")),
        _ => false,
    })
}

/// Теги outbound'ов, через которые подключается данный.
fn dep_tags(o: &Value) -> Vec<String> {
    let mut v = vec![];
    if let Some(t) = o.pointer("/streamSettings/sockopt/dialerProxy").and_then(|t| t.as_str()) {
        v.push(t.to_string());
    }
    if let Some(t) = o.pointer("/proxySettings/tag").and_then(|t| t.as_str()) {
        v.push(t.to_string());
    }
    v
}

/// Связка из нескольких outbound'ов (цепочка или балансировщик).
pub fn is_bundle(v: &Value) -> bool {
    v.get("bundle").and_then(|b| b.as_bool()).unwrap_or(false)
}

/// Outbound, по которому показывается сервер: основной или первый из балансировщика.
pub fn primary(v: &Value) -> &Value {
    if !is_bundle(v) {
        return v;
    }
    let list = v["outbounds"].as_array();
    let main = v["main"].as_str();
    let is_proxy = |o: &&Value| o["protocol"].as_str().map(|p| XRAY_PROTOCOLS.contains(&p)).unwrap_or(false);
    list.and_then(|l| {
        l.iter()
            .find(|o| main.is_some() && o["tag"].as_str() == main)
            .or_else(|| l.iter().find(is_proxy))
    })
    .unwrap_or(v)
}

/// Домены всех серверов связки (для прямого DNS).
pub fn hosts(v: &Value) -> Vec<String> {
    let list: Vec<&Value> = if is_bundle(v) {
        v["outbounds"].as_array().map(|a| a.iter().collect()).unwrap_or_default()
    } else {
        vec![v]
    };
    list.into_iter()
        .map(|o| outbound_endpoint(o).0)
        .filter(|h| !h.is_empty() && h.parse::<std::net::IpAddr>().is_err())
        .map(|h| h.to_lowercase())
        .collect()
}

/// hosts и DNS-серверы конфига. Записи с geosite/geoip пропускаются: баз
/// Xray в приложении нет, а без них Xray не запустится.
fn dns_of(cfg: &Value) -> Option<Value> {
    let d = cfg.get("dns")?;
    let geo = |s: &str| s.starts_with("geosite:") || s.starts_with("geoip:") || s.starts_with("ext:");
    let mut hosts = Map::new();
    if let Some(h) = d.get("hosts").and_then(|h| h.as_object()) {
        for (k, v) in h {
            if !geo(k) {
                hosts.insert(k.clone(), v.clone());
            }
        }
    }
    let mut servers = vec![];
    for sv in d.get("servers").and_then(|s| s.as_array()).into_iter().flatten() {
        let addr = match sv {
            Value::String(a) => Some(sv.clone()).filter(|_| !a.is_empty()),
            Value::Object(o) => {
                // Серверы только для отдельных доменов не переносим.
                let scoped = o.get("domains").and_then(|d| d.as_array()).map(|a| !a.is_empty()).unwrap_or(false);
                match o.get("address").and_then(|a| a.as_str()) {
                    Some(a) if !scoped => {
                        let mut m = Map::new();
                        m.insert("address".into(), json!(a));
                        if let Some(p) = o.get("port") {
                            m.insert("port".into(), p.clone());
                        }
                        Some(Value::Object(m))
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        let skip = addr
            .as_ref()
            .map(|a| {
                let s = a.as_str().or_else(|| a["address"].as_str()).unwrap_or("");
                s == "fakedns" || s.is_empty()
            })
            .unwrap_or(true);
        if !skip {
            servers.push(addr.unwrap());
        }
    }
    if hosts.is_empty() && servers.is_empty() {
        return None;
    }
    Some(json!({"hosts": hosts, "servers": servers}))
}

/// Адрес и порт сервера из outbound Xray (плоский формат или vnext/servers).
pub fn outbound_endpoint(ob: &Value) -> (String, u16) {
    let st = &ob["settings"];
    let node = if st.get("address").is_some() {
        st
    } else if let Some(v) = st.get("vnext").and_then(|v| v.get(0)) {
        v
    } else if let Some(v) = st.get("servers").and_then(|v| v.get(0)) {
        v
    } else {
        st
    };
    (
        node["address"].as_str().unwrap_or("").to_string(),
        node["port"].as_u64().unwrap_or(0) as u16,
    )
}

pub fn outbound_label(ob: &Value) -> String {
    let ss = &ob["streamSettings"];
    let net = ss
        .get("network")
        .or_else(|| ss.get("method"))
        .and_then(|v| v.as_str())
        .unwrap_or("raw");
    transport_label(net, ss["security"].as_str().unwrap_or(""))
}

// ---------------------------------------------------------------------------
// Конфиг Xray
// ---------------------------------------------------------------------------

pub struct XrayEntry<'a> {
    pub tag: &'a str,
    pub port: u16,
    pub outbound: &'a Value,
}

/// Для каждого сервера — SOCKS-вход на 127.0.0.1:port, ведущий в его outbound.
/// `dns` — IP DNS-сервера для разрешения адресов серверов (идёт мимо VPN).
/// `auth` — логин и пароль на SOCKS-входах, чтобы другие программы не могли
/// найти их сканированием портов и воспользоваться.
pub fn build_config(
    entries: &[XrayEntry],
    dns: &str,
    ipv6: bool,
    log_level: &str,
    auth: (&str, &str),
) -> Value {
    let mut inbounds = vec![];
    let mut outbounds = vec![];
    let mut rules = vec![];
    let mut balancers = vec![];
    let mut dns_hosts = Map::new();
    let mut dns_servers: Vec<Value> = vec![];
    let mut observe: Vec<String> = vec![];
    let mut burst: Vec<String> = vec![];
    let mut observatory: Option<Value> = None;
    let mut burst_cfg: Option<Value> = None;
    for e in entries {
        let in_tag = format!("in-{}", e.tag);
        inbounds.push(json!({
            "tag": in_tag,
            "listen": "127.0.0.1",
            "port": e.port,
            "protocol": "socks",
            "settings": {
                "auth": "password",
                "accounts": [{"user": auth.0, "pass": auth.1}],
                "udp": true,
                "ip": "127.0.0.1"
            }
        }));
        if !is_bundle(e.outbound) {
            let out_tag = format!("out-{}", e.tag);
            let mut ob = e.outbound.clone();
            ob["tag"] = json!(out_tag);
            set_resolver(&mut ob, ipv6);
            outbounds.push(ob);
            rules.push(json!({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag}));
            continue;
        }
        if let Some(d) = e.outbound.get("dns") {
            if let Some(h) = d["hosts"].as_object() {
                for (k, v) in h {
                    dns_hosts.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
            for sv in d["servers"].as_array().into_iter().flatten() {
                if !dns_servers.contains(sv) {
                    dns_servers.push(sv.clone());
                }
            }
        }
        // Связка: теги получают префикс сервера, ссылки между ними переписываются.
        let pre = |t: &str| format!("{}~{}", e.tag, t);
        for ob in e.outbound["outbounds"].as_array().into_iter().flatten() {
            let mut ob = ob.clone();
            let t = ob["tag"].as_str().unwrap_or("").to_string();
            ob["tag"] = json!(pre(&t));
            if let Some(d) = ob.pointer("/streamSettings/sockopt/dialerProxy").and_then(|d| d.as_str()) {
                let d = pre(d);
                ob["streamSettings"]["sockopt"]["dialerProxy"] = json!(d);
            }
            if let Some(d) = ob.pointer("/proxySettings/tag").and_then(|d| d.as_str()) {
                let d = pre(d);
                ob["proxySettings"]["tag"] = json!(d);
            }
            set_resolver(&mut ob, ipv6);
            outbounds.push(ob);
        }
        match e.outbound.get("balancer").filter(|b| b.is_object()) {
            Some(b) => {
                let mut b = b.clone();
                let bt = pre(b["tag"].as_str().unwrap_or("balancer"));
                b["tag"] = json!(bt);
                let sel: Vec<String> = b["selector"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str()).map(|x| pre(x)).collect())
                    .unwrap_or_default();
                b["selector"] = json!(sel);
                if let Some(fb) = b["fallbackTag"].as_str() {
                    let fb = pre(fb);
                    b["fallbackTag"] = json!(fb);
                }
                match b.pointer("/strategy/type").and_then(|t| t.as_str()) {
                    Some("leastPing") => {
                        observe.extend(sel.iter().cloned());
                        if observatory.is_none() {
                            observatory = e.outbound.get("observatory").cloned();
                        }
                    }
                    Some("leastLoad") => {
                        burst.extend(sel.iter().cloned());
                        if burst_cfg.is_none() {
                            burst_cfg = e.outbound.get("burstObservatory").cloned();
                        }
                    }
                    _ => {}
                }
                rules.push(json!({"type": "field", "inboundTag": [in_tag], "balancerTag": bt}));
                balancers.push(b);
            }
            None => {
                let main = e.outbound["main"].as_str().unwrap_or("");
                rules.push(json!({"type": "field", "inboundTag": [in_tag], "outboundTag": pre(main)}));
            }
        }
    }
    // Первый outbound — исходящий по умолчанию. Это должен быть прямой выход:
    // через него Xray сам разрешает адреса серверов.
    outbounds.insert(0, json!({"protocol": "freedom", "tag": "direct"}));
    rules.insert(0, json!({"type": "field", "inboundTag": ["xray-dns"], "outboundTag": "direct"}));
    // Сначала DNS из подписки, затем наш прямой DNS как запасной.
    let fallback = json!(dns);
    if !dns_servers.contains(&fallback) {
        dns_servers.push(fallback);
    }
    let level = match log_level {
        "debug" => "debug",
        "error" => "error",
        "info" => "info",
        _ => "warning",
    };
    let mut cfg = json!({
        "log": {"loglevel": level},
        "dns": {
            "tag": "xray-dns",
            "hosts": dns_hosts,
            "servers": dns_servers,
            "queryStrategy": if ipv6 { "UseIP" } else { "UseIPv4" }
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules}
    });
    if !balancers.is_empty() {
        cfg["routing"]["balancers"] = json!(balancers);
    }
    if !observe.is_empty() {
        let mut o = observatory.unwrap_or_else(|| {
            json!({"probeURL": "https://www.gstatic.com/generate_204", "probeInterval": "1m", "enableConcurrency": true})
        });
        o["subjectSelector"] = json!(observe);
        cfg["observatory"] = o;
    }
    if !burst.is_empty() {
        let mut o = burst_cfg.unwrap_or_else(|| {
            json!({"pingConfig": {"destination": "https://www.gstatic.com/generate_204", "interval": "1m", "timeout": "5s", "sampling": 2}})
        });
        o["subjectSelector"] = json!(burst);
        cfg["burstObservatory"] = o;
    }
    cfg
}

/// Адрес сервера разрешаем встроенным DNS Xray: запрос уходит из процесса Xray,
/// и sing-box отпускает его напрямую, без петли через VPN.
fn set_resolver(ob: &mut Value, ipv6: bool) {
    let Some(o) = ob.as_object_mut() else { return };
    let ss = o.entry("streamSettings").or_insert_with(|| json!({}));
    if let Some(ss) = ss.as_object_mut() {
        let sock = ss.entry("sockopt").or_insert_with(|| json!({}));
        if let Some(sock) = sock.as_object_mut() {
            sock.entry("domainStrategy")
                .or_insert_with(|| json!(if ipv6 { "UseIP" } else { "UseIPv4" }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_xhttp_reality() {
        let extra = percent_encoding::utf8_percent_encode(
            r#"{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":"16-32"}}"#,
            percent_encoding::NON_ALPHANUMERIC,
        )
        .to_string();
        let l = format!("vless://9e1f-uuid@5.6.7.8:443?encryption=none&type=xhttp&mode=stream-one&path=%2Fxh&host=&security=reality&pbk=PUBKEY&sid=0a1b&sni=www.apple.com&fp=firefox&spx=%2F&extra={extra}#XH");
        let p = parse_link(&l).unwrap();
        let o = &p.outbound;
        assert_eq!(p.transport, "xhttp · reality");
        assert_eq!(o["settings"]["id"], "9e1f-uuid");
        assert_eq!(o["settings"]["encryption"], "none");
        let ss = &o["streamSettings"];
        assert_eq!(ss["network"], "xhttp");
        assert_eq!(ss["xhttpSettings"]["mode"], "stream-one");
        assert_eq!(ss["xhttpSettings"]["path"], "/xh");
        assert_eq!(ss["xhttpSettings"]["extra"]["xmux"]["maxConcurrency"], "16-32");
        assert_eq!(ss["realitySettings"]["password"], "PUBKEY");
        assert_eq!(ss["realitySettings"]["shortId"], "0a1b");
        assert_eq!(ss["realitySettings"]["serverName"], "www.apple.com");
        assert_eq!(ss["realitySettings"]["fingerprint"], "firefox");
    }

    #[test]
    fn vless_tcp_reality_vision() {
        let l = "vless://u@1.2.3.4:443?type=tcp&security=reality&pbk=K&sid=ab&sni=yahoo.com&flow=xtls-rprx-vision&fp=chrome#TCP";
        let p = parse_link(l).unwrap();
        assert_eq!(p.transport, "tcp · reality");
        assert_eq!(p.outbound["settings"]["flow"], "xtls-rprx-vision");
        assert_eq!(p.outbound["streamSettings"]["network"], "raw");
    }

    #[test]
    fn xray_json_subscription_item() {
        let cfg = json!({"remarks": "🇩🇪 DE", "outbounds": [
            {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": "de.example.com", "port": 443, "users": [{"id": "u", "encryption": "none"}]}]},
             "streamSettings": {"network": "xhttp", "security": "reality", "sockopt": {"dialerProxy": "fragment"}}},
            {"tag": "direct", "protocol": "freedom"}]});
        let (name, b) = outbound_from_config(&cfg).unwrap();
        assert_eq!(name, "🇩🇪 DE");
        let ob = primary(&b);
        // Ссылка на несуществующий outbound убрана.
        assert!(ob["streamSettings"]["sockopt"].get("dialerProxy").is_none());
        assert_eq!(outbound_endpoint(ob), ("de.example.com".to_string(), 443));
        assert_eq!(outbound_label(ob), "xhttp · reality");
    }

    #[test]
    fn config() {
        let ob = parse_link("vless://u@h.example.com:443?type=xhttp&security=tls&sni=h.example.com#x").unwrap().outbound;
        let c = build_config(&[XrayEntry { tag: "s1", port: 10800, outbound: &ob }], "77.88.8.8", false, "info", ("u", "p"));
        assert_eq!(c["inbounds"][0]["settings"]["accounts"][0]["pass"], "p");
        assert_eq!(c["inbounds"][0]["port"], 10800);
        assert_eq!(c["routing"]["rules"][1]["outboundTag"], "out-s1");
        assert_eq!(c["outbounds"][1]["streamSettings"]["sockopt"]["domainStrategy"], "UseIPv4");
        assert_eq!(c["outbounds"][1]["streamSettings"]["tlsSettings"]["serverName"], "h.example.com");
    }

    /// Цепочка: трафик идёт в «proxy» (XHTTP), а он подключается через
    /// промежуточный сервер. Первым в списке стоит промежуточный — раньше
    /// приложение ошибочно брало его и рвало цепочку.
    #[test]
    fn xray_json_chain() {
        let cfg = json!({"remarks": "DE", "outbounds": [
            {"tag": "relay", "protocol": "vless", "settings": {"vnext": [{"address": "ru.example.com", "port": 443, "users": [{"id": "r"}]}]},
             "streamSettings": {"network": "raw", "security": "reality"}},
            {"tag": "de", "protocol": "vless", "settings": {"vnext": [{"address": "de.example.com", "port": 443, "users": [{"id": "u"}]}]},
             "streamSettings": {"network": "xhttp", "security": "reality", "sockopt": {"dialerProxy": "relay"}}},
            {"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": [
                {"type": "field", "domain": ["geosite:private"], "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", "outboundTag": "de"}]}});
        let (_, b) = outbound_from_config(&cfg).unwrap();
        assert!(is_bundle(&b));
        assert_eq!(b["main"], "de");
        assert_eq!(b["outbounds"].as_array().unwrap().len(), 2);
        assert_eq!(primary(&b)["streamSettings"]["network"], "xhttp");
        assert_eq!(hosts(&b).len(), 2);
        let x = build_config(&[XrayEntry { tag: "s1", port: 1000, outbound: &b }], "1.1.1.1", false, "warn", ("u", "p"));
        let obs = x["outbounds"].as_array().unwrap();
        assert!(obs.iter().any(|o| o["tag"] == "s1~de" && o["streamSettings"]["sockopt"]["dialerProxy"] == "s1~relay"));
        assert_eq!(x["routing"]["rules"][1]["outboundTag"], "s1~de");
    }

    #[test]
    fn xray_json_balancer() {
        let cfg = json!({"remarks": "Авто", "outbounds": [
            {"tag": "proxy-1", "protocol": "vless", "settings": {"address": "a.example.com", "port": 443, "id": "u"}, "streamSettings": {"network": "ws", "security": "tls"}},
            {"tag": "proxy-2", "protocol": "vless", "settings": {"address": "b.example.com", "port": 443, "id": "u"}, "streamSettings": {"network": "ws", "security": "tls"}},
            {"tag": "direct", "protocol": "freedom"}],
            "routing": {"balancers": [{"tag": "auto", "selector": ["proxy-"], "strategy": {"type": "leastPing"}}],
                        "rules": [{"type": "field", "network": "tcp,udp", "balancerTag": "auto"}]}});
        let (_, b) = outbound_from_config(&cfg).unwrap();
        assert!(is_bundle(&b));
        let x = build_config(&[XrayEntry { tag: "s2", port: 1001, outbound: &b }], "1.1.1.1", false, "warn", ("u", "p"));
        assert_eq!(x["routing"]["balancers"][0]["selector"][0], "s2~proxy-");
        assert_eq!(x["routing"]["rules"][1]["balancerTag"], "s2~auto");
        assert_eq!(x["observatory"]["subjectSelector"][0], "s2~proxy-");
    }

    /// Без правил Xray отправляет трафик в первый outbound списка.
    #[test]
    fn xray_json_first_outbound_is_default() {
        let cfg = json!({"outbounds": [
            {"tag": "main", "protocol": "vless", "settings": {"address": "fi.example.com", "port": 443, "id": "u"}, "streamSettings": {"network": "raw", "security": "reality"}},
            {"tag": "hy", "protocol": "hysteria", "settings": {"address": "x.example.com", "port": 443}}]});
        let (_, b) = outbound_from_config(&cfg).unwrap();
        assert_eq!(primary(&b)["protocol"], "vless");
        assert_eq!(b["outbounds"].as_array().unwrap().len(), 1);
    }

    /// hosts и DNS-серверы конфига переносятся, geosite — нет; прямой выход —
    /// первый, и DNS самого Xray идёт через него.
    #[test]
    fn xray_json_dns() {
        let cfg = json!({"outbounds": [
            {"tag": "proxy", "protocol": "vless", "settings": {"address": "nl.example.com", "port": 443, "id": "u"}}],
            "dns": {"hosts": {"nl.example.com": "5.6.7.8", "geosite:category-ads-all": "127.0.0.1"},
                    "servers": ["https://1.1.1.1/dns-query", {"address": "8.8.8.8", "domains": ["geosite:google"]}, "fakedns"]}});
        let (_, b) = outbound_from_config(&cfg).unwrap();
        let x = build_config(&[XrayEntry { tag: "s", port: 1, outbound: &b }], "77.88.8.8", false, "warn", ("u", "p"));
        assert_eq!(x["outbounds"][0]["tag"], "direct");
        assert_eq!(x["dns"]["hosts"]["nl.example.com"], "5.6.7.8");
        assert!(x["dns"]["hosts"].get("geosite:category-ads-all").is_none());
        assert_eq!(x["dns"]["servers"], json!(["https://1.1.1.1/dns-query", "77.88.8.8"]));
        assert_eq!(x["routing"]["rules"][0]["inboundTag"][0], "xray-dns");
    }
}
