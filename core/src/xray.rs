//! Xray-core: разбор ссылок VLESS/VMess/Trojan в outbound Xray и генерация конфига.
//!
//! sing-box не поддерживает XHTTP, VLESS Encryption и REALITY с ML-DSA. Такие серверы
//! запускаются в Xray: для каждого сервера Xray открывает локальный SOCKS-вход
//! на 127.0.0.1, а sing-box подключается к нему как к обычному SOCKS-серверу.
//! TUN, раздельное туннелирование и DNS по-прежнему делает sing-box.
//!
//! Формат конфига сверён с Xray-core v26.10 (infra/conf).

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

/// Из одного конфига Xray достаёт основной outbound (tag "proxy" или первый прокси).
pub fn outbound_from_config(cfg: &Value) -> Option<(String, Value)> {
    let obs = cfg.get("outbounds")?.as_array()?;
    let is_proxy = |o: &&Value| {
        o.get("protocol")
            .and_then(|p| p.as_str())
            .map(|p| XRAY_PROTOCOLS.contains(&p))
            .unwrap_or(false)
    };
    let ob = obs
        .iter()
        .filter(is_proxy)
        .find(|o| o.get("tag").and_then(|t| t.as_str()) == Some("proxy"))
        .or_else(|| obs.iter().find(is_proxy))?;
    let name = cfg
        .get("remarks")
        .and_then(|r| r.as_str())
        .or_else(|| ob.get("tag").and_then(|t| t.as_str()))
        .unwrap_or("Xray")
        .to_string();
    Some((name, clean_outbound(ob)))
}

fn clean_outbound(ob: &Value) -> Value {
    let mut ob = ob.clone();
    if let Some(o) = ob.as_object_mut() {
        o.remove("tag");
        o.remove("sendThrough");
        o.remove("proxySettings");
        if let Some(sock) = o
            .get_mut("streamSettings")
            .and_then(|s| s.get_mut("sockopt"))
            .and_then(|s| s.as_object_mut())
        {
            // Цепочки через другие outbound'ы (фрагментация и т.п.) не переносятся.
            sock.remove("dialerProxy");
        }
    }
    ob
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
pub fn build_config(entries: &[XrayEntry], dns: &str, ipv6: bool, log_level: &str) -> Value {
    let mut inbounds = vec![];
    let mut outbounds = vec![];
    let mut rules = vec![];
    for e in entries {
        let in_tag = format!("in-{}", e.tag);
        let out_tag = format!("out-{}", e.tag);
        inbounds.push(json!({
            "tag": in_tag,
            "listen": "127.0.0.1",
            "port": e.port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": true, "ip": "127.0.0.1"}
        }));
        let mut ob = e.outbound.clone();
        ob["tag"] = json!(out_tag);
        // Адрес сервера разрешаем встроенным DNS Xray: запрос уходит из xray.exe,
        // и sing-box отпускает его напрямую, без петли через VPN.
        let ss = ob
            .as_object_mut()
            .unwrap()
            .entry("streamSettings")
            .or_insert_with(|| json!({}));
        if let Some(ss) = ss.as_object_mut() {
            let sock = ss.entry("sockopt").or_insert_with(|| json!({}));
            if let Some(sock) = sock.as_object_mut() {
                sock.entry("domainStrategy")
                    .or_insert_with(|| json!(if ipv6 { "UseIP" } else { "UseIPv4" }));
            }
        }
        outbounds.push(ob);
        rules.push(json!({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag}));
    }
    outbounds.push(json!({"protocol": "freedom", "tag": "direct"}));
    let level = match log_level {
        "debug" => "debug",
        "error" => "error",
        "info" => "info",
        _ => "warning",
    };
    json!({
        "log": {"loglevel": level},
        "dns": {"servers": [dns], "queryStrategy": if ipv6 { "UseIP" } else { "UseIPv4" }},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules}
    })
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
        let (name, ob) = outbound_from_config(&cfg).unwrap();
        assert_eq!(name, "🇩🇪 DE");
        assert!(ob.get("tag").is_none());
        assert!(ob["streamSettings"]["sockopt"].get("dialerProxy").is_none());
        assert_eq!(outbound_endpoint(&ob), ("de.example.com".to_string(), 443));
        assert_eq!(outbound_label(&ob), "xhttp · reality");
    }

    #[test]
    fn config() {
        let ob = parse_link("vless://u@h.example.com:443?type=xhttp&security=tls&sni=h.example.com#x").unwrap().outbound;
        let c = build_config(&[XrayEntry { tag: "s1", port: 10800, outbound: &ob }], "77.88.8.8", false, "info");
        assert_eq!(c["inbounds"][0]["port"], 10800);
        assert_eq!(c["routing"]["rules"][0]["outboundTag"], "out-s1");
        assert_eq!(c["outbounds"][0]["streamSettings"]["sockopt"]["domainStrategy"], "UseIPv4");
        assert_eq!(c["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"], "h.example.com");
    }
}
