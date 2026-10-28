//! Генерация конфигурации sing-box (формат 1.12+, проверено на 1.14).

use std::path::Path;

use serde_json::{json, Map, Value};

use crate::model::{AppMode, CoreChoice, Mode, Platform, Runtime, Server, Settings};
use crate::xray::{self, XrayEntry};

pub const TAG_PROXY: &str = "proxy";
pub const TAG_AUTO: &str = "auto";
pub const TAG_DIRECT: &str = "direct";
pub const URL_TEST: &str = "https://www.gstatic.com/generate_204";

/// Файлы наборов правил, которые кладутся рядом с sing-box (scripts/fetch-singbox.mjs).
pub const RULESET_GEOSITE_RU: &str = "geosite-category-ru.srs";
pub const RULESET_GEOIP_RU: &str = "geoip-ru.srs";
/// На Android файлы лежат среди нативных библиотек, поэтому называются lib*.so.
pub const RULESET_GEOSITE_RU_ANDROID: &str = "libgeositeru.so";
pub const RULESET_GEOIP_RU_ANDROID: &str = "libgeoipru.so";

/// Домены верхнего уровня, которые считаются «российскими» даже без набора правил.
const RU_SUFFIXES: &[&str] = &[".ru", ".su", ".xn--p1ai", ".moscow", ".xn--80adxhks", ".tatar"];

pub struct BuildInput<'a> {
    pub settings: &'a Settings,
    /// Серверы одной подписки (только пригодные к использованию).
    pub servers: Vec<&'a Server>,
    /// `auto` или id сервера, выбранный по умолчанию в селекторе.
    pub default: String,
    /// Папка с файлами .srs. None — наборы правил не используются.
    pub ruleset_dir: Option<&'a Path>,
    /// Имя процесса Xray (`xray.exe`), если ядро Xray установлено.
    pub xray_process: Option<&'a str>,
    /// Режим, в котором реально запускаемся (может отличаться от настроек
    /// после автоматического перехода TUN → системный прокси).
    pub mode: Mode,
    pub platform: Platform,
    /// Случайные порты и пароли этого запуска.
    pub runtime: &'a Runtime,
}

/// Имя TUN-адаптера в Windows. Нейтральное, чтобы не выдавать VPN по названию.
pub const TUN_NAME: &str = "Network Adapter";
pub const TUN_ADDR4: &str = "172.19.0.1/30";
pub const TUN_ADDR6: &str = "fdfe:dcba:9876::1/126";

/// Сколько серверов пойдёт через Xray (нужно заранее выделить им порты).
pub fn xray_count(servers: &[&Server], settings: &Settings) -> usize {
    servers.iter().filter(|s| uses_xray(s, settings)).count()
}

/// Готовые конфигурации: sing-box всегда, Xray — если есть серверы для него.
pub struct Built {
    pub singbox: Value,
    pub xray: Option<Value>,
}

/// Через какое ядро пойдёт сервер.
pub fn uses_xray(s: &Server, settings: &Settings) -> bool {
    s.xray.is_some()
        && (s.outbound.is_none()
            || (settings.core == CoreChoice::Xray
                && matches!(s.protocol.as_str(), "vless" | "vmess" | "trojan")))
}

/// IP DNS-сервера для Xray (адреса серверов разрешаются мимо VPN).
fn plain_dns_ip(addr: &str) -> String {
    let a = addr.trim();
    let a = a.split("://").nth(1).unwrap_or(a);
    let host = a.split(['/', ':']).next().unwrap_or("");
    if host.parse::<std::net::IpAddr>().is_ok() {
        host.to_string()
    } else {
        "77.88.8.8".to_string()
    }
}

// ---------------------------------------------------------------------------
// Списки доменов / IP / приложений
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Matchers {
    domain: Vec<String>,
    suffix: Vec<String>,
    keyword: Vec<String>,
    regex: Vec<String>,
    ip_cidr: Vec<String>,
}

impl Matchers {
    fn from_entries(entries: &[String]) -> Self {
        let mut m = Matchers::default();
        for raw in entries {
            let e = raw.trim();
            if e.is_empty() || e.starts_with("//") || e.starts_with('#') {
                continue;
            }
            if let Some(v) = e.strip_prefix("regexp:") {
                m.regex.push(v.to_string());
            } else if let Some(v) = e.strip_prefix("keyword:") {
                m.keyword.push(v.to_lowercase());
            } else if let Some(v) = e.strip_prefix("full:") {
                m.domain.push(v.to_lowercase());
            } else if let Some(cidr) = as_cidr(e) {
                m.ip_cidr.push(cidr);
            } else if let Some(host) = as_host(e) {
                m.suffix.push(host);
            }
        }
        m
    }

    fn is_empty(&self, with_ip: bool) -> bool {
        self.domain.is_empty()
            && self.suffix.is_empty()
            && self.keyword.is_empty()
            && self.regex.is_empty()
            && (!with_ip || self.ip_cidr.is_empty())
    }

    /// Поля правила. В DNS-правилах IP-условия не используем (в 1.14 они устарели).
    fn fields(&self, with_ip: bool) -> Map<String, Value> {
        let mut r = Map::new();
        let mut put = |k: &str, v: &Vec<String>| {
            if !v.is_empty() {
                r.insert(k.into(), json!(v));
            }
        };
        put("domain", &self.domain);
        put("domain_suffix", &self.suffix);
        put("domain_keyword", &self.keyword);
        put("domain_regex", &self.regex);
        if with_ip {
            put("ip_cidr", &self.ip_cidr);
        }
        r
    }
}

fn as_cidr(e: &str) -> Option<String> {
    let (ip, mask) = match e.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (e, None),
    };
    let addr: std::net::IpAddr = ip.trim_matches(|c| c == '[' || c == ']').parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let bits = match mask {
        Some(m) => m.parse::<u8>().ok().filter(|b| *b <= max)?,
        None => max,
    };
    Some(format!("{addr}/{bits}"))
}

/// Принимает `youtube.com`, `*.youtube.com`, `.youtube.com`, `https://youtube.com/watch`.
fn as_host(e: &str) -> Option<String> {
    let mut s = e.to_lowercase();
    if let Some((_, rest)) = s.split_once("://") {
        s = rest.to_string();
    }
    let s = s.split(['/', '?', '#']).next().unwrap_or("");
    let s = s.rsplit('@').next().unwrap_or(s);
    let s = s.split(':').next().unwrap_or(s);
    let s = s.trim_start_matches("*.").trim_start_matches('.').trim_end_matches('.');
    let ok = !s.is_empty()
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '.' || c == '_');
    ok.then(|| s.to_string())
}

/// `chrome.exe` → process_name, `C:\Games\x.exe` → process_path,
/// `C:\Games\` → все программы из папки.
fn process_fields(apps: &[String]) -> Map<String, Value> {
    let mut names = vec![];
    let mut paths = vec![];
    let mut regex = vec![];
    for a in apps {
        let a = a.trim().trim_matches('"');
        if a.is_empty() {
            continue;
        }
        if a.ends_with('\\') || a.ends_with('/') {
            regex.push(format!("(?i)^{}", regex_escape(a)));
        } else if a.contains('\\') || a.contains('/') {
            paths.push(a.to_string());
        } else {
            names.push(a.to_string());
        }
    }
    let mut r = Map::new();
    if !names.is_empty() {
        r.insert("process_name".into(), json!(names));
    }
    if !paths.is_empty() {
        r.insert("process_path".into(), json!(paths));
    }
    if !regex.is_empty() {
        r.insert("process_path_regex".into(), json!(regex));
    }
    r
}

fn regex_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if "\\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

/// `https://1.1.1.1/dns-query`, `tls://dns.google`, `8.8.8.8`, `udp://9.9.9.9:53`, `local`.
fn dns_server(tag: &str, addr: &str, detour: Option<&str>) -> (Value, bool) {
    let addr = addr.trim();
    if addr.is_empty() || addr.eq_ignore_ascii_case("local") {
        return (json!({"type": "local", "tag": tag}), false);
    }
    let (kind, rest) = match addr.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => ("udp".to_string(), addr),
    };
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h, Some(format!("/{p}"))),
        None => (rest, None),
    };
    let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
        let (h, p) = v6.split_once(']').unwrap_or((v6, ""));
        (h.to_string(), p.trim_start_matches(':').parse::<u16>().ok())
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.parse().ok()),
            _ => (hostport.to_string(), None),
        }
    };
    let mut s = Map::new();
    s.insert("type".into(), json!(kind));
    s.insert("tag".into(), json!(tag));
    s.insert("server".into(), json!(host));
    if let Some(p) = port {
        s.insert("server_port".into(), json!(p));
    }
    if let (Some(p), "https" | "h3") = (&path, kind.as_str()) {
        if p != "/dns-query" {
            s.insert("path".into(), json!(p));
        }
    }
    if let Some(d) = detour {
        s.insert("detour".into(), json!(d));
    }
    let needs_resolver = host.parse::<std::net::IpAddr>().is_err();
    if needs_resolver {
        s.insert("domain_resolver".into(), json!("dns-bootstrap"));
    }
    (Value::Object(s), needs_resolver)
}

// ---------------------------------------------------------------------------
// Сборка конфига
// ---------------------------------------------------------------------------

pub fn build(input: &BuildInput) -> Result<Built, String> {
    let st = input.settings;
    let rt = input.runtime;
    let split = &st.split;
    let android = input.platform == Platform::Android;
    if input.servers.is_empty() {
        return Err("в выбранной подписке нет рабочих серверов".into());
    }

    // ---- outbounds ----
    let mut outbounds = vec![];
    let mut tags = vec![];
    let mut xray_entries: Vec<(String, u16, Value)> = vec![];
    let mut xray_hosts: Vec<String> = vec![];
    for s in &input.servers {
        let ob = if uses_xray(s, st) {
            if input.xray_process.is_none() {
                if s.id == input.default {
                    return Err("для этого сервера нужно ядро Xray, но оно не найдено — переустановите приложение".into());
                }
                continue;
            }
            let port = *rt
                .xray_ports
                .get(xray_entries.len())
                .ok_or("не хватило портов для Xray")?;
            xray_entries.push((s.id.clone(), port, s.xray.clone().unwrap()));
            if !s.address.is_empty() && s.address.parse::<std::net::IpAddr>().is_err() {
                xray_hosts.push(s.address.to_lowercase());
            }
            json!({
                "type": "socks",
                "tag": s.id,
                "server": "127.0.0.1",
                "server_port": port,
                "version": "5",
                "username": rt.socks_user,
                "password": rt.socks_pass
            })
        } else {
            let mut ob = s.outbound.clone().ok_or("сервер без конфигурации")?;
            ob["tag"] = json!(s.id);
            ob
        };
        tags.push(s.id.clone());
        outbounds.push(ob);
    }
    if tags.is_empty() {
        return Err("в выбранной подписке нет серверов, которые можно запустить".into());
    }
    let default = if input.default == TAG_AUTO || tags.contains(&input.default) {
        input.default.clone()
    } else {
        TAG_AUTO.to_string()
    };
    let mut selector_list = vec![TAG_AUTO.to_string()];
    selector_list.extend(tags.iter().cloned());
    outbounds.insert(
        0,
        json!({
            "type": "selector",
            "tag": TAG_PROXY,
            "outbounds": selector_list,
            "default": default,
            "interrupt_exist_connections": true
        }),
    );
    outbounds.insert(
        1,
        json!({
            "type": "urltest",
            "tag": TAG_AUTO,
            "outbounds": tags,
            "url": URL_TEST,
            "interval": "5m",
            "tolerance": 50
        }),
    );
    outbounds.push(json!({"type": "direct", "tag": TAG_DIRECT}));

    // ---- наборы правил ----
    let mut rule_sets = vec![];
    let mut geosite_ru = false;
    let mut geoip_ru = false;
    if split.ru_direct {
        if let Some(dir) = input.ruleset_dir {
            let (gs, gi) = if android {
                (RULESET_GEOSITE_RU_ANDROID, RULESET_GEOIP_RU_ANDROID)
            } else {
                (RULESET_GEOSITE_RU, RULESET_GEOIP_RU)
            };
            for (tag, file, flag) in [
                ("geosite-ru", gs, &mut geosite_ru),
                ("geoip-ru", gi, &mut geoip_ru),
            ] {
                let p = dir.join(file);
                if p.exists() {
                    rule_sets.push(json!({
                        "type": "local",
                        "tag": tag,
                        "format": "binary",
                        "path": p.to_string_lossy()
                    }));
                    *flag = true;
                }
            }
        }
    }

    let direct_m = Matchers::from_entries(&split.direct_domains);
    let proxy_m = Matchers::from_entries(&split.proxy_domains);
    // На Android приложения разделяет сам VpnService: в ядро попадает только
    // трафик тех приложений, которые должны идти через VPN.
    let apps = if android {
        Map::new()
    } else {
        process_fields(split.active_apps())
    };
    let app_split = !apps.is_empty();
    let include_mode = app_split && split.app_mode == AppMode::Include;

    // ---- DNS ----
    // На Android у отдельного процесса sing-box нет системного резолвера.
    let dns_direct_addr = if android && st.dns_direct.trim().eq_ignore_ascii_case("local") {
        "77.88.8.8"
    } else {
        st.dns_direct.as_str()
    };
    let (remote, r_boot) = dns_server("dns-remote", &st.dns_remote, Some(TAG_PROXY));
    let (direct, d_boot) = dns_server("dns-direct", dns_direct_addr, None);
    let mut dns_servers = vec![remote, direct];
    if r_boot || d_boot {
        dns_servers.push(json!({"type": "udp", "tag": "dns-bootstrap", "server": "77.88.8.8"}));
    }
    let mut dns_rules = vec![];
    let xray_used = !xray_entries.is_empty();
    if xray_used {
        // Адреса серверов Xray всегда разрешаем напрямую, иначе будет петля:
        // чтобы подключиться к серверу, нужен DNS, а DNS идёт через этот же сервер.
        let mut r = Map::new();
        if let (Some(p), false) = (input.xray_process, android) {
            r.insert("process_name".into(), json!([p]));
        }
        if !xray_hosts.is_empty() {
            r.insert("domain".into(), json!(xray_hosts));
        }
        if r.len() > 0 {
            r.insert("server".into(), json!("dns-direct"));
            dns_rules.push(Value::Object(r));
        }
    }
    if !direct_m.is_empty(false) {
        let mut r = direct_m.fields(false);
        r.insert("server".into(), json!("dns-direct"));
        dns_rules.push(Value::Object(r));
    }
    if !proxy_m.is_empty(false) {
        let mut r = proxy_m.fields(false);
        r.insert("server".into(), json!("dns-remote"));
        dns_rules.push(Value::Object(r));
    }
    if app_split {
        let mut r = apps.clone();
        r.insert(
            "server".into(),
            json!(if include_mode { "dns-remote" } else { "dns-direct" }),
        );
        dns_rules.push(Value::Object(r));
    }
    if split.ru_direct && !include_mode {
        dns_rules.push(json!({"domain_suffix": RU_SUFFIXES, "server": "dns-direct"}));
        if geosite_ru {
            dns_rules.push(json!({"rule_set": ["geosite-ru"], "server": "dns-direct"}));
        }
    }
    let dns = json!({
        "servers": dns_servers,
        "rules": dns_rules,
        "final": if include_mode { "dns-direct" } else { "dns-remote" },
        "strategy": if st.ipv6 { "prefer_ipv4" } else { "ipv4_only" }
    });

    // ---- inbounds ----
    let mut inbounds = vec![];
    if !android && input.mode == Mode::Tun {
        // IPv6-адрес нужен всегда: так IPv6-трафик тоже попадает в TUN и не утекает
        // мимо VPN, даже если IPv6 выключен (тогда он блокируется правилом ниже).
        inbounds.push(json!({
            "type": "tun",
            "tag": "tun-in",
            "interface_name": TUN_NAME,
            "address": [TUN_ADDR4, TUN_ADDR6],
            "mtu": 9000,
            "auto_route": true,
            "strict_route": true,
            "stack": "mixed"
        }));
    }
    if rt.mixed_port != 0 {
        let mut m = json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": rt.mixed_port
        });
        if rt.mixed_auth {
            m["users"] = json!([{"username": rt.socks_user, "password": rt.socks_pass}]);
        }
        inbounds.push(m);
    }
    if st.allow_lan && !st.lan_password.is_empty() {
        inbounds.push(json!({
            "type": "mixed",
            "tag": "lan-in",
            "listen": "0.0.0.0",
            "listen_port": st.lan_port,
            "users": [{"username": "tunnelka", "password": st.lan_password}]
        }));
    }

    // ---- маршрутизация ----
    let mut rules = vec![
        json!({"action": "sniff"}),
        json!({"protocol": "dns", "action": "hijack-dns"}),
    ];
    if !st.ipv6 {
        rules.push(json!({"ip_version": 6, "action": "reject"}));
    }
    if xray_used && !android {
        // Сам Xray ходит к серверам напрямую (в режиме TUN его трафик тоже
        // попадает в sing-box — без этого правила получится петля).
        // На Android процессы приложения исключены из VPN системой.
        rules.push(json!({"process_name": [input.xray_process.unwrap()], "outbound": TAG_DIRECT}));
    }
    rules.push(json!({"ip_is_private": true, "outbound": TAG_DIRECT}));
    if !direct_m.is_empty(true) {
        let mut r = direct_m.fields(true);
        r.insert("outbound".into(), json!(TAG_DIRECT));
        rules.push(Value::Object(r));
    }
    if !proxy_m.is_empty(true) {
        let mut r = proxy_m.fields(true);
        r.insert("outbound".into(), json!(TAG_PROXY));
        rules.push(Value::Object(r));
    }
    if app_split {
        let mut r = apps.clone();
        r.insert(
            "outbound".into(),
            json!(if include_mode { TAG_PROXY } else { TAG_DIRECT }),
        );
        rules.push(Value::Object(r));
    }
    if split.ru_direct && !include_mode {
        rules.push(json!({"domain_suffix": RU_SUFFIXES, "outbound": TAG_DIRECT}));
        let mut sets = vec![];
        if geosite_ru {
            sets.push("geosite-ru");
        }
        if geoip_ru {
            sets.push("geoip-ru");
        }
        if !sets.is_empty() {
            rules.push(json!({"rule_set": sets, "outbound": TAG_DIRECT}));
        }
    }

    let mut route = json!({
        "rules": rules,
        "final": if include_mode { TAG_DIRECT } else { TAG_PROXY },
        "default_domain_resolver": "dns-direct"
    });
    if !android {
        // На Android приложению недоступен netlink, а исключение из VPN
        // обеспечивает сама система.
        route["auto_detect_interface"] = json!(true);
        if app_split || xray_used {
            route["find_process"] = json!(true);
        }
    }
    if !rule_sets.is_empty() {
        route["rule_set"] = json!(rule_sets);
    }

    let clash = json!({
        "external_controller": format!("127.0.0.1:{}", rt.clash_port),
        "secret": rt.secret
    });

    let xray_cfg = xray_used.then(|| {
        let entries: Vec<XrayEntry> = xray_entries
            .iter()
            .map(|(tag, port, ob)| XrayEntry { tag, port: *port, outbound: ob })
            .collect();
        xray::build_config(
            &entries,
            &plain_dns_ip(dns_direct_addr),
            st.ipv6,
            &st.log_level,
            (&rt.socks_user, &rt.socks_pass),
        )
    });

    let singbox = json!({
        "log": {"level": st.log_level, "timestamp": true},
        "dns": dns,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route,
        "experimental": {"clash_api": clash}
    });
    Ok(Built { singbox, xray: xray_cfg })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::links::link_to_server;
    use crate::model::SplitTunnel;

    fn servers() -> Vec<Server> {
        [
            "vless://u@a.example.com:443?security=reality&pbk=k&sid=1&sni=x.com#A",
            "hy2://p@b.example.com:443#B",
        ]
        .iter()
        .map(|l| link_to_server(l, "t").unwrap())
        .collect()
    }

    fn rt() -> Runtime {
        Runtime {
            mixed_port: 0,
            mixed_auth: false,
            clash_port: 40001,
            secret: "sec".into(),
            socks_user: "u".into(),
            socks_pass: "p".into(),
            xray_ports: vec![40100, 40101],
        }
    }

    fn input<'a>(st: &'a Settings, s: &'a [Server], default: &str, r: &'a Runtime) -> BuildInput<'a> {
        BuildInput {
            settings: st,
            servers: s.iter().collect(),
            default: default.into(),
            ruleset_dir: None,
            xray_process: Some("xray.exe"),
            mode: st.mode,
            platform: Platform::Windows,
            runtime: r,
        }
    }

    #[test]
    fn exclude_apps_and_domains() {
        let mut st = Settings::default();
        st.split = SplitTunnel {
            app_mode: AppMode::Exclude,
            apps_exclude: vec!["Discord.exe".into(), "C:\\Games\\".into(), "D:\\x\\y.exe".into()],
            apps_include: vec!["chrome.exe".into()],
            proxy_domains: vec!["https://www.youtube.com/watch?v=1".into(), "*.googlevideo.com".into()],
            direct_domains: vec!["10.20.0.0/16".into(), "keyword:bank".into(), "8.8.8.8".into()],
            ..Default::default()
        };
        let s = servers();
        let r = rt();
        let cfg = build(&input(&st, &s, &s[0].id, &r)).unwrap().singbox;
        let text = serde_json::to_string_pretty(&cfg).unwrap();
        assert_eq!(cfg["route"]["final"], "proxy");
        assert_eq!(cfg["route"]["find_process"], true);
        assert_eq!(cfg["outbounds"][0]["default"], s[0].id.as_str());
        assert!(text.contains("\"Discord.exe\""));
        assert!(!text.contains("chrome.exe"), "список другого режима не должен попадать в конфиг");
        assert!(text.contains("(?i)^C:\\\\\\\\Games\\\\\\\\"), "{text}");
        assert!(text.contains("\"www.youtube.com\""));
        assert!(text.contains("\"8.8.8.8/32\""));
        let tun = &cfg["inbounds"][0];
        assert_eq!(tun["type"], "tun");
        assert_eq!(tun["address"][1], TUN_ADDR6);
        // В режиме TUN локальный прокси не открывается.
        assert_eq!(cfg["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(cfg["experimental"]["clash_api"]["secret"], "sec");
        assert_eq!(cfg["experimental"]["clash_api"]["external_controller"], "127.0.0.1:40001");
        // IPv6 выключен — блокируется, а не утекает мимо VPN.
        assert_eq!(cfg["route"]["rules"][2]["ip_version"], 6);
        assert!(!cfg["dns"].to_string().contains("ip_cidr"));
    }

    #[test]
    fn include_mode_defaults_to_direct() {
        let mut st = Settings::default();
        st.mode = Mode::Proxy;
        st.split.app_mode = AppMode::Include;
        st.split.apps_include = vec!["chrome.exe".into()];
        let s = servers();
        let mut r = rt();
        r.mixed_port = 45000;
        let cfg = build(&input(&st, &s, "auto", &r)).unwrap().singbox;
        assert_eq!(cfg["route"]["final"], "direct");
        assert_eq!(cfg["dns"]["final"], "dns-direct");
        assert_eq!(cfg["inbounds"][0]["type"], "mixed");
        assert_eq!(cfg["inbounds"][0]["listen_port"], 45000);
        assert!(cfg["inbounds"][0].get("users").is_none());
    }

    #[test]
    fn legacy_apps_migrate_to_current_mode() {
        let mut sp: SplitTunnel = serde_json::from_str(r#"{"app_mode":"include","apps":["a.exe","A.exe"]}"#).unwrap();
        sp.normalize();
        assert_eq!(sp.apps_include, vec!["a.exe"]);
        assert!(sp.apps_exclude.is_empty());
        assert!(!serde_json::to_string(&sp).unwrap().contains("\"apps\""));
    }

    #[test]
    fn android_config() {
        let mut st = Settings::default();
        st.split.app_mode = AppMode::Include;
        st.split.apps_include = vec!["org.telegram.messenger".into()];
        st.dns_direct = "local".into();
        let s = servers();
        let mut r = rt();
        r.mixed_port = 45000;
        r.mixed_auth = true;
        let mut i = input(&st, &s, "auto", &r);
        i.platform = Platform::Android;
        let cfg = build(&i).unwrap().singbox;
        // Приложения разделяет VpnService, в ядре всё идёт через VPN.
        assert_eq!(cfg["route"]["final"], "proxy");
        assert!(cfg["route"].get("auto_detect_interface").is_none());
        assert!(cfg["route"].get("find_process").is_none());
        assert_eq!(cfg["inbounds"][0]["type"], "mixed");
        assert_eq!(cfg["inbounds"][0]["users"][0]["password"], "p");
        assert_eq!(cfg["dns"]["servers"][1]["type"], "udp");
        assert!(!cfg.to_string().contains("process_name"));
    }

    #[test]
    fn lan_sharing_requires_password() {
        let mut st = Settings::default();
        st.allow_lan = true;
        st.lan_password = "pw".into();
        let s = servers();
        let r = rt();
        let cfg = build(&input(&st, &s, "auto", &r)).unwrap().singbox;
        let lan = cfg["inbounds"].as_array().unwrap().iter().find(|i| i["tag"] == "lan-in").unwrap();
        assert_eq!(lan["listen"], "0.0.0.0");
        assert_eq!(lan["users"][0]["password"], "pw");
    }

    #[test]
    fn xhttp_via_xray() {
        let st = Settings::default();
        let s: Vec<Server> = [
            "vless://u@xh.example.com:443?type=xhttp&security=reality&pbk=k&sid=1&sni=www.apple.com#XH",
            "vless://u@1.2.3.4:443?type=tcp&security=reality&pbk=k&sid=1&flow=xtls-rprx-vision#TCP",
        ]
        .iter()
        .map(|l| link_to_server(l, "t").unwrap())
        .collect();
        let r = rt();
        assert_eq!(xray_count(&s.iter().collect::<Vec<_>>(), &st), 1);
        let b = build(&input(&st, &s, &s[0].id, &r)).unwrap();
        let sb = b.singbox;
        let x = b.xray.expect("нужен конфиг Xray");
        // XHTTP → SOCKS на Xray (с паролем), TCP+REALITY → напрямую в sing-box.
        let xh = sb["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == s[0].id.as_str()).unwrap();
        assert_eq!(xh["type"], "socks");
        assert_eq!(xh["server_port"], 40100);
        assert_eq!(xh["password"], "p");
        let tcp = sb["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == s[1].id.as_str()).unwrap();
        assert_eq!(tcp["type"], "vless");
        assert_eq!(x["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(x["inbounds"][0]["port"], 40100);
        assert_eq!(x["inbounds"][0]["settings"]["auth"], "password");
        // Защита от петли.
        let rules = sb["route"]["rules"].as_array().unwrap();
        let loop_rule = rules.iter().find(|r| r.get("process_name").is_some()).unwrap();
        assert_eq!(loop_rule["process_name"][0], "xray.exe");
        assert_eq!(loop_rule["outbound"], "direct");
        assert_eq!(sb["dns"]["rules"][0]["domain"][0], "xh.example.com");

        // «Всегда Xray»: оба сервера через Xray.
        let mut st2 = Settings::default();
        st2.core = CoreChoice::Xray;
        let b = build(&input(&st2, &s, "auto", &r)).unwrap();
        assert_eq!(b.xray.unwrap()["inbounds"].as_array().unwrap().len(), 2);

        // Без Xray XHTTP-сервер выбрать нельзя.
        let mut i = input(&st, &s, &s[0].id, &r);
        i.xray_process = None;
        assert!(build(&i).is_err());
    }

    #[test]
    fn dns_parsing() {
        let (v, b) = dns_server("x", "https://dns.yandex.ru/dns-query", None);
        assert_eq!(v["type"], "https");
        assert_eq!(v["server"], "dns.yandex.ru");
        assert!(b);
        let (v, b) = dns_server("x", "8.8.8.8:5353", Some("proxy"));
        assert_eq!(v["type"], "udp");
        assert_eq!(v["server_port"], 5353);
        assert_eq!(v["detour"], "proxy");
        assert!(!b);
    }
}
