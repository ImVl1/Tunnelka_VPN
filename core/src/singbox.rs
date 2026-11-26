//! Генерация конфигурации sing-box (формат 1.12+, проверено на 1.14).

use std::path::Path;

use serde_json::{json, Map, Value};

use crate::model::{AppMode, CoreChoice, Mode, Platform, Runtime, Server, Settings, ROUTE_DIRECT};
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
/// Зарубежные сервисы на доменах .ru: всегда через VPN. Например, через
/// accounts.google.ru Google проверяет вход — увидев там российский IP, он
/// считает, что пользователь в России (Gemini и другие сервисы недоступны).
const FOREIGN_RU: &[&str] = &["google.ru", "youtube.ru", "googleusercontent.ru", "blogspot.ru"];

pub struct BuildInput<'a> {
    pub settings: &'a Settings,
    /// Серверы всех подписок (только пригодные к использованию): так можно
    /// переключаться между любыми серверами без переподключения.
    pub servers: Vec<&'a Server>,
    /// Автовыбор отдельных подписок: тег группы → id её серверов.
    /// Общий автовыбор (`auto`) — по всем серверам.
    pub autos: Vec<(String, Vec<String>)>,
    /// `auto`, тег автовыбора подписки или id сервера, выбранный по умолчанию.
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
    servers
        .iter()
        .filter(|s| uses_xray(s, settings))
        .map(|s| s.xray.as_ref().map(|x| xray::expand(x).len()).unwrap_or(1))
        .sum()
}

/// Готовые конфигурации: sing-box всегда, Xray — если есть серверы для него.
pub struct Built {
    pub singbox: Value,
    pub xray: Option<Value>,
    /// Серверы с автовыбором внутри (балансировщик провайдера): id сервера →
    /// теги его частей. Пинг такого сервера — лучший из пингов частей.
    pub groups: std::collections::HashMap<String, Vec<String>>,
    /// Конфиг для «белого интернета»: весь трафик идёт через сервер.
    pub domestic: bool,
    /// Всё, что можно выбрать без переподключения: серверы и группы автовыбора.
    pub tags: Vec<String>,
    /// Группы автовыбора: тег → серверы (зарубежные, затем российские).
    pub autos: std::collections::HashMap<String, Vec<String>>,
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
    let hostport = a.split('/').next().unwrap_or("");
    let host = if let Some(v6) = hostport.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else if hostport.parse::<std::net::IpAddr>().is_ok() {
        hostport
    } else {
        hostport.rsplit_once(':').map(|(h, _)| h).unwrap_or(hostport)
    };
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        ip.to_string()
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
        // В строке может быть несколько адресов через запятую или пробел
        // (кроме регулярных выражений — в них запятая и пробел значимы).
        let parts = entries.iter().flat_map(|raw| {
            let e = raw.trim();
            if e.starts_with("regexp:") {
                vec![e.to_string()]
            } else {
                e.split([',', ' ', '\t', ';']).map(|x| x.trim().to_string()).collect()
            }
        });
        for e in parts {
            let e = e.as_str();
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
    let mut s = e.trim();
    if let Some((_, rest)) = s.split_once("://") {
        s = rest.split(['/', '?', '#']).next().unwrap_or("");
        s = s.rsplit('@').next().unwrap_or(s);
    }
    let (ip, mask) = match s.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };
    let ip_str = if let Some(v6) = ip.strip_prefix('[') {
        let (inner, rest) = v6.split_once(']')?;
        if !rest.is_empty() && !rest.starts_with(':') {
            return None;
        }
        inner
    } else if ip.parse::<std::net::IpAddr>().is_ok() {
        ip
    } else if let Some((h, port)) = ip.split_once(':') {
        if !h.contains(':') && port.parse::<u16>().is_ok() {
            h
        } else {
            ip
        }
    } else {
        ip
    };
    let addr: std::net::IpAddr = ip_str.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let bits = match mask {
        Some(m) => m.parse::<u8>().ok().filter(|b| *b <= max)?,
        None => max,
    };
    Some(format!("{addr}/{bits}"))
}

/// Принимает `youtube.com`, `*.youtube.com`, `.youtube.com`, `*.ru`, `*.рф` (все сайты
/// в зоне), адрес из браузера `https://www.youtube.com/watch?v=…`.
/// Кириллические и другие IDN-домены переводятся в Punycode (DNS и SNI работают с ASCII).
fn as_host(e: &str) -> Option<String> {
    let mut s = e.to_lowercase();
    let url = s.contains("://");
    if let Some((_, rest)) = s.split_once("://") {
        s = rest.to_string();
    }
    let s = s.split(['/', '?', '#']).next().unwrap_or("");
    let s = s.rsplit('@').next().unwrap_or(s);
    if s.starts_with('[') {
        return None;
    }
    let s = s.split(':').next().unwrap_or(s);
    let s = s.trim_start_matches('*').trim_start_matches('.').trim_end_matches('.');
    // Из адреса сайта «www.» убираем: правило должно касаться всего сайта.
    let s = match s.strip_prefix("www.") {
        Some(rest) if url && rest.contains('.') => rest,
        _ => s,
    };
    if s.is_empty() {
        return None;
    }
    let ascii = if s.is_ascii() {
        s.to_string()
    } else {
        reqwest::Url::parse(&format!("http://{s}"))
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))?
    };
    let ok = !ascii.is_empty()
        && ascii.parse::<std::net::IpAddr>().is_err()
        && ascii
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_');
    ok.then_some(ascii)
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
    let mut groups = std::collections::HashMap::new();
    let mut seen = std::collections::HashSet::new();
    for s in &input.servers {
        // Один и тот же сервер может быть в нескольких подписках.
        if !seen.insert(s.id.clone()) {
            continue;
        }
        let ob = if uses_xray(s, st) {
            if input.xray_process.is_none() {
                if s.id == input.default {
                    return Err("для этого сервера нужно ядро Xray, но оно не найдено — переустановите приложение".into());
                }
                continue;
            }
            let xv = s.xray.clone().unwrap();
            xray_hosts.extend(xray::hosts(&xv));
            let parts = xray::expand(&xv);
            let socks = |tag: &str, port: u16| {
                json!({
                    "type": "socks",
                    "tag": tag,
                    "server": "127.0.0.1",
                    "server_port": port,
                    "version": "5",
                    "username": rt.socks_user,
                    "password": rt.socks_pass
                })
            };
            let next_port = |used: usize| rt.xray_ports.get(used).copied().ok_or("не хватило портов для Xray");
            if parts.len() == 1 {
                let port = next_port(xray_entries.len())?;
                xray_entries.push((s.id.clone(), port, parts.into_iter().next().unwrap()));
                socks(&s.id, port)
            } else {
                // Автовыбор провайдера: части — отдельные входы Xray, выбирает sing-box.
                let mut members = vec![];
                for (i, part) in parts.into_iter().enumerate() {
                    let port = next_port(xray_entries.len())?;
                    let tag = format!("{}~{i}", s.id);
                    xray_entries.push((tag.clone(), port, part));
                    outbounds.push(socks(&tag, port));
                    members.push(tag);
                }
                groups.insert(s.id.clone(), members.clone());
                // Группа пассивная: сама она серверы не проверяет (иначе при каждом
                // подключении — десятки соединений разом). Лучший сервер внутри
                // выбирает приложение, понемногу; до этого работает первый.
                json!({
                    "type": "selector",
                    "tag": s.id,
                    "outbounds": members,
                    "default": members[0],
                    "interrupt_exist_connections": false
                })
            }
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
    // Российские серверы в автовыбор не входят: через них сайты видят
    // российский IP. Если других нет — входят все.
    let auto_members = |ids: &[String]| -> Vec<String> {
        let ok: Vec<&Server> = input.servers.iter().copied().filter(|s| ids.contains(&s.id) && tags.contains(&s.id)).collect();
        let foreign: Vec<&Server> = ok.iter().copied().filter(|s| !s.is_domestic()).collect();
        let pick = if foreign.is_empty() { ok } else { foreign };
        let mut out: Vec<String> = vec![];
        for s in pick {
            if !out.contains(&s.id) {
                out.push(s.id.clone());
            }
        }
        out
    };
    // Состав группы автовыбора: сначала зарубежные серверы, в конце российские.
    // Российский приложение выберет, только если не ответил ни один зарубежный
    // (например, при «белых списках» у оператора).
    let auto_all = |ids: &[String]| -> Vec<String> {
        let mut out: Vec<String> = vec![];
        let ok = || input.servers.iter().copied().filter(|s| ids.contains(&s.id) && tags.contains(&s.id));
        for s in ok().filter(|s| !s.is_domestic()).chain(ok().filter(|s| s.is_domestic())) {
            if !out.contains(&s.id) {
                out.push(s.id.clone());
            }
        }
        out
    };
    let autos: Vec<(String, Vec<String>)> = input
        .autos
        .iter()
        .map(|(tag, ids)| (tag.clone(), auto_all(ids)))
        .filter(|(_, m)| !m.is_empty())
        .collect();
    let default = if input.default == TAG_AUTO
        || tags.contains(&input.default)
        || autos.iter().any(|(t, _)| *t == input.default)
    {
        input.default.clone()
    } else {
        TAG_AUTO.to_string()
    };
    let mut selector_list = vec![TAG_AUTO.to_string()];
    selector_list.extend(autos.iter().map(|(t, _)| t.clone()));
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
    // Группы автовыбора — простые переключатели: серверы проверяет и лучший
    // выбирает приложение. Встроенный автовыбор sing-box (urltest) для этого
    // не годится: пока идёт его фоновая проверка (при сотне серверов — десятки
    // секунд), запрос проверки группы сразу возвращает пустой ответ.
    let auto_group = |tag: &str, members: &[String]| {
        json!({
            "type": "selector",
            "tag": tag,
            "outbounds": members,
            "default": members[0],
            "interrupt_exist_connections": false
        })
    };
    let all_ids: Vec<String> = tags.clone();
    let mut auto_map = std::collections::HashMap::new();
    auto_map.insert(TAG_AUTO.to_string(), auto_all(&all_ids));
    let mut auto_obs = vec![auto_group(TAG_AUTO, &auto_map[TAG_AUTO])];
    for (tag, members) in &autos {
        auto_obs.push(auto_group(tag, members));
        auto_map.insert(tag.clone(), members.clone());
    }
    for (i, ob) in auto_obs.into_iter().enumerate() {
        outbounds.insert(1 + i, ob);
    }

    // «Белый интернет»: выбран российский сервер. Когда оператор оставляет
    // доступ только к сайтам из белого списка, напрямую открываются лишь они,
    // поэтому весь трафик, включая российские сайты, идёт через сервер.
    let domestic_mode = {
        let ids: Vec<String> = if default == TAG_AUTO {
            auto_members(&all_ids)
        } else if let Some((_, m)) = autos.iter().find(|(t, _)| *t == default) {
            auto_members(m)
        } else {
            vec![default.clone()]
        };
        !ids.is_empty()
            && ids
                .iter()
                .all(|id| input.servers.iter().any(|s| s.id == *id && s.is_domestic()))
    };
    let ru_direct = split.ru_direct && !domestic_mode;
    outbounds.push(json!({"type": "direct", "tag": TAG_DIRECT}));

    // ---- наборы правил ----
    let mut rule_sets = vec![];
    let mut geosite_ru = false;
    let mut geoip_ru = false;
    if ru_direct {
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

    if !android && !split.app_routes.is_empty() && input.mode != Mode::Tun {
        return Err("для индивидуальных правил приложений включите режим TUN".into());
    }
    let mut reject_rules = vec![];
    let mut pinned_rules = vec![];
    let mut app_dns_rules = vec![];
    let mut app_dns_servers = vec![];
    let mut users = vec![json!({"username": rt.socks_user, "password": rt.socks_pass})];
    for (index, rule) in split.app_routes.iter().enumerate() {
        let mut fields = if android {
            let user = format!("app-{}", index + 1);
            users.push(json!({"username": user, "password": rt.socks_pass}));
            Map::from_iter([("auth_user".into(), json!([user]))])
        } else {
            process_fields(std::slice::from_ref(&rule.app))
        };
        if fields.is_empty() {
            return Err("пустое имя приложения в индивидуальном правиле".into());
        }
        if rule.server.as_deref() == Some(ROUTE_DIRECT) {
            let mut dns_match = fields.clone();
            dns_match.insert("server".into(), json!("dns-direct"));
            app_dns_rules.push(Value::Object(dns_match));
            fields.insert("outbound".into(), json!(TAG_DIRECT));
            pinned_rules.push(Value::Object(fields));
        } else if let Some(id) = rule.server.as_ref().filter(|id| tags.contains(id)) {
            let dns_tag = format!("dns-app-{id}");
            if !app_dns_servers.iter().any(|s: &Value| s["tag"] == dns_tag) {
                let (server, _) = dns_server(&dns_tag, &st.dns_remote, Some(id));
                app_dns_servers.push(server);
            }
            let mut dns_match = fields.clone();
            dns_match.insert("server".into(), json!(dns_tag));
            app_dns_rules.push(Value::Object(dns_match));
            fields.insert("outbound".into(), json!(id));
            pinned_rules.push(Value::Object(fields));
        } else {
            // A removed server must never silently move an app to another exit.
            fields.insert("action".into(), json!("reject"));
            reject_rules.push(Value::Object(fields));
        }
    }
    let mut site_route_rules = vec![];
    let mut site_dns_rules = vec![];
    for rule in &split.site_routes {
        let m = Matchers::from_entries(std::slice::from_ref(&rule.site));
        if m.is_empty(true) {
            return Err(format!("некорректный адрес или IP в индивидуальном правиле: «{}»", rule.site));
        }
        if rule.server.as_deref() == Some(ROUTE_DIRECT) {
            if !m.is_empty(false) {
                let mut dns_match = m.fields(false);
                dns_match.insert("server".into(), json!("dns-direct"));
                site_dns_rules.push(Value::Object(dns_match));
            }
            let mut fields = m.fields(true);
            fields.insert("outbound".into(), json!(TAG_DIRECT));
            site_route_rules.push(Value::Object(fields));
        } else if let Some(id) = rule.server.as_ref().filter(|id| tags.contains(id)) {
            if !m.is_empty(false) {
                let dns_tag = format!("dns-app-{id}");
                if !app_dns_servers.iter().any(|s: &Value| s["tag"] == dns_tag) {
                    let (server, _) = dns_server(&dns_tag, &st.dns_remote, Some(id));
                    app_dns_servers.push(server);
                }
                let mut dns_match = m.fields(false);
                dns_match.insert("server".into(), json!(dns_tag));
                site_dns_rules.push(Value::Object(dns_match));
            }
            let mut fields = m.fields(true);
            fields.insert("outbound".into(), json!(id));
            site_route_rules.push(Value::Object(fields));
        } else {
            if !m.is_empty(false) {
                let mut dns_match = m.fields(false);
                dns_match.insert("action".into(), json!("reject"));
                site_dns_rules.push(Value::Object(dns_match));
            }
            let mut fields = m.fields(true);
            fields.insert("action".into(), json!("reject"));
            site_route_rules.push(Value::Object(fields));
        }
    }

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
    dns_servers.extend(app_dns_servers);
    let mut dns_rules = app_dns_rules;
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
    dns_rules.extend(site_dns_rules);
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
    let mut ru_dns = vec![];
    if ru_direct {
        ru_dns.push(json!({"domain_suffix": FOREIGN_RU, "server": "dns-remote"}));
        ru_dns.push(json!({"domain_suffix": RU_SUFFIXES, "server": "dns-direct"}));
        if geosite_ru {
            ru_dns.push(json!({"rule_set": ["geosite-ru"], "server": "dns-direct"}));
        }
    }
    // «Только выбранные приложения через VPN»: российские сайты и у них идут
    // напрямую, поэтому правила для России — раньше правила приложений.
    if include_mode {
        dns_rules.append(&mut ru_dns);
    }
    if app_split {
        let mut r = apps.clone();
        r.insert(
            "server".into(),
            json!(if include_mode { "dns-remote" } else { "dns-direct" }),
        );
        dns_rules.push(Value::Object(r));
    }
    dns_rules.append(&mut ru_dns);
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
            m["users"] = json!(users);
        }
        inbounds.push(m);
    }
    // Раздача VPN через точку доступа (Android): прокси для устройств,
    // подключённых к телефону. Без пароля — прокси в настройках Wi-Fi пароль не
    // поддерживают; чужие (не из локальной сети) подключения отклоняются ниже.
    let lan = android && st.allow_lan && st.lan_port >= 1024;
    if lan {
        inbounds.push(json!({
            "type": "mixed",
            "tag": "lan-in",
            "listen": "0.0.0.0",
            "listen_port": st.lan_port
        }));
    }

    // ---- маршрутизация ----
    let mut rules = vec![];
    if lan {
        rules.push(json!({"inbound": ["lan-in"], "source_ip_is_private": false, "action": "reject"}));
    }
    rules.extend(reject_rules);
    rules.push(json!({"action": "sniff"}));
    rules.push(json!({"protocol": "dns", "action": "hijack-dns"}));
    if !st.ipv6 {
        rules.push(json!({"ip_version": 6, "action": "reject"}));
    }
    if xray_used && !android {
        // Сам Xray ходит к серверам напрямую (в режиме TUN его трафик тоже
        // попадает в sing-box — без этого правила получится петля).
        // На Android процессы приложения исключены из VPN системой.
        rules.push(json!({"process_name": [input.xray_process.unwrap()], "outbound": TAG_DIRECT}));
    }
    rules.extend(pinned_rules);
    rules.extend(site_route_rules);
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
    let mut ru_rules = vec![];
    if ru_direct {
        ru_rules.push(json!({"domain_suffix": FOREIGN_RU, "outbound": TAG_PROXY}));
        ru_rules.push(json!({"domain_suffix": RU_SUFFIXES, "outbound": TAG_DIRECT}));
        if geosite_ru {
            ru_rules.push(json!({"rule_set": ["geosite-ru"], "outbound": TAG_DIRECT}));
        }
        if geoip_ru {
            // По российскому IP напрямую — только если имя сайта неизвестно.
            // Если браузер получил для зарубежного сайта российский адрес
            // (например, свой «безопасный DNS» отдал сервер Google в российской
            // сети), решает имя сайта: зарубежный сайт идёт через VPN, а адрес
            // там найдёт сам сервер. Иначе сайт увидел бы российский IP.
            ru_rules.push(json!({
                "type": "logical",
                "mode": "and",
                "rules": [
                    {"rule_set": ["geoip-ru"]},
                    {"domain_regex": [".+"], "invert": true}
                ],
                "outbound": TAG_DIRECT
            }));
        }
    }
    if include_mode {
        // Только выбранные приложения идут через VPN, но российские сайты и у
        // них — напрямую (остальные приложения и так идут напрямую).
        for mut rule in ru_rules.drain(..) {
            if rule["outbound"] == json!(TAG_DIRECT) {
                rules.push(rule);
            } else {
                // google.ru и т.п. — через VPN только для выбранных приложений.
                let o = rule.as_object_mut().unwrap();
                for (k, v) in apps.iter() {
                    o.insert(k.clone(), v.clone());
                }
                rules.push(rule);
            }
        }
    }
    if app_split {
        if include_mode {
            let mut q = apps.clone();
            q.insert("network".into(), json!("udp"));
            q.insert("port".into(), json!(443));
            q.insert("action".into(), json!("reject"));
            rules.push(Value::Object(q));
        }
        let mut r = apps.clone();
        r.insert(
            "outbound".into(),
            json!(if include_mode { TAG_PROXY } else { TAG_DIRECT }),
        );
        rules.push(Value::Object(r));
    }
    rules.append(&mut ru_rules);

    // QUIC (UDP 443) через VPN не пускаем: многие серверы (VLESS с XTLS Vision)
    // его отвергают, и браузер долго ждёт, прежде чем перейти на обычный HTTPS.
    // Отказ сразу — и сайт открывается через TCP. Так же делает конфиг провайдера.
    if !include_mode {
        rules.push(json!({"network": "udp", "port": 443, "action": "reject"}));
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
        if app_split || xray_used || !split.app_routes.is_empty() {
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

    let mut experimental = json!({"clash_api": clash});
    if android {
        // Android: VPN может перезапуститься без приложения (плитка в шторке,
        // постоянный VPN), поэтому выбранный сервер запоминается в кэше ядра.
        experimental["cache_file"] = json!({"enabled": true, "path": "cache.db"});
    }

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
        "experimental": experimental
    });
    Ok(Built { singbox, xray: xray_cfg, groups, domestic: domestic_mode, tags: selector_list, autos: auto_map })
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
            autos: vec![],
            default: default.into(),
            ruleset_dir: None,
            xray_process: Some("xray.exe"),
            mode: st.mode,
            platform: Platform::Windows,
            runtime: r,
        }
    }

    #[test]
    fn individual_routes_precede_domain_and_split_rules() {
        use crate::model::AppRoute;
        let servers = servers();
        let mut st = Settings::default();
        st.split.app_mode = AppMode::Exclude;
        st.split.apps_exclude = vec!["reader".into()];
        st.split.app_routes = vec![
            AppRoute { app: "game".into(), server: None },
            AppRoute { app: "reader".into(), server: Some(servers[1].id.clone()) },
            AppRoute { app: "stale".into(), server: Some("deleted".into()) },
            AppRoute { app: "bank".into(), server: Some(ROUTE_DIRECT.into()) },
        ];
        let mut runtime = rt();
        runtime.mixed_port = 12345;
        runtime.mixed_auth = true;
        for platform in [Platform::Windows, Platform::Android] {
            let mut params = input(&st, &servers, &servers[0].id, &runtime);
            params.platform = platform;
            let cfg = build(&params).unwrap().singbox;
            let rules = cfg["route"]["rules"].as_array().unwrap();
            let android = platform == Platform::Android;
            let field = if android { "auth_user" } else { "process_name" };
            let app = |i: usize| {
                if android {
                    ["app-1", "app-2", "app-3", "app-4"][i]
                } else {
                    ["game", "reader", "stale", "bank"][i]
                }
            };
            let position = |key: &str, value: &str| rules.iter().position(|r| r[key] == value).unwrap();
            for index in [0, 2] {
                assert!(rules[..position("action", "sniff")].iter().any(|r| r[field][0] == app(index) && r["action"] == "reject"));
            }
            let pin = position("outbound", &servers[1].id);
            assert_eq!(rules[pin][field][0], app(1));
            let direct_pin = rules.iter().position(|r| r[field][0] == app(3) && r["outbound"] == TAG_DIRECT).unwrap();
            let private_ip = rules.iter().position(|r| r["ip_is_private"] == true).unwrap();
            assert!(pin < private_ip);
            assert!(direct_pin < private_ip);
            assert_eq!(cfg["dns"]["rules"][0][field][0], app(1));
            assert_eq!(cfg["dns"]["rules"][1][field][0], app(3));
            assert_eq!(cfg["dns"]["rules"][1]["server"], "dns-direct");
            if android {
                assert_eq!(cfg["inbounds"][0]["users"][2]["username"], "app-2");
                assert_eq!(cfg["inbounds"][0]["users"][4]["username"], "app-4");
            } else {
                params.mode = Mode::Proxy;
                assert!(build(&params).is_err());
            }
        }
    }

    #[test]
    fn individual_site_and_ip_routes() {
        use crate::model::SiteRoute;
        let servers = servers();
        let mut st = Settings::default();
        st.split.proxy_domains = vec!["openai.com".into(), "1.1.1.1".into()];
        st.split.site_routes = vec![
            SiteRoute { site: "https://www.openai.com/chat?q=1".into(), server: Some(servers[1].id.clone()) },
            SiteRoute { site: "http://1.1.1.1:8080/test".into(), server: Some(ROUTE_DIRECT.into()) },
            SiteRoute { site: "ads.example.com".into(), server: None },
            SiteRoute { site: "10.8.0.0/24".into(), server: Some(servers[1].id.clone()) },
            SiteRoute { site: "stale.example.com".into(), server: Some("deleted".into()) },
        ];
        let mut runtime = rt();
        runtime.mixed_port = 12345;
        for mode in [Mode::Tun, Mode::Proxy] {
            let mut params = input(&st, &servers, &servers[0].id, &runtime);
            params.mode = mode;
            let cfg = build(&params).unwrap().singbox;
            let rules = cfg["route"]["rules"].as_array().unwrap();
            let dns_rules = cfg["dns"]["rules"].as_array().unwrap();
            let sniff_pos = rules.iter().position(|r| r["action"] == "sniff").unwrap();
            let priv_pos = rules.iter().position(|r| r["ip_is_private"] == true).unwrap();

            let pin_site = rules.iter().position(|r| r["domain_suffix"][0] == "openai.com" && r["outbound"] == servers[1].id).unwrap();
            let direct_ip = rules.iter().position(|r| r["ip_cidr"][0] == "1.1.1.1/32" && r["outbound"] == TAG_DIRECT).unwrap();
            let block_site = rules.iter().position(|r| r["domain_suffix"][0] == "ads.example.com" && r["action"] == "reject").unwrap();
            let pin_subnet = rules.iter().position(|r| r["ip_cidr"][0] == "10.8.0.0/24" && r["outbound"] == servers[1].id).unwrap();
            let stale_site = rules.iter().position(|r| r["domain_suffix"][0] == "stale.example.com" && r["action"] == "reject").unwrap();

            for pos in [pin_site, direct_ip, block_site, pin_subnet, stale_site] {
                assert!(pos > sniff_pos);
                assert!(pos < priv_pos);
            }
            assert_eq!(dns_rules[0]["domain_suffix"][0], "openai.com");
            assert_eq!(dns_rules[0]["server"], format!("dns-app-{}", servers[1].id));
            assert_eq!(dns_rules[1]["domain_suffix"][0], "ads.example.com");
            assert_eq!(dns_rules[1]["action"], "reject");
            assert_eq!(dns_rules[2]["domain_suffix"][0], "stale.example.com");
            assert_eq!(dns_rules[2]["action"], "reject");
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
        assert!(text.contains("\"youtube.com\""));
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
    fn include_mode_keeps_russian_sites_direct() {
        let mut st = Settings::default();
        st.mode = Mode::Proxy;
        st.split.app_mode = AppMode::Include;
        st.split.apps_include = vec!["chrome.exe".into()];
        st.split.ru_direct = true;
        let s = servers();
        let r = rt();
        let cfg = build(&input(&st, &s, "auto", &r)).unwrap().singbox;
        let rules = cfg["route"]["rules"].as_array().unwrap();
        let pos = |f: &dyn Fn(&Value) -> bool| rules.iter().position(|r| f(r)).unwrap();
        let ru = pos(&|r| r["domain_suffix"].to_string().contains("xn--p1ai") && r["outbound"] == "direct");
        let app = pos(&|r| r["process_name"].is_array() && r["outbound"] == "proxy" && r["domain_suffix"].is_null());
        assert!(ru < app, "российские сайты должны идти напрямую и у выбранных приложений: {}", serde_json::to_string_pretty(rules).unwrap());
        // google.ru — через VPN только для выбранных приложений.
        let g = pos(&|r| r["domain_suffix"].to_string().contains("google.ru"));
        assert_eq!(rules[g]["process_name"][0], "chrome.exe");
        let dns = cfg["dns"]["rules"].as_array().unwrap();
        let ru_dns = dns.iter().position(|r| r["domain_suffix"].to_string().contains("xn--p1ai")).unwrap();
        let app_dns = dns.iter().position(|r| r["process_name"].is_array()).unwrap();
        assert!(ru_dns < app_dns);
    }

    #[test]
    fn auto_groups_are_selectors_with_domestic_last() {
        let st = Settings::default();
        let s: Vec<Server> = [
            "vless://u@ru.example.com:443?security=tls&sni=x.com#%F0%9F%87%B7%F0%9F%87%BA%20RU",
            "vless://u@a.example.com:443?security=reality&pbk=k&sid=1&sni=x.com#A",
            "hy2://p@b.example.com:443#B",
        ]
        .iter()
        .map(|l| link_to_server(l, "t").unwrap())
        .collect();
        assert!(s[0].is_domestic());
        let r = rt();
        let mut inp = input(&st, &s, "auto", &r);
        inp.autos = vec![("auto-t".into(), s.iter().map(|x| x.id.clone()).collect())];
        let b = build(&inp).unwrap();
        for tag in ["auto", "auto-t"] {
            let g = b.singbox["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == tag).unwrap().clone();
            assert_eq!(g["type"], "selector", "{tag}: автовыбор выбирает приложение");
            let m: Vec<String> = g["outbounds"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
            assert_eq!(m.last().unwrap(), &s[0].id, "{tag}: российский сервер — последним");
            assert_eq!(b.autos[tag], m);
        }
        assert!(!b.domestic, "при автовыборе с зарубежными серверами — обычные маршруты");
    }

    #[test]
    fn site_entries() {
        let m = Matchers::from_entries(&[
            "*.ru".into(),
            "*.рф".into(),
            "https://www.мвд.рф/news?x=1".into(),
            "https://www.sberbank.ru/ru/person?x=1".into(),
            "http://Example.COM:8080/a".into(),
            "a.com, b.org  c.net".into(),
            "www.mail.ru".into(),
        ]);
        assert_eq!(
            m.suffix,
            vec![
                "ru",
                "xn--p1ai",
                "xn--b1aew.xn--p1ai",
                "sberbank.ru",
                "example.com",
                "a.com",
                "b.org",
                "c.net",
                "www.mail.ru"
            ]
        );
    }

    #[test]
    fn hotspot_sharing_android_only() {
        let mut st = Settings::default();
        st.allow_lan = true;
        st.lan_port = 2080;
        let s = servers();
        let r = rt();
        let cfg = build(&input(&st, &s, "auto", &r)).unwrap().singbox;
        assert!(!cfg["inbounds"].to_string().contains("lan-in"), "на ПК раздачи нет");
        let mut inp = input(&st, &s, "auto", &r);
        inp.platform = Platform::Android;
        inp.mode = Mode::Proxy;
        let cfg = build(&inp).unwrap().singbox;
        let lan = cfg["inbounds"].as_array().unwrap().iter().find(|i| i["tag"] == "lan-in").unwrap().clone();
        assert_eq!(lan["listen_port"], 2080);
        assert!(lan.get("users").is_none());
        assert_eq!(cfg["route"]["rules"][0]["inbound"][0], "lan-in");
        assert_eq!(cfg["route"]["rules"][0]["source_ip_is_private"], false);
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
        assert_eq!(plain_dns_ip("2606:4700:4700::1111"), "2606:4700:4700::1111");
        assert_eq!(plain_dns_ip("https://[2606:4700:4700::1111]:443/dns-query"), "2606:4700:4700::1111");
        assert_eq!(plain_dns_ip("8.8.8.8:53"), "8.8.8.8");
        assert_eq!(plain_dns_ip("https://dns.yandex.ru/dns-query"), "77.88.8.8");
    }
}
