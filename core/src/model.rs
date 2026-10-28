use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Один сервер из подписки или добавленный вручную.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Server {
    /// Стабильный идентификатор (хэш ссылки), он же тег outbound в sing-box.
    pub id: String,
    pub name: String,
    /// Исходная ссылка (пусто, если сервер пришёл из JSON-подписки sing-box).
    #[serde(default)]
    pub link: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    /// Транспорт и защита для отображения: `tcp · reality`, `xhttp · reality`.
    #[serde(default)]
    pub transport: String,
    /// Готовый outbound sing-box (без тега). None — sing-box такое не умеет.
    #[serde(default)]
    pub outbound: Option<Value>,
    /// Готовый outbound Xray-core (без тега). Нужен для XHTTP, VLESS Encryption и т.п.
    #[serde(default)]
    pub xray: Option<Value>,
    /// Причина, по которой сервер нельзя использовать.
    #[serde(default)]
    pub error: Option<String>,
}

impl Server {
    pub fn usable(&self) -> bool {
        self.outbound.is_some() || self.xray.is_some()
    }

    /// Сервер работает только через Xray.
    pub fn needs_xray(&self) -> bool {
        self.outbound.is_none() && self.xray.is_some()
    }

    /// Протоколы поверх UDP нельзя проверить TCP-пингом.
    pub fn is_udp(&self) -> bool {
        matches!(self.protocol.as_str(), "hysteria2" | "tuic" | "hysteria")
    }
}

/// Данные из заголовка `subscription-userinfo`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SubInfo {
    pub upload: u64,
    pub download: u64,
    /// 0 — безлимит.
    pub total: u64,
    /// Unix-время окончания, 0 — бессрочно.
    pub expire: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    /// None — локальная группа «Мои серверы».
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub info: Option<SubInfo>,
    #[serde(default)]
    pub updated_at: u64,
    /// Интервал автообновления в часах.
    #[serde(default = "default_interval")]
    pub update_interval_h: u32,
    #[serde(default)]
    pub support_url: Option<String>,
    #[serde(default)]
    pub web_page_url: Option<String>,
    #[serde(default)]
    pub announce: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub servers: Vec<Server>,
}

fn default_interval() -> u32 {
    12
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Виртуальный адаптер: весь трафик системы (нужны права администратора).
    #[default]
    Tun,
    /// Системный HTTP/SOCKS-прокси Windows.
    Proxy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AppMode {
    /// Раздельное туннелирование по приложениям выключено.
    #[default]
    Off,
    /// Через VPN идут только выбранные приложения.
    Include,
    /// Через VPN идёт всё, кроме выбранных приложений.
    Exclude,
}

/// Каким ядром подключаться к VLESS/VMess/Trojan.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum CoreChoice {
    /// sing-box, а Xray — только там, где sing-box не умеет (XHTTP и т.п.).
    #[default]
    Auto,
    /// Все VLESS/VMess/Trojan через Xray-core.
    Xray,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SplitTunnel {
    #[serde(default)]
    pub app_mode: AppMode,
    /// Приложения для режима «через VPN только выбранные».
    /// Windows: имена процессов (`chrome.exe`), полные пути или папки (`C:\Games\`).
    /// Android: имена пакетов (`org.telegram.messenger`).
    #[serde(default)]
    pub apps_include: Vec<String>,
    /// Приложения для режима «всё через VPN, кроме выбранных».
    #[serde(default)]
    pub apps_exclude: Vec<String>,
    /// Старый общий список (до версии 1.1). Переносится в список текущего режима.
    #[serde(default, skip_serializing)]
    pub apps: Vec<String>,
    /// Домены/IP/подсети, которые всегда идут через VPN.
    #[serde(default)]
    pub proxy_domains: Vec<String>,
    /// Домены/IP/подсети, которые всегда идут напрямую.
    #[serde(default)]
    pub direct_domains: Vec<String>,
    /// Российские сайты и IP напрямую.
    #[serde(default = "yes")]
    pub ru_direct: bool,
}

impl Default for SplitTunnel {
    fn default() -> Self {
        Self {
            app_mode: AppMode::Off,
            apps_include: vec![],
            apps_exclude: vec![],
            apps: vec![],
            proxy_domains: vec![],
            direct_domains: vec![],
            ru_direct: true,
        }
    }
}

impl SplitTunnel {
    /// Переносит старый общий список в список текущего режима и чистит дубли.
    pub fn normalize(&mut self) {
        if !self.apps.is_empty() {
            let old = std::mem::take(&mut self.apps);
            let target = match self.app_mode {
                AppMode::Include => &mut self.apps_include,
                _ => &mut self.apps_exclude,
            };
            if target.is_empty() {
                *target = old;
            }
        }
        for list in [&mut self.apps_include, &mut self.apps_exclude] {
            let mut seen = std::collections::HashSet::new();
            list.retain(|a| {
                let a = a.trim();
                !a.is_empty() && seen.insert(a.to_lowercase())
            });
        }
    }

    /// Список приложений активного режима.
    pub fn active_apps(&self) -> &[String] {
        match self.app_mode {
            AppMode::Off => &[],
            AppMode::Include => &self.apps_include,
            AppMode::Exclude => &self.apps_exclude,
        }
    }
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    #[serde(default)]
    pub mode: Mode,
    /// Порт локального прокси в режиме «Системный прокси». 0 — случайный при каждом
    /// подключении (так сайтам и программам сложнее найти прокси сканированием портов).
    #[serde(default)]
    pub mixed_port: u16,
    #[serde(default)]
    pub core: CoreChoice,
    /// DNS через VPN: `https://1.1.1.1/dns-query`, `tls://8.8.8.8`, `8.8.8.8`.
    #[serde(default = "dns_remote")]
    pub dns_remote: String,
    /// DNS напрямую: `77.88.8.8`, `https://dns.yandex.ru/dns-query` или `local`.
    #[serde(default = "dns_direct")]
    pub dns_direct: String,
    #[serde(default)]
    pub ipv6: bool,
    /// Раздавать VPN устройствам в локальной сети (прокси с логином и паролем).
    #[serde(default)]
    pub allow_lan: bool,
    #[serde(default = "p_lan")]
    pub lan_port: u16,
    #[serde(default)]
    pub lan_password: String,
    /// Запуск вместе с Windows.
    #[serde(default)]
    pub autostart: bool,
    /// Подключаться при запуске приложения.
    #[serde(default)]
    pub auto_connect: bool,
    /// Если в режиме TUN нет интернета — переключиться на системный прокси.
    #[serde(default = "yes")]
    pub tun_fallback: bool,
    /// Блокировать интернет, если VPN неожиданно отключился.
    #[serde(default)]
    pub kill_switch: bool,
    #[serde(default = "user_agent")]
    pub user_agent: String,
    #[serde(default)]
    pub split: SplitTunnel,
    #[serde(default = "log_level")]
    pub log_level: String,
}

fn p_lan() -> u16 {
    2080
}
fn dns_remote() -> String {
    "https://1.1.1.1/dns-query".into()
}
fn dns_direct() -> String {
    "77.88.8.8".into()
}
fn user_agent() -> String {
    // Большинство панелей (Marzban, Remnawave, 3x-ui) по такому UA отдают
    // обычный список ссылок в base64.
    "v2rayN/7.10.0".into()
}
fn log_level() -> String {
    "warn".into()
}

impl Default for Settings {
    fn default() -> Self {
        serde_json::from_str("{}").expect("default settings")
    }
}

/// Параметры одного запуска ядра: случайные порты и пароли, которые
/// не хранятся на диске и меняются при каждом подключении.
#[derive(Debug, Clone, Default)]
pub struct Runtime {
    /// Локальный прокси (0 — не нужен).
    pub mixed_port: u16,
    /// Требовать логин/пароль на локальном прокси (Android).
    pub mixed_auth: bool,
    pub clash_port: u16,
    pub secret: String,
    pub socks_user: String,
    pub socks_pass: String,
    /// Порты SOCKS-входов Xray, по одному на сервер.
    pub xray_ports: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Platform {
    #[default]
    Windows,
    Android,
}

/// Что выбрано для подключения.
#[derive(Debug, Clone, PartialEq)]
pub enum Selection {
    /// Конкретный сервер.
    Server(String),
    /// Автовыбор по пингу внутри подписки.
    Auto(String),
}

impl Selection {
    pub const AUTO_PREFIX: &'static str = "auto:";

    pub fn parse(s: &str) -> Selection {
        match s.strip_prefix(Self::AUTO_PREFIX) {
            Some(sub) => Selection::Auto(sub.to_string()),
            None => Selection::Server(s.to_string()),
        }
    }
}
