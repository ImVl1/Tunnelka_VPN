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
    /// Имена процессов (`chrome.exe`), полные пути (`C:\Games\x.exe`) или папки (`C:\Games\`).
    #[serde(default)]
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
            apps: vec![],
            proxy_domains: vec![],
            direct_domains: vec![],
            ru_direct: true,
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
    /// Локальный HTTP/SOCKS5-прокси (для системного прокси и других программ).
    #[serde(default = "p_mixed")]
    pub mixed_port: u16,
    /// Отдельный вход для расширения браузера: всё, что сюда пришло, идёт через VPN.
    #[serde(default = "p_ext")]
    pub ext_port: u16,
    /// Локальный API для расширения.
    #[serde(default = "p_api")]
    pub api_port: u16,
    /// Clash API ядра (статистика, переключение серверов на лету).
    #[serde(default = "p_clash")]
    pub clash_port: u16,
    /// Первый порт для локальных SOCKS-входов Xray (по одному на сервер).
    #[serde(default = "p_xray")]
    pub xray_port: u16,
    #[serde(default)]
    pub core: CoreChoice,
    #[serde(default)]
    pub api_token: String,
    /// DNS через VPN: `https://1.1.1.1/dns-query`, `tls://8.8.8.8`, `8.8.8.8`.
    #[serde(default = "dns_remote")]
    pub dns_remote: String,
    /// DNS напрямую: `77.88.8.8`, `https://dns.yandex.ru/dns-query` или `local`.
    #[serde(default = "dns_direct")]
    pub dns_direct: String,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default)]
    pub allow_lan: bool,
    #[serde(default)]
    pub auto_connect: bool,
    #[serde(default = "user_agent")]
    pub user_agent: String,
    #[serde(default)]
    pub split: SplitTunnel,
    #[serde(default = "log_level")]
    pub log_level: String,
}

fn p_mixed() -> u16 {
    2080
}
fn p_ext() -> u16 {
    2081
}
fn p_api() -> u16 {
    2082
}
fn p_clash() -> u16 {
    2083
}
fn p_xray() -> u16 {
    10800
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
    "info".into()
}

impl Default for Settings {
    fn default() -> Self {
        serde_json::from_str("{}").expect("default settings")
    }
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
