//! Состояние приложения, подписки и управление процессами sing-box и Xray.
//! Общий код для Windows и Android.

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::future::join_all;
use serde::{Deserialize, Serialize};
use tunnelka_core::singbox::{self, BuildInput, TAG_AUTO, TAG_PROXY, URL_TEST};
use tunnelka_core::subscription::{self, Fetched};
use tunnelka_core::failover::{self, Candidate};
use tunnelka_core::{auto_tag, AppMode, AppRoute, Mode, Platform, Runtime, Selection, Server, Settings, Subscription};

use crate::{autostart, killswitch, sysproxy};

pub const MANUAL_SUB: &str = "manual";
const MAX_LOG_LINES: usize = 800;

pub const PLATFORM: Platform = if cfg!(target_os = "android") {
    Platform::Android
} else {
    Platform::Windows
};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_token() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Свободные локальные порты (выбирает система).
fn free_ports(n: usize) -> Result<Vec<u16>, String> {
    let listeners: Vec<std::net::TcpListener> = (0..n)
        .map(|_| std::net::TcpListener::bind(("127.0.0.1", 0)))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("нет свободных портов: {e}"))?;
    listeners
        .iter()
        .map(|l| l.local_addr().map(|a| a.port()).map_err(|e| e.to_string()))
        .collect()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Persisted {
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
    /// id сервера или `auto:<id подписки>`.
    #[serde(default)]
    pub selected: Option<String>,
    /// Версия разбора подписок. Если приложение стало разбирать их иначе,
    /// подписки перезагружаются при запуске.
    #[serde(default)]
    pub format: u32,
}

/// 3 — конфиги Xray подписок сохраняются целиком (цепочки, балансировщики, DNS).
const FORMAT: u32 = 3;

#[derive(Default)]
struct Rt {
    child: Option<Child>,
    /// Xray запускается, только если в подписке есть серверы для него.
    xray: Option<Child>,
    started_at: u64,
    active_sub: Option<String>,
    sysproxy_on: bool,
    /// Android: туннель VpnService поднят.
    vpn_on: bool,
    last_error: Option<String>,
    /// Сообщение для пользователя (например, о переходе на системный прокси).
    notice: Option<String>,
    busy: bool,
    /// Android: VPN на паузе (из уведомления).
    paused: bool,
    /// Идёт фоновая проверка интернета после подключения.
    checking: bool,
    /// Адрес, с которым сайты видят пользователя через VPN: (IP, место).
    exit: Option<(String, String)>,
    /// Номер подключения: фоновая проверка не трогает более новое подключение.
    gen: u64,
    /// Режим, в котором реально работает подключение.
    mode: Mode,
    run: Runtime,
    /// Серверы с автовыбором внутри: id → теги частей (см. singbox::Built).
    groups: HashMap<String, Vec<String>>,
    /// Что есть в работающем конфиге: серверы всех подписок и группы
    /// автовыбора. Между ними переключаемся без переподключения.
    tags: std::collections::HashSet<String>,
    /// Работающий конфиг собран для «белого интернета» (всё через сервер).
    domestic: bool,
    /// Группы автовыбора: тег → серверы (зарубежные, затем российские).
    autos: HashMap<String, Vec<String>>,
    /// Предупреждение показано из-за сбоя связи: убрать, когда связь вернётся.
    health_notice: bool,
    /// Результаты идущей проверки пинга (приложение показывает их по мере готовности).
    ping_partial: HashMap<String, i64>,
    /// Скачивание обновления: (получено, всего) байт.
    update_progress: (u64, u64),
    /// Android: время последнего переключения сервера VPN-сервисом, мс.
    monitor_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub platform: &'static str,
    pub running: bool,
    pub busy: bool,
    /// Режим текущего подключения (или из настроек, если отключено).
    pub mode: Mode,
    pub started_at: u64,
    pub selected: Option<String>,
    pub selected_name: Option<String>,
    pub selected_protocol: Option<String>,
    pub active_sub: Option<String>,
    pub last_error: Option<String>,
    pub notice: Option<String>,
    pub core_found: bool,
    pub xray_found: bool,
    pub mixed_port: u16,
    /// Kill switch сейчас блокирует интернет.
    pub kill_switch_active: bool,
    /// Android: VPN на паузе.
    pub paused: bool,
    /// Идёт проверка, что через VPN есть интернет.
    pub checking: bool,
    /// IP, с которым сайты видят пользователя через VPN, и где он находится.
    pub exit_ip: Option<String>,
    pub exit_place: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Traffic {
    pub up: u64,
    pub down: u64,
    pub connections: usize,
}

pub struct Paths {
    pub data: PathBuf,
    /// Android: папка профиля VPN-сервиса (конфиги ядер, журнал, кэш).
    pub vpn_dir: PathBuf,
    pub state: PathBuf,
    pub config: PathBuf,
    pub singbox: PathBuf,
    pub xray: PathBuf,
    pub xray_config: PathBuf,
    pub ruleset_dir: PathBuf,
}

/// Имена файлов ядер. На Android они лежат среди нативных библиотек
/// (только оттуда система разрешает запускать исполняемые файлы).
#[cfg(target_os = "android")]
pub const SINGBOX_EXE: &str = "libsingbox.so";
#[cfg(target_os = "android")]
pub const XRAY_EXE: &str = "libxray.so";
#[cfg(windows)]
pub const SINGBOX_EXE: &str = "sing-box.exe";
#[cfg(windows)]
pub const XRAY_EXE: &str = "xray.exe";
#[cfg(not(any(windows, target_os = "android")))]
pub const SINGBOX_EXE: &str = "sing-box";
#[cfg(not(any(windows, target_os = "android")))]
pub const XRAY_EXE: &str = "xray";

impl Paths {
    /// `core_dir` — явная папка с ядрами (Android: nativeLibraryDir).
    pub fn new(data: PathBuf, resource: Option<PathBuf>, core_dir: Option<PathBuf>) -> Self {
        let android_core = core_dir.is_some();
        let core_dir = core_dir.unwrap_or_else(|| {
            // Где искать ядро: ресурсы установщика, рядом с exe, папка данных.
            let mut candidates = vec![];
            if let Some(r) = &resource {
                candidates.push(r.join("core"));
            }
            if let Ok(cur) = std::env::current_exe() {
                if let Some(dir) = cur.parent() {
                    candidates.push(dir.join("core"));
                    candidates.push(dir.to_path_buf());
                }
            }
            candidates.push(data.join("core"));
            candidates
                .iter()
                .find(|d| d.join(SINGBOX_EXE).exists())
                .cloned()
                .unwrap_or_else(|| data.join("core"))
        });
        // Android: sing-box следит за изменениями файлов правил, а папку нативных
        // библиотек читать целиком нельзя — копируем базы в папку данных.
        let ruleset_dir = if android_core {
            let rules = data.join("rules");
            let _ = std::fs::create_dir_all(&rules);
            for f in [
                singbox::RULESET_GEOSITE_RU_ANDROID,
                singbox::RULESET_GEOIP_RU_ANDROID,
            ] {
                let src = core_dir.join(f);
                let dst = rules.join(f);
                let stale = match (std::fs::metadata(&src), std::fs::metadata(&dst)) {
                    (Ok(a), Ok(b)) => a.len() != b.len(),
                    (Ok(_), Err(_)) => true,
                    _ => false,
                };
                if stale {
                    let _ = std::fs::copy(&src, &dst);
                }
            }
            rules
        } else {
            core_dir.clone()
        };
        // На Android конфиги остаются в закрытой папке приложения: по ним
        // VPN-сервис перезапускает ядра сам (плитка, «Постоянная VPN»).
        let vpn_dir = data.join("vpn");
        let cfg_dir = if android_core {
            let _ = std::fs::create_dir_all(&vpn_dir);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&vpn_dir, std::fs::Permissions::from_mode(0o700));
            }
            vpn_dir.clone()
        } else {
            data.clone()
        };
        Paths {
            state: data.join("state.json"),
            config: cfg_dir.join("config.json"),
            xray_config: cfg_dir.join("xray.json"),
            vpn_dir,
            singbox: core_dir.join(SINGBOX_EXE),
            xray: core_dir.join(XRAY_EXE),
            ruleset_dir,
            data,
        }
    }
}

pub struct Engine {
    pub paths: Paths,
    state: Mutex<Persisted>,
    rt: Mutex<Rt>,
    logs: Arc<Mutex<VecDeque<String>>>,
    http: reqwest::Client,
}

/// Профиль для VPN-сервиса Android: по нему сервис сам запускает ядра.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VpnProfile {
    session: String,
    /// Название сервера для уведомления.
    server: String,
    notify: bool,
    socks_port: u16,
    socks_user: String,
    socks_pass: String,
    app_mode: String,
    apps: Vec<String>,
    #[serde(default)]
    app_routes: Vec<AppRoute>,
    work_dir: String,
    log: String,
    env: HashMap<String, String>,
    processes: Vec<ProcSpec>,
    /// Для приложения: порты и ключи Clash API, если VPN включили без него.
    runtime: Runtime,
    active_sub: String,
    #[serde(default)]
    groups: HashMap<String, Vec<String>>,
    /// Для наблюдения за связью в VPN-сервисе: что выбрано (сервер или группа
    /// автовыбора), можно ли менять сервер и на какие — по ступеням.
    #[serde(default)]
    selected: String,
    #[serde(default)]
    auto_switch: bool,
    #[serde(default)]
    fallback: Vec<Vec<String>>,
    #[serde(default)]
    names: HashMap<String, String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    domestic: bool,
    /// Группы автовыбора и российские серверы: VPN-сервис сам выбирает в них
    /// рабочий сервер, если текущий перестал отвечать.
    #[serde(default)]
    autos: HashMap<String, Vec<String>>,
    #[serde(default)]
    domestic_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProcSpec {
    name: String,
    exe: String,
    args: Vec<String>,
}

impl Engine {
    pub fn load(paths: Paths) -> Arc<Self> {
        let _ = std::fs::create_dir_all(&paths.data);
        let mut st: Persisted = std::fs::read_to_string(&paths.state)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        st.settings.split.normalize();
        if st.format < FORMAT {
            for sub in st.subscriptions.iter_mut().filter(|s| s.url.is_some()) {
                sub.updated_at = 0;
            }
            st.format = FORMAT;
        }
        if st.settings.lan_password.is_empty() {
            st.settings.lan_password = random_token()[..12].to_string();
        }
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(12))
            .build()
            .expect("http client");
        let auto_connect = st.settings.auto_connect;
        let engine = Arc::new(Engine {
            paths,
            state: Mutex::new(st),
            rt: Mutex::new(Rt::default()),
            logs: Arc::new(Mutex::new(VecDeque::new())),
            http,
        });
        engine.save();
        // Остатки временной проверки серверов.
        let _ = std::fs::remove_dir_all(engine.paths.data.join("probe"));
        // На Android ядрами управляет VPN-сервис, он может работать и без окна.
        if PLATFORM != Platform::Android {
            crate::procs::kill_orphans(&engine.paths.singbox);
            crate::procs::kill_orphans(&engine.paths.xray);
            // Остатки конфигов с паролями от прошлого запуска.
            let _ = std::fs::remove_file(&engine.paths.config);
            let _ = std::fs::remove_file(&engine.paths.xray_config);
        }
        // Kill switch остался включённым после сбоя приложения или компьютера.
        // Блокировку не снимаем: интернет вернёт только новое подключение или
        // кнопка «Разблокировать интернет».
        if killswitch::is_active(&engine.paths.data) {
            let _ = auto_connect;
            engine.log("[app] интернет заблокирован kill switch с прошлого запуска — подключитесь или нажмите «Разблокировать интернет»");
        }
        engine
    }

    pub fn log(&self, line: impl Into<String>) {
        push_log(&self.logs, line.into());
    }

    pub fn logs(&self) -> Vec<String> {
        let mut out: Vec<String> = self.logs.lock().unwrap().iter().cloned().collect();
        if PLATFORM == Platform::Android {
            // Ядра на Android запускает VPN-сервис и пишет их вывод в файл.
            if let Ok(text) = std::fs::read_to_string(self.core_log()) {
                let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
                let from = lines.len().saturating_sub(MAX_LOG_LINES / 2);
                out.extend(lines[from..].iter().map(|l| l.to_string()));
            }
        }
        out
    }

    pub fn clear_logs(&self) {
        self.logs.lock().unwrap().clear();
        if PLATFORM == Platform::Android {
            if let Ok(f) = std::fs::OpenOptions::new().write(true).open(self.core_log()) {
                let _ = f.set_len(0);
            }
        }
    }

    fn core_log(&self) -> PathBuf {
        self.paths.vpn_dir.join("core.log")
    }

    fn profile_path(&self) -> PathBuf {
        self.paths.vpn_dir.join("profile.json")
    }

    fn save(&self) {
        let st = self.state.lock().unwrap().clone();
        if let Ok(text) = serde_json::to_string_pretty(&st) {
            let tmp = self.paths.state.with_extension("json.tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(&tmp, &self.paths.state);
            }
        }
    }

    pub fn snapshot(&self) -> Persisted {
        self.state.lock().unwrap().clone()
    }

    pub fn settings(&self) -> Settings {
        self.state.lock().unwrap().settings.clone()
    }

    // -----------------------------------------------------------------------
    // Подписки
    // -----------------------------------------------------------------------

    /// Скачивает подписку: напрямую (с запасным DNS-over-HTTPS), а если сайт
    /// подписки заблокирован — через VPN: работающее подключение или временно
    /// запущенное ядро с уже известными серверами.
    async fn fetch(&self, url: &str, seed: &str, sub_id: Option<&str>) -> Result<Fetched, String> {
        let ua = self.state.lock().unwrap().settings.user_agent.clone();
        let first = match subscription::fetch(url, &ua, seed, None).await {
            Ok(f) => return Ok(f),
            Err(e) => e,
        };
        if let Some(proxy) = self.live_proxy() {
            self.log("[app] подписка напрямую недоступна, загружаю через подключение");
            return subscription::fetch(url, &ua, seed, Some(&proxy))
                .await
                .map_err(|e| format!("{first}; через VPN: {e}"));
        }
        let servers = self.servers_for_temp(sub_id);
        if servers.is_empty() {
            return Err(format!(
                "{first}. Похоже, сайт подписки заблокирован — подключитесь к любому VPN и добавьте подписку ещё раз, дальше Tunnelka будет обновлять её через свои серверы"
            ));
        }
        self.log("[app] подписка напрямую недоступна, загружаю через временное подключение");
        let tc = match self.temp_core(&servers, true).await {
            Ok(tc) => tc,
            Err(e) => return Err(format!("{first}; через VPN: {e}")),
        };
        let proxy = tc.proxy.clone().unwrap_or_default();
        // Автовыбор проверяет серверы в фоне: если первый не сработал, ждём его.
        let mut res = Err(String::new());
        for attempt in 0..3 {
            res = subscription::fetch(url, &ua, seed, Some(&proxy)).await;
            if res.is_ok() {
                break;
            }
            if attempt < 2 {
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
        drop(tc);
        res.map_err(|e| format!("{first}; через VPN: {e}"))
    }

    /// Локальный прокси работающего подключения (если он есть).
    fn live_proxy(&self) -> Option<String> {
        let mut rt = self.rt.lock().unwrap();
        self.reap(&mut rt);
        if !Self::live(&rt) || rt.paused || rt.run.mixed_port == 0 {
            return None;
        }
        Some(if rt.run.mixed_auth {
            format!("http://{}:{}@127.0.0.1:{}", rt.run.socks_user, rt.run.socks_pass, rt.run.mixed_port)
        } else {
            format!("http://127.0.0.1:{}", rt.run.mixed_port)
        })
    }

    /// Серверы для временного подключения: этой подписки или любые известные.
    fn servers_for_temp(&self, sub_id: Option<&str>) -> Vec<Server> {
        let st = self.state.lock().unwrap();
        let mut v: Vec<Server> = sub_id
            .and_then(|id| st.subscriptions.iter().find(|s| s.id == id))
            .map(|s| s.servers.iter().filter(|x| x.usable()).cloned().collect())
            .unwrap_or_default();
        if v.is_empty() {
            v = st
                .subscriptions
                .iter()
                .flat_map(|s| s.servers.iter().filter(|x| x.usable()).cloned())
                .take(40)
                .collect();
        }
        v
    }

    /// Добавляет подписку по ссылке или, если это не http(s), — серверы из текста.
    pub async fn add_subscription(&self, input: &str) -> Result<String, String> {
        let input = input.trim();
        if input.is_empty() {
            return Err("вставьте ссылку на подписку или ссылки на серверы".into());
        }
        let is_url = input.starts_with("http://") || input.starts_with("https://");
        if !is_url || input.lines().count() > 1 {
            return self.add_manual(input).map(|_| MANUAL_SUB.to_string());
        }
        if let Some(existing) = self
            .state
            .lock()
            .unwrap()
            .subscriptions
            .iter()
            .find(|s| s.url.as_deref() == Some(input))
        {
            return Err(format!("подписка уже добавлена: «{}»", existing.name));
        }
        let id = random_token()[..12].to_string();
        let f = self.fetch(input, &id, None).await?;
        let host = input
            .split("://")
            .nth(1)
            .and_then(|r| r.split('/').next())
            .unwrap_or("Подписка")
            .to_string();
        let sub = Subscription {
            id: id.clone(),
            name: f.title.clone().unwrap_or(host),
            url: Some(input.to_string()),
            info: f.info.clone(),
            updated_at: now(),
            update_interval_h: f.update_interval_h.unwrap_or(12),
            support_url: f.support_url.clone(),
            web_page_url: f.web_page_url.clone(),
            announce: f.announce.clone(),
            last_error: None,
            servers: f.servers,
        };
        {
            let mut st = self.state.lock().unwrap();
            st.subscriptions.retain(|s| s.id != id);
            // Ручная группа всегда в конце.
            let pos = st
                .subscriptions
                .iter()
                .position(|s| s.id == MANUAL_SUB)
                .unwrap_or(st.subscriptions.len());
            st.subscriptions.insert(pos, sub);
            if st.selected.is_none() {
                st.selected = Some(format!("{}{id}", Selection::AUTO_PREFIX));
            }
        }
        self.save();
        self.log(format!("[app] подписка добавлена ({id})"));
        Ok(id)
    }

    pub fn add_manual(&self, text: &str) -> Result<usize, String> {
        let f = subscription::parse_body(text, MANUAL_SUB);
        if f.servers.is_empty() {
            return Err("не найдено ни одной ссылки на сервер".into());
        }
        let added;
        {
            let mut st = self.state.lock().unwrap();
            if !st.subscriptions.iter().any(|s| s.id == MANUAL_SUB) {
                st.subscriptions.push(Subscription {
                    id: MANUAL_SUB.into(),
                    name: "Мои серверы".into(),
                    url: None,
                    info: None,
                    updated_at: now(),
                    update_interval_h: 0,
                    support_url: None,
                    web_page_url: None,
                    announce: None,
                    last_error: None,
                    servers: vec![],
                });
            }
            let sub = st
                .subscriptions
                .iter_mut()
                .find(|s| s.id == MANUAL_SUB)
                .unwrap();
            let before = sub.servers.len();
            for s in f.servers {
                if !sub.servers.iter().any(|x| x.id == s.id) {
                    sub.servers.push(s);
                }
            }
            added = sub.servers.len() - before;
            if st.selected.is_none() {
                let first = st
                    .subscriptions
                    .iter()
                    .find(|s| s.id == MANUAL_SUB)
                    .and_then(|s| s.servers.iter().find(|x| x.usable()))
                    .map(|x| x.id.clone());
                st.selected = first;
            }
        }
        self.save();
        Ok(added)
    }

    pub async fn update_subscription(&self, id: &str) -> Result<(), String> {
        let url = {
            let st = self.state.lock().unwrap();
            let sub = st
                .subscriptions
                .iter()
                .find(|s| s.id == id)
                .ok_or("подписка не найдена")?;
            sub.url.clone().ok_or("эту группу нельзя обновить")?
        };
        let res = self.fetch(&url, id, Some(id)).await;
        {
            let mut st = self.state.lock().unwrap();
            if let Some(sub) = st.subscriptions.iter_mut().find(|s| s.id == id) {
                match &res {
                    Ok(f) => {
                        if let Some(t) = &f.title {
                            sub.name = t.clone();
                        }
                        sub.info = f.info.clone();
                        sub.servers = f.servers.clone();
                        sub.updated_at = now();
                        if let Some(h) = f.update_interval_h {
                            sub.update_interval_h = h;
                        }
                        sub.support_url = f.support_url.clone().or(sub.support_url.take());
                        sub.web_page_url = f.web_page_url.clone().or(sub.web_page_url.take());
                        sub.announce = f.announce.clone();
                        sub.last_error = None;
                    }
                    Err(e) => sub.last_error = Some(e.clone()),
                }
            }
        }
        self.save();
        res.map(|_| ())
    }

    /// Автообновление подписок: при запуске приложения и затем раз в час
    /// проверяет, но каждую подписку обновляет не чаще раза в сутки.
    pub async fn update_due(&self) {
        const DAY: u64 = 24 * 3600;
        let due: Vec<String> = {
            let st = self.state.lock().unwrap();
            let t = now();
            st.subscriptions
                .iter()
                .filter(|s| s.url.is_some())
                .filter(|s| t.saturating_sub(s.updated_at) >= DAY)
                .map(|s| s.id.clone())
                .collect()
        };
        for id in due {
            match self.update_subscription(&id).await {
                Ok(()) => self.log(format!("[app] подписка {id} обновлена автоматически")),
                Err(e) => self.log(format!("[app] автообновление подписки {id}: {e}")),
            }
        }
    }

    pub async fn update_all(&self) -> Vec<String> {
        let ids: Vec<String> = {
            let st = self.state.lock().unwrap();
            st.subscriptions
                .iter()
                .filter(|s| s.url.is_some())
                .map(|s| s.id.clone())
                .collect()
        };
        let mut errors = vec![];
        for id in ids {
            if let Err(e) = self.update_subscription(&id).await {
                errors.push(e);
            }
        }
        errors
    }

    pub fn remove_subscription(&self, id: &str) {
        let was_active = self.is_running() && {
            let st = self.state.lock().unwrap();
            match st.selected.as_deref().and_then(|sel| find_selection(&st.subscriptions, sel)) {
                Some(Picked::Auto(sub)) | Some(Picked::Server(sub, _)) => sub.id == id,
                _ => false,
            }
        };
        if was_active {
            self.disconnect();
        }
        {
            let mut st = self.state.lock().unwrap();
            st.subscriptions.retain(|s| s.id != id);
            let still_valid = st
                .selected
                .as_ref()
                .map(|sel| find_selection(&st.subscriptions, sel).is_some())
                .unwrap_or(false);
            if !still_valid {
                st.selected = st
                    .subscriptions
                    .first()
                    .map(|s| format!("{}{}", Selection::AUTO_PREFIX, s.id));
            }
        }
        self.save();
    }

    pub fn rename_subscription(&self, id: &str, name: &str) {
        {
            let mut st = self.state.lock().unwrap();
            if let Some(s) = st.subscriptions.iter_mut().find(|s| s.id == id) {
                s.name = name.trim().chars().take(80).collect();
            }
        }
        self.save();
    }

    pub fn remove_server(&self, id: &str) {
        {
            let mut st = self.state.lock().unwrap();
            for sub in st.subscriptions.iter_mut().filter(|s| s.id == MANUAL_SUB) {
                sub.servers.retain(|s| s.id != id);
            }
            if st.selected.as_deref() == Some(id) {
                st.selected = None;
            }
        }
        self.save();
    }

    // -----------------------------------------------------------------------
    // Подключение
    // -----------------------------------------------------------------------

    /// Подключение работает (ядро запущено или VPN Android включён).
    fn live(rt: &Rt) -> bool {
        rt.child.is_some() || rt.vpn_on
    }

    pub fn is_running(&self) -> bool {
        let mut rt = self.rt.lock().unwrap();
        self.reap(&mut rt);
        Self::live(&rt)
    }

    /// Проверяет, не упало ли ядро (на Android — сверяется с VPN-сервисом).
    fn reap(&self, rt: &mut Rt) {
        if PLATFORM == Platform::Android {
            self.reap_android(rt);
            return;
        }
        let dead = |c: &mut Option<Child>| match c.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(Some(_))),
            None => false,
        };
        let sb_dead = dead(&mut rt.child);
        let xr_dead = dead(&mut rt.xray);
        if !(sb_dead || xr_dead) {
            return;
        }
        for c in [rt.child.take(), rt.xray.take()].into_iter().flatten() {
            let mut c = c;
            let _ = c.kill();
            let _ = c.wait();
        }
        rt.active_sub = None;
        rt.gen += 1;
        if rt.sysproxy_on {
            let _ = sysproxy::unset();
            rt.sysproxy_on = false;
        }
        let tail = self.last_error_line();
        let reason = format!(
            "ядро {} завершилось{}",
            if xr_dead { "Xray" } else { "sing-box" },
            tail.map(|t| format!(": {t}")).unwrap_or_default()
        );
        let ks = killswitch::is_active(&self.paths.data);
        rt.last_error = Some(if ks {
            format!("{reason}. Интернет заблокирован kill switch — подключитесь снова или нажмите «Разблокировать интернет»")
        } else {
            reason
        });
    }

    /// Android: VPN-сервис живёт сам по себе — его можно включить плиткой в шторке,
    /// поставить на паузу или отключить из уведомления.
    fn reap_android(&self, rt: &mut Rt) {
        if rt.busy {
            return;
        }
        let vs = tauri_plugin_tunnelka_vpn::state();
        if vs.active() {
            rt.paused = vs.state == "paused";
            if !rt.vpn_on {
                // VPN включили без приложения — берём параметры из профиля.
                if let Some(p) = self.read_profile() {
                    rt.vpn_on = true;
                    rt.run = p.runtime;
                    rt.groups = p.groups;
                    rt.tags = p.tags.into_iter().collect();
                    rt.domestic = p.domestic;
                    rt.autos = p.autos;
                    rt.active_sub = Some(p.active_sub);
                    rt.mode = Mode::Tun;
                    rt.last_error = None;
                    rt.gen += 1;
                }
            }
            if vs.started_at > 0 {
                rt.started_at = vs.started_at;
            }
        } else if rt.vpn_on {
            rt.vpn_on = false;
            rt.paused = false;
            rt.active_sub = None;
            rt.started_at = 0;
            rt.gen += 1;
            // Без ошибки — значит, VPN отключили кнопкой в уведомлении или плиткой.
            rt.last_error = vs.error;
        }
    }

    fn read_profile(&self) -> Option<VpnProfile> {
        std::fs::read_to_string(self.profile_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    }

    fn last_error_line(&self) -> Option<String> {
        let logs = self.logs();
        logs.iter()
            .rev()
            .take(40)
            .find(|l| {
                let low = l.to_lowercase();
                low.contains("fatal") || low.contains("error") || low.contains("failed")
            })
            .cloned()
    }

    fn selected_name(st: &Persisted) -> Option<(String, Option<String>)> {
        st.selected
            .as_ref()
            .and_then(|s| find_selection(&st.subscriptions, s))
            .map(|p| match p {
                Picked::Server(_, srv) => (srv.name.clone(), Some(srv.protocol.clone())),
                Picked::Auto(sub) => (format!("Автовыбор · {}", sub.name), None),
                Picked::All => ("Автовыбор+".to_string(), None),
            })
    }

    /// Выбранный конкретный сервер (не автовыбор).
    fn selected_server(st: &Persisted) -> Option<Server> {
        match st.selected.as_deref().and_then(|s| find_selection(&st.subscriptions, s)) {
            Some(Picked::Server(_, s)) => Some(s.clone()),
            _ => None,
        }
    }

    /// Что наблюдать VPN-сервису Android: выбранный тег, ступени замены и
    /// названия серверов для уведомления.
    fn monitor_plan(st: &Persisted) -> (String, Vec<Vec<String>>, HashMap<String, String>) {
        let mut names = HashMap::new();
        let mut cands = vec![];
        for sub in &st.subscriptions {
            for s in sub.servers.iter().filter(|s| s.usable()) {
                names.entry(s.id.clone()).or_insert_with(|| s.name.clone());
                cands.push(Candidate { sub_id: &sub.id, server: s });
            }
        }
        match st.selected.as_deref().and_then(|s| find_selection(&st.subscriptions, s)) {
            Some(Picked::All) => (TAG_AUTO.to_string(), vec![], names),
            Some(Picked::Auto(sub)) => (auto_tag(&sub.id), vec![], names),
            Some(Picked::Server(sub, s)) => {
                let tiers = failover::tiers(s, &sub.id, &cands, &st.settings.switch_order);
                (s.id.clone(), tiers, names)
            }
            None => (String::new(), vec![], names),
        }
    }

    /// Android: VPN-сервис сам следит за связью и при сбое меняет сервер.
    /// Приложение узнаёт об этом из файла monitor.json.
    fn sync_monitor(&self) {
        if PLATFORM != Platform::Android {
            return;
        }
        let Ok(text) = std::fs::read_to_string(self.paths.vpn_dir.join("monitor.json")) else { return };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { return };
        let at = v["at"].as_u64().unwrap_or(0);
        {
            let mut rt = self.rt.lock().unwrap();
            if at <= rt.monitor_at || at / 1000 + 5 < rt.started_at {
                return;
            }
            rt.monitor_at = at;
            if let Some(n) = v["notice"].as_str().filter(|n| !n.is_empty()) {
                rt.notice = Some(n.to_string());
                self.log(format!("[vpn] {n}"));
            }
            if v["switched"].as_bool() == Some(true) {
                rt.exit = None;
            }
        }
        if let Some(sel) = v["selected"].as_str().filter(|s| !s.is_empty()) {
            let changed = {
                let mut st = self.state.lock().unwrap();
                let known = st.subscriptions.iter().any(|sub| sub.servers.iter().any(|x| x.id == sel));
                if known && st.selected.as_deref() != Some(sel) {
                    st.selected = Some(sel.to_string());
                    true
                } else {
                    false
                }
            };
            if changed {
                self.save();
            }
        }
    }

    pub fn status(&self) -> Status {
        self.sync_monitor();
        let (settings, selected, subs_name) = {
            let st = self.state.lock().unwrap();
            (st.settings.clone(), st.selected.clone(), Self::selected_name(&st))
        };
        let mut rt = self.rt.lock().unwrap();
        self.reap(&mut rt);
        let running = Self::live(&rt);
        Status {
            platform: if PLATFORM == Platform::Android { "android" } else { "windows" },
            running,
            busy: rt.busy,
            mode: if running { rt.mode } else { settings.mode },
            started_at: rt.started_at,
            selected,
            selected_name: subs_name.as_ref().map(|n| n.0.clone()),
            selected_protocol: subs_name.and_then(|n| n.1),
            active_sub: rt.active_sub.clone(),
            last_error: rt.last_error.clone(),
            notice: rt.notice.clone(),
            core_found: self.paths.singbox.exists(),
            xray_found: self.paths.xray.exists(),
            mixed_port: if running && rt.mode == Mode::Proxy { rt.run.mixed_port } else { 0 },
            kill_switch_active: killswitch::is_active(&self.paths.data),
            paused: running && rt.paused,
            checking: running && rt.checking,
            exit_ip: rt.exit.as_ref().filter(|_| running && !rt.paused).map(|e| e.0.clone()),
            exit_place: rt.exit.as_ref().filter(|_| running && !rt.paused).map(|e| e.1.clone()),
        }
    }

    pub async fn connect(self: &Arc<Self>) -> Result<Status, String> {
        {
            let mut rt = self.rt.lock().unwrap();
            if rt.busy {
                return Err("подождите, идёт подключение".into());
            }
            rt.busy = true;
            rt.notice = None;
            rt.checking = false;
        }
        let settings = self.settings();
        let mode = if PLATFORM == Platform::Android { Mode::Tun } else { settings.mode };
        let res = self.connect_inner(mode).await;
        if res.is_err() {
            self.stop_process();
        }
        let gen = {
            let mut rt = self.rt.lock().unwrap();
            rt.busy = false;
            if let Err(e) = &res {
                rt.last_error = Some(e.clone());
            }
            rt.gen
        };
        // Проверка идёт уже после подключения, в фоне: отвечает ли сервер и
        // (в режиме TUN на Windows) есть ли через туннель интернет.
        let _ = settings;
        if res.is_ok() {
            self.rt.lock().unwrap().checking = true;
            let me = self.clone();
            tauri::async_runtime::spawn(async move { me.health_watch(gen).await });
        }
        res.map(|_| self.status())
    }

    fn spawn(&self, exe: &PathBuf, args: &[&std::ffi::OsStr], prefix: &'static str) -> Result<Child, String> {
        let mut cmd = Command::new(exe);
        cmd.args(args)
            .current_dir(&self.paths.data)
            .env("XRAY_LOCATION_ASSET", &self.paths.ruleset_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let name = exe.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("не удалось запустить {name}: {e}"))?;
        if let Some(out) = child.stdout.take() {
            pipe_logs(out, self.logs.clone(), prefix);
        }
        if let Some(err) = child.stderr.take() {
            pipe_logs(err, self.logs.clone(), prefix);
        }
        Ok(child)
    }

    async fn connect_inner(&self, mode: Mode) -> Result<(), String> {
        if !self.paths.singbox.exists() {
            return Err(format!(
                "не найдено ядро sing-box: {}",
                self.paths.singbox.display()
            ));
        }
        let android = PLATFORM == Platform::Android;
        // Если уже запущено — перезапускаем с новой конфигурацией. На Android
        // VPN-сервис перезапускается сам по команде запуска, без разрыва VPN.
        // Kill switch при этом не снимаем, чтобы не было утечки между запусками.
        if !android {
            self.stop_process();
        }

        let (config, sub_id, settings, run, server_name) = {
            let st = self.state.lock().unwrap();
            let sel = st
                .selected
                .clone()
                .ok_or("выберите сервер или подписку")?;
            let picked =
                find_selection(&st.subscriptions, &sel).ok_or("выбранный сервер не найден")?;
            let (sub_id, default) = match picked {
                Picked::Server(sub, s) => {
                    if !s.usable() {
                        return Err(format!(
                            "сервер не поддерживается: {}",
                            s.error.clone().unwrap_or_default()
                        ));
                    }
                    (sub.id.clone(), s.id.clone())
                }
                Picked::Auto(sub) => (sub.id.clone(), auto_tag(&sub.id)),
                Picked::All => (String::new(), TAG_AUTO.to_string()),
            };
            // В конфиг попадают серверы всех подписок: тогда переключение между
            // ними, автовыбор по всем подпискам и проверка пинга работают без
            // переподключения.
            let mut seen = std::collections::HashSet::new();
            let servers: Vec<&Server> = st
                .subscriptions
                .iter()
                .flat_map(|s| s.servers.iter())
                .filter(|s| s.usable() && seen.insert(s.id.clone()))
                .collect();
            let autos: Vec<(String, Vec<String>)> = st
                .subscriptions
                .iter()
                .map(|sub| {
                    let ids = sub.servers.iter().filter(|s| s.usable()).map(|s| s.id.clone()).collect();
                    (auto_tag(&sub.id), ids)
                })
                .collect();
            // Порты и пароли — случайные на каждое подключение.
            let n_xray = if self.paths.xray.exists() {
                singbox::xray_count(&servers, &st.settings)
            } else {
                0
            };
            let mut ports = free_ports(2 + n_xray)?;
            let clash_port = ports.remove(0);
            let random_mixed = ports.remove(0);
            let mixed_port = if android {
                random_mixed
            } else if mode == Mode::Proxy {
                if st.settings.mixed_port != 0 {
                    st.settings.mixed_port
                } else {
                    random_mixed
                }
            } else {
                0
            };
            let run = Runtime {
                mixed_port,
                mixed_auth: android,
                clash_port,
                secret: random_token(),
                socks_user: random_token()[..10].to_string(),
                socks_pass: random_token(),
                xray_ports: ports,
            };
            let xray_name = self.paths.xray.exists().then_some(XRAY_EXE);
            let built = singbox::build(&BuildInput {
                settings: &st.settings,
                servers,
                autos,
                default,
                ruleset_dir: Some(&self.paths.ruleset_dir),
                xray_process: xray_name,
                mode,
                platform: PLATFORM,
                runtime: &run,
            })?;
            let name = Self::selected_name(&st).map(|n| n.0).unwrap_or_default();
            (built, sub_id, st.settings.clone(), run, name)
        };
        {
            let mut rt = self.rt.lock().unwrap();
            rt.tags = config.tags.iter().cloned().collect();
            rt.domestic = config.domestic;
            rt.autos = config.autos.clone();
            rt.groups = config.groups.clone();
        }
        if config.domestic {
            self.log("[app] российский сервер: весь трафик идёт через него (режим «белого интернета»)");
        }

        if android {
            return self.start_android(config, sub_id, settings, run, server_name).await;
        }

        // Kill switch включается параллельно с запуском ядер (PowerShell долго
        // стартует), но подключение не считается готовым, пока он не включился.
        let ks_task = if settings.kill_switch {
            if killswitch::is_active(&self.paths.data) {
                None
            } else {
                let mut programs = vec![self.paths.singbox.clone(), self.paths.xray.clone()];
                if let Ok(me) = std::env::current_exe() {
                    programs.push(me);
                }
                let data = self.paths.data.clone();
                Some(tauri::async_runtime::spawn_blocking(move || {
                    killswitch::enable(&data, &programs, &[singbox::TUN_ADDR4, singbox::TUN_ADDR6])
                }))
            }
        } else {
            if killswitch::is_active(&self.paths.data) {
                let _ = killswitch::disable(&self.paths.data);
            }
            None
        };

        let started = self.start_cores(&config, mode, &run).await;
        let started = match started {
            Ok(()) => match ks_task {
                Some(t) => match t.await.map_err(|e| e.to_string()).and_then(|r| r) {
                    Ok(off) if !off.is_empty() => {
                        self.log(format!(
                            "[app] брандмауэр Windows выключен для профилей: {} — kill switch там не сработает",
                            off.join(", ")
                        ));
                        Ok(())
                    }
                    Ok(_) => {
                        self.log("[app] kill switch включён");
                        Ok(())
                    }
                    Err(e) => {
                        // Без kill switch VPN всё равно работает — не оставляем
                        // пользователя совсем без интернета, а сообщаем, что не так.
                        self.log(format!("[app] kill switch не включился: {e}"));
                        self.rt.lock().unwrap().notice = Some(format!(
                            "Kill switch не включился, VPN работает без него. Причина — {e}"
                        ));
                        Ok(())
                    }
                },
                None => Ok(()),
            },
            Err(e) => {
                if let Some(t) = ks_task {
                    let _ = t.await;
                }
                Err(e)
            }
        };
        started?;

        {
            let mut rt = self.rt.lock().unwrap();
            rt.started_at = now();
            rt.active_sub = Some(sub_id);
            rt.last_error = None;
            rt.mode = mode;
            rt.run = run.clone();
            rt.gen += 1;
        }
        if mode == Mode::Proxy {
            sysproxy::set(run.mixed_port)?;
            self.rt.lock().unwrap().sysproxy_on = true;
        }
        self.log("[app] подключено");
        Ok(())
    }

    /// Windows: запускает Xray (если нужен) и sing-box и ждёт, пока ядро ответит.
    async fn start_cores(&self, config: &singbox::Built, mode: Mode, run: &Runtime) -> Result<(), String> {
        // Сначала Xray: sing-box будет подключаться к его SOCKS-входам.
        let xray_child = match &config.xray {
            Some(xcfg) => {
                write_private(&self.paths.xray_config, xcfg)?;
                self.log(format!(
                    "[app] запуск Xray: {} сервер(ов)",
                    xcfg["inbounds"].as_array().map(|a| a.len()).unwrap_or(0)
                ));
                let c = self.paths.xray_config.clone();
                Some(self.spawn(
                    &self.paths.xray,
                    &["run".as_ref(), "-c".as_ref(), c.as_os_str()],
                    "[xray] ",
                )?)
            }
            None => None,
        };
        write_private(&self.paths.config, &config.singbox)?;
        self.log(format!(
            "[app] запуск ядра, режим: {}",
            if mode == Mode::Tun { "TUN" } else { "системный прокси" }
        ));
        let cfg_path = self.paths.config.clone();
        let data = self.paths.data.clone();
        let child = self.spawn(
            &self.paths.singbox,
            &[
                "run".as_ref(),
                "-c".as_ref(),
                cfg_path.as_os_str(),
                "-D".as_ref(),
                data.as_os_str(),
                "--disable-color".as_ref(),
            ],
            "",
        );
        let child = match child {
            Ok(c) => c,
            Err(e) => {
                if let Some(mut x) = xray_child {
                    let _ = x.kill();
                }
                return Err(e);
            }
        };
        let clash = {
            let mut rt = self.rt.lock().unwrap();
            rt.child = Some(child);
            rt.xray = xray_child;
            rt.last_error = None;
            rt.run = run.clone();
            rt.groups = config.groups.clone();
            (format!("http://127.0.0.1:{}", rt.run.clash_port), rt.run.secret.clone())
        };

        // Ждём, пока ядро поднимется (обычно доли секунды), вместо фиксированной паузы.
        let ready = self.wait_ready(&clash.0, &clash.1).await;
        // Ядра уже прочитали конфиги — файлы с паролями серверов больше не нужны.
        let (c1, c2) = (self.paths.config.clone(), self.paths.xray_config.clone());
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = std::fs::remove_file(c1);
            let _ = std::fs::remove_file(c2);
        });
        if !ready {
            let err = self
                .rt
                .lock()
                .unwrap()
                .last_error
                .clone()
                .unwrap_or_else(|| "ядро не ответило за 10 секунд".into());
            let hint = if mode == Mode::Tun && err.to_lowercase().contains("access is denied") {
                " — для режима TUN запустите приложение от имени администратора"
            } else {
                ""
            };
            return Err(format!("{err}{hint}"));
        }
        if mode == Mode::Tun {
            // Windows ещё настраивает маршруты нового адаптера.
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        Ok(())
    }

    /// Ждёт ответа Clash API ядра. false — ядро завершилось или не ответило.
    async fn wait_ready(&self, base: &str, secret: &str) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if !self.is_running() {
                return false;
            }
            let ok = self
                .http
                .get(format!("{base}/version"))
                .bearer_auth(secret)
                .timeout(Duration::from_millis(500))
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            if ok {
                return true;
            }
        }
        false
    }

    /// Android: сохраняет конфиги и профиль и запускает VPN-сервис, который
    /// сам запускает ядра. Повторный запуск перезапускает подключение.
    async fn start_android(
        &self,
        config: singbox::Built,
        sub_id: String,
        settings: Settings,
        run: Runtime,
        server_name: String,
    ) -> Result<(), String> {
        let dir = self.paths.vpn_dir.clone();
        // Выбор сервера из настроек важнее запомненного ядром.
        let _ = std::fs::remove_file(dir.join("cache.db"));
        let mut processes = vec![];
        let _ = std::fs::remove_file(&self.paths.xray_config);
        if let Some(xcfg) = &config.xray {
            write_private(&self.paths.xray_config, xcfg)?;
            processes.push(ProcSpec {
                name: "Xray".into(),
                exe: self.paths.xray.to_string_lossy().into_owned(),
                args: vec!["run".into(), "-c".into(), self.paths.xray_config.to_string_lossy().into_owned()],
            });
        }
        write_private(&self.paths.config, &config.singbox)?;
        processes.push(ProcSpec {
            name: "sing-box".into(),
            exe: self.paths.singbox.to_string_lossy().into_owned(),
            args: vec![
                "run".into(),
                "-c".into(),
                self.paths.config.to_string_lossy().into_owned(),
                "-D".into(),
                dir.to_string_lossy().into_owned(),
                "--disable-color".into(),
            ],
        });
        let split = &settings.split;
        let (selected, fallback, names) = Self::monitor_plan(&self.state.lock().unwrap());
        let _ = std::fs::remove_file(dir.join("monitor.json"));
        let profile = VpnProfile {
            session: "Tunnelka".into(),
            server: server_name,
            notify: settings.notification,
            socks_port: run.mixed_port,
            socks_user: run.socks_user.clone(),
            socks_pass: run.socks_pass.clone(),
            app_mode: match split.app_mode {
                AppMode::Off => "off",
                AppMode::Include => "include",
                AppMode::Exclude => "exclude",
            }
            .into(),
            apps: split.active_apps().to_vec(),
            app_routes: split.app_routes.clone(),
            work_dir: dir.to_string_lossy().into_owned(),
            log: self.core_log().to_string_lossy().into_owned(),
            env: HashMap::from([(
                "XRAY_LOCATION_ASSET".to_string(),
                self.paths.ruleset_dir.to_string_lossy().into_owned(),
            )]),
            processes,
            runtime: run.clone(),
            active_sub: sub_id.clone(),
            groups: config.groups.clone(),
            selected,
            auto_switch: settings.auto_switch,
            fallback,
            names,
            tags: config.tags.clone(),
            domestic: config.domestic,
            autos: config.autos.clone(),
            domestic_ids: self.domestic_ids(),
        };
        let path = self.profile_path();
        write_private(&path, &serde_json::to_value(&profile).map_err(|e| e.to_string())?)?;
        self.log(format!(
            "[app] запуск VPN{}",
            if config.xray.is_some() { " (sing-box + Xray)" } else { "" }
        ));
        {
            let mut rt = self.rt.lock().unwrap();
            rt.run = run;
            rt.groups = config.groups.clone();
            rt.mode = Mode::Tun;
        }
        let args = tauri_plugin_tunnelka_vpn::StartArgs {
            profile: path.to_string_lossy().into_owned(),
            notify: settings.notification,
        };
        tauri::async_runtime::spawn_blocking(move || tauri_plugin_tunnelka_vpn::start(args))
            .await
            .map_err(|e| e.to_string())??;
        {
            let mut rt = self.rt.lock().unwrap();
            rt.vpn_on = true;
            rt.paused = false;
            rt.started_at = now();
            rt.active_sub = Some(sub_id);
            rt.last_error = None;
            rt.gen += 1;
        }
        self.log("[app] подключено");
        Ok(())
    }

    /// Android: обновляет поля профиля работающего VPN (название сервера в
    /// уведомлении, показ уведомления).
    fn refresh_profile(&self) {
        if PLATFORM != Platform::Android || !self.is_running() {
            return;
        }
        let Some(mut p) = self.read_profile() else { return };
        {
            let st = self.state.lock().unwrap();
            p.server = Self::selected_name(&st).map(|n| n.0).unwrap_or_default();
            p.notify = st.settings.notification;
            p.auto_switch = st.settings.auto_switch;
            let (selected, fallback, names) = Self::monitor_plan(&st);
            p.selected = selected;
            p.fallback = fallback;
            p.names = names;
        }
        if let Ok(v) = serde_json::to_value(&p) {
            if write_private(&self.profile_path(), &v).is_ok() {
                let _ = tauri_plugin_tunnelka_vpn::refresh();
            }
        }
    }

    /// Фоновая проверка после подключения, затем постоянное наблюдение за
    /// связью. Если выбранный сервер не отвечает: у автовыбора — перепроверка
    /// группы, у сервера с вариантами — выбор рабочего варианта, иначе (если
    /// включено «auto_switch») — переход на похожий рабочий сервер. Если в
    /// режиме TUN на Windows сервер работает, а интернета нет — включает
    /// системный прокси (настройка «tun_fallback»).
    async fn health_watch(self: Arc<Self>, gen: u64) {
        let done = |me: &Self| {
            let mut rt = me.rt.lock().unwrap();
            if rt.gen == gen { rt.checking = false; }
        };

        // Автовыбор: приложение само проверяет серверы группы; первый ответивший
        // включается сразу. Плановая проверка позже сравнит задержки.
        // Сервер с автовыбором внутри: сразу выбираем в нём лучший рабочий вариант.
        let mut ok = if let Some(tag) = self.selected_auto_tag() {
            match self.pick_auto(&tag, true, gen).await {
                Some(p) => {
                    self.auto_picked(&p);
                    true
                }
                None => false,
            }
        } else {
            match self.selected_group() {
                Some(g) => self.tune_group(&g, gen).await,
                None => false,
            }
        };
        if !ok && self.same_gen(gen) {
            ok = self.server_delay(TAG_PROXY).await.is_some();
        }
        if !self.same_gen(gen) {
            done(&self);
            return;
        }
        if !ok {
            self.log("[app] сервер не отвечает");
            if PLATFORM == Platform::Windows && killswitch::is_active(&self.paths.data) {
                // На случай, если мешает брандмауэр: его состояние — в журнал.
                // Блокировку при этом не трогаем.
                for l in tauri::async_runtime::spawn_blocking(killswitch::diagnose).await.unwrap_or_default() {
                    self.log(format!("[ks] {l}"));
                }
            }
            if self.recover(gen, true).await && self.same_gen(gen) {
                done(&self);
                self.check_exit().await;
            }
        } else {
            done(&self);
            let settings = self.settings();
            let tun = PLATFORM != Platform::Android && self.rt.lock().unwrap().mode == Mode::Tun;
            if tun && settings.tun_fallback && settings.split.app_routes.is_empty()
                && !self.internet_works().await && self.same_gen(gen)
            {
                self.log("[app] в режиме TUN нет интернета — переключаюсь на системный прокси");
                if let Some(new_gen) = self.fallback_to_proxy().await {
                    let me = self.clone();
                    tauri::async_runtime::spawn(async move {
                        me.check_exit().await;
                        me.monitor(new_gen).await;
                    });
                }
                return;
            }
            if self.same_gen(gen) {
                self.check_exit().await;
            }
        }
        done(&self);
        // На Android за связью следит VPN-сервис: он работает и без приложения.
        if PLATFORM != Platform::Android {
            self.monitor(gen).await;
        }
    }

    /// Подключение то же, что при запуске проверки, и работает.
    fn same_gen(&self, gen: u64) -> bool {
        let rt = self.rt.lock().unwrap();
        rt.gen == gen && Self::live(&rt) && !rt.busy && !rt.paused
    }

    /// Переход из режима TUN на системный прокси. Возвращает номер нового подключения.
    async fn fallback_to_proxy(&self) -> Option<u64> {
        {
            let mut rt = self.rt.lock().unwrap();
            if rt.busy {
                rt.checking = false;
                return None;
            }
            rt.busy = true;
        }
        let res = self.connect_inner(Mode::Proxy).await;
        if res.is_err() {
            self.stop_process();
        }
        let mut rt = self.rt.lock().unwrap();
        rt.busy = false;
        rt.checking = false;
        match res {
            Ok(()) => {
                rt.notice = Some(
                    "В режиме TUN не было интернета (такое бывает у некоторых провайдеров) — включён системный прокси. В этом режиме браузер может показать сайтам ваш настоящий IP через WebRTC".into(),
                );
                Some(rt.gen)
            }
            Err(e) => {
                rt.last_error = Some(e);
                None
            }
        }
    }

    /// Постоянное наблюдение (Windows): раз в 30 секунд проверяет, что через
    /// выбранный сервер есть интернет. Если сервер перестал отвечать, а у самого
    /// компьютера интернет есть — восстанавливает связь (см. `recover`).
    async fn monitor(&self, gen: u64) {
        let mut offline_logged = false;
        let mut round: u32 = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            round += 1;
            {
                let rt = self.rt.lock().unwrap();
                if rt.gen != gen || !Self::live(&rt) {
                    return;
                }
                if rt.busy || rt.paused {
                    continue;
                }
            }
            if self.server_delay(TAG_PROXY).await.is_some() {
                offline_logged = false;
                self.clear_health_notice();
                // Автовыбор раз в 10 минут перепроверяет серверы и переходит на
                // заметно более быстрый (текущее соединение не рвётся без нужды).
                if round % 20 == 0 {
                    if let Some(tag) = self.selected_auto_tag() {
                        if let Some(p) = self.pick_auto(&tag, false, gen).await {
                            self.auto_picked(&p);
                        }
                    }
                }
                continue;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
            if !self.same_gen(gen) {
                continue;
            }
            if self.server_delay(TAG_PROXY).await.is_some() {
                self.clear_health_notice();
                continue;
            }
            // Если пропал интернет у самого компьютера, менять сервер бесполезно.
            if !self.own_internet().await {
                if !offline_logged {
                    self.log("[app] нет интернета у компьютера — жду, когда появится");
                    offline_logged = true;
                }
                continue;
            }
            offline_logged = false;
            self.log("[app] сервер перестал отвечать");
            if self.recover(gen, false).await {
                if self.same_gen(gen) { self.check_exit().await; }
            } else {
                // Ничего не нашлось — следующая попытка не сразу.
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        }
    }

    /// Есть ли интернет у самого устройства (мимо VPN).
    async fn own_internet(&self) -> bool {
        let bypass = {
            let rt = self.rt.lock().unwrap();
            PLATFORM == Platform::Windows && rt.mode == Mode::Tun
        };
        let targets = ["77.88.8.8:53", "1.1.1.1:443", "8.8.8.8:443"];
        let checks = targets.iter().map(|t| {
            let addr: std::net::SocketAddr = t.parse().unwrap();
            tauri::async_runtime::spawn_blocking(move || {
                crate::netbind::connect_ms(addr, bypass, Duration::from_secs(3)).is_some()
            })
        });
        join_all(checks).await.into_iter().any(|r| r.unwrap_or(false))
    }

    /// Тег группы автовыбора, если выбран автовыбор.
    fn selected_auto_tag(&self) -> Option<String> {
        let sel = self.state.lock().unwrap().selected.clone()?;
        match Selection::parse(&sel) {
            Selection::AutoAll => Some(TAG_AUTO.to_string()),
            Selection::Auto(sub) => Some(auto_tag(&sub)),
            Selection::Server(_) => None,
        }
    }

    /// Российские серверы во всех подписках.
    fn domestic_ids(&self) -> Vec<String> {
        let st = self.state.lock().unwrap();
        st.subscriptions
            .iter()
            .flat_map(|s| s.servers.iter())
            .filter(|s| s.is_domestic())
            .map(|s| s.id.clone())
            .collect()
    }

    /// Убирает предупреждение о сбое связи, когда связь вернулась.
    fn clear_health_notice(&self) {
        let mut rt = self.rt.lock().unwrap();
        if rt.health_notice {
            rt.notice = None;
            rt.health_notice = false;
        }
    }

    async fn first_live(&self, ids: Vec<String>, groups: &HashMap<String, Vec<String>>, gen: u64)
        -> Option<(String, i64, Option<String>)>
    {
        use futures::stream::{self, StreamExt};
        let (base, secret) = self.clash_base();
        let candidates = ids.into_iter().flat_map(|id| {
            let parts = groups.get(&id).cloned().unwrap_or_else(|| vec![id.clone()]);
            parts.into_iter().map(move |part| (id.clone(), part))
        });
        let probes = stream::iter(candidates).map(|(id, part)| {
            let (base, secret) = (&base, &secret);
            async move {
                let ms = proxy_delay(&self.http, base, secret, &part, 3000).await?;
                Some((id.clone(), ms, (part != id).then_some(part)))
            }
        }).buffer_unordered(16);
        futures::pin_mut!(probes);
        while self.same_gen(gen) {
            if let Some(result) = probes.next().await? {
                return self.same_gen(gen).then_some(result);
            }
        }
        None
    }

    /// При подключении берём первый ответ, при плановой проверке сравниваем задержки.
    /// Российские серверы проверяем после зарубежных.
    async fn pick_auto(&self, tag: &str, eager: bool, gen: u64) -> Option<(String, i64, bool)> {
        use futures::stream::{self, StreamExt};
        let (members, groups) = {
            let rt = self.rt.lock().unwrap();
            (rt.autos.get(tag).cloned()?, rt.groups.clone())
        };
        let domestic: std::collections::HashSet<String> = self.domestic_ids().into_iter().collect();
        let (foreign, dom): (Vec<String>, Vec<String>) = members.into_iter().partition(|id| !domestic.contains(id));
        let (base, secret) = self.clash_base();
        let current = if eager { None } else { self.server_delay(TAG_PROXY).await };
        let apply = |id: String, part: Option<String>| {
            let (groups, tag) = (&groups, tag);
            async move {
                if let (Some(part), true) = (part, groups.contains_key(&id)) {
                    if self.clash_put(&id, &part).await.is_err() { return false; }
                }
                self.same_gen(gen) && self.clash_put(tag, &id).await.is_ok()
            }
        };
        for (set, is_dom) in [(foreign, false), (dom, true)] {
            if set.is_empty() {
                continue;
            }
            if eager {
                if let Some((id, ms, part)) = self.first_live(set, &groups, gen).await {
                    if apply(id.clone(), part).await { return Some((id, ms, is_dom)); }
                }
                continue;
            }
            let sem = Arc::new(tokio::sync::Semaphore::new(16));
            let mut tests = stream::iter(set)
                .map(|id| {
                    let sem = sem.clone();
                    let groups = &groups;
                    let (base, secret) = (&base, &secret);
                    async move {
                        let parts = groups.get(&id).cloned().unwrap_or_else(|| vec![id.clone()]);
                        let runs = parts.into_iter().map(|m| {
                            let sem = sem.clone();
                            async move {
                                let _permit = sem.acquire_owned().await.ok();
                                let ms = proxy_delay(&self.http, base, secret, &m, 5000).await.unwrap_or(0);
                                (m, ms)
                            }
                        });
                        let best = join_all(runs).await.into_iter().filter(|(_, ms)| *ms > 0).min_by_key(|(_, ms)| *ms);
                        match best {
                            Some((m, ms)) => (id.clone(), ms, (m != id).then_some(m)),
                            None => (id, 0, None),
                        }
                    }
                })
                .buffer_unordered(64);
            let mut best: Option<(String, i64, Option<String>)> = None;
            while let Some((id, ms, part)) = tests.next().await {
                if ms <= 0 {
                    continue;
                }
                if best.as_ref().map_or(true, |b| ms < b.1) {
                    best = Some((id, ms, part));
                }
            }
            drop(tests);
            let Some((id, ms, part)) = best else { continue };
            if !self.same_gen(gen) { return None; }
            let switch = current.map_or(true, |cur| ms + 100 < cur);
            if switch && !apply(id.clone(), part).await {
                continue;
            }
            return Some((id, ms, is_dom));
        }
        None
    }

    /// Запись в журнал и предупреждение после выбора сервера автовыбором.
    fn auto_picked(&self, p: &(String, i64, bool)) {
        let name = {
            let st = self.state.lock().unwrap();
            st.subscriptions
                .iter()
                .flat_map(|s| s.servers.iter())
                .find(|s| s.id == p.0)
                .map(|s| s.name.clone())
                .unwrap_or_else(|| p.0.clone())
        };
        self.log(format!("[app] автовыбор: «{name}» ({} мс)", p.1));
        let mut rt = self.rt.lock().unwrap();
        if p.2 {
            rt.notice = Some(format!(
                "Зарубежные серверы не отвечают — подключено через российский «{name}». Сайты видят российский IP"
            ));
            rt.health_notice = true;
        } else if rt.health_notice {
            rt.notice = None;
            rt.health_notice = false;
        }
    }

    /// Восстанавливает связь, когда выбранный сервер не отвечает. true — получилось.
    async fn recover(&self, gen: u64, already_probed: bool) -> bool {
        if !self.same_gen(gen) { return false; }
        let old = {
            let st = self.state.lock().unwrap();
            Self::selected_name(&st).map(|n| n.0).unwrap_or_default()
        };
        let set_notice = |me: &Self, text: String| {
            let mut rt = me.rt.lock().unwrap();
            if rt.gen != gen { return; }
            rt.notice = Some(text);
            rt.health_notice = true;
        };

        if let Some(tag) = self.selected_auto_tag() {
            if !already_probed {
                if let Some(p) = self.pick_auto(&tag, true, gen).await {
                    self.auto_picked(&p);
                    self.rt.lock().unwrap().exit = None;
                    return true;
                }
            }
            set_notice(self, "Ни один сервер автовыбора сейчас не отвечает. Приложение продолжит проверять их само".into());
            return false;
        }
        if let Some(g) = self.selected_group() {
            if !already_probed && self.tune_group(&g, gen).await && self.server_delay(TAG_PROXY).await.is_some() {
                return true;
            }
        }
        if !self.settings().auto_switch {
            set_notice(self, format!("«{old}» не отвечает — выберите другой сервер"));
            return false;
        }
        let tiers = Self::monitor_plan(&self.state.lock().unwrap()).1;
        let (tags, groups) = {
            let rt = self.rt.lock().unwrap();
            (rt.tags.clone(), rt.groups.clone())
        };
        for tier in tiers {
            if !self.same_gen(gen) {
                return false;
            }
            let ids: Vec<String> = tier.into_iter().filter(|id| tags.contains(id)).collect();
            if ids.is_empty() {
                continue;
            }
            let Some((id, _, part)) = self.first_live(ids, &groups, gen).await else { continue };
            if let Some(part) = part {
                if self.clash_put(&id, &part).await.is_err() { continue; }
            }
            if !self.same_gen(gen) || self.clash_select(&id).await.is_err() { continue; }
            if !self.same_gen(gen) { return false; }
            let new = {
                let mut st = self.state.lock().unwrap();
                st.selected = Some(id.clone());
                Self::selected_name(&st).map(|n| n.0).unwrap_or_default()
            };
            self.save();
            self.refresh_profile();
            self.log(format!("[app] переключено на «{new}»"));
            set_notice(self, format!("«{old}» перестал отвечать — подключено через «{new}»"));
            self.rt.lock().unwrap().exit = None;
            return true;
        }
        set_notice(self, format!("«{old}» не отвечает, похожих рабочих серверов сейчас нет"));
        false
    }

    /// Есть ли выход в интернет обычным путём (в режиме TUN — через туннель).
    async fn internet_works(&self) -> bool {
        let client = match reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(4))
            .pool_max_idle_per_host(0)
            .build()
        {
            Ok(c) => c,
            Err(_) => return false,
        };
        const URLS: [&str; 2] = [
            "http://cp.cloudflare.com/generate_204",
            "http://www.gstatic.com/generate_204",
        ];
        for attempt in 0..2 {
            // Оба адреса проверяются одновременно, хватит одного ответа.
            let checks = URLS.iter().map(|u| {
                let c = client.clone();
                async move {
                    c.get(*u)
                        .send()
                        .await
                        .map(|r| r.status().is_success())
                        .unwrap_or(false)
                }
            });
            if join_all(checks).await.into_iter().any(|ok| ok) {
                return true;
            }
            if attempt < 1 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        false
    }

    async fn server_delay(&self, tag: &str) -> Option<i64> {
        let (base, secret) = self.clash_base();
        proxy_delay(&self.http, &base, &secret, tag, 3500).await
    }

    /// Узнаёт, с каким IP сайты видят пользователя через VPN, — чтобы это было
    /// видно на главном экране. Если IP российский, а выбран зарубежный сервер,
    /// предупреждает.
    async fn check_exit(&self) {
        let include_app = self.state.lock().unwrap().settings.split.app_mode == AppMode::Include;
        let (gen, include_split) = {
            let rt = self.rt.lock().unwrap();
            (rt.gen, PLATFORM == Platform::Windows && rt.mode == Mode::Tun && include_app)
        };
        // В режиме «только выбранные программы» само приложение идёт напрямую.
        if include_split {
            return;
        }
        let mut b = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .user_agent("curl/8.9");
        b = match self.live_proxy() {
            Some(p) => match reqwest::Proxy::all(&p) {
                Ok(px) => b.proxy(px),
                Err(_) => return,
            },
            None => b.no_proxy(),
        };
        let Ok(client) = b.build() else { return };
        let mut found: Option<(String, String, String)> = None;
        if let Ok(r) = client.get("https://ipinfo.io/json").send().await {
            if let Ok(v) = r.json::<serde_json::Value>().await {
                if let Some(ip) = v["ip"].as_str() {
                    let cc = v["country"].as_str().unwrap_or("").to_string();
                    found = Some((ip.to_string(), cc, v["city"].as_str().unwrap_or("").to_string()));
                }
            }
        }
        if found.is_none() {
            if let Ok(r) = client.get("https://ifconfig.co/json").send().await {
                if let Ok(v) = r.json::<serde_json::Value>().await {
                    if let Some(ip) = v["ip"].as_str() {
                        let cc = v["country_iso"].as_str().unwrap_or("").to_string();
                        found = Some((ip.to_string(), cc, v["city"].as_str().unwrap_or("").to_string()));
                    }
                }
            }
        }
        let Some((ip, cc, city)) = found else { return };
        let flag: String = cc
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .filter_map(|c| char::from_u32(0x1F1E6 + (c.to_ascii_uppercase() as u32 - 'A' as u32)))
            .collect();
        let place = [format!("{flag} {cc}").trim().to_string(), city]
            .into_iter()
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()
            .join(", ");
        let selected_domestic = {
            let st = self.state.lock().unwrap();
            Self::selected_server(&st).map(|s| s.is_domestic()).unwrap_or(false)
        } || self.rt.lock().unwrap().domestic;
        let mut rt = self.rt.lock().unwrap();
        if rt.gen != gen {
            return;
        }
        self.log(format!("[app] сайты видят IP {ip} ({place})"));
        if cc.eq_ignore_ascii_case("RU") && !selected_domestic {
            rt.notice = Some(
                "Сайты видят российский IP: сервер выходит в интернет из России. Выберите сервер в другой стране".into(),
            );
        }
        rt.exit = Some((ip, place));
    }

    /// Выбранный сервер, если у него автовыбор внутри (группа частей).
    fn selected_group(&self) -> Option<String> {
        let selected = self.state.lock().unwrap().selected.clone();
        match selected.as_deref().map(Selection::parse) {
            Some(Selection::Server(id)) if self.rt.lock().unwrap().groups.contains_key(&id) => Some(id),
            _ => None,
        }
    }

    async fn tune_group(&self, id: &str, gen: u64) -> bool {
        let groups = self.rt.lock().unwrap().groups.clone();
        let Some((_, ms, Some(part))) = self.first_live(vec![id.to_string()], &groups, gen).await else {
            return false;
        };
        if self.clash_put(id, &part).await.is_err() { return false; }
        self.log(format!("[app] внутри сервера выбран вариант {part} ({ms} мс)"));
        true
    }

    /// Останавливает ядра, VPN и системный прокси. Kill switch не трогает.
    fn stop_process(&self) {
        let mut rt = self.rt.lock().unwrap();
        if PLATFORM == Platform::Android {
            if rt.vpn_on || tauri_plugin_tunnelka_vpn::state().active() {
                let _ = tauri_plugin_tunnelka_vpn::stop();
            }
            rt.vpn_on = false;
            rt.paused = false;
        }
        for c in [rt.child.take(), rt.xray.take()].into_iter().flatten() {
            let mut c = c;
            let _ = c.kill();
            let _ = c.wait();
        }
        if rt.sysproxy_on {
            let _ = sysproxy::unset();
            rt.sysproxy_on = false;
        }
        rt.active_sub = None;
        rt.started_at = 0;
        rt.checking = false;
        rt.exit = None;
        rt.gen += 1;
        if PLATFORM != Platform::Android {
            let _ = std::fs::remove_file(&self.paths.config);
            let _ = std::fs::remove_file(&self.paths.xray_config);
        }
    }

    /// Отключение VPN. Если включён kill switch, блокировка остаётся: интернет
    /// вернёт новое подключение или «Разблокировать интернет» (`unblock`).
    pub fn disconnect(&self) -> Status {
        let was = self.is_running();
        self.stop_process();
        let blocked = killswitch::is_active(&self.paths.data);
        if blocked && !self.settings().kill_switch {
            // Kill switch в настройках уже выключен — блокировка не нужна.
            return self.unblock();
        }
        if was {
            self.log(if blocked {
                "[app] отключено, интернет заблокирован kill switch"
            } else {
                "[app] отключено"
            });
        }
        {
            let mut rt = self.rt.lock().unwrap();
            rt.last_error = None;
            rt.notice = None;
        }
        self.status()
    }

    /// «Разблокировать интернет»: VPN останавливается, блокировка kill switch снимается.
    pub fn unblock(&self) -> Status {
        self.stop_process();
        if killswitch::is_active(&self.paths.data) {
            match killswitch::disable(&self.paths.data) {
                Ok(()) => self.log("[app] kill switch снят, интернет разблокирован"),
                Err(e) => self.log(format!("[app] kill switch: {e}")),
            }
        }
        {
            let mut rt = self.rt.lock().unwrap();
            rt.last_error = None;
            rt.notice = None;
        }
        self.status()
    }

    #[cfg_attr(mobile, allow(dead_code))]
    pub async fn toggle(self: &Arc<Self>) -> Result<Status, String> {
        if self.is_running() {
            Ok(self.disconnect())
        } else {
            self.connect().await
        }
    }

    pub async fn restart_if_running(self: &Arc<Self>) -> Result<(), String> {
        if self.is_running() {
            self.connect().await.map(|_| ())
        } else {
            Ok(())
        }
    }

    /// Выбор сервера. Если сервер есть в работающем конфиге — переключаем на лету.
    pub async fn select(self: &Arc<Self>, sel: &str) -> Result<Status, String> {
        let (is_auto, tag, domestic) = {
            let mut st = self.state.lock().unwrap();
            let picked = find_selection(&st.subscriptions, sel).ok_or("сервер не найден")?;
            let r = match picked {
                Picked::All => (true, TAG_AUTO.to_string(), false),
                Picked::Auto(sub) => (true, auto_tag(&sub.id), false),
                Picked::Server(_, s) => (false, s.id.clone(), s.is_domestic()),
            };
            st.selected = Some(sel.to_string());
            r
        };
        self.save();
        let (running, in_config, domestic_now) = {
            let mut rt = self.rt.lock().unwrap();
            self.reap(&mut rt);
            (Self::live(&rt) && !rt.paused, rt.tags.contains(&tag), rt.domestic)
        };
        if !running {
            return Ok(self.status());
        }
        // Автовыбор проверяет серверы, только если запущен с ним; российский
        // сервер меняет маршруты («белый интернет») — в этих случаях перезапуск.
        if is_auto || !in_config || domestic != domestic_now {
            self.connect().await?;
            return Ok(self.status());
        }
        if let Err(e) = self.clash_select(&tag).await {
            self.log(format!("[app] переключение на лету не удалось ({e}), перезапуск"));
            self.connect().await?;
            return Ok(self.status());
        }
        {
            let mut rt = self.rt.lock().unwrap();
            rt.exit = None;
            rt.notice = None;
        }
        self.refresh_profile();
        let gen = {
            let mut rt = self.rt.lock().unwrap();
            rt.gen += 1;
            rt.checking = true;
            rt.gen
        };
        let me = self.clone();
        tauri::async_runtime::spawn(async move { me.health_watch(gen).await });
        Ok(self.status())
    }

    pub async fn save_settings(self: &Arc<Self>, mut new: Settings) -> Result<Status, String> {
        let old = self.settings();
        if new.mixed_port != 0 && new.mixed_port < 1024 {
            return Err(format!("порт {} недопустим, используйте 1024–65535 или 0", new.mixed_port));
        }
        // Раздача — только с телефона через точку доступа.
        if PLATFORM != Platform::Android {
            new.allow_lan = false;
        }
        if new.allow_lan && new.lan_port < 1024 {
            return Err(format!("порт {} недопустим, используйте 1024–65535", new.lan_port));
        }
        if new.lan_password.trim().len() < 6 {
            new.lan_password = old.lan_password.clone();
        }
        new.split.normalize();
        if PLATFORM == Platform::Windows && new.mode != Mode::Tun && !new.split.app_routes.is_empty() {
            return Err("для индивидуальных правил приложений включите режим TUN".into());
        }
        if new.autostart != old.autostart {
            autostart::set(new.autostart, &self.paths.data)?;
        }
        let connection_changed = {
            let mut a = old.clone();
            let mut b = new.clone();
            // Эти настройки не требуют переподключения.
            for s in [&mut a, &mut b] {
                s.autostart = false;
                s.auto_connect = false;
                s.notification = true;
                s.user_agent.clear();
                s.auto_switch = true;
                s.switch_order.clear();
            }
            a != b
        };
        let notify_changed = old.notification != new.notification
            || old.auto_switch != new.auto_switch
            || old.switch_order != new.switch_order;
        self.state.lock().unwrap().settings = new;
        self.save();
        let ks_off = old.kill_switch && !self.settings().kill_switch;
        if connection_changed {
            self.restart_if_running().await?;
        } else if notify_changed {
            self.refresh_profile();
        }
        // Kill switch выключили, когда VPN не работает: блокировка больше не нужна.
        if ks_off && !self.is_running() && killswitch::is_active(&self.paths.data) {
            return Ok(self.unblock());
        }
        Ok(self.status())
    }

    // -----------------------------------------------------------------------
    // Clash API ядра: переключение, задержки, трафик
    // -----------------------------------------------------------------------

    fn clash_base(&self) -> (String, String) {
        let rt = self.rt.lock().unwrap();
        (
            format!("http://127.0.0.1:{}", rt.run.clash_port),
            rt.run.secret.clone(),
        )
    }

    async fn clash_select(&self, tag: &str) -> Result<(), String> {
        self.clash_put(TAG_PROXY, tag).await?;
        self.log(format!("[app] сервер переключён: {tag}"));
        Ok(())
    }

    /// Выбор внутри группы-селектора sing-box.
    async fn clash_put(&self, group: &str, tag: &str) -> Result<(), String> {
        let (base, secret) = self.clash_base();
        let r = self
            .http
            .put(format!("{base}/proxies/{}", enc(group)))
            .bearer_auth(secret)
            .json(&serde_json::json!({ "name": tag }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if r.status().is_success() {
            Ok(())
        } else {
            Err(format!("HTTP {}", r.status()))
        }
    }

    pub async fn traffic(&self) -> Option<Traffic> {
        {
            let mut rt = self.rt.lock().unwrap();
            self.reap(&mut rt);
            if !Self::live(&rt) || rt.paused {
                return None;
            }
        }
        let (base, secret) = self.clash_base();
        let v: serde_json::Value = self
            .http
            .get(format!("{base}/connections"))
            .bearer_auth(secret)
            .timeout(Duration::from_secs(2))
            .send()
            .await
            .ok()?
            .json()
            .await
            .ok()?;
        Some(Traffic {
            up: v["uploadTotal"].as_u64().unwrap_or(0),
            down: v["downloadTotal"].as_u64().unwrap_or(0),
            connections: v["connections"].as_array().map(|a| a.len()).unwrap_or(0),
        })
    }

    /// Задержка до серверов подписки (`*` — всех подписок), мс. Серверы из
    /// работающего подключения проверяются через него, остальные — через
    /// временно запущенное ядро. Результаты появляются по мере готовности
    /// (`ping_progress`). 0 — нет ответа.
    pub async fn ping(&self, sub_id: &str) -> HashMap<String, i64> {
        let servers: Vec<Server> = {
            let st = self.state.lock().unwrap();
            let mut seen = std::collections::HashSet::new();
            st.subscriptions
                .iter()
                .filter(|s| sub_id == "*" || s.id == sub_id)
                .flat_map(|s| s.servers.iter())
                .filter(|x| x.usable() && seen.insert(x.id.clone()))
                .cloned()
                .collect()
        };
        let (live, tags, groups) = {
            let mut rt = self.rt.lock().unwrap();
            self.reap(&mut rt);
            rt.ping_partial.clear();
            (Self::live(&rt) && !rt.paused, rt.tags.clone(), rt.groups.clone())
        };
        let (via_live, rest): (Vec<Server>, Vec<Server>) =
            servers.into_iter().partition(|s| live && tags.contains(&s.id));
        let mut out = HashMap::new();
        let live_task = async {
            if via_live.is_empty() {
                return HashMap::new();
            }
            let (base, secret) = self.clash_base();
            self.ping_servers(&base, &secret, &via_live, &groups).await
        };
        let temp_task = async {
            if rest.is_empty() {
                return HashMap::new();
            }
            match self.temp_core(&rest, false).await {
                Ok(tc) => self.ping_servers(&tc.base, &tc.secret, &rest, &tc.groups).await,
                Err(e) => {
                    self.log(format!("[app] проверка через ядро не удалась ({e}), TCP-пинг"));
                    let tasks = rest.clone().into_iter().map(|s| async move {
                        let ms = if s.is_udp() { -1 } else { tcp_ping(&s.address, s.port).await.unwrap_or(0) };
                        (s.id.clone(), ms)
                    });
                    join_all(tasks).await.into_iter().collect()
                }
            }
        };
        let (a, b) = futures::join!(live_task, temp_task);
        out.extend(a);
        out.extend(b);
        out
    }

    /// Проверка новой версии приложения на GitHub (только по кнопке).
    pub async fn check_update(&self) -> Result<UpdateInfo, String> {
        let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
        let text = self.get_text_any(&url).await?;
        let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("ответ GitHub не разобран: {e}"))?;
        let tag = v["tag_name"].as_str().unwrap_or_default();
        let latest = tag.trim_start_matches('v').to_string();
        let current = env!("CARGO_PKG_VERSION").to_string();
        let want = |name: &str| match PLATFORM {
            Platform::Android => name.ends_with(".apk"),
            _ => name.ends_with("-setup.exe") || name.ends_with(".exe"),
        };
        let asset = v["assets"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|a| want(a["name"].as_str().unwrap_or_default()));
        let notes: String = v["body"].as_str().unwrap_or_default().chars().take(1500).collect();
        Ok(UpdateInfo {
            available: newer(&latest, &current) && asset.is_some(),
            current,
            latest,
            notes,
            url: asset.and_then(|a| a["browser_download_url"].as_str()).unwrap_or_default().to_string(),
            size: asset.and_then(|a| a["size"].as_u64()).unwrap_or(0),
            page: v["html_url"].as_str().unwrap_or_default().to_string(),
        })
    }

    /// Текст по адресу: напрямую, а если не вышло — через работающий VPN.
    async fn get_text_any(&self, url: &str) -> Result<String, String> {
        let direct = self
            .http
            .get(url)
            .header("User-Agent", "Tunnelka")
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .and_then(|r| r.error_for_status());
        let resp = match direct {
            Ok(r) => r,
            Err(e) => {
                let Some(proxy) = self.live_proxy() else { return Err(format!("нет связи с GitHub: {e}")) };
                let c = reqwest::Client::builder()
                    .proxy(reqwest::Proxy::all(&proxy).map_err(|e| e.to_string())?)
                    .timeout(Duration::from_secs(20))
                    .build()
                    .map_err(|e| e.to_string())?;
                c.get(url)
                    .header("User-Agent", "Tunnelka")
                    .send()
                    .await
                    .and_then(|r| r.error_for_status())
                    .map_err(|e| format!("нет связи с GitHub: {e}"))?
            }
        };
        resp.text().await.map_err(|e| e.to_string())
    }

    /// Скачивает установщик новой версии в `dir`. Возвращает путь к файлу.
    pub async fn download_update(&self, url: &str, dir: &std::path::Path) -> Result<PathBuf, String> {
        let allowed = url.starts_with(&format!("https://github.com/{REPO}/releases/download/"));
        if !allowed {
            return Err("недопустимый адрес обновления".into());
        }
        let name = url.rsplit('/').next().unwrap_or("update").replace(['/', '\\', ':'], "_");
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let path = dir.join(&name);
        let build = |proxy: Option<String>| -> Result<reqwest::Client, String> {
            let mut b = reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(15))
                .read_timeout(Duration::from_secs(30));
            b = match proxy {
                Some(p) => b.proxy(reqwest::Proxy::all(&p).map_err(|e| e.to_string())?),
                None => b.no_proxy(),
            };
            b.build().map_err(|e| e.to_string())
        };
        let mut last = String::new();
        for proxy in [None, self.live_proxy()] {
            if last.len() > 0 && proxy.is_none() {
                break;
            }
            let client = build(proxy)?;
            match self.download_with(&client, url, &path).await {
                Ok(()) => return Ok(path),
                Err(e) => last = e,
            }
        }
        Err(format!("не удалось скачать обновление: {last}"))
    }

    async fn download_with(&self, client: &reqwest::Client, url: &str, path: &std::path::Path) -> Result<(), String> {
        use std::io::Write;
        let mut resp = client
            .get(url)
            .header("User-Agent", "Tunnelka")
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| e.to_string())?;
        let total = resp.content_length().unwrap_or(0);
        self.rt.lock().unwrap().update_progress = (0, total);
        let tmp = path.with_extension("part");
        let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        let mut got = 0u64;
        while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
            f.write_all(&chunk).map_err(|e| e.to_string())?;
            got += chunk.len() as u64;
            self.rt.lock().unwrap().update_progress = (got, total);
        }
        drop(f);
        if total > 0 && got != total {
            return Err("файл скачался не полностью".into());
        }
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())
    }

    pub fn update_progress(&self) -> (u64, u64) {
        self.rt.lock().unwrap().update_progress
    }

    /// Промежуточные результаты идущей проверки пинга.
    pub fn ping_progress(&self) -> HashMap<String, i64> {
        self.rt.lock().unwrap().ping_partial.clone()
    }

    /// Проверка серверов через Clash API ядра. Сначала настоящий запрос через
    /// сервер (у сервера с вариантами — через каждый вариант); у рабочих затем
    /// показывается пинг до самого сервера — время одного TCP-соединения, как в
    /// других клиентах. Если его измерить нельзя (UDP-протоколы, чужой TUN),
    /// остаётся время запроса. Одновременно идёт не больше 16 проверок:
    /// сотни соединений разом провайдер может принять за атаку.
    async fn ping_servers(
        &self,
        base: &str,
        secret: &str,
        servers: &[Server],
        groups: &HashMap<String, Vec<String>>,
    ) -> HashMap<String, i64> {
        use futures::stream::{self, StreamExt};
        let bypass_tun = PLATFORM == Platform::Windows && {
            let rt = self.rt.lock().unwrap();
            Self::live(&rt) && !rt.paused && rt.mode == Mode::Tun
        };
        let sem = Arc::new(tokio::sync::Semaphore::new(16));
        stream::iter(servers.to_vec())
            .map(|s| {
                let sem = sem.clone();
                async move {
                    let members = groups.get(&s.id).cloned().unwrap_or_else(|| vec![s.id.clone()]);
                    let tests = members.into_iter().map(|m| {
                        let sem = sem.clone();
                        async move {
                            let _permit = sem.acquire_owned().await.ok();
                            let ms = proxy_delay(&self.http, base, secret, &m, 4000).await.unwrap_or(0);
                            (m, ms)
                        }
                    });
                    let best = join_all(tests).await.into_iter().filter(|(_, ms)| *ms > 0).min_by_key(|(_, ms)| *ms);
                    let shown = match best {
                        None => 0,
                        Some((part, ms)) => {
                            let (host, port, proto) = endpoint_of(&s, Some(&part));
                            if host.is_empty() || matches!(proto.as_str(), "hysteria" | "hysteria2" | "tuic") {
                                ms
                            } else {
                                // Меньше 3 мс до зарубежного сервера не бывает — значит,
                                // соединение перехватил чужой VPN; показываем проверку.
                                tcp_rtt(&host, port, bypass_tun).await.filter(|r| *r >= 3).unwrap_or(ms)
                            }
                        }
                    };
                    self.rt.lock().unwrap().ping_partial.insert(s.id.clone(), shown);
                    (s.id.clone(), shown)
                }
            })
            .buffer_unordered(64)
            .collect()
            .await
    }

    /// Временное ядро с указанными серверами (без TUN и системного прокси).
    /// `with_proxy` — открыть локальный прокси с паролем (для загрузки подписки).
    /// Процессы останавливаются, когда результат выходит из области видимости.
    async fn temp_core(&self, servers: &[Server], with_proxy: bool) -> Result<TempCore, String> {
        if !self.paths.singbox.exists() {
            return Err("нет ядра sing-box".into());
        }
        let (built, run) = {
            let st = self.state.lock().unwrap();
            let mut settings = st.settings.clone();
            settings.allow_lan = false;
            settings.log_level = "error".into();
            settings.split.app_mode = AppMode::Off;
            settings.split.app_routes.clear();
            let refs: Vec<&Server> = servers.iter().collect();
            let n_xray = if self.paths.xray.exists() { singbox::xray_count(&refs, &settings) } else { 0 };
            let mut ports = free_ports(2 + n_xray)?;
            let clash_port = ports.remove(0);
            let mixed = ports.remove(0);
            let run = Runtime {
                mixed_port: if with_proxy { mixed } else { 0 },
                mixed_auth: with_proxy,
                clash_port,
                secret: random_token(),
                socks_user: random_token()[..10].to_string(),
                socks_pass: random_token(),
                xray_ports: ports,
            };
            let default = if servers.len() > 1 { TAG_AUTO.to_string() } else { servers[0].id.clone() };
            let built = singbox::build(&BuildInput {
                settings: &settings,
                servers: refs,
                autos: vec![],
                default,
                ruleset_dir: Some(&self.paths.ruleset_dir),
                xray_process: self.paths.xray.exists().then_some(XRAY_EXE),
                mode: Mode::Proxy,
                platform: PLATFORM,
                runtime: &run,
            })?;
            (built, run)
        };
        let mut built = built;
        if !with_proxy {
            // Для проверки пинга автовыбор не нужен: группы без своих проверок,
            // чтобы не удваивать число соединений.
            if let Some(obs) = built.singbox["outbounds"].as_array_mut() {
                for o in obs.iter_mut().filter(|o| o["type"] == "urltest") {
                    let first = o["outbounds"][0].clone();
                    let m = o.as_object_mut().unwrap();
                    m.insert("type".into(), serde_json::json!("selector"));
                    for k in ["url", "interval", "tolerance"] {
                        m.remove(k);
                    }
                    m.insert("default".into(), first);
                }
            }
        }
        let dir = self.paths.data.join("probe").join(&random_token()[..8]);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let mut guard = Probe { children: vec![], dir: dir.clone() };
        if let Some(x) = &built.xray {
            let p = dir.join("xray.json");
            write_private(&p, x)?;
            guard.children.push(self.spawn(&self.paths.xray, &["run".as_ref(), "-c".as_ref(), p.as_os_str()], "[проверка xray] ")?);
        }
        let p = dir.join("config.json");
        write_private(&p, &built.singbox)?;
        guard.children.push(self.spawn(
            &self.paths.singbox,
            &["run".as_ref(), "-c".as_ref(), p.as_os_str(), "-D".as_ref(), dir.as_os_str(), "--disable-color".as_ref()],
            "[проверка] ",
        )?);
        let base = format!("http://127.0.0.1:{}", run.clash_port);
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        loop {
            if guard.children.iter_mut().any(|c| matches!(c.try_wait(), Ok(Some(_)))) {
                return Err("ядро завершилось".into());
            }
            let ok = self
                .http
                .get(format!("{base}/version"))
                .bearer_auth(&run.secret)
                .timeout(Duration::from_millis(500))
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            if ok {
                break;
            }
            if std::time::Instant::now() > deadline {
                return Err("ядро не ответило".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let proxy = with_proxy.then(|| {
            format!("http://{}:{}@127.0.0.1:{}", run.socks_user, run.socks_pass, run.mixed_port)
        });
        Ok(TempCore { _guard: guard, base, secret: run.secret, proxy, groups: built.groups })
    }

    /// Выход из приложения: ядра останавливаются. Блокировка kill switch
    /// остаётся (если он включён в настройках): интернет вернёт подключение или
    /// кнопка «Разблокировать интернет» после следующего запуска.
    #[cfg_attr(mobile, allow(dead_code))]
    pub fn shutdown(&self) {
        self.stop_process();
        if killswitch::is_active(&self.paths.data) && !self.settings().kill_switch {
            let _ = killswitch::disable(&self.paths.data);
        }
    }
}

/// Репозиторий с выпусками приложения.
const REPO: &str = "ImVl1/Tunnelka_VPN";

/// Новая версия приложения.
#[derive(Debug, Clone, Serialize)]
pub struct UpdateInfo {
    pub available: bool,
    pub current: String,
    pub latest: String,
    pub notes: String,
    pub url: String,
    pub size: u64,
    pub page: String,
}

/// `a` новее `b` (версии вида 1.3.5).
fn newer(a: &str, b: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> { v.split(['.', '-']).map(|x| x.parse().unwrap_or(0)).take(3).collect() };
    parse(a) > parse(b)
}

/// Что выбрано: автовыбор по всем подпискам, автовыбор подписки или сервер.
pub enum Picked<'a> {
    All,
    Auto(&'a Subscription),
    Server(&'a Subscription, &'a Server),
}

/// Находит выбранное по строке выбора.
pub fn find_selection<'a>(subs: &'a [Subscription], sel: &str) -> Option<Picked<'a>> {
    match Selection::parse(sel) {
        Selection::AutoAll => subs.iter().any(|s| s.servers.iter().any(|x| x.usable())).then_some(Picked::All),
        Selection::Auto(sub_id) => subs.iter().find(|s| s.id == sub_id).map(Picked::Auto),
        Selection::Server(id) => subs.iter().find_map(|sub| {
            sub.servers
                .iter()
                .find(|s| s.id == id)
                .map(|srv| Picked::Server(sub, srv))
        }),
    }
}

/// Адрес, порт и протокол сервера; для сервера с автовыбором — выбранной части.
fn endpoint_of(s: &Server, best: Option<&str>) -> (String, u16, String) {
    let part = best
        .and_then(|t| t.rsplit_once('~'))
        .and_then(|(_, i)| i.parse::<usize>().ok())
        .and_then(|i| s.xray.as_ref().map(|x| tunnelka_core::xray::expand(x)).and_then(|p| p.into_iter().nth(i)));
    match part {
        Some(p) => {
            let m = tunnelka_core::xray::primary(&p);
            let (a, port) = tunnelka_core::xray::outbound_endpoint(m);
            (a, port, m["protocol"].as_str().unwrap_or("").to_string())
        }
        None => (s.address.clone(), s.port, s.protocol.clone()),
    }
}

/// Задержка через outbound (сервер или группу) по Clash API, мс.
async fn proxy_delay(http: &reqwest::Client, base: &str, secret: &str, tag: &str, timeout_ms: u32) -> Option<i64> {
    let url = format!("{base}/proxies/{}/delay?timeout={timeout_ms}&url={URL_TEST}", enc(tag));
    let v: serde_json::Value = http
        .get(url)
        .bearer_auth(secret)
        .timeout(Duration::from_millis(timeout_ms as u64 + 2000))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    v["delay"].as_i64().filter(|d| *d > 0)
}

/// Временное ядро: адрес Clash API, ключ, локальный прокси и группы серверов.
struct TempCore {
    _guard: Probe,
    base: String,
    secret: String,
    proxy: Option<String>,
    groups: HashMap<String, Vec<String>>,
}

/// Процессы временной проверки серверов: останавливаются в любом случае.
struct Probe {
    children: Vec<Child>,
    dir: PathBuf,
}

impl Drop for Probe {
    fn drop(&mut self) {
        for c in self.children.iter_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Записывает конфиг, доступный только текущему пользователю (на Unix/Android).
fn write_private(path: &PathBuf, value: &serde_json::Value) -> Result<(), String> {
    let text = serde_json::to_string(value).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Тег для адреса Clash API.
fn enc(tag: &str) -> String {
    tag.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Время TCP-соединения с сервером, мс (на Windows в режиме TUN — мимо туннеля).
async fn tcp_rtt(host: &str, port: u16, bypass_tun: bool) -> Option<i64> {
    let addr = tokio::net::lookup_host((host, port)).await.ok().and_then(|it| {
        let all: Vec<std::net::SocketAddr> = it.collect();
        all.iter().find(|a| a.is_ipv4()).or(all.first()).copied()
    })?;
    tauri::async_runtime::spawn_blocking(move || crate::netbind::connect_ms(addr, bypass_tun, Duration::from_secs(2)))
        .await
        .ok()
        .flatten()
}

async fn tcp_ping(host: &str, port: u16) -> Option<i64> {
    let start = std::time::Instant::now();
    let addr = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    match tokio::time::timeout(Duration::from_secs(4), tokio::net::TcpStream::connect(addr)).await
    {
        Ok(Ok(_)) => Some(start.elapsed().as_millis().max(1) as i64),
        _ => None,
    }
}

fn push_log(logs: &Mutex<VecDeque<String>>, line: String) {
    let mut l = logs.lock().unwrap();
    l.push_back(line);
    // Ядра пишут сотни строк в минуту. Чтобы они не вытесняли редкие и важные
    // сообщения приложения (ошибки, диагностику), первыми удаляются строки ядер.
    while l.len() > MAX_LOG_LINES {
        let own = |x: &String| x.starts_with("[app]") || x.starts_with("[ks]") || x.starts_with("[vpn]");
        match l.iter().position(|x| !own(x)) {
            Some(i) => {
                l.remove(i);
            }
            None => {
                l.pop_front();
            }
        }
    }
}

fn pipe_logs<R: std::io::Read + Send + 'static>(
    r: R,
    logs: Arc<Mutex<VecDeque<String>>>,
    prefix: &'static str,
) {
    std::thread::spawn(move || {
        let reader = BufReader::new(r);
        for line in reader.lines().map_while(Result::ok) {
            push_log(&logs, format!("{prefix}{line}"));
        }
    });
}

#[cfg(test)]
mod health_tests {
    use std::io::Write;
    use super::*;

    #[test]
    fn fast_group_member_wins_while_another_probe_is_stalled() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut rt = Rt::default();
        rt.vpn_on = true;
        rt.run.clash_port = listener.local_addr().unwrap().port();
        let engine = Engine {
            paths: Paths::new(std::env::temp_dir(), None, None),
            rt: Mutex::new(rt),
            state: Mutex::new(Persisted::default()),
            logs: Arc::new(Mutex::new(VecDeque::new())),
            http: reqwest::Client::builder().no_proxy().build().unwrap(),
        };
        let peer = std::thread::spawn(move || {
            let mut stalled = Vec::new();
            for stream in listener.incoming().take(2) {
                let mut stream = stream.unwrap();
                let mut line = String::new();
                BufReader::new(&stream).read_line(&mut line).unwrap();
                if line.contains("/slow/") {
                    stalled.push(stream);
                } else {
                    assert!(line.contains("/fast/"));
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\n{\"delay\":25}").unwrap();
                }
            }
            // Keep the unanswered connection open past the test deadline.
            std::thread::sleep(Duration::from_millis(1500));
        });
        let groups = HashMap::from([("group".into(), vec!["slow".into(), "fast".into()])]);
        let gen = engine.rt.lock().unwrap().gen;
        tauri::async_runtime::block_on(async {
            let winner = tokio::time::timeout(Duration::from_secs(1),
                engine.first_live(vec!["group".into()], &groups, gen)).await.unwrap();
            assert_eq!(winner, Some(("group".into(), 25, Some("fast".into()))));
        });
        peer.join().unwrap();
    }
}
