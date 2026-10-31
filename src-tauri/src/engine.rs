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
use tunnelka_core::{AppMode, Mode, Platform, Runtime, Selection, Server, Settings, Subscription};

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
}

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
    /// Номер подключения: фоновая проверка не трогает более новое подключение.
    gen: u64,
    /// Режим, в котором реально работает подключение.
    mode: Mode,
    run: Runtime,
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
    work_dir: String,
    log: String,
    env: HashMap<String, String>,
    processes: Vec<ProcSpec>,
    /// Для приложения: порты и ключи Clash API, если VPN включили без него.
    runtime: Runtime,
    active_sub: String,
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
        // На Android ядрами управляет VPN-сервис, он может работать и без окна.
        if PLATFORM != Platform::Android {
            crate::procs::kill_orphans(&engine.paths.singbox);
            crate::procs::kill_orphans(&engine.paths.xray);
            // Остатки конфигов с паролями от прошлого запуска.
            let _ = std::fs::remove_file(&engine.paths.config);
            let _ = std::fs::remove_file(&engine.paths.xray_config);
        }
        // Kill switch остался включённым после сбоя приложения. Если подключение
        // при запуске выключено, возвращаем интернет, иначе ждём подключения.
        if killswitch::is_active(&engine.paths.data) && !auto_connect {
            match killswitch::disable(&engine.paths.data) {
                Ok(()) => engine.log("[app] kill switch от прошлого запуска снят"),
                Err(e) => engine.log(format!("[app] kill switch: {e}")),
            }
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

    async fn fetch(&self, url: &str, seed: &str) -> Result<Fetched, String> {
        let ua = self.state.lock().unwrap().settings.user_agent.clone();
        // В режиме системного прокси само приложение ходит напрямую; если панель
        // недоступна, пробуем через локальный прокси ядра.
        let proxy_port = {
            let rt = self.rt.lock().unwrap();
            (rt.child.is_some() && rt.mode == Mode::Proxy && PLATFORM == Platform::Windows)
                .then_some(rt.run.mixed_port)
                .filter(|p| *p != 0)
        };
        match subscription::fetch(url, &ua, seed, None).await {
            Ok(f) => Ok(f),
            Err(e) => match proxy_port {
                Some(port) => {
                    let proxy = format!("http://127.0.0.1:{port}");
                    subscription::fetch(url, &ua, seed, Some(&proxy))
                        .await
                        .map_err(|e2| format!("{e}; через VPN: {e2}"))
                }
                None => Err(e),
            },
        }
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
        let f = self.fetch(input, &id).await?;
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
        let res = self.fetch(&url, id).await;
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
        let was_active = self.rt.lock().unwrap().active_sub.as_deref() == Some(id);
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
            .map(|(sub, srv)| match srv {
                Some(srv) => (srv.name.clone(), Some(srv.protocol.clone())),
                None => (format!("Автовыбор · {}", sub.name), None),
            })
    }

    pub fn status(&self) -> Status {
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
        // Проверка интернета в режиме TUN идёт в фоне: подключение уже работает,
        // а если у провайдера TUN не даёт интернета — переключимся на прокси.
        if res.is_ok() && PLATFORM != Platform::Android && mode == Mode::Tun && settings.tun_fallback {
            self.rt.lock().unwrap().checking = true;
            let me = self.clone();
            tauri::async_runtime::spawn(async move { me.tun_watch(gen).await });
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
            let (sub, srv) =
                find_selection(&st.subscriptions, &sel).ok_or("выбранный сервер не найден")?;
            let servers: Vec<&Server> = sub.servers.iter().filter(|s| s.usable()).collect();
            let default = match srv {
                Some(s) => {
                    if !s.usable() {
                        return Err(format!(
                            "сервер не поддерживается: {}",
                            s.error.clone().unwrap_or_default()
                        ));
                    }
                    s.id.clone()
                }
                None => TAG_AUTO.to_string(),
            };
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
                default,
                ruleset_dir: Some(&self.paths.ruleset_dir),
                xray_process: xray_name,
                mode,
                platform: PLATFORM,
                runtime: &run,
            })?;
            let name = Self::selected_name(&st).map(|n| n.0).unwrap_or_default();
            (built, sub.id.clone(), st.settings.clone(), run, name)
        };

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
                    Err(e) => Err(format!("kill switch: {e}")),
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
            work_dir: dir.to_string_lossy().into_owned(),
            log: self.core_log().to_string_lossy().into_owned(),
            env: HashMap::from([(
                "XRAY_LOCATION_ASSET".to_string(),
                self.paths.ruleset_dir.to_string_lossy().into_owned(),
            )]),
            processes,
            runtime: run.clone(),
            active_sub: sub_id.clone(),
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
        }
        if let Ok(v) = serde_json::to_value(&p) {
            if write_private(&self.profile_path(), &v).is_ok() {
                let _ = tauri_plugin_tunnelka_vpn::refresh();
            }
        }
    }

    /// Фоновая проверка после подключения в режиме TUN (Windows).
    async fn tun_watch(self: Arc<Self>, gen: u64) {
        let same = |me: &Self| {
            let rt = me.rt.lock().unwrap();
            rt.gen == gen && rt.child.is_some() && !rt.busy
        };
        let done = |me: &Self| me.rt.lock().unwrap().checking = false;
        if self.internet_works().await || !same(&self) {
            done(&self);
            return;
        }
        self.log("[app] через TUN нет интернета, проверяю серверы");
        let sub_id = self.rt.lock().unwrap().active_sub.clone().unwrap_or_default();
        let tun_broken = if self.server_delay(TAG_PROXY).await.is_some() {
            // Сервер отвечает, а программы в интернет выйти не могут — TUN не работает.
            true
        } else {
            // Текущий сервер не отвечает: ищем рабочий.
            let pings = self.ping(&sub_id).await;
            let best = pings
                .into_iter()
                .filter(|(_, ms)| *ms > 0)
                .min_by_key(|(_, ms)| *ms)
                .map(|(id, _)| id);
            match best {
                None => {
                    if same(&self) {
                        self.rt.lock().unwrap().notice =
                            Some("Ни один сервер подписки сейчас не отвечает".into());
                    }
                    done(&self);
                    return;
                }
                Some(best) => {
                    if !same(&self) || self.clash_select(&best).await.is_err() {
                        done(&self);
                        return;
                    }
                    if self.internet_works().await {
                        let name = {
                            let st = self.state.lock().unwrap();
                            find_selection(&st.subscriptions, &best)
                                .and_then(|(_, s)| s.map(|s| s.name.clone()))
                                .unwrap_or_default()
                        };
                        self.rt.lock().unwrap().notice =
                            Some(format!("Выбранный сервер не отвечал — подключено через «{name}»"));
                        done(&self);
                        return;
                    }
                    true
                }
            }
        };
        if !tun_broken || !same(&self) {
            done(&self);
            return;
        }
        self.log("[app] в режиме TUN нет интернета — переключаюсь на системный прокси");
        {
            let mut rt = self.rt.lock().unwrap();
            if rt.busy {
                rt.checking = false;
                return;
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
                    "В режиме TUN не было интернета (такое бывает у некоторых провайдеров) — включён системный прокси".into(),
                )
            }
            Err(e) => rt.last_error = Some(e),
        }
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
        for attempt in 0..3 {
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
            if attempt < 2 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        false
    }

    async fn server_delay(&self, tag: &str) -> Option<i64> {
        let (base, secret) = self.clash_base();
        let url = format!("{base}/proxies/{tag}/delay?timeout=5000&url={URL_TEST}");
        let r = self.http.get(url).bearer_auth(secret).send().await.ok()?;
        let v: serde_json::Value = r.json().await.ok()?;
        v["delay"].as_i64().filter(|d| *d > 0)
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
        rt.gen += 1;
        if PLATFORM != Platform::Android {
            let _ = std::fs::remove_file(&self.paths.config);
            let _ = std::fs::remove_file(&self.paths.xray_config);
        }
    }

    /// Отключение по кнопке: ядра останавливаются, kill switch снимается.
    pub fn disconnect(&self) -> Status {
        let was = self.is_running();
        self.stop_process();
        if killswitch::is_active(&self.paths.data) {
            match killswitch::disable(&self.paths.data) {
                Ok(()) => self.log("[app] kill switch выключен"),
                Err(e) => self.log(format!("[app] kill switch: {e}")),
            }
        }
        if was {
            self.log("[app] отключено");
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

    /// Выбор сервера. Если ядро запущено с той же подпиской — переключаем на лету.
    pub async fn select(self: &Arc<Self>, sel: &str) -> Result<Status, String> {
        let target_sub = {
            let mut st = self.state.lock().unwrap();
            let (sub, _) =
                find_selection(&st.subscriptions, sel).ok_or("сервер не найден")?;
            let sub_id = sub.id.clone();
            st.selected = Some(sel.to_string());
            sub_id
        };
        self.save();
        let active = {
            let mut rt = self.rt.lock().unwrap();
            self.reap(&mut rt);
            if Self::live(&rt) && !rt.paused { rt.active_sub.clone() } else { None }
        };
        match active {
            Some(a) if a == target_sub => {
                let tag = match Selection::parse(sel) {
                    Selection::Auto(_) => TAG_AUTO.to_string(),
                    Selection::Server(id) => id,
                };
                if let Err(e) = self.clash_select(&tag).await {
                    self.log(format!("[app] переключение на лету не удалось ({e}), перезапуск"));
                    self.connect().await?;
                } else {
                    self.refresh_profile();
                }
            }
            Some(_) => {
                self.connect().await?;
            }
            None => {}
        }
        Ok(self.status())
    }

    pub async fn save_settings(self: &Arc<Self>, mut new: Settings) -> Result<Status, String> {
        let old = self.settings();
        if new.mixed_port != 0 && new.mixed_port < 1024 {
            return Err(format!("порт {} недопустим, используйте 1024–65535 или 0", new.mixed_port));
        }
        if new.allow_lan && new.lan_port < 1024 {
            return Err(format!("порт {} недопустим, используйте 1024–65535", new.lan_port));
        }
        if new.lan_password.trim().len() < 6 {
            new.lan_password = old.lan_password.clone();
        }
        new.split.normalize();
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
            }
            a != b
        };
        let notify_changed = old.notification != new.notification;
        self.state.lock().unwrap().settings = new;
        self.save();
        if connection_changed {
            self.restart_if_running().await?;
        } else if notify_changed {
            self.refresh_profile();
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
        let (base, secret) = self.clash_base();
        let r = self
            .http
            .put(format!("{base}/proxies/{TAG_PROXY}"))
            .bearer_auth(secret)
            .json(&serde_json::json!({ "name": tag }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if r.status().is_success() {
            self.log(format!("[app] сервер переключён: {tag}"));
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

    /// Задержка до серверов подписки, мс. Если ядро запущено с этой подпиской —
    /// реальная проверка через сервер (URL-тест), иначе TCP-пинг.
    /// 0 — нет ответа, -1 — UDP-протокол, проверить без подключения нельзя.
    pub async fn ping(&self, sub_id: &str) -> HashMap<String, i64> {
        let servers: Vec<Server> = {
            let st = self.state.lock().unwrap();
            st.subscriptions
                .iter()
                .find(|s| s.id == sub_id)
                .map(|s| s.servers.iter().filter(|x| x.usable()).cloned().collect())
                .unwrap_or_default()
        };
        let live = {
            let mut rt = self.rt.lock().unwrap();
            self.reap(&mut rt);
            Self::live(&rt) && !rt.paused && rt.active_sub.as_deref() == Some(sub_id)
        };
        let (base, secret) = self.clash_base();
        let tasks: Vec<_> = servers
            .into_iter()
            .map(|s| {
                let http = self.http.clone();
                let base = base.clone();
                let secret = secret.clone();
                async move {
                    let ms = if live {
                        let url = format!(
                            "{base}/proxies/{}/delay?timeout=5000&url={}",
                            s.id, URL_TEST
                        );
                        match http.get(url).bearer_auth(secret).send().await {
                            Ok(r) => r
                                .json::<serde_json::Value>()
                                .await
                                .ok()
                                .and_then(|v| v["delay"].as_i64())
                                .unwrap_or(0),
                            Err(_) => 0,
                        }
                    } else if s.is_udp() {
                        -1
                    } else {
                        tcp_ping(&s.address, s.port).await.unwrap_or(0)
                    };
                    (s.id, ms)
                }
            })
            .collect();
        // Ограничиваем параллельность, чтобы не душить сеть на больших подписках.
        let mut out = HashMap::new();
        let mut iter = tasks.into_iter();
        loop {
            let chunk: Vec<_> = iter.by_ref().take(24).collect();
            if chunk.is_empty() {
                break;
            }
            for (id, ms) in join_all(chunk).await {
                out.insert(id, ms);
            }
        }
        out
    }

    /// Полный выход из приложения: всё останавливается, интернет разблокируется.
    #[cfg_attr(mobile, allow(dead_code))]
    pub fn shutdown(&self) {
        self.stop_process();
        if killswitch::is_active(&self.paths.data) {
            let _ = killswitch::disable(&self.paths.data);
        }
    }
}

/// Находит подписку и сервер (None — автовыбор) по строке выбора.
pub fn find_selection<'a>(
    subs: &'a [Subscription],
    sel: &str,
) -> Option<(&'a Subscription, Option<&'a Server>)> {
    match Selection::parse(sel) {
        Selection::Auto(sub_id) => subs.iter().find(|s| s.id == sub_id).map(|s| (s, None)),
        Selection::Server(id) => subs.iter().find_map(|sub| {
            sub.servers
                .iter()
                .find(|s| s.id == id)
                .map(|srv| (sub, Some(srv)))
        }),
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
    while l.len() > MAX_LOG_LINES {
        l.pop_front();
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
