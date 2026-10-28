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
}

#[derive(Debug, Clone, Serialize)]
pub struct Traffic {
    pub up: u64,
    pub down: u64,
    pub connections: usize,
}

pub struct Paths {
    pub data: PathBuf,
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
        Paths {
            state: data.join("state.json"),
            config: data.join("config.json"),
            xray_config: data.join("xray.json"),
            singbox: core_dir.join(SINGBOX_EXE),
            xray: core_dir.join(XRAY_EXE),
            ruleset_dir: core_dir,
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

/// Чем закончилась попытка подключения.
enum Outcome {
    Ok,
    /// В режиме TUN нет интернета, а сервер работает — нужен системный прокси.
    TunBroken,
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
        crate::procs::kill_orphans(&engine.paths.singbox);
        crate::procs::kill_orphans(&engine.paths.xray);
        // Остатки конфигов с паролями от прошлого запуска.
        let _ = std::fs::remove_file(&engine.paths.config);
        let _ = std::fs::remove_file(&engine.paths.xray_config);
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
        self.logs.lock().unwrap().iter().cloned().collect()
    }

    pub fn clear_logs(&self) {
        self.logs.lock().unwrap().clear();
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

    pub async fn update_due(&self) {
        let due: Vec<String> = {
            let st = self.state.lock().unwrap();
            let t = now();
            st.subscriptions
                .iter()
                .filter(|s| s.url.is_some() && s.update_interval_h > 0)
                .filter(|s| t.saturating_sub(s.updated_at) >= s.update_interval_h as u64 * 3600)
                .map(|s| s.id.clone())
                .collect()
        };
        for id in due {
            if let Err(e) = self.update_subscription(&id).await {
                self.log(format!("[app] автообновление подписки {id}: {e}"));
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

    pub fn is_running(&self) -> bool {
        let mut rt = self.rt.lock().unwrap();
        self.reap(&mut rt);
        rt.child.is_some()
    }

    /// Проверяет, не упало ли ядро (или туннель Android).
    fn reap(&self, rt: &mut Rt) {
        let dead = |c: &mut Option<Child>| match c.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(Some(_))),
            None => false,
        };
        let sb_dead = dead(&mut rt.child);
        let xr_dead = dead(&mut rt.xray);
        let vpn_dead = PLATFORM == Platform::Android
            && rt.vpn_on
            && rt.child.is_some()
            && !tauri_plugin_tunnelka_vpn::state().running;
        if !(sb_dead || xr_dead || vpn_dead) {
            return;
        }
        for c in [rt.child.take(), rt.xray.take()].into_iter().flatten() {
            let mut c = c;
            let _ = c.kill();
            let _ = c.wait();
        }
        if rt.vpn_on {
            let _ = tauri_plugin_tunnelka_vpn::stop();
            rt.vpn_on = false;
        }
        rt.active_sub = None;
        if rt.sysproxy_on {
            let _ = sysproxy::unset();
            rt.sysproxy_on = false;
        }
        let reason = if vpn_dead {
            tauri_plugin_tunnelka_vpn::state()
                .error
                .unwrap_or_else(|| "VPN отключён системой".into())
        } else {
            let tail = self.last_error_line();
            format!(
                "ядро {} завершилось{}",
                if xr_dead { "Xray" } else { "sing-box" },
                tail.map(|t| format!(": {t}")).unwrap_or_default()
            )
        };
        let ks = killswitch::is_active(&self.paths.data);
        rt.last_error = Some(if ks {
            format!("{reason}. Интернет заблокирован kill switch — подключитесь снова или нажмите «Разблокировать интернет»")
        } else {
            reason
        });
    }

    fn last_error_line(&self) -> Option<String> {
        let logs = self.logs.lock().unwrap();
        logs.iter()
            .rev()
            .take(40)
            .find(|l| {
                let low = l.to_lowercase();
                low.contains("fatal") || low.contains("error") || low.contains("failed")
            })
            .cloned()
    }

    pub fn status(&self) -> Status {
        let (settings, selected, subs_name) = {
            let st = self.state.lock().unwrap();
            let sel = st.selected.clone();
            let name = sel
                .as_ref()
                .and_then(|s| find_selection(&st.subscriptions, s))
                .map(|(sub, srv)| match srv {
                    Some(srv) => (srv.name.clone(), Some(srv.protocol.clone())),
                    None => (format!("Автовыбор · {}", sub.name), None),
                });
            (st.settings.clone(), sel, name)
        };
        let mut rt = self.rt.lock().unwrap();
        self.reap(&mut rt);
        let running = rt.child.is_some();
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
            mixed_port: if running { rt.run.mixed_port } else { 0 },
            kill_switch_active: killswitch::is_active(&self.paths.data),
        }
    }

    pub async fn connect(&self) -> Result<Status, String> {
        {
            let mut rt = self.rt.lock().unwrap();
            if rt.busy {
                return Err("подождите, идёт подключение".into());
            }
            rt.busy = true;
            rt.notice = None;
        }
        let mode = self.settings().mode;
        let mut res = self.connect_inner(mode, true).await;
        if let Ok(Outcome::TunBroken) = res {
            self.log("[app] в режиме TUN нет интернета — переключаюсь на системный прокси");
            res = self.connect_inner(Mode::Proxy, false).await;
            if res.is_ok() {
                self.rt.lock().unwrap().notice = Some(
                    "В режиме TUN не было интернета (такое бывает у некоторых провайдеров) — включён системный прокси".into(),
                );
            }
        }
        let res = res.map(|_| ());
        if res.is_err() {
            self.stop_process();
        }
        {
            let mut rt = self.rt.lock().unwrap();
            rt.busy = false;
            if let Err(e) = &res {
                rt.last_error = Some(e.clone());
            }
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

    async fn connect_inner(&self, mode: Mode, allow_fallback: bool) -> Result<Outcome, String> {
        if !self.paths.singbox.exists() {
            return Err(format!(
                "не найдено ядро sing-box: {}",
                self.paths.singbox.display()
            ));
        }
        // Если уже запущено — перезапускаем с новой конфигурацией.
        // Kill switch при этом не снимаем, чтобы не было утечки между запусками.
        self.stop_process();
        let android = PLATFORM == Platform::Android;
        let mode = if android { Mode::Tun } else { mode };

        let (config, sub_id, settings, run) = {
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
            (built, sub.id.clone(), st.settings.clone(), run)
        };

        // Kill switch включаем до запуска ядер, чтобы не было окна для утечки.
        if !android {
            if settings.kill_switch {
                let mut programs = vec![self.paths.singbox.clone(), self.paths.xray.clone()];
                if let Ok(me) = std::env::current_exe() {
                    programs.push(me);
                }
                let tun = [singbox::TUN_ADDR4, singbox::TUN_ADDR6];
                match killswitch::enable(&self.paths.data, &programs, &tun) {
                    Ok(off) if !off.is_empty() => self.log(format!(
                        "[app] брандмауэр Windows выключен для профилей: {} — kill switch там не сработает",
                        off.join(", ")
                    )),
                    Ok(_) => self.log("[app] kill switch включён"),
                    Err(e) => return Err(format!("kill switch: {e}")),
                }
            } else if killswitch::is_active(&self.paths.data) {
                let _ = killswitch::disable(&self.paths.data);
            }
        }

        // Сначала Xray (если нужен): sing-box будет подключаться к его SOCKS-входам.
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
            if android {
                "VPN Android"
            } else if mode == Mode::Tun {
                "TUN"
            } else {
                "системный прокси"
            }
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
        {
            let mut rt = self.rt.lock().unwrap();
            rt.child = Some(child);
            rt.xray = xray_child;
            rt.started_at = now();
            rt.active_sub = Some(sub_id.clone());
            rt.last_error = None;
            rt.mode = mode;
            rt.run = run.clone();
        }

        // Даём ядру подняться и проверяем, что оно живо.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        // Ядра уже прочитали конфиги — файлы с паролями серверов больше не нужны.
        let _ = std::fs::remove_file(&self.paths.config);
        let _ = std::fs::remove_file(&self.paths.xray_config);
        if !self.is_running() {
            let err = self
                .rt
                .lock()
                .unwrap()
                .last_error
                .clone()
                .unwrap_or_else(|| "ядро завершилось при запуске".into());
            let hint = if mode == Mode::Tun && !android && err.to_lowercase().contains("access is denied") {
                " — для режима TUN запустите приложение от имени администратора"
            } else {
                ""
            };
            return Err(format!("{err}{hint}"));
        }

        if android {
            let split = &settings.split;
            let args = tauri_plugin_tunnelka_vpn::StartArgs {
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
                ipv6: settings.ipv6,
                session: "Tunnelka".into(),
            };
            tauri::async_runtime::spawn_blocking(move || tauri_plugin_tunnelka_vpn::start(args))
                .await
                .map_err(|e| e.to_string())??;
            self.rt.lock().unwrap().vpn_on = true;
        } else if mode == Mode::Proxy {
            sysproxy::set(run.mixed_port)?;
            self.rt.lock().unwrap().sysproxy_on = true;
        }

        if !android && mode == Mode::Tun && allow_fallback && settings.tun_fallback {
            if let Some(outcome) = self.check_tun(&sub_id).await? {
                return Ok(outcome);
            }
        }
        self.log("[app] подключено");
        Ok(Outcome::Ok)
    }

    /// Проверяет, что в режиме TUN есть интернет. None — всё в порядке.
    async fn check_tun(&self, sub_id: &str) -> Result<Option<Outcome>, String> {
        if self.internet_works().await {
            return Ok(None);
        }
        self.log("[app] через TUN нет интернета, проверяю серверы");
        if self.server_delay(TAG_PROXY).await.is_some() {
            // Сервер отвечает, а программы в интернет выйти не могут — TUN не работает.
            return Ok(Some(Outcome::TunBroken));
        }
        // Текущий сервер не отвечает: ищем рабочий.
        let pings = self.ping(sub_id).await;
        let best = pings
            .into_iter()
            .filter(|(_, ms)| *ms > 0)
            .min_by_key(|(_, ms)| *ms)
            .map(|(id, _)| id);
        let Some(best) = best else {
            return Err("ни один сервер подписки не отвечает".into());
        };
        self.clash_select(&best).await?;
        let name = {
            let st = self.state.lock().unwrap();
            find_selection(&st.subscriptions, &best)
                .and_then(|(_, s)| s.map(|s| s.name.clone()))
                .unwrap_or_default()
        };
        if self.internet_works().await {
            self.rt.lock().unwrap().notice =
                Some(format!("Выбранный сервер не отвечал — подключено через «{name}»"));
            return Ok(None);
        }
        Ok(Some(Outcome::TunBroken))
    }

    /// Есть ли выход в интернет обычным путём (в режиме TUN — через туннель).
    async fn internet_works(&self) -> bool {
        let client = match reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
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
            for url in URLS {
                if let Ok(r) = client.get(url).send().await {
                    if r.status().is_success() {
                        return true;
                    }
                }
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

    /// Останавливает ядра, туннель и системный прокси. Kill switch не трогает.
    fn stop_process(&self) {
        let mut rt = self.rt.lock().unwrap();
        if rt.vpn_on {
            let _ = tauri_plugin_tunnelka_vpn::stop();
            rt.vpn_on = false;
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
        let _ = std::fs::remove_file(&self.paths.config);
        let _ = std::fs::remove_file(&self.paths.xray_config);
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
    pub async fn toggle(&self) -> Result<Status, String> {
        if self.is_running() {
            Ok(self.disconnect())
        } else {
            self.connect().await
        }
    }

    pub async fn restart_if_running(&self) -> Result<(), String> {
        if self.is_running() {
            self.connect().await.map(|_| ())
        } else {
            Ok(())
        }
    }

    /// Выбор сервера. Если ядро запущено с той же подпиской — переключаем на лету.
    pub async fn select(&self, sel: &str) -> Result<Status, String> {
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
            rt.child.as_ref().and(rt.active_sub.clone())
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
                }
            }
            Some(_) => {
                self.connect().await?;
            }
            None => {}
        }
        Ok(self.status())
    }

    pub async fn save_settings(&self, mut new: Settings) -> Result<Status, String> {
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
                s.user_agent.clear();
            }
            a != b
        };
        self.state.lock().unwrap().settings = new;
        self.save();
        if connection_changed {
            self.restart_if_running().await?;
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
        if !self.is_running() {
            return None;
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
            rt.child.is_some() && rt.active_sub.as_deref() == Some(sub_id)
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
