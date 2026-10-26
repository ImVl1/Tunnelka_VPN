//! Состояние приложения, подписки и управление процессами sing-box и Xray.

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
use tunnelka_core::{Mode, Selection, Server, Settings, Subscription};

use crate::sysproxy;

pub const MANUAL_SUB: &str = "manual";
const MAX_LOG_LINES: usize = 800;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
struct Runtime {
    child: Option<Child>,
    /// Xray запускается, только если в подписке есть серверы для него.
    xray: Option<Child>,
    started_at: u64,
    active_sub: Option<String>,
    sysproxy_on: bool,
    last_error: Option<String>,
    busy: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub running: bool,
    pub busy: bool,
    pub mode: Mode,
    pub started_at: u64,
    pub selected: Option<String>,
    pub selected_name: Option<String>,
    pub selected_protocol: Option<String>,
    pub active_sub: Option<String>,
    pub last_error: Option<String>,
    pub core_found: bool,
    pub xray_found: bool,
    pub ext_port: u16,
    pub mixed_port: u16,
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

pub const XRAY_EXE: &str = if cfg!(windows) { "xray.exe" } else { "xray" };

impl Paths {
    pub fn new(data: PathBuf, resource: Option<PathBuf>) -> Self {
        let exe = if cfg!(windows) { "sing-box.exe" } else { "sing-box" };
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
        let core_dir = candidates
            .iter()
            .find(|d| d.join(exe).exists())
            .cloned()
            .unwrap_or_else(|| data.join("core"));
        Paths {
            state: data.join("state.json"),
            config: data.join("config.json"),
            xray_config: data.join("xray.json"),
            singbox: core_dir.join(exe),
            xray: core_dir.join(XRAY_EXE),
            ruleset_dir: core_dir,
            data,
        }
    }
}

pub struct Engine {
    pub paths: Paths,
    state: Mutex<Persisted>,
    rt: Mutex<Runtime>,
    logs: Arc<Mutex<VecDeque<String>>>,
    http: reqwest::Client,
}

fn random_token() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

impl Engine {
    pub fn load(paths: Paths) -> Arc<Self> {
        let _ = std::fs::create_dir_all(&paths.data);
        let mut st: Persisted = std::fs::read_to_string(&paths.state)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        if st.settings.api_token.is_empty() {
            st.settings.api_token = random_token();
        }
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(12))
            .build()
            .expect("http client");
        let engine = Arc::new(Engine {
            paths,
            state: Mutex::new(st),
            rt: Mutex::new(Runtime::default()),
            logs: Arc::new(Mutex::new(VecDeque::new())),
            http,
        });
        engine.save();
        crate::procs::kill_orphans(&engine.paths.singbox);
        crate::procs::kill_orphans(&engine.paths.xray);
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
        let (ua, mixed) = {
            let s = self.state.lock().unwrap();
            (s.settings.user_agent.clone(), s.settings.mixed_port)
        };
        match subscription::fetch(url, &ua, seed, None).await {
            Ok(f) => Ok(f),
            Err(e) if self.is_running() => {
                // Панель может быть недоступна напрямую — пробуем через VPN.
                let proxy = format!("http://127.0.0.1:{mixed}");
                subscription::fetch(url, &ua, seed, Some(&proxy))
                    .await
                    .map_err(|e2| format!("{e}; через VPN: {e2}"))
            }
            Err(e) => Err(e),
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
        let id = uuid::Uuid::new_v4().simple().to_string()[..12].to_string();
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
                s.name = name.trim().to_string();
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

    /// Проверяет, не упал ли процесс ядра.
    fn reap(&self, rt: &mut Runtime) {
        let dead = |c: &mut Option<Child>| match c.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(Some(_))),
            None => false,
        };
        let sb_dead = dead(&mut rt.child);
        let xr_dead = dead(&mut rt.xray);
        if sb_dead || xr_dead {
            for c in [rt.child.take(), rt.xray.take()].into_iter().flatten() {
                let mut c = c;
                let _ = c.kill();
                let _ = c.wait();
            }
            rt.active_sub = None;
            if rt.sysproxy_on {
                let _ = sysproxy::unset();
                rt.sysproxy_on = false;
            }
            let tail = self.last_error_line();
            rt.last_error = Some(format!(
                "ядро {} завершилось{}",
                if xr_dead { "Xray" } else { "sing-box" },
                tail.map(|t| format!(": {t}")).unwrap_or_default()
            ));
        }
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
        Status {
            running: rt.child.is_some(),
            busy: rt.busy,
            mode: settings.mode,
            started_at: rt.started_at,
            selected,
            selected_name: subs_name.as_ref().map(|n| n.0.clone()),
            selected_protocol: subs_name.and_then(|n| n.1),
            active_sub: rt.active_sub.clone(),
            last_error: rt.last_error.clone(),
            core_found: self.paths.singbox.exists(),
            xray_found: self.paths.xray.exists(),
            ext_port: settings.ext_port,
            mixed_port: settings.mixed_port,
        }
    }

    pub async fn connect(&self) -> Result<Status, String> {
        {
            let mut rt = self.rt.lock().unwrap();
            if rt.busy {
                return Err("подождите, идёт подключение".into());
            }
            rt.busy = true;
        }
        let res = self.connect_inner().await;
        {
            let mut rt = self.rt.lock().unwrap();
            rt.busy = false;
            if let Err(e) = &res {
                rt.last_error = Some(e.clone());
            }
        }
        res.map(|_| self.status())
    }

    async fn connect_inner(&self) -> Result<(), String> {
        if !self.paths.singbox.exists() {
            return Err(format!(
                "не найдено ядро sing-box: {}",
                self.paths.singbox.display()
            ));
        }
        // Если уже запущено — перезапускаем с новой конфигурацией.
        self.stop_process();

        let (config, sub_id, settings) = {
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
            let xray_name = self.paths.xray.exists().then_some(XRAY_EXE);
            let built = singbox::build(&BuildInput {
                settings: &st.settings,
                servers,
                default,
                ruleset_dir: Some(&self.paths.ruleset_dir),
                xray_process: xray_name,
            })?;
            (built, sub.id.clone(), st.settings.clone())
        };

        let text = serde_json::to_string_pretty(&config.singbox).map_err(|e| e.to_string())?;
        std::fs::write(&self.paths.config, text).map_err(|e| e.to_string())?;

        // Сначала Xray (если нужен): sing-box будет подключаться к его SOCKS-входам.
        if let Some(xcfg) = &config.xray {
            let text = serde_json::to_string_pretty(xcfg).map_err(|e| e.to_string())?;
            std::fs::write(&self.paths.xray_config, text).map_err(|e| e.to_string())?;
            let mut xcmd = Command::new(&self.paths.xray);
            xcmd.arg("run")
                .arg("-c")
                .arg(&self.paths.xray_config)
                .current_dir(&self.paths.data)
                .env("XRAY_LOCATION_ASSET", &self.paths.ruleset_dir)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                xcmd.creation_flags(0x0800_0000);
            }
            self.log(format!(
                "[app] запуск Xray: {} сервер(ов) через XHTTP/Xray",
                xcfg["inbounds"].as_array().map(|a| a.len()).unwrap_or(0)
            ));
            let mut xchild = xcmd
                .spawn()
                .map_err(|e| format!("не удалось запустить Xray: {e}"))?;
            if let Some(out) = xchild.stdout.take() {
                pipe_logs_prefixed(out, self.logs.clone(), "[xray] ");
            }
            if let Some(err) = xchild.stderr.take() {
                pipe_logs_prefixed(err, self.logs.clone(), "[xray] ");
            }
            self.rt.lock().unwrap().xray = Some(xchild);
        }

        let mut cmd = Command::new(&self.paths.singbox);
        cmd.arg("run")
            .arg("-c")
            .arg(&self.paths.config)
            .arg("-D")
            .arg(&self.paths.data)
            .arg("--disable-color")
            .current_dir(&self.paths.data)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        self.log(format!(
            "[app] запуск ядра, режим: {}",
            if settings.mode == Mode::Tun { "TUN" } else { "системный прокси" }
        ));
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("не удалось запустить sing-box: {e}"))?;
        if let Some(out) = child.stdout.take() {
            pipe_logs(out, self.logs.clone());
        }
        if let Some(err) = child.stderr.take() {
            pipe_logs(err, self.logs.clone());
        }
        {
            let mut rt = self.rt.lock().unwrap();
            rt.child = Some(child);
            rt.started_at = now();
            rt.active_sub = Some(sub_id);
            rt.last_error = None;
        }

        // Даём ядру подняться и проверяем, что оно живо.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        if !self.is_running() {
            let err = self
                .rt
                .lock()
                .unwrap()
                .last_error
                .clone()
                .unwrap_or_else(|| "ядро завершилось при запуске".into());
            let hint = if settings.mode == Mode::Tun && err.to_lowercase().contains("access is denied") {
                " — для режима TUN запустите приложение от имени администратора"
            } else {
                ""
            };
            return Err(format!("{err}{hint}"));
        }

        if settings.mode == Mode::Proxy {
            sysproxy::set(settings.mixed_port)?;
            self.rt.lock().unwrap().sysproxy_on = true;
        }
        self.log("[app] подключено");
        Ok(())
    }

    fn stop_process(&self) {
        let mut rt = self.rt.lock().unwrap();
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
    }

    pub fn disconnect(&self) -> Status {
        let was = self.is_running();
        self.stop_process();
        if was {
            self.log("[app] отключено");
        }
        self.rt.lock().unwrap().last_error = None;
        self.status()
    }

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
        {
            let mut st = self.state.lock().unwrap();
            if new.api_token.trim().is_empty() {
                new.api_token = st.settings.api_token.clone();
            }
            let ports = [new.mixed_port, new.ext_port, new.api_port, new.clash_port, new.xray_port];
            for (i, p) in ports.iter().enumerate() {
                if *p < 1024 {
                    return Err(format!("порт {p} недопустим, используйте 1024–65535"));
                }
                if ports[i + 1..].contains(p) {
                    return Err(format!("порт {p} указан дважды"));
                }
            }
            for p in [new.mixed_port, new.ext_port, new.api_port, new.clash_port] {
                if p >= new.xray_port && p < new.xray_port.saturating_add(500) {
                    return Err(format!(
                        "порт {p} попадает в диапазон Xray {}–{}",
                        new.xray_port,
                        new.xray_port.saturating_add(499)
                    ));
                }
            }
            new.split.apps.retain(|a| !a.trim().is_empty());
            new.split.apps.dedup();
            st.settings = new;
        }
        self.save();
        self.restart_if_running().await?;
        Ok(self.status())
    }

    pub fn regenerate_token(&self) -> String {
        let t = random_token();
        self.state.lock().unwrap().settings.api_token = t.clone();
        self.save();
        t
    }

    // -----------------------------------------------------------------------
    // Clash API ядра: переключение, задержки, трафик
    // -----------------------------------------------------------------------

    fn clash_base(&self) -> (String, String) {
        let s = self.state.lock().unwrap();
        (
            format!("http://127.0.0.1:{}", s.settings.clash_port),
            s.settings.api_token.clone(),
        )
    }

    async fn clash_select(&self, tag: &str) -> Result<(), String> {
        let (base, token) = self.clash_base();
        let r = self
            .http
            .put(format!("{base}/proxies/{TAG_PROXY}"))
            .bearer_auth(token)
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
        let (base, token) = self.clash_base();
        let v: serde_json::Value = self
            .http
            .get(format!("{base}/connections"))
            .bearer_auth(token)
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
        let (base, token) = self.clash_base();
        let tasks = servers.into_iter().map(|s| {
            let http = self.http.clone();
            let base = base.clone();
            let token = token.clone();
            async move {
                let ms = if live {
                    let url = format!(
                        "{base}/proxies/{}/delay?timeout=5000&url={}",
                        s.id,
                        URL_TEST
                    );
                    match http.get(url).bearer_auth(token).send().await {
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
        });
        // Ограничиваем параллельность, чтобы не душить сеть на больших подписках.
        let mut out = HashMap::new();
        let tasks: Vec<_> = tasks.collect();
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

    /// Остановка при выходе из приложения.
    pub fn shutdown(&self) {
        self.stop_process();
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

async fn tcp_ping(host: &str, port: u16) -> Option<i64> {
    let start = std::time::Instant::now();
    let addr = format!("{host}:{port}");
    let addr = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        addr
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

fn pipe_logs<R: std::io::Read + Send + 'static>(r: R, logs: Arc<Mutex<VecDeque<String>>>) {
    pipe_logs_prefixed(r, logs, "");
}

fn pipe_logs_prefixed<R: std::io::Read + Send + 'static>(
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
