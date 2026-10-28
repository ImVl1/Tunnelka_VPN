//! Список программ для раздельного туннелирования и очистка «зависших» ядер.

use std::path::Path;

use serde::Serialize;
use sysinfo::{ProcessesToUpdate, System};

#[derive(Debug, Clone, Serialize)]
pub struct AppEntry {
    /// Что сохраняется в настройках: имя .exe (Windows) или пакет (Android).
    pub id: String,
    /// Что показывается пользователю.
    pub label: String,
    /// Подробности: путь к программе или имя пакета.
    pub detail: Option<String>,
}

/// Системные процессы, которые бессмысленно показывать в списке.
#[cfg(not(target_os = "android"))]
const HIDDEN: &[&str] = &[
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe", "winlogon.exe",
    "conhost.exe", "sihost.exe", "ctfmon.exe", "runtimebroker.exe", "dllhost.exe",
    "taskhostw.exe", "searchhost.exe", "startmenuexperiencehost.exe",
    "textinputhost.exe", "shellexperiencehost.exe", "memory compression",
    "secure system", "system idle process", "wudfhost.exe", "spoolsv.exe",
    "audiodg.exe", "sing-box.exe", "xray.exe", "tunnelka.exe", "msedgewebview2.exe",
];

#[cfg(target_os = "android")]
pub fn list() -> Result<Vec<AppEntry>, String> {
    Ok(tauri_plugin_tunnelka_vpn::apps()?
        .into_iter()
        .map(|a| AppEntry {
            id: a.package.clone(),
            label: a.label,
            detail: Some(a.package),
        })
        .collect())
}

#[cfg(not(target_os = "android"))]
pub fn list() -> Result<Vec<AppEntry>, String> {
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut map: std::collections::BTreeMap<String, AppEntry> = Default::default();
    for p in sys.processes().values() {
        let name = p.name().to_string_lossy().to_string();
        if name.is_empty() || HIDDEN.contains(&name.to_lowercase().as_str()) {
            continue;
        }
        let path = p.exe().map(|e| e.to_string_lossy().to_string());
        if cfg!(windows) {
            // Пропускаем системные программы из C:\Windows.
            if let Some(pp) = &path {
                if pp.to_lowercase().starts_with(r"c:\windows\") {
                    continue;
                }
            }
        }
        map.entry(name.to_lowercase()).or_insert(AppEntry {
            id: name.clone(),
            label: name,
            detail: path,
        });
    }
    Ok(map.into_values().collect())
}

/// Завершает ядро, оставшееся от прошлого запуска (например, после сбоя).
pub fn kill_orphans(exe: &Path) {
    let Ok(target) = exe.canonicalize() else {
        return;
    };
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    for p in sys.processes().values() {
        if let Some(path) = p.exe().and_then(|e| e.canonicalize().ok()) {
            if path == target {
                p.kill();
            }
        }
    }
}
