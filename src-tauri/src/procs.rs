//! Список запущенных программ (для выбора в раздельном туннелировании)
//! и очистка «зависших» процессов ядра.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;
use sysinfo::{ProcessesToUpdate, System};

#[derive(Debug, Clone, Serialize)]
pub struct ProcInfo {
    pub name: String,
    pub path: Option<String>,
}

/// Системные процессы, которые бессмысленно показывать в списке.
const HIDDEN: &[&str] = &[
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe", "winlogon.exe",
    "conhost.exe", "sihost.exe", "ctfmon.exe", "runtimebroker.exe", "dllhost.exe",
    "taskhostw.exe", "searchhost.exe", "startmenuexperiencehost.exe",
    "textinputhost.exe", "shellexperiencehost.exe", "memory compression",
    "secure system", "system idle process", "wudfhost.exe", "spoolsv.exe",
    "audiodg.exe", "sing-box.exe", "tunnelka.exe", "msedgewebview2.exe",
];

pub fn list() -> Vec<ProcInfo> {
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut map: BTreeMap<String, ProcInfo> = BTreeMap::new();
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
        map.entry(name.to_lowercase()).or_insert(ProcInfo { name, path });
    }
    map.into_values().collect()
}

/// Завершает sing-box, оставшийся от прошлого запуска (например, после сбоя).
pub fn kill_orphans(singbox: &Path) {
    let Ok(target) = singbox.canonicalize() else {
        return;
    };
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    for p in sys.processes().values() {
        if let Some(exe) = p.exe().and_then(|e| e.canonicalize().ok()) {
            if exe == target {
                p.kill();
            }
        }
    }
}
