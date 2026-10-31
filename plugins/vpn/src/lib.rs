//! Мост к Android VpnService. На остальных платформах — пустая заглушка.

use serde::{Deserialize, Serialize};
use tauri::{
    plugin::{Builder, TauriPlugin},
    Runtime,
};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AndroidInfo {
    /// Папка с исполняемыми файлами ядер (libsingbox.so, libxray.so).
    pub native_lib_dir: String,
    pub files_dir: String,
    pub sdk: i32,
}

/// Запуск VPN. Сервис сам запускает ядра по профилю (JSON-файл), поэтому
/// может включиться и без приложения: из плитки в шторке или «Постоянной VPN».
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartArgs {
    pub profile: String,
    pub notify: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub package: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VpnState {
    /// "stopped" | "starting" | "running" | "paused"
    #[serde(default)]
    pub state: String,
    /// Туннель поднят и работает.
    #[serde(default)]
    pub running: bool,
    /// Время подключения, секунды Unix.
    #[serde(default)]
    pub started_at: u64,
    #[serde(default)]
    pub error: Option<String>,
}

impl VpnState {
    /// Сервис занят VPN (подключается, работает или на паузе).
    pub fn active(&self) -> bool {
        matches!(self.state.as_str(), "starting" | "running" | "paused")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Battery {
    #[serde(default)]
    pub unrestricted: bool,
}

#[cfg(target_os = "android")]
mod imp {
    use super::*;
    use std::sync::OnceLock;
    use tauri::plugin::PluginHandle;

    static HANDLE: OnceLock<PluginHandle<tauri::Wry>> = OnceLock::new();

    pub fn register<R: Runtime>(api: tauri::plugin::PluginApi<R, ()>) -> Result<(), String> {
        let h = api
            .register_android_plugin("app.tunnelka.vpn", "VpnPlugin")
            .map_err(|e| e.to_string())?;
        // Приложение использует только Wry; приводим тип через Any.
        let any: Box<dyn std::any::Any> = Box::new(h);
        if let Ok(h) = any.downcast::<PluginHandle<tauri::Wry>>() {
            let _ = HANDLE.set(*h);
        }
        Ok(())
    }

    fn h() -> Result<&'static PluginHandle<tauri::Wry>, String> {
        HANDLE.get().ok_or_else(|| "VPN-плагин не инициализирован".to_string())
    }

    pub fn call<A: Serialize, T: serde::de::DeserializeOwned>(cmd: &str, args: A) -> Result<T, String> {
        h()?.run_mobile_plugin(cmd, args).map_err(|e| e.to_string())
    }
}

/// Сведения о путях приложения на Android.
pub fn info() -> Result<AndroidInfo, String> {
    #[cfg(target_os = "android")]
    return imp::call("info", ());
    #[cfg(not(target_os = "android"))]
    Err("только для Android".into())
}

/// Запрашивает разрешение на VPN (диалог системы) и запускает туннель.
pub fn start(args: StartArgs) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let _: serde_json::Value = imp::call("start", args)?;
        return Ok(());
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = args;
        Err("только для Android".into())
    }
}

pub fn stop() -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let _: serde_json::Value = imp::call("stop", ())?;
        return Ok(());
    }
    #[cfg(not(target_os = "android"))]
    Ok(())
}

pub fn state() -> VpnState {
    #[cfg(target_os = "android")]
    return imp::call("state", ()).unwrap_or_default();
    #[cfg(not(target_os = "android"))]
    VpnState::default()
}

/// Сервис перечитывает профиль (название сервера, показ уведомления).
pub fn refresh() -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let _: serde_json::Value = imp::call("refresh", ())?;
        return Ok(());
    }
    #[cfg(not(target_os = "android"))]
    Ok(())
}

/// Ограничивает ли система работу приложения в фоне (экономия батареи).
pub fn battery() -> Battery {
    #[cfg(target_os = "android")]
    return imp::call("battery", ()).unwrap_or_default();
    #[cfg(not(target_os = "android"))]
    Battery { unrestricted: true }
}

/// Открывает системный запрос «Не ограничивать работу в фоне».
pub fn open_battery_settings() -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let _: serde_json::Value = imp::call("openBatterySettings", ())?;
        return Ok(());
    }
    #[cfg(not(target_os = "android"))]
    Err("только для Android".into())
}

/// Открывает настройки уведомлений приложения.
pub fn open_notification_settings() -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let _: serde_json::Value = imp::call("openNotificationSettings", ())?;
        return Ok(());
    }
    #[cfg(not(target_os = "android"))]
    Err("только для Android".into())
}

/// Установленные приложения с иконкой на рабочем столе.
pub fn apps() -> Result<Vec<AppInfo>, String> {
    #[cfg(target_os = "android")]
    {
        #[derive(Deserialize)]
        struct R {
            apps: Vec<AppInfo>,
        }
        let r: R = imp::call("apps", ())?;
        return Ok(r.apps);
    }
    #[cfg(not(target_os = "android"))]
    Ok(vec![])
}

/// Открывает системные настройки VPN (постоянный VPN и блокировка без VPN).
pub fn open_vpn_settings() -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let _: serde_json::Value = imp::call("openVpnSettings", ())?;
        return Ok(());
    }
    #[cfg(not(target_os = "android"))]
    Err("только для Android".into())
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("tunnelka-vpn")
        .setup(|_app, _api| {
            #[cfg(target_os = "android")]
            imp::register(_api)?;
            Ok(())
        })
        .build()
}
