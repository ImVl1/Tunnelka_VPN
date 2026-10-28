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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartArgs {
    pub socks_port: u16,
    pub socks_user: String,
    pub socks_pass: String,
    /// "off" | "include" | "exclude"
    pub app_mode: String,
    pub apps: Vec<String>,
    pub ipv6: bool,
    pub session: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub package: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VpnState {
    pub running: bool,
    #[serde(default)]
    pub error: Option<String>,
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
