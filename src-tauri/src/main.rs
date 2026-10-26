#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod engine;
mod procs;
mod sysproxy;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use engine::{Engine, Paths, Persisted, Status, Traffic};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, RunEvent, State, WindowEvent};
use tunnelka_core::Settings;

type E<'a> = State<'a, Arc<Engine>>;

#[tauri::command]
fn get_state(e: E<'_>) -> Persisted {
    e.snapshot()
}

#[tauri::command]
fn status(e: E<'_>) -> Status {
    e.status()
}

#[tauri::command]
async fn add_subscription(e: E<'_>, input: String) -> Result<String, String> {
    e.add_subscription(&input).await
}

#[tauri::command]
async fn update_subscription(e: E<'_>, id: String) -> Result<(), String> {
    e.update_subscription(&id).await
}

#[tauri::command]
async fn update_all(e: E<'_>) -> Result<Vec<String>, String> {
    Ok(e.update_all().await)
}

#[tauri::command]
fn remove_subscription(e: E<'_>, id: String) {
    e.remove_subscription(&id)
}

#[tauri::command]
fn rename_subscription(e: E<'_>, id: String, name: String) {
    e.rename_subscription(&id, &name)
}

#[tauri::command]
fn add_manual(e: E<'_>, text: String) -> Result<usize, String> {
    e.add_manual(&text)
}

#[tauri::command]
fn remove_server(e: E<'_>, id: String) {
    e.remove_server(&id)
}

#[tauri::command]
async fn select_server(e: E<'_>, id: String) -> Result<Status, String> {
    e.select(&id).await
}

#[tauri::command]
async fn connect(e: E<'_>) -> Result<Status, String> {
    e.connect().await
}

#[tauri::command]
fn disconnect(e: E<'_>) -> Status {
    e.disconnect()
}

#[tauri::command]
async fn save_settings(e: E<'_>, settings: Settings) -> Result<Status, String> {
    e.save_settings(settings).await
}

#[tauri::command]
fn regenerate_token(e: E<'_>) -> String {
    e.regenerate_token()
}

#[tauri::command]
async fn ping(e: E<'_>, sub_id: String) -> Result<HashMap<String, i64>, String> {
    Ok(e.ping(&sub_id).await)
}

#[tauri::command]
async fn traffic(e: E<'_>) -> Result<Option<Traffic>, String> {
    Ok(e.traffic().await)
}

#[tauri::command]
fn logs(e: E<'_>) -> Vec<String> {
    e.logs()
}

#[tauri::command]
fn clear_logs(e: E<'_>) {
    e.clear_logs()
}

#[tauri::command]
fn list_processes() -> Vec<procs::ProcInfo> {
    procs::list()
}

#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    if !(url.starts_with("https://") || url.starts_with("http://") || url.starts_with("tg://")) {
        return Err("недопустимая ссылка".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", &url])
            .creation_flags(0x0800_0000)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new("xdg-open")
            .arg(&url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Открыть Tunnelka", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "Подключить / отключить", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &toggle, &sep, &quit])?;
    let mut builder = TrayIconBuilder::with_id("main")
        .tooltip("Tunnelka")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main(app),
            "toggle" => {
                let engine = app.state::<Arc<Engine>>().inner().clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = engine.toggle().await {
                        engine.log(format!("[app] {e}"));
                    }
                });
            }
            "quit" => {
                app.state::<Arc<Engine>>().shutdown();
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let data = app
                .path()
                .app_data_dir()
                .expect("не удалось определить папку данных");
            let resource = app.path().resource_dir().ok();
            let engine = Engine::load(Paths::new(data, resource));
            app.manage(engine.clone());

            api::spawn(engine.clone());
            build_tray(app)?;

            // Автообновление подписок + автоподключение.
            let e2 = engine.clone();
            tauri::async_runtime::spawn(async move {
                if e2.settings().auto_connect {
                    if let Err(err) = e2.connect().await {
                        e2.log(format!("[app] автоподключение: {err}"));
                    }
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
                loop {
                    e2.update_due().await;
                    tokio::time::sleep(Duration::from_secs(30 * 60)).await;
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            // Закрытие окна сворачивает приложение в трей.
            if let WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            status,
            add_subscription,
            update_subscription,
            update_all,
            remove_subscription,
            rename_subscription,
            add_manual,
            remove_server,
            select_server,
            connect,
            disconnect,
            save_settings,
            regenerate_token,
            ping,
            traffic,
            logs,
            clear_logs,
            list_processes,
            open_url
        ])
        .build(tauri::generate_context!())
        .expect("ошибка запуска Tauri")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                if let Some(engine) = app.try_state::<Arc<Engine>>() {
                    engine.shutdown();
                }
            }
        });
}
