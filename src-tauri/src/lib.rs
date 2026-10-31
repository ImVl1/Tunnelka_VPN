//! Tunnelka: общий код приложения для Windows и Android.

mod autostart;
mod engine;
mod killswitch;
mod procs;
mod sysproxy;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use engine::{Engine, Paths, Persisted, Status, Traffic};
use tauri::{Manager, State};
use tunnelka_core::Settings;

type E<'a> = State<'a, Arc<Engine>>;

// Команды, которые могут обращаться к VPN-сервису Android, объявлены async:
// так они выполняются вне главного потока и не блокируют интерфейс.

#[tauri::command]
fn get_state(e: E<'_>) -> Persisted {
    e.snapshot()
}

#[tauri::command]
async fn status(e: E<'_>) -> Result<Status, String> {
    Ok(e.status())
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
async fn remove_subscription(e: E<'_>, id: String) -> Result<(), String> {
    e.remove_subscription(&id);
    Ok(())
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
async fn disconnect(e: E<'_>) -> Result<Status, String> {
    Ok(e.disconnect())
}

#[tauri::command]
async fn save_settings(e: E<'_>, settings: Settings) -> Result<Status, String> {
    e.save_settings(settings).await
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

/// Программы для раздельного туннелирования: запущенные процессы (Windows)
/// или установленные приложения (Android).
#[tauri::command]
async fn list_apps() -> Result<Vec<procs::AppEntry>, String> {
    tauri::async_runtime::spawn_blocking(procs::list)
        .await
        .map_err(|e| e.to_string())?
}

/// Android: системные настройки VPN (постоянный VPN, блокировка без VPN).
#[tauri::command]
async fn open_vpn_settings() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(tauri_plugin_tunnelka_vpn::open_vpn_settings)
        .await
        .map_err(|e| e.to_string())?
}

/// Android: ограничивает ли система работу в фоне.
#[tauri::command]
async fn battery_status() -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(|| tauri_plugin_tunnelka_vpn::battery().unrestricted)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn open_battery_settings() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(tauri_plugin_tunnelka_vpn::open_battery_settings)
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn open_notification_settings() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(tauri_plugin_tunnelka_vpn::open_notification_settings)
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
fn open_url(app: tauri::AppHandle, url: String) -> Result<(), String> {
    if !(url.starts_with("https://") || url.starts_with("http://") || url.starts_with("tg://")) {
        return Err("недопустимая ссылка".into());
    }
    #[cfg(windows)]
    {
        let _ = app;
        use std::os::windows::process::CommandExt;
        std::process::Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", &url])
            .creation_flags(0x0800_0000)
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        use tauri::Emitter;
        // На Android ссылку открывает интерфейс через window.open.
        app.emit("open-url", url).map_err(|e| e.to_string())
    }
}

#[cfg(desktop)]
fn show_main(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

#[cfg(desktop)]
fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

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

/// Папка нативных библиотек Android (там же лежат ядра). Определяется по пути,
/// из которого загружена библиотека самого приложения: вызывать Kotlin-плагин
/// из setup нельзя — он выполняется в главном потоке, который здесь занят.
fn native_lib_dir() -> Option<std::path::PathBuf> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    maps.lines()
        .filter_map(|l| l.split_whitespace().last())
        .find(|p| p.ends_with("/libtunnelka_lib.so"))
        .and_then(|p| std::path::Path::new(p).parent().map(|d| d.to_path_buf()))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default();

    // Второй запуск (ярлык, меню «Пуск») не открывает новую копию, а показывает
    // уже работающее окно. Плагин должен регистрироваться первым.
    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main(app);
        }));
    }

    builder = builder.plugin(tauri_plugin_tunnelka_vpn::init());

    builder
        .setup(|app| {
            let data = app
                .path()
                .app_data_dir()
                .expect("не удалось определить папку данных");
            let resource = app.path().resource_dir().ok();
            // На Android ядра лежат среди нативных библиотек приложения.
            let core_dir = if cfg!(target_os = "android") { native_lib_dir() } else { None };
            let engine = Engine::load(Paths::new(data, resource, core_dir));
            app.manage(engine.clone());

            #[cfg(desktop)]
            {
                build_tray(app)?;
                // При запуске вместе с Windows окно не показываем — только значок в трее.
                if autostart::launched_at_login() {
                    if let Some(w) = app.get_webview_window("main") {
                        let _ = w.hide();
                    }
                }
            }

            // Автоподключение.
            let e2 = engine.clone();
            tauri::async_runtime::spawn(async move {
                if e2.settings().auto_connect {
                    // На Android даём интерфейсу загрузиться: системе нужно
                    // показать окно разрешения VPN поверх приложения.
                    if cfg!(target_os = "android") {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                    // VPN мог уже работать (включён из шторки) — не перезапускаем.
                    if !e2.is_running() {
                        if let Err(err) = e2.connect().await {
                            e2.log(format!("[app] автоподключение: {err}"));
                        }
                    }
                }
            });
            // Автообновление подписок: после запуска и далее раз в час проверяем,
            // но каждую подписку обновляем не чаще раза в сутки.
            let e3 = engine.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(Duration::from_secs(4)).await;
                loop {
                    e3.update_due().await;
                    tokio::time::sleep(Duration::from_secs(60 * 60)).await;
                }
            });
            Ok(())
        })
        .on_window_event(|_window, _event| {
            // Закрытие окна сворачивает приложение в трей.
            #[cfg(desktop)]
            if let tauri::WindowEvent::CloseRequested { api, .. } = _event {
                let _ = _window.hide();
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
            ping,
            traffic,
            logs,
            clear_logs,
            list_apps,
            open_vpn_settings,
            battery_status,
            open_battery_settings,
            open_notification_settings,
            open_url
        ])
        .build(tauri::generate_context!())
        .expect("ошибка запуска Tauri")
        .run(|_app, _event| {
            // На Android процесс завершает система (и вызывать VPN-плагин из главного
            // потока при выходе нельзя), поэтому останавливаем ядра только на ПК.
            #[cfg(desktop)]
            if let tauri::RunEvent::Exit = _event {
                if let Some(engine) = _app.try_state::<Arc<Engine>>() {
                    engine.shutdown();
                }
            }
        });
}
