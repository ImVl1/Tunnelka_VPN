fn main() {
    let mut attrs = tauri_build::Attributes::new();
    // В релизной сборке приложение сразу просит права администратора:
    // без них Windows не даст создать TUN-адаптер.
    // `tauri dev` запускается без манифеста — для TUN запускайте терминал от администратора.
    if std::env::var("PROFILE").as_deref() == Ok("release") {
        attrs = attrs.windows_attributes(
            tauri_build::WindowsAttributes::new().app_manifest(include_str!("windows-app.manifest")),
        );
    }
    tauri_build::try_build(attrs).expect("failed to run tauri-build");
}
