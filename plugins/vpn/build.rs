// Плагин вызывается только из Rust (run_mobile_plugin), поэтому команд для JS нет.
const COMMANDS: &[&str] = &[];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .build();
}
