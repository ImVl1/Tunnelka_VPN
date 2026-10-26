//! Ядро Tunnelka: модели, разбор ссылок и подписок, генерация конфига sing-box.
//! Не зависит от Tauri, поэтому тестируется на любой ОС: `cargo test -p tunnelka-core`.

pub mod links;
pub mod model;
pub mod singbox;
pub mod subscription;
pub mod xray;

pub use model::*;
