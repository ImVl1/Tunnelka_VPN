//! Системный прокси Windows (режим «Системный прокси»).

pub const BYPASS: &str = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>";

#[cfg(windows)]
mod imp {
    use std::sync::Mutex;
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    use super::BYPASS;

    const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    struct PrevProxy {
        server: Option<String>,
        override_list: Option<String>,
    }

    static PREV: Mutex<Option<PrevProxy>> = Mutex::new(None);

    fn refresh() {
        use windows_sys::Win32::Networking::WinInet::{
            InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
        };
        unsafe {
            InternetSetOptionW(
                std::ptr::null(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null(),
                0,
            );
            InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
        }
    }

    pub fn set(port: u16) -> Result<(), String> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu.create_subkey(KEY).map_err(|e| e.to_string())?;
        {
            let mut prev = PREV.lock().unwrap();
            if prev.is_none() {
                let server: Option<String> = key.get_value("ProxyServer").ok();
                let override_list: Option<String> = key.get_value("ProxyOverride").ok();
                // Сохраняем только чужие настройки прокси (не наш прошлый 127.0.0.1).
                if !server.as_deref().unwrap_or("").starts_with("127.0.0.1:") {
                    *prev = Some(PrevProxy { server, override_list });
                }
            }
        }
        key.set_value("ProxyEnable", &1u32).map_err(|e| e.to_string())?;
        key.set_value("ProxyServer", &format!("127.0.0.1:{port}"))
            .map_err(|e| e.to_string())?;
        key.set_value("ProxyOverride", &BYPASS)
            .map_err(|e| e.to_string())?;
        refresh();
        Ok(())
    }

    pub fn unset() -> Result<(), String> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu.create_subkey(KEY).map_err(|e| e.to_string())?;
        key.set_value("ProxyEnable", &0u32).map_err(|e| e.to_string())?;
        if let Some(prev) = PREV.lock().unwrap().take() {
            if let Some(s) = prev.server {
                let _ = key.set_value("ProxyServer", &s);
            }
            if let Some(o) = prev.override_list {
                let _ = key.set_value("ProxyOverride", &o);
            }
        }
        refresh();
        Ok(())
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn set(_port: u16) -> Result<(), String> {
        Err("системный прокси настраивается автоматически только в Windows".into())
    }
    pub fn unset() -> Result<(), String> {
        Ok(())
    }
}

pub use imp::{set, unset};

#[cfg(test)]
mod tests {
    use super::BYPASS;

    fn matches_wininet(pattern: &str, host: &str) -> bool {
        if let Some(prefix) = pattern.strip_suffix('*') {
            host.starts_with(prefix)
        } else {
            pattern.eq_ignore_ascii_case(host)
        }
    }

    #[test]
    fn bypass_covers_only_rfc1918_172_range() {
        let entries: Vec<&str> = BYPASS.split(';').collect();
        assert!(!entries.contains(&"172.2*"));
        for second in 16..=31 {
            let ip = format!("172.{second}.1.1");
            assert!(entries.iter().any(|p| matches_wininet(p, &ip)), "{ip} must bypass proxy");
        }
        for public_ip in ["172.2.1.1", "172.15.1.1", "172.32.1.1", "172.217.16.14", "172.253.63.100"] {
            assert!(
                !entries.iter().any(|p| matches_wininet(p, public_ip)),
                "public IP {public_ip} must not bypass proxy"
            );
        }
    }
}
