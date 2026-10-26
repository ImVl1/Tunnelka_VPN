//! Системный прокси Windows (режим «Системный прокси»).

#[cfg(windows)]
mod imp {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const BYPASS: &str = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;172.30.*;172.31.*;192.168.*;<local>";

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
