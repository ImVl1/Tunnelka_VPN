//! Kill switch для Windows: пока VPN включён, брандмауэр Windows запрещает любые
//! исходящие соединения, кроме трафика через TUN, самих ядер, локальной сети и
//! loopback. Если ядро упадёт, программы не смогут выйти в интернет напрямую.
//!
//! Работает через политику брандмауэра «блокировать исходящие по умолчанию» и
//! разрешающие правила в группе «Tunnelka Kill Switch». Исходная политика
//! сохраняется в файл и восстанавливается при отключении.

use std::path::{Path, PathBuf};

#[cfg_attr(not(windows), allow(dead_code))]
pub const GROUP: &str = "Tunnelka Kill Switch";

/// Файл-маркер с сохранённой политикой брандмауэра.
fn state_file(data: &Path) -> PathBuf {
    data.join("killswitch.json")
}

pub fn is_active(data: &Path) -> bool {
    state_file(data).exists()
}

/// Экранирование строки для PowerShell в одинарных кавычках.
#[cfg_attr(not(windows), allow(dead_code))]
fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

#[cfg(windows)]
fn run_ps(script: &str) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    let out = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| format!("не удалось запустить PowerShell: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(format!("брандмауэр Windows: {}", err.lines().next().unwrap_or("ошибка")))
    }
}

/// Включает kill switch. `programs` — исполняемые файлы, которым разрешён прямой
/// выход в интернет (ядра и само приложение). Повторный вызов безопасен.
#[cfg(windows)]
pub fn enable(data: &Path, programs: &[PathBuf], tun_cidrs: &[&str]) -> Result<Vec<String>, String> {
    let state = state_file(data);
    let mut script = String::from("$ErrorActionPreference='Stop'\n");
    script += &format!("$g={}\n", ps_quote(GROUP));
    // Исходную политику сохраняем только один раз, иначе запишем свою же блокировку.
    if !state.exists() {
        script += &format!(
            "Get-NetFirewallProfile | Select-Object Name,@{{n='Out';e={{$_.DefaultOutboundAction.ToString()}}}},@{{n='On';e={{[bool]$_.Enabled}}}} | ConvertTo-Json | Set-Content -Encoding UTF8 -Path {}\n",
            ps_quote(&state.to_string_lossy())
        );
    }
    script += "Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n";
    let rule = |name: &str, extra: &str| {
        format!(
            "New-NetFirewallRule -DisplayName {} -Group $g -Direction Outbound -Action Allow {extra} | Out-Null\n",
            ps_quote(&format!("Tunnelka: {name}"))
        )
    };
    script += &rule("loopback", "-RemoteAddress 127.0.0.0/8,::1");
    script += &rule("локальная сеть", "-RemoteAddress LocalSubnet");
    script += &rule("DHCP", "-Protocol UDP -RemotePort 67,547");
    if !tun_cidrs.is_empty() {
        let list = tun_cidrs.iter().map(|c| ps_quote(c)).collect::<Vec<_>>().join(",");
        script += &rule("TUN", &format!("-LocalAddress {list}"));
    }
    for p in programs.iter().filter(|p| p.exists()) {
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        script += &rule(&name, &format!("-Program {}", ps_quote(&p.to_string_lossy())));
    }
    script += "Set-NetFirewallProfile -All -DefaultOutboundAction Block\n";
    // Профили, где брандмауэр выключен: там блокировка не сработает.
    script += "Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name }\n";
    let out = run_ps(&script);
    if out.is_err() {
        let _ = disable(data);
    }
    Ok(out?
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Выключает kill switch и возвращает исходную политику брандмауэра.
#[cfg(windows)]
pub fn disable(data: &Path) -> Result<(), String> {
    let state = state_file(data);
    let mut script = String::from("$ErrorActionPreference='Continue'\n");
    script += &format!(
        "Get-NetFirewallRule -Group {} -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n",
        ps_quote(GROUP)
    );
    if state.exists() {
        script += &format!(
            "$s = Get-Content -Raw -Path {} | ConvertFrom-Json\n\
             foreach ($p in @($s)) {{ Set-NetFirewallProfile -Name $p.Name -DefaultOutboundAction $p.Out }}\n",
            ps_quote(&state.to_string_lossy())
        );
    } else {
        // Состояние потеряно — возвращаем стандартную политику Windows.
        script += "Set-NetFirewallProfile -All -DefaultOutboundAction NotConfigured\n";
    }
    run_ps(&script)?;
    let _ = std::fs::remove_file(&state);
    Ok(())
}

#[cfg(not(windows))]
pub fn enable(_data: &Path, _programs: &[PathBuf], _tun: &[&str]) -> Result<Vec<String>, String> {
    Err("kill switch доступен только в Windows".into())
}

#[cfg(not(windows))]
pub fn disable(data: &Path) -> Result<(), String> {
    let _ = std::fs::remove_file(state_file(data));
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn quoting() {
        assert_eq!(super::ps_quote("C:\\It's\\x.exe"), "'C:\\It''s\\x.exe'");
    }
}
