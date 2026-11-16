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

/// Обёртка скрипта: вывод в UTF-8 (иначе русский текст ошибок приходит в
/// кодировке консоли и превращается в «�»), и каждая ошибка — одной строкой
/// `ERR:` с названием шага, на котором она случилась.
#[cfg_attr(not(windows), allow(dead_code))]
fn wrap_script(body: &str) -> String {
    format!(
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8\n\
         $ErrorActionPreference='Stop'\n\
         $step='запуск'\n\
         try {{\n{body}\n}} catch {{ [Console]::Out.WriteLine('ERR:' + $step + ': ' + $_.Exception.Message); exit 1 }}\n"
    )
}

/// Скрипт для `-EncodedCommand`: base64 от UTF-16LE. Так текст доходит до
/// PowerShell без искажений, что бы в нём ни было (кириллица, кавычки, пути).
#[cfg_attr(not(windows), allow(dead_code))]
fn encode_command(script: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let mut out = String::with_capacity(bytes.len() * 4 / 3 + 4);
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Текст из вывода PowerShell: UTF-8, а если не получилось — кодировка
/// консоли Windows для русского языка (CP866).
#[cfg_attr(not(windows), allow(dead_code))]
fn decode(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes
            .iter()
            .map(|&b| match b {
                0x00..=0x7F => b as char,
                0x80..=0xAF => char::from_u32(0x0410 + (b - 0x80) as u32).unwrap_or('?'),
                0xE0..=0xEF => char::from_u32(0x0440 + (b - 0xE0) as u32).unwrap_or('?'),
                0xF0 => 'Ё',
                0xF1 => 'ё',
                _ => '?',
            })
            .collect(),
    }
}

/// Путь в обычном виде. Tauri отдаёт пути с префиксом `\\?\` (например,
/// `\\?\C:\Program Files\Tunnelka\sing-box.exe`), а брандмауэр Windows такой
/// путь не принимает: «Приложение содержит недопустимые знаки».
#[cfg_attr(not(windows), allow(dead_code))]
fn plain_path(p: &str) -> String {
    let p = p.replace('/', "\\");
    if let Some(rest) = p.strip_prefix("\\\\?\\UNC\\") {
        format!("\\\\{rest}")
    } else if let Some(rest) = p.strip_prefix("\\\\?\\") {
        rest.to_string()
    } else {
        p
    }
}

/// Сеть CIDR без «лишних» битов адреса: 172.19.0.1/30 → 172.19.0.0/30.
/// Брандмауэр Windows принимает не все записи с битами узла.
#[cfg_attr(not(windows), allow(dead_code))]
fn network(cidr: &str) -> String {
    let Some((ip, bits)) = cidr.split_once('/') else { return cidr.to_string() };
    let Ok(bits) = bits.parse::<u32>() else { return cidr.to_string() };
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) if bits <= 32 => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            format!("{}/{bits}", std::net::Ipv4Addr::from(u32::from(a) & mask))
        }
        Ok(std::net::IpAddr::V6(a)) if bits <= 128 => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            format!("{}/{bits}", std::net::Ipv6Addr::from(u128::from(a) & mask))
        }
        _ => cidr.to_string(),
    }
}

#[cfg(windows)]
fn run_ps(body: &str) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    let script = wrap_script(body);
    let out = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encode_command(&script),
        ])
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| format!("не удалось запустить PowerShell: {e}"))?;
    let stdout = decode(&out.stdout);
    if out.status.success() {
        return Ok(stdout);
    }
    let err = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("ERR:").map(|e| e.trim().to_string()))
        .or_else(|| decode(&out.stderr).lines().map(str::trim).find(|l| !l.is_empty()).map(String::from))
        .unwrap_or_else(|| format!("код {}", out.status.code().unwrap_or(-1)));
    Err(format!("брандмауэр Windows: {err}"))
}

/// Включает kill switch. `programs` — исполняемые файлы, которым разрешён прямой
/// выход в интернет (ядра и само приложение). Повторный вызов безопасен.
#[cfg(windows)]
pub fn enable(data: &Path, programs: &[PathBuf], tun_cidrs: &[&str]) -> Result<Vec<String>, String> {
    let state = state_file(data);
    let mut script = String::new();
    script += &format!("$g={}\n", ps_quote(GROUP));
    // Без службы брандмауэра правила не применить — понятная ошибка вместо загадочной.
    script += "$step='служба брандмауэра'\n\
               $svc = Get-Service -Name MpsSvc -ErrorAction SilentlyContinue\n\
               if (-not $svc -or $svc.Status -ne 'Running') { throw 'служба «Брандмауэр Защитника Windows» (MpsSvc) не запущена — возможно, её отключил сторонний антивирус' }\n";
    // Исходную политику сохраняем только один раз, иначе запишем свою же блокировку.
    if !state.exists() {
        script += "$step='сохранение настроек брандмауэра'\n";
        script += &format!(
            "Get-NetFirewallProfile | Select-Object Name,@{{n='Out';e={{$_.DefaultOutboundAction.ToString()}}}},@{{n='On';e={{[bool]$_.Enabled}}}} | ConvertTo-Json | Set-Content -Encoding UTF8 -Path {}\n",
            ps_quote(&state.to_string_lossy())
        );
    }
    script += "$step='удаление старых правил'\n";
    script += "Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n";
    let rule = |name: &str, extra: &str| {
        format!(
            "$step={}\nNew-NetFirewallRule -DisplayName {} -Group $g -Direction Outbound -Action Allow {extra} | Out-Null\n",
            ps_quote(&format!("правило «{name}»")),
            ps_quote(&format!("Tunnelka: {name}"))
        )
    };
    // Правила-помощники: если брандмауэр какое-то из них не примет, kill switch
    // всё равно включается (петлевые адреса Windows и так не блокирует; IPv6-адрес
    // ::1 в правилах брандмауэр вообще не принимает).
    let optional = |name: &str, extra: &str| {
        format!(
            "try {{ New-NetFirewallRule -DisplayName {} -Group $g -Direction Outbound -Action Allow {extra} | Out-Null }} catch {{ }}\n",
            ps_quote(&format!("Tunnelka: {name}"))
        )
    };
    script += &optional("loopback", "-RemoteAddress 127.0.0.0/8");
    script += &rule("local network", "-RemoteAddress LocalSubnet");
    script += &optional("DHCP", "-Protocol UDP -RemotePort 67,547");
    if !tun_cidrs.is_empty() {
        let list = tun_cidrs.iter().map(|c| ps_quote(&network(c))).collect::<Vec<_>>().join(",");
        script += &rule("TUN", &format!("-LocalAddress {list}"));
    }
    for p in programs.iter().filter(|p| p.exists()) {
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        script += &rule(&name, &format!("-Program {}", ps_quote(&plain_path(&p.to_string_lossy()))));
        // Ответы на соединения этих программ: входящее разрешение (не обязательно,
        // но на части систем без него ответы теряются).
        script += &format!(
            "try {{ New-NetFirewallRule -DisplayName {} -Group $g -Direction Inbound -Action Allow -Program {} | Out-Null }} catch {{ }}\n",
            ps_quote(&format!("Tunnelka: {name} (in)")),
            ps_quote(&plain_path(&p.to_string_lossy()))
        );
    }
    script += "$step='блокировка исходящих соединений'\n";
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
    script += "$step='снятие блокировки'\n";
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

/// Диагностика: что сейчас в брандмауэре. Строки пишутся в журнал приложения,
/// чтобы по ним можно было понять, почему kill switch мешает подключению.
#[cfg(windows)]
pub fn diagnose() -> Vec<String> {
    let mut script = String::new();
    script += &format!("$g={}\n", ps_quote(GROUP));
    script += "$ErrorActionPreference='Continue'\n\
        Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { \"profile $($_.Name): enabled=$($_.Enabled) out=$($_.DefaultOutboundAction) in=$($_.DefaultInboundAction) localRules=$($_.AllowLocalFirewallRules)\" }\n\
        Get-NetConnectionProfile | ForEach-Object { \"network $($_.InterfaceAlias): $($_.NetworkCategory)\" }\n\
        $rules = @(Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue)\n\
        \"rules in store: $($rules.Count)\"\n\
        foreach ($r in $rules) { $a = $r | Get-NetFirewallApplicationFilter; $d = $r | Get-NetFirewallAddressFilter; \"rule $($r.DisplayName): enabled=$($r.Enabled) action=$($r.Action) profile=$($r.Profile) status=$($r.PrimaryStatus) program=$($a.Program) local=$($d.LocalAddress -join ',') remote=$($d.RemoteAddress -join ',')\" }\n\
        $act = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.Group -eq $g })\n\
        \"rules active: $($act.Count)\"\n\
        $blk = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Block -Enabled True -ErrorAction SilentlyContinue)\n\
        \"outbound block rules: $($blk.Count)\"\n\
        $blk | Select-Object -First 12 | ForEach-Object { \"block $($_.DisplayName) [$($_.PolicyStoreSourceType)]\" }\n\
        Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction SilentlyContinue | ForEach-Object { \"third-party firewall: $($_.displayName)\" }\n\
        Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object { \"antivirus: $($_.displayName)\" }\n";
    match run_ps(&script) {
        Ok(out) => out.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
        Err(e) => vec![format!("диагностика не удалась: {e}")],
    }
}

/// Временное правило для диагностики: `extra` — условия New-NetFirewallRule.
/// Пустая строка — только удалить прежнее временное правило.
#[cfg(windows)]
pub fn test_rule(extra: &str) -> Result<(), String> {
    let mut script = format!("$g={}\n$n='Tunnelka: test'\n", ps_quote(GROUP));
    script += "Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n";
    if !extra.is_empty() {
        script += &format!("$step='временное правило'\nNew-NetFirewallRule -DisplayName $n -Group $g -Action Allow {extra} | Out-Null\n");
    }
    run_ps(&script).map(|_| ())
}

#[cfg(not(windows))]
pub fn test_rule(_extra: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(not(windows))]
pub fn diagnose() -> Vec<String> {
    Vec::new()
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
    fn helpers() {
        assert_eq!(super::network("172.19.0.1/30"), "172.19.0.0/30");
        assert_eq!(super::network("fdfe:dcba:9876::1/126"), "fdfe:dcba:9876::/126");
        // «Отказано» в CP866
        assert_eq!(super::decode(&[0x8E, 0xE2, 0xAA, 0xA0, 0xA7, 0xA0, 0xAD, 0xAE]), "Отказано");
        assert_eq!(super::decode("ок".as_bytes()), "ок");
        assert!(super::wrap_script("x").contains("UTF8"));
        assert_eq!(super::plain_path(r"\\?\C:\Program Files\Tunnelka\sing-box.exe"), r"C:\Program Files\Tunnelka\sing-box.exe");
        assert_eq!(super::plain_path(r"\\?\UNC\srv\share\a.exe"), r"\\srv\share\a.exe");
        assert_eq!(super::plain_path(r"C:\a\b.exe"), r"C:\a\b.exe");
        // «ab» в UTF-16LE = 61 00 62 00
        assert_eq!(super::encode_command("ab"), "YQBiAA==");
    }

    #[test]
    fn quoting() {
        assert_eq!(super::ps_quote("C:\\It's\\x.exe"), "'C:\\It''s\\x.exe'");
    }
}
