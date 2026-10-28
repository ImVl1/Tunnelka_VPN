//! Автозапуск вместе с Windows через Планировщик заданий.
//!
//! Приложению нужны права администратора, а программы из раздела «Автозагрузка»
//! Windows с такими правами не запускает. Задание планировщика с «наивысшими
//! правами» запускается при входе в систему без запроса UAC.

#[cfg_attr(not(windows), allow(dead_code))]
pub const TASK: &str = "Tunnelka";
pub const ARG: &str = "--autostart";

#[cfg(windows)]
fn schtasks(args: &[&str]) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let out = std::process::Command::new("schtasks.exe")
        .args(args)
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// XML задания: без ограничений по батарее и времени работы
/// (по умолчанию планировщик не запускает задания от батареи и
/// останавливает их через 72 часа).
#[cfg_attr(not(windows), allow(dead_code))]
fn task_xml(exe: &str, user: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Запуск Tunnelka при входе в Windows</Description></RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId><Delay>PT10S</Delay></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>{exe}</Command><Arguments>{ARG}</Arguments></Exec>
  </Actions>
</Task>
"#,
        exe = xml_escape(exe),
        user = xml_escape(user),
    )
}

#[cfg(windows)]
pub fn set(enabled: bool, data: &std::path::Path) -> Result<(), String> {
    if !enabled {
        // Задания может не быть — это не ошибка.
        let _ = schtasks(&["/Delete", "/TN", TASK, "/F"]);
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let user = match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        (Ok(d), Ok(u)) => format!("{d}\\{u}"),
        (_, Ok(u)) => u,
        _ => return Err("не удалось определить пользователя Windows".into()),
    };
    let xml = task_xml(&exe.to_string_lossy(), &user);
    // schtasks ожидает UTF-16 с BOM.
    let mut bytes = vec![0xFF, 0xFE];
    for u in xml.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    let path = data.join("autostart.xml");
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
    let res = schtasks(&["/Create", "/TN", TASK, "/XML", &path.to_string_lossy(), "/F"]);
    let _ = std::fs::remove_file(&path);
    res.map_err(|e| format!("не удалось включить автозапуск: {e}"))
}

#[cfg(not(windows))]
pub fn set(enabled: bool, _data: &std::path::Path) -> Result<(), String> {
    if enabled {
        Err("автозапуск доступен только в Windows".into())
    } else {
        Ok(())
    }
}

/// Приложение запущено планировщиком при входе в систему.
#[cfg_attr(mobile, allow(dead_code))]
pub fn launched_at_login() -> bool {
    std::env::args().any(|a| a == ARG)
}

#[cfg(test)]
mod tests {
    #[test]
    fn xml() {
        let x = super::task_xml("C:\\Program Files\\Tunnelka\\tunnelka.exe", "PC\\Vova & Co");
        assert!(x.contains("<UserId>PC\\Vova &amp; Co</UserId>"));
        assert!(x.contains("<Arguments>--autostart</Arguments>"));
        assert!(x.contains("<DisallowStartIfOnBatteries>false"));
    }
}
