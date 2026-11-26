//! Пинг до сервера: время TCP-соединения с ним (одно рукопожатие).
//!
//! Пока на Windows работает TUN, обычное соединение попадёт в туннель, и
//! рукопожатие завершит сам sing-box за доли миллисекунды. Поэтому сокет
//! привязывается к физическому сетевому адаптеру (IP_UNICAST_IF) — как это делает
//! sing-box для своих соединений.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Время соединения с `addr`, мс. `bypass_tun` — подключаться мимо TUN.
pub fn connect_ms(addr: SocketAddr, bypass_tun: bool, timeout: Duration) -> Option<i64> {
    let if_index = if bypass_tun { physical_index() } else { None };
    if bypass_tun && if_index.is_none() {
        return None;
    }
    let domain = if addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
    let sock = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP)).ok()?;
    if let Some(idx) = if_index {
        bind_interface(&sock, idx, addr.is_ipv4())?;
    }
    let start = Instant::now();
    sock.connect_timeout(&addr.into(), timeout).ok()?;
    Some(start.elapsed().as_millis().max(1) as i64)
}

#[cfg(windows)]
fn bind_interface(sock: &socket2::Socket, idx: u32, v4: bool) -> Option<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, IPPROTO_IPV6, SOCKET};
    const IP_UNICAST_IF: i32 = 31;
    const IPV6_UNICAST_IF: i32 = 31;
    // Для IPv4 индекс передаётся в сетевом порядке байт, для IPv6 — в обычном.
    let (level, opt, val) = if v4 {
        (IPPROTO_IP, IP_UNICAST_IF, idx.to_be())
    } else {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, idx)
    };
    let r = unsafe {
        setsockopt(
            sock.as_raw_socket() as SOCKET,
            level,
            opt,
            &val as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        )
    };
    (r == 0).then_some(())
}

#[cfg(not(windows))]
fn bind_interface(_sock: &socket2::Socket, _idx: u32, _v4: bool) -> Option<()> {
    None
}

/// Индекс адаптера, через который идёт маршрут по умолчанию в обход TUN.
#[cfg(windows)]
fn physical_index() -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex, FreeMibTable,
        GetIpForwardTable2, GetIpInterfaceEntry, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    unsafe {
        // Индекс нашего TUN-адаптера, чтобы его пропустить.
        let alias: Vec<u16> = tunnelka_core::singbox::TUN_NAME.encode_utf16().chain(Some(0)).collect();
        let mut luid: NET_LUID_LH = std::mem::zeroed();
        let mut tun_index = 0u32;
        if ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) == 0 {
            let _ = ConvertInterfaceLuidToIndex(&luid, &mut tun_index);
        }
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        if GetIpForwardTable2(AF_INET, &mut table) != 0 || table.is_null() {
            return None;
        }
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
        // В Windows итоговая метрика маршрута складывается из смещения маршрута
        // (row.Metric) и метрики самого адаптера (iface.Metric).
        let effective_metric = |if_index: u32, route_metric: u32| -> Option<u32> {
            let mut iface: MIB_IPINTERFACE_ROW = std::mem::zeroed();
            iface.Family = AF_INET;
            iface.InterfaceIndex = if_index;
            if GetIpInterfaceEntry(&mut iface) == 0 {
                if iface.Connected == 0 {
                    return None;
                }
                Some(route_metric.saturating_add(iface.Metric))
            } else {
                Some(route_metric)
            }
        };
        let best = rows
            .iter()
            .filter(|r| {
                r.DestinationPrefix.PrefixLength == 0
                    && r.InterfaceIndex != tun_index
                    && r.InterfaceIndex != 0
            })
            .filter_map(|r| effective_metric(r.InterfaceIndex, r.Metric).map(|m| (m, r.InterfaceIndex)))
            .min_by_key(|(m, _)| *m)
            .map(|(_, idx)| idx);
        FreeMibTable(table as *const core::ffi::c_void);
        best
    }
}

#[cfg(not(windows))]
fn physical_index() -> Option<u32> {
    None
}
