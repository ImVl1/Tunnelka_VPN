<p align="center">
  <img src="assets/icon.png" width="128" height="128" alt="Tunnelka" />
</p>

<h1 align="center">Tunnelka</h1>

<p align="center">
  A VPN client for VLESS, VMess, Trojan, Shadowsocks, Hysteria2 and TUIC subscriptions.<br />
  Windows and Android.
</p>

<p align="center">
  <a href="https://imvl1.github.io/Tunnelka_VPN/"><b>Download</b></a>
  &nbsp;·&nbsp;
  <a href="https://github.com/ImVl1/Tunnelka_VPN/releases/latest">Latest release</a>
  &nbsp;·&nbsp;
  <a href="README.ru.md">Читать на русском</a>
</p>

<p align="center">
  <img src="assets/screenshots/windows-servers.png" width="640" alt="Tunnelka for Windows" />
  &nbsp;
  <img src="assets/screenshots/android-home.png" width="200" alt="Tunnelka for Android" />
</p>

## Features

**Subscriptions.** Paste the link from your provider's bot or dashboard: Marzban, Remnawave, 3x-ui, Hiddify and other panels work out of the box. Tunnelka shows remaining traffic, the expiry date and provider announcements, and refreshes subscriptions automatically once a day after launch. Plain and base64 link lists and sing-box / Xray JSON configs are supported. Individual servers can be added as links.

**Protocols.** VLESS (REALITY, TLS, XTLS Vision, XHTTP, WebSocket, gRPC, HTTPUpgrade), VMess, Trojan, Shadowsocks and Shadowsocks 2022, Hysteria2 with port hopping, TUIC, SOCKS5 and HTTP(S).

**Split tunneling.**
- By app: "everything through the VPN except selected apps" or "only selected apps through the VPN". Each mode keeps its own list.
- By site: "through the VPN" and "direct" lists of domains, IP addresses and subnets.
- Russian sites and IP addresses can be sent direct with a single switch.

**Connection.**
- Automatic selection of the lowest-latency server and switching between servers without dropping the connection.
- If the selected server stops answering, Tunnelka moves to a working one.
- Windows: TUN mode (all traffic on the computer) or system proxy. If your ISP breaks TUN, the app falls back to the system proxy on its own.
- Android: system VPN for all apps, a Quick Settings tile, Pause and Disconnect buttons in the notification, and Always-on VPN support. The VPN keeps running after the app is swiped away from recents.

**Security.**
- Kill switch (Windows): if the VPN drops unexpectedly, the firewall keeps programs from reaching the internet directly. On Android, use the system "Always-on VPN" and "Block connections without VPN" settings.
- DNS queries and IPv6 never bypass the tunnel.
- Local ports are randomized on every connection and protected by a random password, so other programs can't discover or use the proxy.

**Convenience.** Tray icon, start with Windows and connect on launch (both off by default), sharing the VPN with the local network behind a password, and a log viewer.

## System requirements

- Windows 10 or 11, 64-bit. TUN mode requires administrator rights.
- Android 7.0 or newer on an arm64 processor (almost every modern phone).

## How it works

The interface and logic are written in Rust with [Tauri](https://tauri.app) and shared between both platforms. Connections are handled by [sing-box](https://github.com/SagerNet/sing-box); servers that sing-box doesn't support (XHTTP, VLESS Encryption) are run through [Xray-core](https://github.com/XTLS/Xray-core) automatically. On Android the tunnel is created by the system VpnService together with [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel).

## License

Tunnelka is released under the MIT license. The bundled cores keep their own licenses: sing-box — GPL-3.0, Xray-core — MPL-2.0, hev-socks5-tunnel — MIT. The Inter font is licensed under the SIL Open Font License 1.1.
