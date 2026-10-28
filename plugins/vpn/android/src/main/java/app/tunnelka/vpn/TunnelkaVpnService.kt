package app.tunnelka.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import hev.htproxy.TProxyService
import java.io.File

/**
 * VPN-сервис: создаёт TUN-интерфейс и передаёт его в hev-socks5-tunnel, который
 * отправляет весь трафик в локальный SOCKS5 ядра sing-box (с логином и паролем).
 *
 * Сами ядра запускает Rust-часть приложения. Процессы приложения исключены из VPN,
 * поэтому ядра подключаются к серверам напрямую, без петли.
 */
class TunnelkaVpnService : VpnService() {

    companion object {
        const val ACTION_START = "app.tunnelka.vpn.START"
        const val ACTION_STOP = "app.tunnelka.vpn.STOP"
        private const val TAG = "TunnelkaVpn"
        private const val CHANNEL = "vpn"
        private const val NOTIFICATION_ID = 1

        private const val TUN_IPV4 = "198.18.0.1"
        private const val TUN_DNS = "198.18.0.2"
        private const val TUN_IPV6 = "fc00::1"
        private const val MTU = 8500

        @Volatile
        var running = false
            private set

        /** Сервис запущен и библиотека туннеля работает. */
        fun alive(): Boolean = running && try {
            TProxyService.TProxyIsRunning()
        } catch (_: Throwable) {
            false
        }

        @Volatile
        var lastError: String? = null
            private set
    }

    private var tun: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                startForegroundCompat(intent.getStringExtra("session") ?: "Tunnelka")
                try {
                    startTunnel(intent)
                    lastError = null
                } catch (e: Exception) {
                    Log.e(TAG, "start failed", e)
                    lastError = e.message ?: e.toString()
                    stopTunnel()
                    stopSelf()
                }
            }
        }
        // Если система убьёт сервис, не перезапускать его без ядер.
        return START_NOT_STICKY
    }

    private fun startTunnel(intent: Intent) {
        stopTunnel()
        val port = intent.getIntExtra("socksPort", 0)
        val user = intent.getStringExtra("socksUser") ?: ""
        val pass = intent.getStringExtra("socksPass") ?: ""
        val appMode = intent.getStringExtra("appMode") ?: "off"
        val apps = intent.getStringArrayListExtra("apps") ?: arrayListOf()
        require(port in 1..65535) { "не указан порт ядра" }

        val builder = Builder()
            .setSession(intent.getStringExtra("session") ?: "Tunnelka")
            .setMtu(MTU)
            .addAddress(TUN_IPV4, 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(TUN_DNS)
            // IPv6 тоже заворачиваем в туннель, чтобы он не утекал мимо VPN.
            // Если IPv6 выключен в настройках, ядро его блокирует.
            .addAddress(TUN_IPV6, 128)
            .addRoute("::", 0)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        val selected = apps.map { it.trim() }.filter { it.isNotEmpty() && it != packageName }
        if (appMode == "include" && selected.isNotEmpty()) {
            // Через VPN идут только выбранные приложения (своё приложение не входит).
            var added = 0
            for (p in selected) {
                try {
                    builder.addAllowedApplication(p); added++
                } catch (_: PackageManager.NameNotFoundException) {
                }
            }
            require(added > 0) { "ни одно из выбранных приложений не установлено" }
        } else {
            // Ядра работают в процессах этого приложения — исключаем его из VPN.
            builder.addDisallowedApplication(packageName)
            if (appMode == "exclude") {
                for (p in selected) {
                    try {
                        builder.addDisallowedApplication(p)
                    } catch (_: PackageManager.NameNotFoundException) {
                    }
                }
            }
        }

        val pfd = builder.establish() ?: error("нет разрешения на VPN")
        tun = pfd

        val config = File(cacheDir, "tunnel.yml")
        config.writeText(
            """
            |tunnel:
            |  mtu: $MTU
            |  ipv4: $TUN_IPV4
            |  ipv6: '$TUN_IPV6'
            |socks5:
            |  port: $port
            |  address: 127.0.0.1
            |  udp: 'udp'
            |  username: '${yaml(user)}'
            |  password: '${yaml(pass)}'
            |misc:
            |  task-stack-size: 81920
            |  log-level: warn
            |""".trimMargin()
        )
        // Файл доступен только приложению. Библиотека читает его в своём потоке
        // уже после возврата из TProxyStartService, поэтому удаляем при отключении.
        if (!TProxyService.TProxyStartService(config.absolutePath, pfd.fd)) {
            error("не удалось запустить туннель")
        }
        // Убеждаемся, что туннель прочитал настройки и работает.
        Thread.sleep(400)
        if (!TProxyService.TProxyIsRunning()) {
            error("туннель остановился сразу после запуска")
        }
        running = true
    }

    private fun yaml(s: String) = s.replace("'", "''")

    private fun stopTunnel() {
        if (running) {
            try {
                TProxyService.TProxyStopService()
            } catch (e: Throwable) {
                Log.w(TAG, "stop failed", e)
            }
        }
        running = false
        File(cacheDir, "tunnel.yml").delete()
        try {
            tun?.close()
        } catch (_: Exception) {
        }
        tun = null
    }

    /** Пользователь отключил VPN в системе или включил другой VPN. */
    override fun onRevoke() {
        lastError = "VPN отключён системой"
        stopTunnel()
        stopSelf()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    private fun startForegroundCompat(title: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, "VPN", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val launch = packageManager.getLaunchIntentForPackage(packageName)
        val pi = launch?.let {
            PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE)
        }
        val n: Notification = (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            Notification.Builder(this, CHANNEL) else @Suppress("DEPRECATION") Notification.Builder(this))
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(title)
            .setContentText("VPN подключён")
            .setOngoing(true)
            .setContentIntent(pi)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, n)
        }
    }
}
