package app.tunnelka.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.service.quicksettings.TileService
import android.util.Log
import androidx.core.app.NotificationCompat
import hev.htproxy.TProxyService
import org.json.JSONObject
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors

/**
 * VPN-сервис Tunnelka. Сам запускает ядра (sing-box и, если нужно, Xray) по профилю,
 * который подготовило приложение, создаёт TUN-интерфейс и передаёт его в
 * hev-socks5-tunnel. Поэтому VPN работает и без открытого приложения: после
 * закрытия из списка недавних, из плитки в шторке и при «Постоянной VPN».
 *
 * Процессы приложения исключены из VPN, поэтому ядра ходят к серверам напрямую.
 */
class TunnelkaVpnService : VpnService() {

    enum class State { STOPPED, STARTING, RUNNING, PAUSED }

    companion object {
        const val ACTION_START = "app.tunnelka.vpn.START"
        const val ACTION_STOP = "app.tunnelka.vpn.STOP"
        const val ACTION_PAUSE = "app.tunnelka.vpn.PAUSE"
        const val ACTION_RESUME = "app.tunnelka.vpn.RESUME"
        const val ACTION_REFRESH = "app.tunnelka.vpn.REFRESH"
        private const val ACTION_ALWAYS_ON = "android.net.VpnService"

        private const val TAG = "TunnelkaVpn"
        private const val CHANNEL_OLD = "vpn"
        private const val CHANNEL = "vpn_status"
        private const val CHANNEL_QUIET = "vpn_quiet"
        private const val NOTIFICATION_ID = 1

        private const val PREFS = "tunnelka_vpn"
        private const val KEY_PROFILE = "profile"
        private const val KEY_WANTED = "wanted"

        private const val TUN_IPV4 = "198.18.0.1"
        private const val TUN_DNS = "198.18.0.2"
        private const val TUN_IPV6 = "fc00::1"
        private const val MTU = 8500

        @Volatile
        var state: State = State.STOPPED
            private set

        @Volatile
        var lastError: String? = null
            private set

        /** Время подключения, секунды Unix. */
        @Volatile
        var startedAt: Long = 0
            private set

        @Volatile
        private var hevRunning = false

        /** Туннель поднят и библиотека туннеля работает. */
        fun alive(): Boolean = state == State.RUNNING && hevRunning && try {
            TProxyService.TProxyIsRunning()
        } catch (_: Throwable) {
            false
        }

        /** Вызывается перед запуском, чтобы не принять старую ошибку за новую. */
        fun markStarting() {
            lastError = null
            state = State.STARTING
        }

        fun intent(ctx: Context, action: String): Intent =
            Intent(ctx, TunnelkaVpnService::class.java).setAction(action)

        private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

        fun profilePath(ctx: Context): String? =
            prefs(ctx).getString(KEY_PROFILE, null)?.takeIf { File(it).exists() }

        fun setProfilePath(ctx: Context, path: String) {
            prefs(ctx).edit().putString(KEY_PROFILE, path).apply()
        }

        private fun setWanted(ctx: Context, on: Boolean) {
            prefs(ctx).edit().putBoolean(KEY_WANTED, on).apply()
        }

        private fun wanted(ctx: Context) = prefs(ctx).getBoolean(KEY_WANTED, false)
    }

    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val procs = mutableListOf<Process>()
    private var tun: ParcelFileDescriptor? = null
    private var profile: JSONObject? = null
    private var watchdog: Thread? = null
    private var restarts = 0

    @Volatile
    private var latestStartId = 0

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestStartId = startId
        when (intent?.action) {
            ACTION_STOP -> worker.execute { stopAll(startId) }
            ACTION_PAUSE -> worker.execute { pause() }
            ACTION_REFRESH -> worker.execute {
                profile = readProfile()
                postNotification()
            }
            ACTION_START, ACTION_RESUME, ACTION_ALWAYS_ON -> {
                if (state != State.STARTING) markStarting()
                if (!foreground()) return START_NOT_STICKY
                worker.execute { start() }
            }
            else -> {
                // Система перезапустила сервис после нехватки памяти.
                if (!wanted(this) || profilePath(this) == null) {
                    stopSelf(startId)
                    return START_NOT_STICKY
                }
                markStarting()
                if (!foreground()) return START_NOT_STICKY
                worker.execute { start() }
            }
        }
        return START_STICKY
    }

    /** Закрытие приложения из списка недавних не отключает VPN. */
    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
    }

    private fun foreground(): Boolean = try {
        val n = buildNotification()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, n)
        }
        true
    } catch (e: Exception) {
        Log.e(TAG, "startForeground", e)
        lastError = "система не разрешила запустить VPN в фоне — откройте Tunnelka"
        state = State.STOPPED
        stopSelf()
        false
    }

    // ------------------------------------------------------------------
    // Запуск и остановка
    // ------------------------------------------------------------------

    private fun readProfile(): JSONObject? = profilePath(this)?.let {
        try {
            JSONObject(File(it).readText())
        } catch (e: Exception) {
            Log.e(TAG, "profile", e)
            null
        }
    }

    private fun start() {
        try {
            stopInternal()
            markStarting()
            updateUi()
            val p = readProfile() ?: error("нет сохранённого подключения — откройте Tunnelka и подключитесь")
            profile = p
            startCores(p)
            startTunnel(p)
            state = State.RUNNING
            startedAt = System.currentTimeMillis() / 1000
            setWanted(this, true)
            startWatchdog()
            updateUi()
        } catch (e: Exception) {
            Log.e(TAG, "start failed", e)
            lastError = e.message ?: e.toString()
            stopInternal()
            state = State.STOPPED
            setWanted(this, false)
            updateUi()
            main.post {
                stopForegroundCompat()
                stopSelf()
            }
        }
    }

    private fun startCores(p: JSONObject) {
        val workDir = File(p.getString("workDir"))
        val log = File(p.getString("log"))
        // Журнал ядер начинается заново при каждом подключении.
        log.writeText("")
        val env = p.optJSONObject("env")
        val list = p.getJSONArray("processes")
        for (i in 0 until list.length()) {
            val spec = list.getJSONObject(i)
            val cmd = mutableListOf(spec.getString("exe"))
            val args = spec.getJSONArray("args")
            for (j in 0 until args.length()) cmd.add(args.getString(j))
            val pb = ProcessBuilder(cmd)
                .directory(workDir)
                .redirectErrorStream(true)
            env?.keys()?.forEach { k -> pb.environment()[k] = env.getString(k) }
            val proc = pb.start()
            procs.add(proc)
            pipeToLog(proc, log)
        }
        // Ждём, пока sing-box откроет локальный порт.
        val port = p.getInt("socksPort")
        val deadline = System.currentTimeMillis() + 10_000
        while (true) {
            procs.forEachIndexed { i, proc ->
                if (!isAlive(proc)) {
                    val name = list.getJSONObject(i).optString("name", "ядро")
                    error("$name завершилось при запуске${lastLine(log)}")
                }
            }
            if (portOpen(port)) break
            if (System.currentTimeMillis() > deadline) error("ядро не ответило за 10 секунд")
            Thread.sleep(50)
        }
    }

    /** Вывод ядра дописывается в журнал (его показывает приложение). */
    private fun pipeToLog(proc: Process, log: File) {
        val t = Thread {
            try {
                proc.inputStream.bufferedReader().useLines { lines ->
                    java.io.FileWriter(log, true).use { w ->
                        for (line in lines) {
                            // Журнал не растёт бесконечно при долгой работе.
                            if (log.length() > 2_000_000) log.writeText("")
                            w.write(line); w.write("\n"); w.flush()
                        }
                    }
                }
            } catch (_: Exception) {
            }
        }
        t.isDaemon = true
        t.start()
    }

    private fun portOpen(port: Int): Boolean = try {
        Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 200) }
        true
    } catch (_: Exception) {
        false
    }

    private fun isAlive(p: Process): Boolean = if (Build.VERSION.SDK_INT >= 26) p.isAlive else try {
        p.exitValue(); false
    } catch (_: IllegalThreadStateException) {
        true
    }

    private fun lastLine(log: File): String = try {
        log.readLines().lastOrNull { it.isNotBlank() }?.let { ": ${it.take(300)}" } ?: ""
    } catch (_: Exception) {
        ""
    }

    private fun startTunnel(p: JSONObject) {
        val port = p.getInt("socksPort")
        val user = p.optString("socksUser")
        val pass = p.optString("socksPass")
        val appMode = p.optString("appMode", "off")
        val appsJson = p.optJSONArray("apps")
        val apps = (0 until (appsJson?.length() ?: 0)).map { appsJson!!.getString(it).trim() }
        val session = p.optString("session", "Tunnelka")

        val builder = Builder()
            .setSession(session)
            .setMtu(MTU)
            .addAddress(TUN_IPV4, 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(TUN_DNS)
            // IPv6 тоже заворачиваем в туннель, чтобы он не утекал мимо VPN.
            // Если IPv6 выключен в настройках, ядро его блокирует.
            .addAddress(TUN_IPV6, 128)
            .addRoute("::", 0)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        packageManager.getLaunchIntentForPackage(packageName)?.let {
            builder.setConfigureIntent(
                PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE)
            )
        }

        val selected = apps.filter { it.isNotEmpty() && it != packageName }
        if (appMode == "include" && selected.isNotEmpty()) {
            var added = 0
            for (a in selected) {
                try {
                    builder.addAllowedApplication(a); added++
                } catch (_: PackageManager.NameNotFoundException) {
                }
            }
            require(added > 0) { "ни одно из выбранных приложений не установлено" }
        } else {
            // Ядра работают в процессах этого приложения — исключаем его из VPN.
            builder.addDisallowedApplication(packageName)
            if (appMode == "exclude") {
                for (a in selected) {
                    try {
                        builder.addDisallowedApplication(a)
                    } catch (_: PackageManager.NameNotFoundException) {
                    }
                }
            }
        }

        val pfd = builder.establish() ?: error("нет разрешения на VPN — откройте Tunnelka")
        tun = pfd

        // Файл доступен только приложению. Библиотека читает его в своём потоке
        // уже после возврата из TProxyStartService, поэтому удаляется при отключении.
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
        if (!TProxyService.TProxyStartService(config.absolutePath, pfd.fd)) {
            error("не удалось запустить туннель")
        }
        hevRunning = true
        val deadline = System.currentTimeMillis() + 1500
        while (!TProxyService.TProxyIsRunning()) {
            if (System.currentTimeMillis() > deadline) error("туннель остановился сразу после запуска")
            Thread.sleep(30)
        }
    }

    private fun yaml(s: String) = s.replace("'", "''")

    /** Останавливает туннель и ядра, сервис остаётся. */
    private fun stopInternal() {
        watchdog?.interrupt()
        watchdog = null
        if (hevRunning) {
            try {
                TProxyService.TProxyStopService()
            } catch (e: Throwable) {
                Log.w(TAG, "hev stop", e)
            }
            hevRunning = false
        }
        File(cacheDir, "tunnel.yml").delete()
        try {
            tun?.close()
        } catch (_: Exception) {
        }
        tun = null
        for (p in procs) {
            try {
                p.destroy()
            } catch (_: Exception) {
            }
        }
        for (p in procs) {
            try {
                if (Build.VERSION.SDK_INT >= 26) {
                    if (!p.waitFor(1, java.util.concurrent.TimeUnit.SECONDS)) p.destroyForcibly()
                } else {
                    p.waitFor()
                }
            } catch (_: Exception) {
            }
        }
        procs.clear()
        startedAt = 0
    }

    private fun pause() {
        if (state != State.RUNNING) return
        stopInternal()
        state = State.PAUSED
        updateUi()
    }

    private fun stopAll(startId: Int) {
        stopInternal()
        state = State.STOPPED
        setWanted(this, false)
        updateUi()
        main.post {
            // Если за это время пришла команда запуска, сервис остаётся.
            if (latestStartId == startId) {
                stopForegroundCompat()
                stopSelf(startId)
            }
        }
    }

    /** Следит за ядрами: если одно упало, перезапускает подключение один раз. */
    private fun startWatchdog() {
        val t = Thread {
            try {
                var since = System.currentTimeMillis()
                while (!Thread.currentThread().isInterrupted) {
                    Thread.sleep(2000)
                    if (state != State.RUNNING) continue
                    val ok = procs.all { isAlive(it) } && TProxyService.TProxyIsRunning()
                    if (ok) {
                        if (System.currentTimeMillis() - since > 60_000) restarts = 0
                        continue
                    }
                    val log = profile?.optString("log")?.let { File(it) }
                    val reason = "ядро остановилось${log?.let { lastLine(it) } ?: ""}"
                    Log.w(TAG, reason)
                    if (restarts < 1) {
                        restarts++
                        since = System.currentTimeMillis()
                        worker.execute { start() }
                    } else {
                        worker.execute {
                            lastError = reason
                            stopInternal()
                            state = State.STOPPED
                            setWanted(this, false)
                            updateUi()
                            main.post {
                                stopForegroundCompat()
                                stopSelf()
                            }
                        }
                    }
                    return@Thread
                }
            } catch (_: InterruptedException) {
            }
        }
        t.isDaemon = true
        watchdog = t
        t.start()
    }

    /** Пользователь отключил VPN в системе или включил другой VPN. */
    override fun onRevoke() {
        worker.execute {
            lastError = "VPN отключён системой"
            stopInternal()
            state = State.STOPPED
            setWanted(this, false)
            updateUi()
            main.post {
                stopForegroundCompat()
                stopSelf()
            }
        }
    }

    override fun onDestroy() {
        worker.execute {
            stopInternal()
            if (state != State.STOPPED) state = State.STOPPED
            updateTile()
        }
        worker.shutdown()
        super.onDestroy()
    }

    // ------------------------------------------------------------------
    // Уведомление и плитка
    // ------------------------------------------------------------------

    private fun updateUi() {
        if (state != State.STOPPED) postNotification()
        updateTile()
    }

    private fun updateTile() {
        if (Build.VERSION.SDK_INT >= 24) {
            try {
                TileService.requestListeningState(
                    this, ComponentName(this, TunnelkaTileService::class.java)
                )
            } catch (_: Exception) {
            }
        }
    }

    private fun postNotification() {
        main.post {
            try {
                val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                nm.notify(NOTIFICATION_ID, buildNotification())
            } catch (e: Exception) {
                Log.w(TAG, "notify", e)
            }
        }
    }

    private fun channels(nm: NotificationManager) {
        if (Build.VERSION.SDK_INT < 26) return
        // Старый канал показывал счётчик на значке приложения.
        nm.deleteNotificationChannel(CHANNEL_OLD)
        val main = NotificationChannel(CHANNEL, "Состояние VPN", NotificationManager.IMPORTANCE_LOW).apply {
            setShowBadge(false)
            description = "Кнопки паузы и отключения VPN"
        }
        val quiet = NotificationChannel(CHANNEL_QUIET, "Состояние VPN (свёрнуто)", NotificationManager.IMPORTANCE_MIN).apply {
            setShowBadge(false)
            description = "Используется, когда уведомление выключено в настройках Tunnelka"
        }
        nm.createNotificationChannel(main)
        nm.createNotificationChannel(quiet)
    }

    private fun buildNotification(): Notification {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        channels(nm)
        val p = profile ?: readProfile().also { profile = it }
        val show = p?.optBoolean("notify", true) ?: true
        val server = p?.optString("server")?.takeIf { it.isNotBlank() }

        val title = when (state) {
            State.RUNNING -> "Подключено"
            State.PAUSED -> "Пауза"
            else -> "Подключение…"
        }
        val open = packageManager.getLaunchIntentForPackage(packageName)?.let {
            PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE)
        }
        val b = NotificationCompat.Builder(this, if (show) CHANNEL else CHANNEL_QUIET)
            .setSmallIcon(R.drawable.ic_tunnelka)
            .setContentTitle(title)
            .setContentText(server ?: "Tunnelka")
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setBadgeIconType(NotificationCompat.BADGE_ICON_NONE)
            .setNumber(0)
            .setPriority(if (show) NotificationCompat.PRIORITY_LOW else NotificationCompat.PRIORITY_MIN)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setContentIntent(open)
        if (Build.VERSION.SDK_INT >= 31) {
            b.setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
        }
        when (state) {
            State.RUNNING -> b.addAction(0, "Пауза", action(ACTION_PAUSE, 1))
            State.PAUSED -> b.addAction(0, "Продолжить", action(ACTION_RESUME, 2))
            else -> {}
        }
        b.addAction(0, "Отключить", action(ACTION_STOP, 3))
        return b.build()
    }

    private fun action(name: String, code: Int): PendingIntent {
        val i = intent(this, name)
        val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        return if (name == ACTION_RESUME && Build.VERSION.SDK_INT >= 26) {
            PendingIntent.getForegroundService(this, code, i, flags)
        } else {
            PendingIntent.getService(this, code, i, flags)
        }
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= 24) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }
}
