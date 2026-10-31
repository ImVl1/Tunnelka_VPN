package app.tunnelka.vpn

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import androidx.activity.result.ActivityResult
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSArray
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@InvokeArg
class StartArgs {
    /** Профиль подключения (JSON), который подготовило приложение. */
    var profile: String = ""
    /** Показывать уведомление — тогда спрашиваем разрешение на уведомления. */
    var notify: Boolean = true
}

@TauriPlugin
class VpnPlugin(private val activity: Activity) : Plugin(activity) {

    private var pending: StartArgs? = null
    private val main = Handler(Looper.getMainLooper())

    @Command
    fun info(invoke: Invoke) {
        val r = JSObject()
        r.put("nativeLibDir", activity.applicationInfo.nativeLibraryDir)
        r.put("filesDir", activity.filesDir.absolutePath)
        r.put("sdk", Build.VERSION.SDK_INT)
        invoke.resolve(r)
    }

    @Command
    fun start(invoke: Invoke) {
        val args = invoke.parseArgs(StartArgs::class.java)
        if (args.notify) askNotifications()
        val prepare = VpnService.prepare(activity)
        if (prepare != null) {
            // Система спросит у пользователя разрешение на VPN.
            pending = args
            startActivityForResult(invoke, prepare, "onVpnPermission")
        } else {
            launch(invoke, args)
        }
    }

    @ActivityCallback
    private fun onVpnPermission(invoke: Invoke, result: ActivityResult) {
        val args = pending
        pending = null
        if (result.resultCode == Activity.RESULT_OK && args != null) {
            launch(invoke, args)
        } else {
            invoke.reject("Разрешение на VPN не выдано")
        }
    }

    private fun launch(invoke: Invoke, args: StartArgs) {
        TunnelkaVpnService.setProfilePath(activity, args.profile)
        TunnelkaVpnService.markStarting()
        try {
            ContextCompat.startForegroundService(
                activity, TunnelkaVpnService.intent(activity, TunnelkaVpnService.ACTION_START)
            )
        } catch (e: Exception) {
            invoke.reject(e.message ?: e.toString())
            return
        }
        // Ждём, пока сервис запустит ядра и поднимет туннель или сообщит об ошибке.
        val started = System.currentTimeMillis()
        val check = object : Runnable {
            override fun run() {
                val st = TunnelkaVpnService.state
                when {
                    TunnelkaVpnService.alive() -> invoke.resolve(JSObject())
                    st == TunnelkaVpnService.State.STOPPED ->
                        invoke.reject(TunnelkaVpnService.lastError ?: "VPN-сервис остановился")
                    System.currentTimeMillis() - started > 20_000 ->
                        invoke.reject("VPN-сервис не запустился за 20 секунд")
                    else -> main.postDelayed(this, 50)
                }
            }
        }
        main.postDelayed(check, 50)
    }

    @Command
    fun stop(invoke: Invoke) {
        if (TunnelkaVpnService.state != TunnelkaVpnService.State.STOPPED) {
            activity.startService(TunnelkaVpnService.intent(activity, TunnelkaVpnService.ACTION_STOP))
        }
        invoke.resolve(JSObject())
    }

    /** Перечитать профиль (например, название сервера или показ уведомления). */
    @Command
    fun refresh(invoke: Invoke) {
        if (TunnelkaVpnService.state != TunnelkaVpnService.State.STOPPED) {
            activity.startService(TunnelkaVpnService.intent(activity, TunnelkaVpnService.ACTION_REFRESH))
        }
        invoke.resolve(JSObject())
    }

    @Command
    fun state(invoke: Invoke) {
        val r = JSObject()
        r.put("state", TunnelkaVpnService.state.name.lowercase())
        r.put("running", TunnelkaVpnService.alive())
        r.put("startedAt", TunnelkaVpnService.startedAt)
        TunnelkaVpnService.profilePath(activity)?.let { r.put("profile", it) }
        TunnelkaVpnService.lastError?.let { r.put("error", it) }
        invoke.resolve(r)
    }

    /** Работает ли приложение без ограничений экономии батареи. */
    @Command
    fun battery(invoke: Invoke) {
        val r = JSObject()
        val pm = activity.getSystemService(android.content.Context.POWER_SERVICE) as android.os.PowerManager
        r.put("unrestricted", Build.VERSION.SDK_INT < 23 || pm.isIgnoringBatteryOptimizations(activity.packageName))
        invoke.resolve(r)
    }

    @Command
    fun openBatterySettings(invoke: Invoke) {
        val direct = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
            .setData(android.net.Uri.parse("package:" + activity.packageName))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            activity.startActivity(direct)
        } catch (_: Exception) {
            activity.startActivity(
                Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        }
        invoke.resolve(JSObject())
    }

    @Command
    fun openNotificationSettings(invoke: Invoke) {
        val intent = if (Build.VERSION.SDK_INT >= 26) {
            Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                .putExtra(Settings.EXTRA_APP_PACKAGE, activity.packageName)
        } else {
            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                .setData(android.net.Uri.parse("package:" + activity.packageName))
        }
        activity.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        invoke.resolve(JSObject())
    }

    @Command
    fun apps(invoke: Invoke) {
        Thread {
            val pm = activity.packageManager
            val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            val list = pm.queryIntentActivities(launcher, 0)
                .map { it.activityInfo.packageName to it.loadLabel(pm).toString() }
                .filter { it.first != activity.packageName }
                .distinctBy { it.first }
                .sortedBy { it.second.lowercase() }
            val arr = JSArray()
            for ((pkg, label) in list) {
                val o = JSObject()
                o.put("package", pkg)
                o.put("label", label)
                arr.put(o)
            }
            val r = JSObject()
            r.put("apps", arr)
            invoke.resolve(r)
        }.start()
    }

    @Command
    fun openVpnSettings(invoke: Invoke) {
        val intent = Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        activity.startActivity(intent)
        invoke.resolve(JSObject())
    }

    private var askedNotifications = false

    private fun askNotifications() {
        if (askedNotifications) return
        askedNotifications = true
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(activity, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            ActivityCompat.requestPermissions(
                activity, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1001
            )
        }
    }
}
