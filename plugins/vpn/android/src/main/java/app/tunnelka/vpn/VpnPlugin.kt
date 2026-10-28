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
    var socksPort: Int = 0
    var socksUser: String = ""
    var socksPass: String = ""
    var appMode: String = "off"
    var apps: List<String> = emptyList()
    var ipv6: Boolean = false
    var session: String = "Tunnelka"
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
        askNotifications()
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
        val intent = Intent(activity, TunnelkaVpnService::class.java).apply {
            action = TunnelkaVpnService.ACTION_START
            putExtra("socksPort", args.socksPort)
            putExtra("socksUser", args.socksUser)
            putExtra("socksPass", args.socksPass)
            putExtra("appMode", args.appMode)
            putStringArrayListExtra("apps", ArrayList(args.apps))
            putExtra("ipv6", args.ipv6)
            putExtra("session", args.session)
        }
        ContextCompat.startForegroundService(activity, intent)
        // Ждём, пока сервис поднимет туннель или сообщит об ошибке.
        val started = System.currentTimeMillis()
        val check = object : Runnable {
            override fun run() {
                when {
                    TunnelkaVpnService.running -> invoke.resolve(JSObject())
                    TunnelkaVpnService.lastError != null ->
                        invoke.reject(TunnelkaVpnService.lastError)
                    System.currentTimeMillis() - started > 8000 ->
                        invoke.reject("VPN-сервис не запустился")
                    else -> main.postDelayed(this, 100)
                }
            }
        }
        main.postDelayed(check, 100)
    }

    @Command
    fun stop(invoke: Invoke) {
        val intent = Intent(activity, TunnelkaVpnService::class.java).apply {
            action = TunnelkaVpnService.ACTION_STOP
        }
        if (TunnelkaVpnService.running) {
            activity.startService(intent)
        }
        invoke.resolve(JSObject())
    }

    @Command
    fun state(invoke: Invoke) {
        val r = JSObject()
        r.put("running", TunnelkaVpnService.running)
        TunnelkaVpnService.lastError?.let { r.put("error", it) }
        invoke.resolve(r)
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
