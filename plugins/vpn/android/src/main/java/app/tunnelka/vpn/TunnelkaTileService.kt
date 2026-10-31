package app.tunnelka.vpn

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat

/**
 * Плитка «Tunnelka» в шторке быстрых настроек: включает и выключает VPN
 * без открытия приложения. Добавляется через «Изменить» в шторке.
 */
class TunnelkaTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        render()
    }

    override fun onClick() {
        super.onClick()
        when (TunnelkaVpnService.state) {
            TunnelkaVpnService.State.STOPPED -> turnOn()
            else -> startService(TunnelkaVpnService.intent(this, TunnelkaVpnService.ACTION_STOP))
        }
        render()
    }

    private fun turnOn() {
        // Без разрешения на VPN или без сохранённого подключения нужен интерфейс.
        if (VpnService.prepare(this) != null || TunnelkaVpnService.profilePath(this) == null) {
            openApp()
            return
        }
        try {
            TunnelkaVpnService.markStarting()
            ContextCompat.startForegroundService(
                this, TunnelkaVpnService.intent(this, TunnelkaVpnService.ACTION_START)
            )
        } catch (_: Exception) {
            openApp()
        }
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun openApp() {
        val launch = packageManager.getLaunchIntentForPackage(packageName) ?: return
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(
                PendingIntent.getActivity(this, 0, launch, PendingIntent.FLAG_IMMUTABLE)
            )
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(launch)
        }
    }

    private fun render() {
        val tile = qsTile ?: return
        val st = TunnelkaVpnService.state
        tile.state = if (st == TunnelkaVpnService.State.STOPPED) Tile.STATE_INACTIVE else Tile.STATE_ACTIVE
        tile.label = "Tunnelka"
        if (Build.VERSION.SDK_INT >= 29) {
            tile.subtitle = when (st) {
                TunnelkaVpnService.State.RUNNING -> "Подключено"
                TunnelkaVpnService.State.STARTING -> "Подключение…"
                TunnelkaVpnService.State.PAUSED -> "Пауза"
                TunnelkaVpnService.State.STOPPED -> "Выключено"
            }
        }
        tile.updateTile()
    }
}
