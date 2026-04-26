package com.adblocker

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import com.adblocker.filter.engine.FilterEngine
import com.adblocker.utils.Logger
import com.adblocker.vpn.AdBlockerVpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class AdBlockerApp : Application() {

    companion object {
        lateinit var instance: AdBlockerApp
            private set
    }

    val appScope     = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val filterEngine: FilterEngine by lazy { FilterEngine(this) }

    override fun onCreate() {
        super.onCreate()
        instance = this

        // Регистрируем полноценный BouncyCastle.
        // Android имеет урезанный встроенный BC без SHA256WithRSA —
        // убираем его и вставляем полный на позицию 1.
        Security.removeProvider("BC")
        Security.insertProviderAt(BouncyCastleProvider(), 1)

        // Создаём notification channel (единый CHANNEL_ID совпадает с VpnService)
        createNotificationChannel()

        // Предзагружаем фильтрующий движок в фоне
        appScope.launch {
            Logger.i("App", "Loading filter engine…")
            filterEngine.initialize()
            Logger.i("App", "Filter engine ready: ${filterEngine.ruleCount} rules")
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            // Используем тот же channel_id что и сам сервис — дублей нет
            if (nm.getNotificationChannel(AdBlockerVpnService.NOTIFICATION_CHANNEL_ID) == null) {
                NotificationChannel(
                    AdBlockerVpnService.NOTIFICATION_CHANNEL_ID,
                    "AdBlocker VPN",
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    description = "Active while AdBlocker VPN is running"
                    nm.createNotificationChannel(this)
                }
            }
        }
    }
}
