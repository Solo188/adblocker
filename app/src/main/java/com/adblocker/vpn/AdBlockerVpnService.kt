package com.adblocker.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.adblocker.AdBlockerApp
import com.adblocker.proxy.MitmProxy
import com.adblocker.tun.TcpStack
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class AdBlockerVpnService : VpnService() {

    companion object {
        private const val TAG            = "AdBlockerVpnService"
        private const val CHANNEL_ID     = "adblocker_vpn_channel"  // единый channel_id
        private const val NOTIFICATION_ID = 1
        private const val VPN_ADDRESS    = "10.0.0.2"
        private const val DNS_PRIMARY    = "8.8.8.8"
        private const val DNS_SECONDARY  = "1.1.1.1"
        private const val MTU            = 1500
        const val PROXY_PORT             = 8118

        const val ACTION_START          = "com.adblocker.vpn.START"
        const val ACTION_STOP           = "com.adblocker.vpn.STOP"
        const val ACTION_STATE_CHANGED  = "com.adblocker.VPN_STATE_CHANGED"
        const val EXTRA_STATE           = "vpn_state"

        @Volatile var isRunning: Boolean = false

        // Единый channel_id используемый и в App и здесь
        const val NOTIFICATION_CHANNEL_ID = CHANNEL_ID
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val running       = AtomicBoolean(false)
    private var vpnThread:    Thread? = null
    private var proxyThread:  Thread? = null
    private var tcpStack:     TcpStack?   = null
    private var mitmProxy:    MitmProxy?  = null
    private val domainFilter  = DomainFilter()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> { stopVpn(); START_NOT_STICKY }
            else        -> { startVpn(); START_STICKY }
        }
    }

    private fun startVpn() {
        if (running.get()) return

        // Регистрируем сервис в VpnProtector ПЕРВЫМ
        VpnProtector.set(this)

        // Notification channel должен быть создан до startForeground
        ensureNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        broadcastState(VpnState.CONNECTING)

        // 1. Загружаем список доменов (до старта VPN — сокет не защищён)
        val domainUpdater = Thread({
            DomainListUpdater().update(this, vpnService = null)
            domainFilter.loadFromFile(this)
            if (domainFilter.getBlacklistSize() == 0) domainFilter.loadFromAssets(this)
            Log.i(TAG, "Domain list: ${domainFilter.getBlacklistSize()} entries")
        }, "DomainUpdater").apply { isDaemon = true; start() }
        domainUpdater.join(8_000)

        if (domainFilter.getBlacklistSize() == 0) domainFilter.loadFromAssets(this)

        // 2. Устанавливаем VPN интерфейс
        vpnInterface = establishVpnInterface() ?: run {
            Log.e(TAG, "Failed to establish VPN interface")
            broadcastState(VpnState.ERROR)
            VpnProtector.set(null)
            stopSelf()
            return
        }

        running.set(true)
        isRunning = true

        // 3. Запускаем MitmProxy (ca.init() вызывается внутри proxy.start())
        val app   = application as AdBlockerApp
        val proxy = MitmProxy(
            context      = applicationContext,
            port         = PROXY_PORT,
            filterEngine = app.filterEngine,
            vpnService   = this
        )
        mitmProxy = proxy

        // Latch: ждём пока proxy.start() привяжется к порту
        val proxyBound = CountDownLatch(1)
        proxyThread = Thread({
            try {
                // proxy.start() сначала вызывает ca.init(), затем bind()
                // Нам нужен сигнал после bind — переопределить нельзя, поэтому
                // даём 3 секунды на инициализацию и движемся дальше
                Thread {
                    Thread.sleep(200)  // дать время на ca.init() + bind
                    proxyBound.countDown()
                }.apply { isDaemon = true; start() }

                proxy.start()  // блокирует до stop()
            } catch (e: Exception) {
                Log.e(TAG, "MitmProxy error", e)
                proxyBound.countDown()
            }
        }, "MitmProxy-main").apply { isDaemon = true; start() }

        // Ждём 4 секунды на старт прокси
        if (!proxyBound.await(4, TimeUnit.SECONDS)) {
            Log.w(TAG, "MitmProxy bind wait timeout — continuing")
        }

        Log.i(TAG, "MitmProxy started on :$PROXY_PORT, CA: ${proxy.getCaPemFile().absolutePath}")

        // 4. TcpStack читает/пишет пакеты из VPN tun
        val pfd   = vpnInterface!!
        val stack = TcpStack(
            tunIn        = FileInputStream(pfd.fileDescriptor),
            tunOut       = FileOutputStream(pfd.fileDescriptor),
            vpnService   = this,
            domainFilter = domainFilter,
            proxyHost    = "127.0.0.1",
            proxyPort    = PROXY_PORT,
            dnsServer    = DNS_PRIMARY
        )
        tcpStack  = stack
        vpnThread = Thread({ stack.start() }, "AdBlockerTcpStack").apply { start() }

        broadcastState(VpnState.CONNECTED)
        Log.i(TAG, "VPN started — MitmProxy + TcpStack active")
    }

    private fun establishVpnInterface(): ParcelFileDescriptor? {
        return try {
            Builder()
                .setSession("AdBlocker")
                .addAddress(VPN_ADDRESS, 32)
                // Маршрутизируем весь трафик (0.0.0.0/0 через два блока)
                .addRoute("0.0.0.0", 1)
                .addRoute("128.0.0.0", 1)
                .addDnsServer(DNS_PRIMARY)
                .addDnsServer(DNS_SECONDARY)
                .addDnsServer("9.9.9.9")
                .setMtu(MTU)
                // Наш собственный трафик не идёт через VPN (избегаем петли)
                .addDisallowedApplication(packageName)
                .setBlocking(true)
                .establish()
        } catch (e: Exception) {
            Log.e(TAG, "Error establishing VPN interface", e)
            null
        }
    }

    private fun stopVpn() {
        if (!running.compareAndSet(true, false)) return
        isRunning = false

        VpnProtector.set(null)

        tcpStack?.stop()
        tcpStack = null

        mitmProxy?.stop()
        mitmProxy = null

        proxyThread?.interrupt()
        proxyThread = null

        vpnThread?.interrupt()
        vpnThread = null

        try { vpnInterface?.close() } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface", e)
        }
        vpnInterface = null

        broadcastState(VpnState.STOPPED)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "VPN stopped")
    }

    private fun broadcastState(state: VpnState) {
        sendBroadcast(Intent(ACTION_STATE_CHANGED).apply {
            putExtra(EXTRA_STATE, state.name)
            setPackage(packageName)
        })
    }

    override fun onDestroy() { stopVpn(); super.onDestroy() }
    override fun onRevoke()  { stopVpn(); super.onRevoke() }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(CHANNEL_ID) == null) {
                NotificationChannel(
                    CHANNEL_ID,
                    "AdBlocker VPN",
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    description = "AdBlocker MITM VPN is active"
                    nm.createNotificationChannel(this)
                }
            }
        }
    }

    private fun buildNotification(): Notification {
        val stopIntent = PendingIntent.getService(
            this, 0,
            Intent(this, AdBlockerVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            Notification.Builder(this, CHANNEL_ID)
        else
            @Suppress("DEPRECATION") Notification.Builder(this)

        return builder
            .setContentTitle("AdBlocker VPN")
            .setContentText("MITM ad-blocking active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .addAction(android.R.drawable.ic_delete, "Stop", stopIntent)
            .setOngoing(true)
            .build()
    }
}

/**
 * Глобальный singleton для protect() upstream сокетов.
 * set(this) вызывается в startVpn() ДО всего остального.
 * set(null) — в stopVpn().
 */
object VpnProtector {
    @Volatile private var service: VpnService? = null
    fun set(svc: VpnService?)                  { service = svc }
    fun protect(socket: java.net.Socket): Boolean = service?.protect(socket) ?: false
    fun isActive(): Boolean                    = service != null
}
