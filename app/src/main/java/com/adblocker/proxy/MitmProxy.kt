package com.adblocker.proxy

import android.content.Context
import android.net.VpnService
import android.util.Log
import com.adblocker.filter.engine.FilterEngine
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * MITM HTTP/HTTPS прокси на чистых java.net сокетах.
 *
 * Не использует Netty/LittleProxy — все upstream сокеты защищены
 * через VpnService.protect() до connect(), чтобы не зациклить трафик через tun.
 *
 * ИСПРАВЛЕНИЯ:
 *  - ca.init() вызывается ОДИН РАЗ в start(). AdBlockerVpnService больше не вызывает
 *    ca.init() самостоятельно — проблема двойной инициализации устранена.
 *  - Возвращает File CA PEM через getCaPemFile() после start().
 */
class MitmProxy(
    private val context: Context,
    private val port: Int,
    private val filterEngine: FilterEngine,
    private val vpnService: VpnService?
) {
    companion object {
        private const val TAG             = "MitmProxy"
        private const val THREAD_POOL_SIZE = 64
        private const val ACCEPT_TIMEOUT  = 1_000  // ms — для проверки running
    }

    private val running      = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private val threadPool   = Executors.newFixedThreadPool(THREAD_POOL_SIZE) { r ->
        Thread(r, "MitmProxy-worker").apply { isDaemon = true }
    }

    val ca     = CertificateAuthority(context)
    val filter = AdFilter(filterEngine)

    /**
     * Инициализирует CA и запускает accept-loop.
     * Блокирует вызывающий поток — вызывать в отдельном потоке.
     */
    fun start() {
        // Инициализируем CA ОДИН РАЗ здесь
        ca.init()

        val ss = ServerSocket()
        ss.bind(java.net.InetSocketAddress("127.0.0.1", port))
        ss.soTimeout = ACCEPT_TIMEOUT
        serverSocket = ss

        running.set(true)
        Log.i(TAG, "MitmProxy listening on 127.0.0.1:$port")

        acceptLoop(ss)
    }

    fun stop() {
        running.set(false)
        try { serverSocket?.close() } catch (_: Exception) {}
        threadPool.shutdown()
        try { threadPool.awaitTermination(3, TimeUnit.SECONDS) } catch (_: Exception) {}
        threadPool.shutdownNow()
        Log.i(TAG, "MitmProxy stopped")
    }

    fun isReady(): Boolean = running.get() && serverSocket != null

    fun getCaPemFile(): java.io.File = ca.getCaPemFile()

    private fun acceptLoop(ss: ServerSocket) {
        while (running.get()) {
            val client: Socket = try {
                ss.accept()
            } catch (e: java.net.SocketTimeoutException) {
                continue
            } catch (e: Exception) {
                if (running.get()) Log.e(TAG, "Accept error: ${e.message}")
                break
            }

            threadPool.submit {
                try {
                    MitmConnection(client, ca, filter, vpnService).handle()
                } catch (e: Exception) {
                    Log.d(TAG, "Connection handler error: ${e.message}")
                    try { client.close() } catch (_: Exception) {}
                }
            }
        }
    }
}
