package com.adblocker.tun

import android.net.VpnService
import android.util.Log
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ExecutorService

/**
 * TcpTunnel — соединяет TcpControlBlock с MitmProxy через CONNECT.
 *
 * Соединение клиент→прокси: java.net.Socket с vpnService.protect() до connect().
 * Loopback 127.0.0.1 не маршрутизируется через VPN (нет маршрута 127/8),
 * поэтому protect() здесь технически не нужен, но оставляем для надёжности.
 *
 * MitmProxy сам открывает upstream к реальному серверу через protect().
 */
class TcpTunnel(
    private val tcb: TcpControlBlock,
    private val proxyHost: String,
    private val proxyPort: Int,
    private val vpnService: VpnService?,
    private val originalDstHost: String,
    private val originalDstPort: Int,
    private val executor: ExecutorService
) {
    companion object {
        private const val TAG = "TcpTunnel"
        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val READ_BUFFER_SIZE   = 32_768
    }

    @Volatile private var socket: Socket? = null
    @Volatile private var started = false

    fun connect() {
        if (started) return
        started = true
        executor.submit {
            try {
                openUpstream()
            } catch (e: Exception) {
                Log.w(TAG, "Connect failed $originalDstHost:$originalDstPort: ${e.message}")
                tcb.close()
            }
        }
    }

    private fun openUpstream() {
        // Соединяемся к MitmProxy (loopback, не идёт через VPN tun)
        val sock = Socket()
        vpnService?.protect(sock)
        sock.connect(InetSocketAddress(proxyHost, proxyPort), CONNECT_TIMEOUT_MS)
        sock.soTimeout = 0
        sock.tcpNoDelay = true
        socket = sock

        // Шлём HTTP CONNECT — MitmProxy откроет upstream к реальному серверу
        val connectReq = "CONNECT $originalDstHost:$originalDstPort HTTP/1.1\r\n" +
                         "Host: $originalDstHost:$originalDstPort\r\n\r\n"
        sock.outputStream.write(connectReq.toByteArray(Charsets.US_ASCII))
        sock.outputStream.flush()

        // Читаем ответ прокси (должен быть "HTTP/1.1 200 Connection Established")
        val statusLine = readStatusLine(sock)
        if (!statusLine.startsWith("HTTP/1.1 200") && !statusLine.startsWith("HTTP/1.0 200")) {
            Log.w(TAG, "Proxy CONNECT rejected: [$statusLine] for $originalDstHost:$originalDstPort")
            sock.close()
            tcb.sendFin()
            return
        }

        // Устанавливаем upstream writer — теперь данные от клиента идут в прокси
        tcb.upstreamWriter = sock.outputStream
        Log.d(TAG, "Tunnel open: ${tcb.tuple.srcPort} -> $originalDstHost:$originalDstPort")

        // Читаем данные от прокси и отправляем клиенту
        readUpstream(sock)
    }

    /**
     * Читает HTTP ответ побайтово до \r\n\r\n, возвращает первую строку.
     */
    private fun readStatusLine(sock: Socket): String {
        val input = sock.inputStream
        val sb    = StringBuilder(256)
        var b0 = -1; var b1 = -1; var b2 = -1
        while (true) {
            val b = input.read()
            if (b == -1) break
            sb.append(b.toChar())
            if (b0 == '\r'.code && b1 == '\n'.code && b2 == '\r'.code && b == '\n'.code) break
            b0 = b1; b1 = b2; b2 = b
        }
        return sb.lines().firstOrNull() ?: ""
    }

    private fun readUpstream(sock: Socket) {
        val buf    = ByteArray(READ_BUFFER_SIZE)
        val stream = sock.inputStream
        try {
            while (!tcb.closed) {
                val n = stream.read(buf)
                if (n == -1) {
                    if (!tcb.closed) tcb.sendFin()
                    break
                }
                if (n > 0) tcb.sendToClient(buf.copyOf(n))
            }
        } catch (e: Exception) {
            if (!tcb.closed) {
                Log.d(TAG, "Read error ($originalDstHost:$originalDstPort): ${e.message}")
                tcb.sendFin()
            }
        } finally {
            tcb.close()
            try { sock.close() } catch (_: Exception) {}
        }
    }

    fun close() {
        try { socket?.close() } catch (_: Exception) {}
    }
}
