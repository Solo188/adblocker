package com.adblocker.proxy

import android.net.VpnService
import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocket

/**
 * Обрабатывает одно клиентское соединение к MITM прокси.
 *
 * Протокол:
 *   HTTP  (порт 80) → читаем запрос напрямую, форвардим без TLS
 *   HTTPS (порт 443+) → клиент шлёт CONNECT, мы отвечаем 200,
 *       делаем TLS-handshake с клиентом (наш поддельный сертификат),
 *       открываем TLS к реальному серверу с ALPN h2/http1.1,
 *       если h2 — binary pipe, если http/1.1 — фильтруем запросы
 *
 * ИСПРАВЛЕНИЯ:
 *   1. Double-close: clientSslSock создаётся с autoClose=false — SSLSocket
 *      не закрывает underlying clientSocket при своём закрытии. Сам clientSocket
 *      закрывается в finally блоке handle() ровно один раз.
 *   2. keep-alive guard: перед каждым readRequest проверяем isConnected/isClosed.
 *   3. Весь upstream закрывается в finally — нет утечек сокетов.
 */
class MitmConnection(
    private val clientSocket: Socket,
    private val ca: CertificateAuthority,
    private val filter: AdFilter,
    private val vpnService: VpnService?
) {
    companion object {
        private const val TAG             = "MitmConn"
        private const val UPSTREAM_TIMEOUT = 15_000
        private const val MAX_BODY         = 10 * 1024 * 1024  // 10 MB
        private const val PIPE_BUF         = 32_768
        private const val KEEPALIVE_TIMEOUT = 5_000  // ms — ждём следующего запроса
    }

    fun handle() {
        try {
            clientSocket.soTimeout = 30_000
            val clientIn  = clientSocket.inputStream
            val clientOut = clientSocket.outputStream

            val req = HttpParser.readRequest(clientIn) ?: return

            if (req.isConnect()) {
                handleConnect(req.uri, clientIn, clientOut)
            } else {
                handleHttp(req, clientIn, clientOut)
            }
        } catch (e: Exception) {
            Log.d(TAG, "Connection error: ${e.message}")
        } finally {
            // Один закрытие clientSocket — SSLSocket создаётся с autoClose=false
            try { clientSocket.close() } catch (_: Exception) {}
        }
    }

    // ── HTTPS via CONNECT ─────────────────────────────────────────────────────

    private fun handleConnect(
        hostPort: String,
        clientIn: InputStream,
        clientOut: OutputStream
    ) {
        val host = hostPort.substringBefore(':')
        val port = hostPort.substringAfter(':').toIntOrNull() ?: 443

        // Отвечаем 200 Connection Established
        clientOut.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
        clientOut.flush()

        if (port == 80) {
            // Нестандартный CONNECT к HTTP — просто пробрасываем TCP
            handlePlainHttpTunnel(host, port, clientIn, clientOut)
            return
        }

        // TLS handshake с клиентом (autoClose=false — не закрывает clientSocket)
        val serverCtx     = ca.getServerSslContext(host)
        val clientSslSock = serverCtx.socketFactory
            .createSocket(clientSocket, clientIn, false) as SSLSocket
        clientSslSock.useClientMode = false
        clientSslSock.enabledProtocols = clientSslSock.supportedProtocols
            .filter { it.startsWith("TLS") }.toTypedArray()

        try {
            clientSslSock.startHandshake()
        } catch (e: Exception) {
            Log.d(TAG, "TLS handshake with client failed ($host): ${e.message}")
            return
        }

        val sslIn  = clientSslSock.inputStream
        val sslOut = clientSslSock.outputStream

        // Открываем upstream TLS с ALPN
        val (upstreamSock, negotiatedProto) = openUpstreamTls(host, port)
            ?: run {
                try {
                    HttpParser.writeSimpleResponse(sslOut, 502, "Bad Gateway",
                        "Cannot connect to $host")
                } catch (_: Exception) {}
                return
            }

        try {
            if (negotiatedProto == "h2") {
                // HTTP/2: бинарный протокол — только pipe байтов
                pipeBidirectional(sslIn, sslOut,
                    upstreamSock.inputStream, upstreamSock.outputStream)
            } else {
                // HTTP/1.1 с фильтрацией
                processHttpLoop(host, "https", sslIn, sslOut, upstreamSock)
            }
        } finally {
            try { upstreamSock.close() } catch (_: Exception) {}
            try { clientSslSock.close() } catch (_: Exception) {}
        }
    }

    /**
     * Bidirectional pipe для HTTP/2 (бинарный frame-протокол).
     * Запускаем daemon-поток client→server, сами читаем server→client.
     */
    private fun pipeBidirectional(
        clientIn: InputStream, clientOut: OutputStream,
        serverIn: InputStream, serverOut: OutputStream
    ) {
        val buf = ByteArray(PIPE_BUF)
        val c2s = Thread({
            try {
                val b = ByteArray(PIPE_BUF)
                while (true) {
                    val n = clientIn.read(b)
                    if (n == -1) break
                    serverOut.write(b, 0, n)
                    serverOut.flush()
                }
            } catch (_: Exception) {}
        }, "H2-c2s").apply { isDaemon = true; start() }

        try {
            while (true) {
                val n = serverIn.read(buf)
                if (n == -1) break
                clientOut.write(buf, 0, n)
                clientOut.flush()
            }
        } catch (_: Exception) {}
        c2s.interrupt()
    }

    private fun handlePlainHttpTunnel(
        host: String, port: Int,
        clientIn: InputStream, clientOut: OutputStream
    ) {
        val upSock = try {
            val s = Socket()
            vpnService?.protect(s)
            s.connect(InetSocketAddress(host, port), UPSTREAM_TIMEOUT)
            s.soTimeout = UPSTREAM_TIMEOUT
            s
        } catch (e: Exception) {
            Log.d(TAG, "Plain HTTP tunnel connect failed ($host:$port): ${e.message}")
            return
        }
        try {
            pipeBidirectional(clientIn, clientOut, upSock.inputStream, upSock.outputStream)
        } finally {
            try { upSock.close() } catch (_: Exception) {}
        }
    }

    private fun openUpstreamTls(host: String, port: Int): Pair<SSLSocket, String>? {
        return try {
            val sock = Socket()
            vpnService?.protect(sock)   // КРИТИЧНО: protect ДО connect
            sock.connect(InetSocketAddress(host, port), UPSTREAM_TIMEOUT)
            sock.soTimeout = UPSTREAM_TIMEOUT

            val ctx     = ca.getUpstreamSslContext()
            val sslSock = ctx.socketFactory.createSocket(sock, host, port, true) as SSLSocket
            sslSock.useClientMode = true

            // ALPN: h2 и http/1.1 — API 29+ (Android 10+, у нас minSdk=30)
            try {
                val params = sslSock.sslParameters
                params.applicationProtocols = arrayOf("h2", "http/1.1")
                sslSock.sslParameters = params
            } catch (_: Exception) {}

            sslSock.startHandshake()

            val proto = try {
                sslSock.applicationProtocol?.takeIf { it.isNotEmpty() } ?: "http/1.1"
            } catch (_: Exception) { "http/1.1" }

            sslSock to proto
        } catch (e: Exception) {
            Log.d(TAG, "Upstream TLS failed ($host:$port): ${e.message}")
            null
        }
    }

    // ── Plain HTTP (port 80) ──────────────────────────────────────────────────

    private fun handleHttp(
        firstReq: HttpParser.HttpRequest,
        clientIn: InputStream,
        clientOut: OutputStream
    ) {
        val host = firstReq.host().substringBefore(':').ifBlank {
            // Fallback: хост из абсолютного URI
            try { java.net.URL(firstReq.uri).host } catch (_: Exception) { return }
        }
        val port = firstReq.host().substringAfter(':', "80").toIntOrNull() ?: 80

        val upstreamSock = try {
            val s = Socket()
            vpnService?.protect(s)
            s.connect(InetSocketAddress(host, port), UPSTREAM_TIMEOUT)
            s.soTimeout = UPSTREAM_TIMEOUT
            s
        } catch (e: Exception) {
            Log.d(TAG, "Upstream HTTP connect failed ($host:$port): ${e.message}")
            try { HttpParser.writeSimpleResponse(clientOut, 502, "Bad Gateway") } catch (_: Exception) {}
            return
        }

        try {
            var keepGoing = processOneRequest(
                "http", firstReq, host, clientOut,
                upstreamSock.inputStream, upstreamSock.outputStream
            )
            while (keepGoing) {
                // keep-alive: ждём следующий запрос с коротким таймаутом
                clientSocket.soTimeout = KEEPALIVE_TIMEOUT
                val req = try {
                    HttpParser.readRequest(clientIn)
                } catch (_: java.net.SocketTimeoutException) { null }
                    ?: break
                clientSocket.soTimeout = 30_000
                keepGoing = processOneRequest(
                    "http", req, host, clientOut,
                    upstreamSock.inputStream, upstreamSock.outputStream
                )
            }
        } finally {
            try { upstreamSock.close() } catch (_: Exception) {}
        }
    }

    // ── HTTP/1.1 loop (after HTTPS CONNECT) ──────────────────────────────────

    private fun processHttpLoop(
        host: String,
        scheme: String,
        clientIn: InputStream,
        clientOut: OutputStream,
        upstream: SSLSocket
    ) {
        val upIn  = upstream.inputStream
        val upOut = upstream.outputStream

        while (true) {
            // Guard: проверяем что upstream ещё жив
            if (upstream.isClosed) break

            clientSocket.soTimeout = KEEPALIVE_TIMEOUT
            val req = try {
                HttpParser.readRequest(clientIn)
            } catch (_: java.net.SocketTimeoutException) { null }
                ?: break
            clientSocket.soTimeout = 30_000

            val keepGoing = processOneRequest(scheme, req, host, clientOut, upIn, upOut)
            if (!keepGoing) break
        }
    }

    // ── Core request/response ─────────────────────────────────────────────────

    private fun processOneRequest(
        scheme: String,
        req: HttpParser.HttpRequest,
        host: String,
        clientOut: OutputStream,
        upIn: InputStream,
        upOut: OutputStream
    ): Boolean {
        val url     = buildUrl(scheme, host, req.uri)
        val info    = AdFilter.RequestInfo(
            host        = host,
            url         = url,
            method      = req.method,
            referer     = req.header("referer"),
            accept      = req.header("accept"),
            contentType = req.header("content-type")
        )

        if (filter.shouldBlock(info)) {
            filter.logRequest(host, url, true, 204)
            try {
                HttpParser.writeSimpleResponse(clientOut, 204, "No Content")
            } catch (_: Exception) {}
            return true
        }

        val upstreamReq = prepareUpstreamRequest(req, host)

        try {
            HttpParser.writeRequest(upOut, upstreamReq)
        } catch (e: Exception) {
            Log.d(TAG, "Upstream write failed: ${e.message}")
            try { HttpParser.writeSimpleResponse(clientOut, 502, "Bad Gateway") } catch (_: Exception) {}
            return false
        }

        val resp = try {
            HttpParser.readResponse(upIn)
        } catch (e: Exception) {
            Log.d(TAG, "Upstream read failed: ${e.message}")
            try { HttpParser.writeSimpleResponse(clientOut, 502, "Bad Gateway") } catch (_: Exception) {}
            return false
        } ?: run {
            try { HttpParser.writeSimpleResponse(clientOut, 502, "Bad Gateway") } catch (_: Exception) {}
            return false
        }

        // Inject CSS/JS и обработка YouTube JSON
        val contentType = resp.contentType()
        if (resp.body.isNotEmpty() && resp.body.size < MAX_BODY) {
            filter.patchCsp(resp.headers)
            val processed = filter.processResponseBody(
                body         = resp.body,
                contentType  = contentType,
                host         = host,
                url          = url,
                isYouTubeApi = info.isYouTubeApi
            )
            if (processed != null) resp.body = processed
        }

        // Transfer-Encoding: chunked несовместим с нашим writeResponse (добавляет Content-Length)
        resp.headers.remove("transfer-encoding")

        filter.logRequest(host, url, false, resp.statusCode)

        return try {
            HttpParser.writeResponse(clientOut, resp)
            val conn = resp.header("connection") ?: ""
            !conn.contains("close", ignoreCase = true) && resp.statusCode != 101
        } catch (e: Exception) {
            Log.d(TAG, "Client write failed: ${e.message}")
            false
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun prepareUpstreamRequest(
        req: HttpParser.HttpRequest,
        host: String
    ): HttpParser.HttpRequest {
        val headers = req.headers.toMutableMap()
        headers.remove("proxy-connection")
        headers.remove("proxy-authorization")
        headers["connection"] = "keep-alive"
        // Убираем Accept-Encoding — мы не декодируем gzip/br/zstd
        headers.remove("accept-encoding")
        // Нормализуем абсолютный URI → относительный
        val uri = if (req.uri.startsWith("http://") || req.uri.startsWith("https://")) {
            try {
                val u = java.net.URL(req.uri)
                buildString {
                    append(u.path.ifEmpty { "/" })
                    if (u.query != null) { append('?'); append(u.query) }
                }
            } catch (_: Exception) { req.uri }
        } else req.uri
        return req.copy(uri = uri, headers = headers)
    }

    private fun buildUrl(scheme: String, host: String, uri: String): String {
        if (uri.startsWith("http://") || uri.startsWith("https://")) return uri
        val path = if (uri.startsWith("/")) uri else "/$uri"
        return "$scheme://$host$path"
    }
}
