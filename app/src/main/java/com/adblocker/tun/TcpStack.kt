package com.adblocker.tun

import android.net.VpnService
import android.util.Log
import com.adblocker.vpn.DnsPacketParser
import com.adblocker.vpn.DomainFilter
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * TcpStack — диспетчер пакетов из tun fd.
 *
 * UDP:53  → DNS-фильтрация + форвардинг (в отдельном пуле, не блокирует TCP)
 * UDP:443 → дроп QUIC/HTTP3 (форсируем TCP)
 * TCP:80/443 → TCP state machine + туннелирование через MitmProxy
 * Остальное → RST (быстрое закрытие)
 *
 * ИСПРАВЛЕНИЯ vs предыдущей версии:
 *  1. DNS форвардинг перенесён в dnsExecutor — UDP timeout 3 сек больше не
 *     блокирует обработку TCP пакетов в основном цикле.
 *  2. tunnelTable.putIfAbsent — атомарное создание тоннеля (без дублей).
 *  3. RST для нефильтруемых TCP портов — быстрая обратная связь.
 */
class TcpStack(
    private val tunIn:        java.io.FileInputStream,
    private val tunOut:       java.io.FileOutputStream,
    private val vpnService:   VpnService,
    private val domainFilter: DomainFilter,
    private val proxyHost:    String = "127.0.0.1",
    private val proxyPort:    Int    = 8118,
    private val dnsServer:    String = "8.8.8.8",
    private val dnsPort:      Int    = 53
) : TunWriter {

    companion object {
        private const val TAG                  = "TcpStack"
        private const val MTU                  = 1500
        private const val CLEANUP_INTERVAL_MS  = 30_000L
        private const val TCB_TIMEOUT_MS       = 90_000L
        private const val MAX_TCB              = 1024
        private const val DNS_CACHE_TTL_MS     = 60_000L
        private const val DNS_CACHE_MAX        = 2048
    }

    private val running        = AtomicBoolean(false)
    private val tcbTable       = ConcurrentHashMap<TcpTuple, TcpControlBlock>(256)
    private val tunnelTable    = ConcurrentHashMap<TcpTuple, TcpTunnel>(256)
    private val tunLock        = Any()

    // Пул для TCP тоннелей (каждый блокирует на I/O)
    private val tunnelExecutor = Executors.newCachedThreadPool { r ->
        Thread(r, "Tunnel-worker").apply { isDaemon = true }
    }

    // Отдельный пул для DNS — UDP запросы могут блокировать на timeout
    private val dnsExecutor = Executors.newFixedThreadPool(4) { r ->
        Thread(r, "DNS-worker").apply { isDaemon = true }
    }

    // DNS кэш: домен → ответный UDP payload
    private val dnsCache = LinkedHashMap<String, DnsCacheEntry>(512, 0.75f, true)

    data class DnsCacheEntry(val response: ByteArray, val expiresAt: Long) {
        fun isExpired() = System.currentTimeMillis() > expiresAt
    }

    private val cleanupExecutor = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "TcpStack-cleanup").apply { isDaemon = true }
    }

    // ── Start / Stop ──────────────────────────────────────────────────────────

    fun start() {
        running.set(true)
        cleanupExecutor.scheduleAtFixedRate(
            ::cleanupDeadConnections,
            CLEANUP_INTERVAL_MS, CLEANUP_INTERVAL_MS, TimeUnit.MILLISECONDS
        )
        Log.i(TAG, "TcpStack started (proxy=$proxyHost:$proxyPort)")
        runLoop()
    }

    fun stop() {
        running.set(false)
        cleanupExecutor.shutdownNow()
        tunnelExecutor.shutdownNow()
        dnsExecutor.shutdownNow()
        tunnelTable.values.forEach { it.close() }
        tcbTable.values.forEach    { it.close() }
        tunnelTable.clear()
        tcbTable.clear()
        Log.i(TAG, "TcpStack stopped")
    }

    // ── Main loop ─────────────────────────────────────────────────────────────

    private fun runLoop() {
        val buf = ByteArray(MTU)
        while (running.get()) {
            try {
                val len = tunIn.read(buf)
                if (len <= 0) continue
                val packet = Packet.wrap(buf.copyOf(len), len) ?: continue
                dispatch(packet)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt(); break
            } catch (e: Exception) {
                if (running.get()) Log.e(TAG, "Packet dispatch error: ${e.message}")
            }
        }
        Log.i(TAG, "TcpStack loop stopped")
    }

    // ── Dispatcher ────────────────────────────────────────────────────────────

    private fun dispatch(p: Packet) {
        when {
            p.isUdp && p.udpDstPort == 443    -> { /* дроп QUIC — форсируем TCP/TLS */ }
            p.isUdp && p.udpDstPort == dnsPort -> handleDnsAsync(p)
            p.isTcp && (p.tcpDstPort == 80 || p.tcpDstPort == 443) -> handleTcp(p)
            p.isTcp -> {
                // RST для не-HTTP/HTTPS TCP — быстрая обратная связь вместо timeout
                write(p.buildRst())
            }
            // Прочий UDP — дроп
        }
    }

    // ── TCP ───────────────────────────────────────────────────────────────────

    private fun handleTcp(p: Packet) {
        val tuple = TcpTuple.from(p)

        if (p.tcpHasFlag(Packet.TCP_SYN) && !p.tcpHasFlag(Packet.TCP_ACK)) {
            handleNewSyn(p, tuple)
            return
        }

        val tcb = tcbTable[tuple]
        if (tcb == null) {
            write(p.buildRst()); return
        }

        val responses = tcb.handlePacket(p)
        responses.forEach { write(it) }

        // Атомарно создаём тоннель при первом ESTABLISHED пакете
        if (tcb.state == TcpState.ESTABLISHED && !tunnelTable.containsKey(tuple)) {
            openTunnelOnce(tcb, tuple)
        }

        if (tcb.closed) {
            tcbTable.remove(tuple)
            tunnelTable.remove(tuple)?.close()
        }
    }

    private fun handleNewSyn(p: Packet, tuple: TcpTuple) {
        if (tcbTable.size >= MAX_TCB) {
            Log.w(TAG, "TCB table full, dropping SYN")
            write(p.buildRst()); return
        }
        val tcb = TcpControlBlock(tuple, this)
        tcbTable[tuple] = tcb
        tcb.handlePacket(p).forEach { write(it) }
    }

    private fun openTunnelOnce(tcb: TcpControlBlock, tuple: TcpTuple) {
        val dstIp   = TcpTuple.unpackIp(tcb.tuple.dstIp)
        val dstHost = InetAddress.getByAddress(dstIp).hostAddress ?: dstIp.joinToString(".")
        val dstPort = tcb.tuple.dstPort

        val tunnel = TcpTunnel(
            tcb             = tcb,
            proxyHost       = proxyHost,
            proxyPort       = proxyPort,
            vpnService      = vpnService,
            originalDstHost = dstHost,
            originalDstPort = dstPort,
            executor        = tunnelExecutor
        )

        // putIfAbsent атомарен: только первый вызов вставляет и запускает
        val existing = tunnelTable.putIfAbsent(tuple, tunnel)
        if (existing == null) {
            tunnel.connect()
            Log.d(TAG, "Tunnel opened: :${tcb.tuple.srcPort} → $dstHost:$dstPort")
        }
        // Если existing != null — tunnel уже есть, новый объект просто дропается
    }

    // ── DNS (async) ───────────────────────────────────────────────────────────

    /**
     * DNS обрабатывается в dnsExecutor — не блокирует tun-loop.
     * Захватываем все данные из пакета ДО передачи в поток (пакет может быть переиспользован).
     */
    private fun handleDnsAsync(p: Packet) {
        val payload  = p.udpPayload.copyOf()
        val srcIp    = p.srcIp.copyOf()
        val dstIp    = p.dstIp.copyOf()
        val srcPort  = p.udpSrcPort

        dnsExecutor.submit {
            try {
                handleDns(payload, srcIp, dstIp, srcPort)
            } catch (e: Exception) {
                Log.e(TAG, "DNS handler error: ${e.message}")
            }
        }
    }

    private fun handleDns(
        payload: ByteArray,
        srcIp: ByteArray, dstIp: ByteArray,
        srcPort: Int
    ) {
        if (payload.isEmpty()) return
        val domain = DnsPacketParser.extractDomain(payload)?.lowercase()

        if (domain != null) {
            // Проверяем кэш
            val cached = synchronized(dnsCache) { dnsCache[domain] }
            if (cached != null && !cached.isExpired()) {
                write(buildUdpResponse(dstIp, srcIp, srcPort, cached.response))
                return
            }

            // Блокируем рекламный домен
            if (domainFilter.isBlocked(domain)) {
                Log.d(TAG, "DNS blocked: $domain")
                write(buildUdpResponse(dstIp, srcIp, srcPort,
                    DnsPacketParser.buildBlockedResponse(payload)))
                return
            }
        }

        // Форвардим к реальным DNS
        forwardDns(payload, srcIp, dstIp, srcPort, domain)
    }

    private fun forwardDns(
        payload: ByteArray,
        srcIp: ByteArray, dstIp: ByteArray,
        srcPort: Int,
        domain: String?
    ) {
        val servers = listOf(dnsServer, "1.1.1.1", "9.9.9.9")
        for (server in servers) {
            try {
                val sock = DatagramSocket()
                vpnService.protect(sock)
                val response: ByteArray
                sock.use { s ->
                    s.soTimeout = 3_000
                    s.send(DatagramPacket(payload, payload.size,
                        InetAddress.getByName(server), dnsPort))
                    val buf  = ByteArray(512)
                    val recv = DatagramPacket(buf, buf.size)
                    s.receive(recv)
                    response = buf.copyOf(recv.length)
                }
                // Кэшируем ответ
                if (domain != null) {
                    synchronized(dnsCache) {
                        if (dnsCache.size >= DNS_CACHE_MAX) {
                            dnsCache.keys.firstOrNull()?.let { dnsCache.remove(it) }
                        }
                        dnsCache[domain] = DnsCacheEntry(
                            response,
                            System.currentTimeMillis() + DNS_CACHE_TTL_MS
                        )
                    }
                }
                write(buildUdpResponse(dstIp, srcIp, srcPort, response))
                return
            } catch (e: java.net.SocketTimeoutException) {
                Log.d(TAG, "DNS timeout from $server${if (domain != null) " for $domain" else ""}")
            } catch (e: Exception) {
                Log.e(TAG, "DNS error from $server: ${e.message}")
            }
        }
        // Все серверы недоступны — возвращаем SERVFAIL
        write(buildUdpResponse(dstIp, srcIp, srcPort, DnsPacketParser.buildServFail(payload)))
    }

    private fun buildUdpResponse(
        srcIp: ByteArray, dstIp: ByteArray,
        dstPort: Int, dns: ByteArray
    ) = PacketUtils.buildUdpPacket(
        srcIp   = srcIp,
        dstIp   = dstIp,
        srcPort = dnsPort,
        dstPort = dstPort,
        payload = dns
    )

    // ── TunWriter ─────────────────────────────────────────────────────────────

    override fun write(packet: ByteArray) {
        if (!running.get()) return
        try {
            synchronized(tunLock) { tunOut.write(packet) }
        } catch (e: Exception) {
            if (running.get()) Log.e(TAG, "tun write error: ${e.message}")
        }
    }

    // ── Cleanup ───────────────────────────────────────────────────────────────

    private fun cleanupDeadConnections() {
        val now  = System.currentTimeMillis()
        val dead = mutableListOf<TcpTuple>()
        tcbTable.forEach { (tuple, tcb) ->
            if (tcb.closed || (now - tcb.createdAt) > TCB_TIMEOUT_MS) {
                dead.add(tuple)
                tcb.close()
            }
        }
        dead.forEach { tuple ->
            tcbTable.remove(tuple)
            tunnelTable.remove(tuple)?.close()
        }
        if (dead.isNotEmpty()) {
            Log.d(TAG, "Cleanup: removed ${dead.size}, active: ${tcbTable.size}")
        }
    }
}
