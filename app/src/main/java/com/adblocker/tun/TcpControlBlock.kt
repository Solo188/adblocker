package com.adblocker.tun

import android.util.Log
import com.adblocker.tun.Packet.Companion.TCP_ACK
import com.adblocker.tun.Packet.Companion.TCP_FIN
import com.adblocker.tun.Packet.Companion.TCP_PSH
import com.adblocker.tun.Packet.Companion.TCP_RST
import com.adblocker.tun.Packet.Companion.TCP_SYN
import java.io.OutputStream

data class TcpTuple(
    val srcIp: Int,
    val srcPort: Int,
    val dstIp: Int,
    val dstPort: Int
) {
    companion object {
        fun from(p: Packet): TcpTuple = TcpTuple(
            srcIp   = packIp(p.srcIp),
            srcPort = p.tcpSrcPort,
            dstIp   = packIp(p.dstIp),
            dstPort = p.tcpDstPort
        )

        fun packIp(b: ByteArray): Int =
            ((b[0].toInt() and 0xFF) shl 24) or
            ((b[1].toInt() and 0xFF) shl 16) or
            ((b[2].toInt() and 0xFF) shl 8)  or
            (b[3].toInt() and 0xFF)

        fun unpackIp(v: Int): ByteArray = byteArrayOf(
            (v shr 24 and 0xFF).toByte(),
            (v shr 16 and 0xFF).toByte(),
            (v shr 8  and 0xFF).toByte(),
            (v        and 0xFF).toByte()
        )
    }

    fun srcIpBytes() = unpackIp(srcIp)
    fun dstIpBytes() = unpackIp(dstIp)
}

enum class TcpState {
    LISTEN, SYN_RCVD, ESTABLISHED, FIN_WAIT, CLOSE_WAIT, CLOSED
}

/**
 * Transmission Control Block — состояние одного TCP соединения.
 *
 * Thread-safety:
 *   seqLock защищает _localSeq и _localAck от гонки между:
 *   - TcpStack-thread (handlePacket)
 *   - TcpTunnel-thread (sendToClient)
 *
 *   sendToClient() полностью атомарен: closed проверяется под seqLock,
 *   чтобы исключить частичную отправку при одновременном close().
 */
class TcpControlBlock(
    val tuple: TcpTuple,
    private val tunWriter: TunWriter
) {
    companion object {
        private const val TAG              = "TCB"
        private const val WINDOW_SIZE      = 65535
        private const val MAX_SEGMENT_SIZE = 1460
    }

    @Volatile var state: TcpState = TcpState.LISTEN

    // Защита sequence numbers
    private val seqLock  = Any()
    private var _localSeq: Long = System.nanoTime() and 0xFFFFFFFFL
    private var _localAck: Long = 0L

    @Volatile var remoteSeq: Long = 0L

    // Устанавливается TcpTunnel после успешного CONNECT к прокси
    @Volatile var upstreamWriter: OutputStream? = null

    @Volatile var closed     = false
    val createdAt: Long      = System.currentTimeMillis()

    // ── handlePacket ──────────────────────────────────────────────────────────

    fun handlePacket(p: Packet): List<ByteArray> {
        if (closed) return listOf(p.buildRst())
        if (p.tcpHasFlag(TCP_RST)) { close(); return emptyList() }

        return when (state) {
            TcpState.LISTEN      -> handleListen(p)
            TcpState.SYN_RCVD   -> handleSynRcvd(p)
            TcpState.ESTABLISHED,
            TcpState.CLOSE_WAIT  -> handleEstablished(p)
            TcpState.FIN_WAIT    -> handleFinWait(p)
            TcpState.CLOSED      -> listOf(p.buildRst())
        }
    }

    private fun handleListen(p: Packet): List<ByteArray> {
        if (!p.tcpHasFlag(TCP_SYN) || p.tcpHasFlag(TCP_ACK)) return listOf(p.buildRst())

        remoteSeq = p.tcpSeq
        val seq: Long
        val ack = (remoteSeq + 1) and 0xFFFFFFFFL
        synchronized(seqLock) {
            seq       = _localSeq
            _localAck = ack
        }
        state = TcpState.SYN_RCVD

        val synAck = buildResponse(TCP_SYN or TCP_ACK, seq, ack)
        synchronized(seqLock) { _localSeq = (seq + 1) and 0xFFFFFFFFL }

        Log.d(TAG, "SYN → SYN-ACK: ${tuple.srcPort}→${tuple.dstPort}")
        return listOf(synAck)
    }

    private fun handleSynRcvd(p: Packet): List<ByteArray> {
        if (!p.tcpHasFlag(TCP_ACK)) return emptyList()
        remoteSeq = p.tcpSeq
        state     = TcpState.ESTABLISHED
        Log.d(TAG, "ESTABLISHED: ${tuple.srcPort}→${tuple.dstPort}")
        return emptyList()
    }

    private fun handleEstablished(p: Packet): List<ByteArray> {
        val result  = mutableListOf<ByteArray>()
        val payload = p.tcpPayload

        if (payload.isNotEmpty()) {
            remoteSeq = p.tcpSeq
            val newAck = (remoteSeq + payload.size) and 0xFFFFFFFFL
            synchronized(seqLock) { _localAck = newAck }

            try {
                upstreamWriter?.write(payload)
                upstreamWriter?.flush()
            } catch (e: Exception) {
                Log.w(TAG, "Upstream write failed: ${e.message}")
                close()
                result.add(p.buildRst())
                return result
            }

            val (seq, ack) = synchronized(seqLock) { _localSeq to _localAck }
            result.add(buildResponse(TCP_ACK, seq, ack))
        }

        if (p.tcpHasFlag(TCP_FIN)) {
            val (seq, newAck) = synchronized(seqLock) {
                _localAck = (_localAck + 1) and 0xFFFFFFFFL
                _localSeq to _localAck
            }
            state = TcpState.CLOSE_WAIT

            result.add(buildResponse(TCP_ACK,           seq, newAck))
            result.add(buildResponse(TCP_FIN or TCP_ACK, seq, newAck))
            synchronized(seqLock) { _localSeq = (seq + 1) and 0xFFFFFFFFL }

            close()
            Log.d(TAG, "FIN received, closing: ${tuple.srcPort}→${tuple.dstPort}")
        }

        return result
    }

    private fun handleFinWait(p: Packet): List<ByteArray> {
        if (p.tcpHasFlag(TCP_ACK) || p.tcpHasFlag(TCP_FIN)) close()
        return emptyList()
    }

    // ── sendToClient ──────────────────────────────────────────────────────────

    /**
     * Отправляет данные клиенту через tun fd.
     * Полностью атомарна: если closed=true при входе — ничего не отправляется.
     * Нет ситуации «половина сегментов ушла, потом close».
     */
    fun sendToClient(data: ByteArray) {
        // Быстрая проверка без lock
        if (closed || state != TcpState.ESTABLISHED) return

        var offset = 0
        while (offset < data.size) {
            val segLen  = minOf(MAX_SEGMENT_SIZE, data.size - offset)
            val segment = data.copyOfRange(offset, offset + segLen)
            val pkt: ByteArray

            synchronized(seqLock) {
                // Повторная проверка под lock — close() мог прийти между итерациями
                if (closed) return
                pkt = buildResponse(TCP_PSH or TCP_ACK, _localSeq, _localAck, segment)
                _localSeq = (_localSeq + segLen) and 0xFFFFFFFFL
            }

            tunWriter.write(pkt)
            offset += segLen
        }
    }

    fun sendFin() {
        if (closed) return
        val pkt: ByteArray
        synchronized(seqLock) {
            pkt = buildResponse(TCP_FIN or TCP_ACK, _localSeq, _localAck)
            _localSeq = (_localSeq + 1) and 0xFFFFFFFFL
        }
        tunWriter.write(pkt)
        state = TcpState.FIN_WAIT
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun buildResponse(
        flags: Int, seq: Long, ack: Long,
        payload: ByteArray = ByteArray(0)
    ): ByteArray = Packet.buildTcpResponse(
        srcIp   = tuple.dstIpBytes(),
        dstIp   = tuple.srcIpBytes(),
        srcPort = tuple.dstPort,
        dstPort = tuple.srcPort,
        seq     = seq, ack = ack,
        flags   = flags,
        window  = WINDOW_SIZE,
        payload = payload
    )

    fun close() {
        closed = true
        state  = TcpState.CLOSED
        try { upstreamWriter?.close() } catch (_: Exception) {}
    }
}

interface TunWriter {
    fun write(packet: ByteArray)
}
