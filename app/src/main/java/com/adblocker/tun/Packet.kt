package com.adblocker.tun

import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * Парсит сырой IPv4 пакет из tun fd.
 * Все вычисления checksum вынесены в PacketUtils object.
 */
class Packet(private val raw: ByteArray, val length: Int) {

    companion object {
        const val PROTO_TCP = 6
        const val PROTO_UDP = 17

        const val TCP_FIN = 0x01
        const val TCP_SYN = 0x02
        const val TCP_RST = 0x04
        const val TCP_PSH = 0x08
        const val TCP_ACK = 0x10

        fun wrap(buf: ByteArray, len: Int): Packet? {
            if (len < 20) return null
            val version = (buf[0].toInt() and 0xFF) shr 4
            if (version != 4) return null
            return Packet(buf, len)
        }

        /**
         * Строит TCP пакет с нуля — не требует экземпляра Packet.
         * Вызывается из TcpControlBlock.buildResponse().
         */
        fun buildTcpResponse(
            srcIp: ByteArray, dstIp: ByteArray,
            srcPort: Int, dstPort: Int,
            seq: Long, ack: Long, flags: Int,
            window: Int = 65535,
            payload: ByteArray = ByteArray(0)
        ): ByteArray {
            val tcpLen   = 20 + payload.size
            val totalLen = 20 + tcpLen
            val out = ByteArray(totalLen)
            val b = ByteBuffer.wrap(out)

            // IP header
            b.put(0x45.toByte()); b.put(0)
            b.putShort(totalLen.toShort())
            b.putShort(0); b.putShort(0x4000.toShort())
            b.put(64); b.put(PROTO_TCP.toByte())
            b.putShort(0)           // checksum placeholder
            b.put(srcIp); b.put(dstIp)

            PacketUtils.writeShort(out, 10, PacketUtils.ipChecksum(out, 20))

            // TCP header
            b.putShort(srcPort.toShort()); b.putShort(dstPort.toShort())
            b.putInt(seq.toInt()); b.putInt(ack.toInt())
            b.put(0x50.toByte())    // data offset = 5
            b.put(flags.toByte())
            b.putShort(window.toShort())
            b.putShort(0)           // checksum placeholder
            b.putShort(0)           // urgent
            if (payload.isNotEmpty()) b.put(payload)

            val tcpSeg = out.copyOfRange(20, totalLen)
            PacketUtils.writeShort(out, 20 + 16, PacketUtils.tcpChecksum(srcIp, dstIp, tcpSeg))

            return out
        }
    }

    // ── IP header ────────────────────────────────────────────────────────────

    val ipHeaderLen: Int = ((raw[0].toInt() and 0x0F) * 4)
    val protocol: Int   get() = raw[9].toInt() and 0xFF
    val isTcp: Boolean  get() = protocol == PROTO_TCP
    val isUdp: Boolean  get() = protocol == PROTO_UDP

    val srcIp: ByteArray get() = raw.copyOfRange(12, 16)
    val dstIp: ByteArray get() = raw.copyOfRange(16, 20)

    // ── TCP header ───────────────────────────────────────────────────────────

    val tcpSrcPort: Int get() {
        check(isTcp) { "Not TCP" }
        return readShortAt(ipHeaderLen).toInt() and 0xFFFF
    }
    val tcpDstPort: Int get() {
        check(isTcp) { "Not TCP" }
        return readShortAt(ipHeaderLen + 2).toInt() and 0xFFFF
    }
    val tcpSeq: Long get() {
        check(isTcp) { "Not TCP" }
        return readIntAt(ipHeaderLen + 4).toLong() and 0xFFFFFFFFL
    }
    val tcpAck: Long get() {
        check(isTcp) { "Not TCP" }
        return readIntAt(ipHeaderLen + 8).toLong() and 0xFFFFFFFFL
    }
    val tcpDataOffset: Int get() {
        check(isTcp) { "Not TCP" }
        return ((raw[ipHeaderLen + 12].toInt() and 0xFF) shr 4) * 4
    }
    val tcpFlags: Int get() {
        check(isTcp) { "Not TCP" }
        return raw[ipHeaderLen + 13].toInt() and 0xFF
    }
    val tcpWindow: Int get() {
        check(isTcp) { "Not TCP" }
        return readShortAt(ipHeaderLen + 14).toInt() and 0xFFFF
    }
    fun tcpHasFlag(flag: Int): Boolean = (tcpFlags and flag) != 0

    val tcpPayload: ByteArray get() {
        check(isTcp) { "Not TCP" }
        val start = ipHeaderLen + tcpDataOffset
        return if (length > start) raw.copyOfRange(start, length) else ByteArray(0)
    }
    val tcpPayloadLength: Int get() {
        check(isTcp) { "Not TCP" }
        return (length - ipHeaderLen - tcpDataOffset).coerceAtLeast(0)
    }

    // ── UDP header ───────────────────────────────────────────────────────────

    val udpSrcPort: Int get() {
        check(isUdp) { "Not UDP" }
        return readShortAt(ipHeaderLen).toInt() and 0xFFFF
    }
    val udpDstPort: Int get() {
        check(isUdp) { "Not UDP" }
        return readShortAt(ipHeaderLen + 2).toInt() and 0xFFFF
    }
    val udpLength: Int get() {
        check(isUdp) { "Not UDP" }
        return readShortAt(ipHeaderLen + 4).toInt() and 0xFFFF
    }
    val udpPayload: ByteArray get() {
        check(isUdp) { "Not UDP" }
        val start = ipHeaderLen + 8
        val payLen = udpLength - 8
        return if (payLen > 0) raw.copyOfRange(start, start + payLen) else ByteArray(0)
    }

    // ── Instance builder — используется только для buildRst() ────────────────

    fun buildRst(): ByteArray {
        val ackNum = if (tcpHasFlag(TCP_ACK)) tcpAck
                     else (tcpSeq + tcpPayloadLength) and 0xFFFFFFFFL
        return buildTcpResponse(
            srcIp   = dstIp, dstIp = srcIp,
            srcPort = tcpDstPort, dstPort = tcpSrcPort,
            seq     = tcpAck, ack = ackNum,
            flags   = TCP_RST or TCP_ACK
        )
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun readShortAt(offset: Int): Short =
        (((raw[offset].toInt() and 0xFF) shl 8) or (raw[offset + 1].toInt() and 0xFF)).toShort()

    private fun readIntAt(offset: Int): Int =
        ((raw[offset].toInt() and 0xFF) shl 24) or
        ((raw[offset + 1].toInt() and 0xFF) shl 16) or
        ((raw[offset + 2].toInt() and 0xFF) shl 8) or
        (raw[offset + 3].toInt() and 0xFF)
}

/**
 * Утилиты для вычисления checksum и построения UDP пакетов.
 * Вынесены из Packet чтобы не было двух companion object.
 */
object PacketUtils {

    fun writeShort(buf: ByteArray, offset: Int, value: Short) {
        buf[offset]     = (value.toInt() shr 8 and 0xFF).toByte()
        buf[offset + 1] = (value.toInt()        and 0xFF).toByte()
    }

    fun ipChecksum(header: ByteArray, len: Int): Short {
        var sum = 0; var i = 0
        while (i < len) {
            sum += ((header[i].toInt() and 0xFF) shl 8) or (header[i + 1].toInt() and 0xFF)
            i += 2
        }
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toShort()
    }

    fun tcpChecksum(srcIp: ByteArray, dstIp: ByteArray, tcpData: ByteArray): Short {
        var sum = pseudoHeader(srcIp, dstIp, 6, tcpData.size)
        sum = addData(sum, tcpData)
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toShort()
    }

    fun udpChecksum(srcIp: ByteArray, dstIp: ByteArray, udpData: ByteArray): Short {
        var sum = pseudoHeader(srcIp, dstIp, 17, udpData.size)
        sum = addData(sum, udpData)
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toShort()
    }

    private fun pseudoHeader(srcIp: ByteArray, dstIp: ByteArray, proto: Int, len: Int): Int {
        var sum = 0
        for (i in 0 until 4 step 2) {
            sum += ((srcIp[i].toInt() and 0xFF) shl 8) or (srcIp[i + 1].toInt() and 0xFF)
            sum += ((dstIp[i].toInt() and 0xFF) shl 8) or (dstIp[i + 1].toInt() and 0xFF)
        }
        return sum + proto + len
    }

    private fun addData(sum0: Int, data: ByteArray): Int {
        var sum = sum0; var i = 0
        while (i < data.size - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (data.size % 2 == 1) sum += (data.last().toInt() and 0xFF) shl 8
        return sum
    }

    fun buildUdpPacket(
        srcIp: ByteArray, dstIp: ByteArray,
        srcPort: Int, dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpLen   = 8 + payload.size
        val totalLen = 20 + udpLen
        val out = ByteArray(totalLen)
        val b = ByteBuffer.wrap(out)

        b.put(0x45.toByte()); b.put(0)
        b.putShort(totalLen.toShort())
        b.putShort(0); b.putShort(0x4000.toShort())
        b.put(64); b.put(Packet.PROTO_UDP.toByte())
        b.putShort(0); b.put(srcIp); b.put(dstIp)
        writeShort(out, 10, ipChecksum(out, 20))

        b.putShort(srcPort.toShort()); b.putShort(dstPort.toShort())
        b.putShort(udpLen.toShort()); b.putShort(0)
        b.put(payload)

        val udpSeg = out.copyOfRange(20, totalLen)
        writeShort(out, 26, udpChecksum(srcIp, dstIp, udpSeg))

        return out
    }
}
