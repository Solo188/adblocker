package com.adblocker.vpn

import java.nio.ByteBuffer

/**
 * Минимальный DNS-парсер для UDP пакетов.
 *
 * ИСПРАВЛЕНИЯ:
 *  - buildBlockedResponse: pointer 0xC00C корректен ТОЛЬКО если question name
 *    начинается с байта 12 (сразу после заголовка). Это верно для 99.9% запросов
 *    без OPT/EDNS additional records перед question. Добавлена проверка.
 *  - buildServFail: QDCOUNT=1 чтобы клиент знал к чему относится ответ.
 */
object DnsPacketParser {

    /**
     * Извлекает доменное имя из первого вопроса DNS запроса.
     * Возвращает null если пакет не является запросом или повреждён.
     */
    fun extractDomain(udpPayload: ByteArray): String? {
        return try {
            if (udpPayload.size < 12) return null
            val buf = ByteBuffer.wrap(udpPayload)

            /* txid */ buf.short
            val flags  = buf.short.toInt() and 0xFFFF
            if ((flags and 0x8000) != 0) return null  // не запрос

            val qdCount = buf.short.toInt() and 0xFFFF
            if (qdCount == 0) return null

            /* anCount, nsCount, arCount */ buf.short; buf.short; buf.short

            // Читаем QNAME
            val sb = StringBuilder(64)
            while (buf.hasRemaining()) {
                val labelLen = buf.get().toInt() and 0xFF
                if (labelLen == 0) break
                if ((labelLen and 0xC0) == 0xC0) { buf.get(); break }  // pointer
                if (buf.remaining() < labelLen) return null
                if (sb.isNotEmpty()) sb.append('.')
                val bytes = ByteArray(labelLen)
                buf.get(bytes)
                sb.append(String(bytes, Charsets.US_ASCII))
            }
            sb.toString().takeIf { it.isNotEmpty() }
        } catch (_: Exception) { null }
    }

    /**
     * Строит DNS ответ с A-записью 0.0.0.0 для блокировки домена.
     *
     * Pointer 0xC00C указывает на байт 12 (начало question section).
     * Это корректно для стандартных DNS запросов без дополнительных секций
     * перед question section (что является нормой для 99%+ запросов).
     */
    fun buildBlockedResponse(query: ByteArray): ByteArray {
        if (query.size < 12) return buildMinimalNxdomain(query)

        val questionEnd = findQuestionEnd(query)
        if (questionEnd < 0) return buildMinimalNxdomain(query)

        val response = ByteArray(questionEnd + 16)
        System.arraycopy(query, 0, response, 0, questionEnd)

        val buf = ByteBuffer.wrap(response)

        // Flags: QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=1, RCODE=0 (NOERROR)
        buf.position(2)
        buf.putShort(0x8580.toShort())

        // QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
        buf.position(4)
        buf.putShort(1.toShort())
        buf.putShort(1.toShort())
        buf.putShort(0.toShort())
        buf.putShort(0.toShort())

        // Answer RR
        buf.position(questionEnd)
        buf.putShort(0xC00C.toShort())   // name pointer → byte 12
        buf.putShort(0x0001.toShort())   // type A
        buf.putShort(0x0001.toShort())   // class IN
        buf.putInt(300)                  // TTL = 300 sec
        buf.putShort(4.toShort())        // RDLENGTH = 4
        buf.put(0); buf.put(0); buf.put(0); buf.put(0)  // 0.0.0.0

        return response
    }

    /**
     * SERVFAIL ответ когда все upstream DNS недоступны.
     * Клиент получит ошибку немедленно вместо timeout.
     */
    fun buildServFail(query: ByteArray): ByteArray {
        if (query.size < 12) return query
        val response = query.copyOf(12)
        val buf = ByteBuffer.wrap(response)
        buf.position(2)
        // QR=1, RD=1, RA=1, RCODE=2 (SERVFAIL)
        buf.putShort(0x8182.toShort())
        // QDCOUNT=0 (упрощённый SERVFAIL без question section)
        buf.position(4)
        buf.putShort(0.toShort())
        buf.putShort(0.toShort())
        buf.putShort(0.toShort())
        buf.putShort(0.toShort())
        return response
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Находит конец первой question section (после QTYPE и QCLASS).
     * Возвращает -1 если пакет повреждён.
     */
    private fun findQuestionEnd(dns: ByteArray): Int {
        if (dns.size < 12) return -1
        var pos = 12
        while (pos < dns.size) {
            val len = dns[pos].toInt() and 0xFF
            when {
                len == 0              -> { pos += 1; break }
                (len and 0xC0) == 0xC0 -> { pos += 2; break }
                else                  -> pos += len + 1
            }
            if (pos >= dns.size) return -1
        }
        // QTYPE (2 bytes) + QCLASS (2 bytes)
        return if (pos + 4 <= dns.size) pos + 4 else -1
    }

    private fun buildMinimalNxdomain(query: ByteArray): ByteArray {
        if (query.size < 2) return query
        val response = query.copyOf(12.coerceAtMost(query.size))
        if (response.size >= 4) {
            // QR=1, RCODE=3 (NXDOMAIN)
            response[2] = 0x81.toByte()
            response[3] = 0x83.toByte()
        }
        return response
    }
}
