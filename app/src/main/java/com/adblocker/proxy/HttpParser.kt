package com.adblocker.proxy

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.Charset

/**
 * Минимальный HTTP/1.1 парсер на чистом InputStream.
 * Не использует никаких сторонних библиотек.
 */
object HttpParser {

    data class HttpRequest(
        val method: String,
        val uri: String,
        val version: String,
        val headers: MutableMap<String, String>,  // lowercase keys
        val rawHeaderBytes: ByteArray,
        var body: ByteArray = ByteArray(0)
    ) {
        fun header(name: String) = headers[name.lowercase()]
        fun host(): String = header("host") ?: ""
        fun isConnect() = method.equals("CONNECT", ignoreCase = true)
        fun contentLength(): Int = header("content-length")?.trim()?.toIntOrNull() ?: 0
    }

    data class HttpResponse(
        val version: String,
        val statusCode: Int,
        val statusText: String,
        val headers: MutableMap<String, String>,
        var body: ByteArray = ByteArray(0)
    ) {
        fun header(name: String) = headers[name.lowercase()]
        fun contentLength(): Int = header("content-length")?.trim()?.toIntOrNull() ?: -1
        fun isChunked() = header("transfer-encoding")?.contains("chunked", true) == true
        fun contentType() = header("content-type") ?: ""
    }

    // ── Request reading ───────────────────────────────────────────────────────

    /**
     * Читает HTTP запрос из потока. Возвращает null при закрытии соединения.
     */
    fun readRequest(input: InputStream): HttpRequest? {
        val headerBytes = readUntilDoubleNewline(input) ?: return null
        val headerText  = String(headerBytes, Charsets.ISO_8859_1)
        val lines       = headerText.split("\r\n")
        if (lines.isEmpty()) return null

        val requestLine = lines[0].split(" ")
        if (requestLine.size < 3) return null

        val method  = requestLine[0]
        val uri     = requestLine[1]
        val version = requestLine[2]

        val headers = mutableMapOf<String, String>()
        for (i in 1 until lines.size) {
            val line = lines[i]
            val colon = line.indexOf(':')
            if (colon > 0) {
                val key = line.substring(0, colon).trim().lowercase()
                val val_ = line.substring(colon + 1).trim()
                headers[key] = val_
            }
        }

        val req = HttpRequest(method, uri, version, headers, headerBytes)

        // Читаем тело если есть Content-Length
        val cl = req.contentLength()
        if (cl > 0) {
            req.body = readExactly(input, cl)
        }

        return req
    }

    // ── Response reading ──────────────────────────────────────────────────────

    /**
     * Читает HTTP ответ полностью включая тело.
     */
    fun readResponse(input: InputStream): HttpResponse? {
        val headerBytes = readUntilDoubleNewline(input) ?: return null
        val headerText  = String(headerBytes, Charsets.ISO_8859_1)
        val lines       = headerText.split("\r\n")
        if (lines.isEmpty()) return null

        val statusLine = lines[0].split(" ", limit = 3)
        if (statusLine.size < 2) return null

        val version    = statusLine[0]
        val statusCode = statusLine[1].toIntOrNull() ?: 0
        val statusText = if (statusLine.size >= 3) statusLine[2] else ""

        val headers = mutableMapOf<String, String>()
        for (i in 1 until lines.size) {
            val line = lines[i]
            val colon = line.indexOf(':')
            if (colon > 0) {
                val key = line.substring(0, colon).trim().lowercase()
                val v   = line.substring(colon + 1).trim()
                headers[key] = v
            }
        }

        val resp = HttpResponse(version, statusCode, statusText, headers)

        resp.body = when {
            resp.isChunked() -> readChunked(input)
            resp.contentLength() >= 0 -> {
                val cl = resp.contentLength()
                if (cl > 0) readExactly(input, cl) else ByteArray(0)
            }
            // Для 204/304/1xx — тела нет
            statusCode in listOf(204, 304) || statusCode < 200 -> ByteArray(0)
            else -> readUntilClose(input)
        }

        return resp
    }

    // ── Writing ───────────────────────────────────────────────────────────────

    fun writeRequest(out: OutputStream, req: HttpRequest) {
        val sb = StringBuilder()
        sb.append("${req.method} ${req.uri} ${req.version}\r\n")
        req.headers.forEach { (k, v) -> sb.append("$k: $v\r\n") }
        sb.append("\r\n")
        out.write(sb.toString().toByteArray(Charsets.ISO_8859_1))
        if (req.body.isNotEmpty()) out.write(req.body)
        out.flush()
    }

    fun writeResponse(out: OutputStream, resp: HttpResponse) {
        val sb = StringBuilder()
        sb.append("${resp.version} ${resp.statusCode} ${resp.statusText}\r\n")
        resp.headers.forEach { (k, v) -> sb.append("$k: $v\r\n") }
        sb.append("content-length: ${resp.body.size}\r\n")
        sb.append("\r\n")
        out.write(sb.toString().toByteArray(Charsets.ISO_8859_1))
        if (resp.body.isNotEmpty()) out.write(resp.body)
        out.flush()
    }

    fun writeSimpleResponse(out: OutputStream, code: Int, text: String, body: String = "") {
        val bodyBytes = body.toByteArray(Charsets.UTF_8)
        val sb = StringBuilder()
        sb.append("HTTP/1.1 $code $text\r\n")
        sb.append("content-length: ${bodyBytes.size}\r\n")
        sb.append("connection: close\r\n")
        sb.append("\r\n")
        out.write(sb.toString().toByteArray(Charsets.ISO_8859_1))
        if (bodyBytes.isNotEmpty()) out.write(bodyBytes)
        out.flush()
    }

    // ── Low-level I/O ─────────────────────────────────────────────────────────

    private fun readUntilDoubleNewline(input: InputStream): ByteArray? {
        val buf = ByteArrayOutputStream(1024)
        var b0 = -1; var b1 = -1; var b2 = -1
        while (true) {
            val b = input.read()
            if (b == -1) return if (buf.size() == 0) null else buf.toByteArray()
            buf.write(b)
            if (b0 == '\r'.code && b1 == '\n'.code && b2 == '\r'.code && b == '\n'.code) {
                // Убираем финальный \r\n\r\n из заголовков
                val bytes = buf.toByteArray()
                return bytes.copyOf(bytes.size - 4)
            }
            b0 = b1; b1 = b2; b2 = b
        }
    }

    fun readExactly(input: InputStream, length: Int): ByteArray {
        if (length <= 0) return ByteArray(0)
        val buf = ByteArray(length)
        var read = 0
        while (read < length) {
            val n = input.read(buf, read, length - read)
            if (n == -1) break
            read += n
        }
        return if (read == length) buf else buf.copyOf(read)
    }

    private fun readChunked(input: InputStream): ByteArray {
        val result = ByteArrayOutputStream()
        while (true) {
            val sizeLine = readLine(input) ?: break
            val chunkSize = sizeLine.trim().substringBefore(';').toIntOrNull(16) ?: break
            if (chunkSize == 0) {
                readLine(input) // trailing CRLF
                break
            }
            val chunk = readExactly(input, chunkSize)
            result.write(chunk)
            readLine(input) // CRLF after chunk
        }
        return result.toByteArray()
    }

    private fun readLine(input: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            if (b == -1) return if (sb.isEmpty()) null else sb.toString()
            if (b == '\n'.code) return sb.toString().trimEnd('\r')
            sb.append(b.toChar())
        }
    }

    private fun readUntilClose(input: InputStream): ByteArray {
        val buf = ByteArrayOutputStream()
        val tmp = ByteArray(8192)
        while (true) {
            val n = input.read(tmp)
            if (n == -1) break
            buf.write(tmp, 0, n)
        }
        return buf.toByteArray()
    }
}
