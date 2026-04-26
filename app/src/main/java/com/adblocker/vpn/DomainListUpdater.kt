package com.adblocker.vpn

import android.content.Context
import android.net.VpnService
import android.util.Log
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Скачивает актуальный список рекламных доменов из Steven Black unified hosts
 * и сохраняет в filesDir/domains.txt.
 *
 * Вызывается ДО старта VPN интерфейса — защита сокета не нужна.
 * Если VPN уже активен при вызове — передаём vpnService для protect().
 *
 * Использует только стандартный HttpURLConnection (без OkHttp).
 */
class DomainListUpdater {

    companion object {
        private const val TAG               = "DomainListUpdater"
        private const val HOSTS_URL         =
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
        private const val CONNECT_TIMEOUT   = 12_000
        private const val READ_TIMEOUT      = 25_000
        private const val DOMAINS_FILE      = "domains.txt"
        private val SKIP_DOMAINS = setOf(
            "localhost", "localhost.localdomain",
            "broadcasthost", "ip6-localhost",
            "ip6-loopback", "ip6-allnodes",
            "ip6-allrouters", "ip6-allhosts"
        )
    }

    fun update(context: Context, vpnService: VpnService? = null) {
        try {
            val conn = (URL(HOSTS_URL).openConnection() as HttpURLConnection).apply {
                connectTimeout          = CONNECT_TIMEOUT
                readTimeout             = READ_TIMEOUT
                instanceFollowRedirects = true
                setRequestProperty("User-Agent", "AdBlocker/2.0")
            }

            // Если VPN уже активен — пытаемся protect сокет через reflection
            if (vpnService != null) {
                protectSocket(conn, vpnService)
            }

            if (conn.responseCode != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "HTTP ${conn.responseCode}")
                conn.disconnect()
                return
            }

            val domains = conn.inputStream.bufferedReader(Charsets.UTF_8).useLines { lines ->
                lines
                    .map     { it.trim() }
                    .filter  { it.isNotEmpty() && !it.startsWith('#') }
                    .mapNotNull { parseLine(it) }
                    .filter  { d -> d.isNotBlank() && '.' in d && d !in SKIP_DOMAINS }
                    .toList()
            }
            conn.disconnect()

            if (domains.isEmpty()) {
                Log.w(TAG, "Received empty domain list — skipping write")
                return
            }

            File(context.filesDir, DOMAINS_FILE).writeText(
                domains.joinToString("\n"),
                Charsets.UTF_8
            )
            Log.i(TAG, "Domain list updated: ${domains.size} entries")
        } catch (e: Exception) {
            Log.w(TAG, "Domain list update failed: ${e.message}")
        }
    }

    private fun parseLine(line: String): String? {
        // Формат: "0.0.0.0 domain.com" или "127.0.0.1 domain.com"
        val parts = line.split(Regex("\\s+"), limit = 2)
        if (parts.size < 2) return null
        val ip = parts[0]
        if (ip != "0.0.0.0" && ip != "127.0.0.1") return null
        return parts[1].lowercase().trim().takeIf { it.isNotEmpty() }
    }

    private fun protectSocket(conn: HttpURLConnection, svc: VpnService) {
        try {
            // Принудительно подключаем чтобы получить socket
            conn.connect()
            val f = conn.javaClass.getDeclaredField("sock")
            f.isAccessible = true
            val sock = f.get(conn) as? java.net.Socket
            if (sock != null) svc.protect(sock)
        } catch (_: Exception) {
            // Не все реализации HttpURLConnection имеют поле "sock"
        }
    }
}
