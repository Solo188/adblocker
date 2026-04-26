package com.adblocker.proxy

import android.content.Context
import android.util.Log
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Генерирует корневой CA и подписывает сертификаты для каждого хоста.
 * Кэширует SSLContext по хосту — повторные соединения не пересоздают сертификат.
 *
 * ИСПРАВЛЕНИЯ:
 *  - getCaPemFile() всегда перезаписывает PEM из текущего caCert.
 *    Ранее если CA перегенерировался (старый p12 удалён), PEM оставался устаревшим.
 *  - generateCa() удаляет устаревший PEM при перегенерации CA.
 */
class CertificateAuthority(private val context: Context) {

    companion object {
        private const val TAG      = "CertAuth"
        private const val CA_FILE  = "mitm_ca.p12"
        private const val CA_PASS  = "adblocker_ca_2024"
        private const val PEM_FILE = "mitm_ca.pem"
        private const val SIGN_ALG = "SHA256WithRSA"
    }

    private lateinit var caKey:  PrivateKey
    private lateinit var caCert: X509Certificate

    private val sslCache = ConcurrentHashMap<String, SSLContext>(64)

    // TrustAll для upstream — мы сами проверяем MITM, не проверяем сервер
    val upstreamTrustManager: X509TrustManager = object : X509TrustManager {
        override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
        override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    /**
     * Загружает или генерирует корневой CA.
     * Вызывать один раз — из MitmProxy.start().
     */
    fun init() {
        val caFile = File(context.filesDir, CA_FILE)
        if (caFile.exists()) {
            try {
                loadCa(caFile)
                Log.i(TAG, "Root CA loaded from ${caFile.absolutePath}")
                return
            } catch (e: Exception) {
                Log.w(TAG, "Failed to load CA, regenerating: ${e.message}")
                caFile.delete()
                // Удаляем устаревший PEM при перегенерации
                File(context.filesDir, PEM_FILE).delete()
            }
        }
        generateCa(caFile)
        Log.i(TAG, "Root CA generated: ${caFile.absolutePath}")
    }

    /**
     * Возвращает PEM-файл CA сертификата.
     * Всегда перезаписывает из текущего caCert — никогда не отдаёт устаревший.
     */
    fun getCaPemFile(): File {
        val pem     = File(context.filesDir, PEM_FILE)
        val encoded = java.util.Base64.getMimeEncoder(64, "\n".toByteArray())
            .encodeToString(caCert.encoded)
        pem.writeText("-----BEGIN CERTIFICATE-----\n$encoded\n-----END CERTIFICATE-----\n")
        return pem
    }

    fun getServerSslContext(host: String): SSLContext =
        sslCache.computeIfAbsent(stripPort(host)) { h -> buildServerSslContext(h) }

    fun getUpstreamSslContext(): SSLContext =
        SSLContext.getInstance("TLS").also {
            it.init(null, arrayOf<TrustManager>(upstreamTrustManager), SecureRandom())
        }

    // ── Private ───────────────────────────────────────────────────────────────

    private fun stripPort(host: String) = host.substringBefore(':')

    private fun loadCa(file: File) {
        val ks = KeyStore.getInstance("PKCS12")
        file.inputStream().use { ks.load(it, CA_PASS.toCharArray()) }
        caKey  = ks.getKey("ca", CA_PASS.toCharArray()) as PrivateKey
        caCert = ks.getCertificate("ca") as X509Certificate
    }

    private fun generateCa(file: File) {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048, SecureRandom())
        val kp = kpg.generateKeyPair()

        val now    = Date()
        val expire = Date(now.time + 10L * 365 * 24 * 3600 * 1000)
        val name   = X500Name("CN=AdBlocker CA, O=AdBlocker, C=RU")

        val builder = JcaX509v3CertificateBuilder(
            name, BigInteger.valueOf(1L), now, expire, name, kp.public
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        builder.addExtension(Extension.keyUsage, true,
            KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))

        val signer = JcaContentSignerBuilder(SIGN_ALG).build(kp.private)
        val cert   = JcaX509CertificateConverter().getCertificate(builder.build(signer))

        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, CA_PASS.toCharArray())
        ks.setKeyEntry("ca", kp.private, CA_PASS.toCharArray(), arrayOf(cert))
        file.outputStream().use { ks.store(it, CA_PASS.toCharArray()) }

        caKey  = kp.private
        caCert = cert
    }

    private fun buildServerSslContext(host: String): SSLContext {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048, SecureRandom())
        val kp: KeyPair = kpg.generateKeyPair()

        val now     = Date()
        val expire  = Date(now.time + 365L * 24 * 3600 * 1000)
        val subject = X500Name("CN=$host, O=AdBlocker MITM, C=RU")
        val serial  = BigInteger(64, SecureRandom())
        val caName  = X500Name.getInstance(caCert.subjectX500Principal.encoded)

        val builder = JcaX509v3CertificateBuilder(
            caName, serial, now, expire, subject, kp.public
        )
        // SAN обязателен — браузеры не принимают сертификаты только с CN
        val san = GeneralNames(GeneralName(GeneralName.dNSName, host))
        builder.addExtension(Extension.subjectAlternativeName, false, san)
        builder.addExtension(Extension.basicConstraints, false, BasicConstraints(false))
        builder.addExtension(Extension.keyUsage, true,
            KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment))

        val signer = JcaContentSignerBuilder(SIGN_ALG).build(caKey)
        val cert   = JcaX509CertificateConverter().getCertificate(builder.build(signer))

        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry("server", kp.private, null, arrayOf(cert, caCert))

        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, null)

        return SSLContext.getInstance("TLS").also {
            it.init(kmf.keyManagers, null, SecureRandom())
        }
    }
}
