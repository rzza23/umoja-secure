package com.umoja.secure.transport

import android.util.Log
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit

/**
 * HTTP client wrapper for talking to the Umoja backend.
 *
 * When TransportConfig.useTor is true, all requests go through a SOCKS5
 * proxy (the host's Tor in dev, embedded tor-android in production) and
 * use the .onion address. Requests to .onion hostnames skip real DNS
 * (Tor resolves them at the SOCKS layer).
 */
class HttpClient(baseUrl: String) {

    companion object {
        private const val TAG = "UmojaHttp"

        val DEV_BASE_URL: String get() = TransportConfig.httpBaseUrl

        private val JSON = "application/json; charset=utf-8".toMediaType()

        private const val CONNECT_TIMEOUT_SECONDS = 30L
        private const val READ_TIMEOUT_SECONDS = 60L
        private const val WRITE_TIMEOUT_SECONDS = 60L

        private val DUMMY_ONION_IP: List<InetAddress> =
            listOf(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
    }

    private val baseUrl: String = baseUrl.trimEnd('/')
    private val client: OkHttpClient = buildClient()

    private fun buildClient(): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(WRITE_TIMEOUT_SECONDS, TimeUnit.SECONDS)

        if (TransportConfig.useTor) {
            builder.proxy(
                Proxy(
                    Proxy.Type.SOCKS,
                    InetSocketAddress(
                        TransportConfig.SOCKS_HOST,
                        TransportConfig.SOCKS_PORT,
                    ),
                ),
            )
            builder.dns(object : Dns {
                override fun lookup(hostname: String): List<InetAddress> {
                    return if (hostname.endsWith(".onion")) {
                        DUMMY_ONION_IP
                    } else {
                        Dns.SYSTEM.lookup(hostname)
                    }
                }
            })
        }

        return builder.build()
    }

    fun postJson(path: String, body: String, bearer: String? = null): HttpResult {
        val request = Request.Builder()
            .url(baseUrl + path)
            .post(body.toRequestBody(JSON))
            .apply { if (bearer != null) header("Authorization", "Bearer $bearer") }
            .build()
        return execute(request)
    }

    fun get(path: String, bearer: String? = null): HttpResult {
        val request = Request.Builder()
            .url(baseUrl + path)
            .get()
            .apply { if (bearer != null) header("Authorization", "Bearer $bearer") }
            .build()
        return execute(request)
    }

    private fun execute(request: Request): HttpResult {
        return try {
            client.newCall(request).execute().use { response ->
                HttpResult(
                    code = response.code,
                    body = response.body?.string() ?: "",
                )
            }
        } catch (e: IOException) {
            Log.e(
                TAG,
                "HTTP ${request.method} ${request.url} failed: " +
                    "${e.javaClass.simpleName}: ${e.message}",
                e,
            )
            throw HttpException("network_error", e)
        }
    }
}

data class HttpResult(val code: Int, val body: String)

class HttpException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
