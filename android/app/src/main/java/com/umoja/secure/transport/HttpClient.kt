package com.umoja.secure.transport

import android.util.Log
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit

/**
 * HTTP client wrapper for talking to the Umoja backend.
 *
 * Tor mode: instead of asking OkHttp to use SOCKS directly (which
 * resolves hostnames locally and breaks .onion), we start a local
 * HTTP-to-SOCKS5 bridge and point OkHttp at it with Proxy.Type.HTTP.
 * The bridge sees the request in absolute-URI form, extracts the
 * hostname, and dials SOCKS5 with ATYP=0x03 so Tor handles the .onion
 * resolution.
 *
 * Clearnet mode: no proxy, plain HTTP to 127.0.0.1:8080 via adb reverse.
 */
class HttpClient(baseUrl: String) {

    companion object {
        private const val TAG = "UmojaHttp"

        val DEV_BASE_URL: String get() = TransportConfig.httpBaseUrl

        private val JSON = "application/json; charset=utf-8".toMediaType()

        private const val CONNECT_TIMEOUT_SECONDS = 90L
        private const val READ_TIMEOUT_SECONDS = 90L
        private const val WRITE_TIMEOUT_SECONDS = 90L
    }

    private val baseUrl: String = baseUrl.trimEnd('/')
    private val client: OkHttpClient = buildClient()

    private fun buildClient(): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(WRITE_TIMEOUT_SECONDS, TimeUnit.SECONDS)

        if (TransportConfig.useTor) {
            val bridgePort = Socks5Bridge.start()
            builder.proxy(
                Proxy(
                    Proxy.Type.HTTP,
                    InetSocketAddress("127.0.0.1", bridgePort),
                ),
            )
            // Each request should get a fresh SOCKS session. Pooling
            // doesn't help behind Tor anyway (latency dominates).
            builder.connectionPool(okhttp3.ConnectionPool(0, 1, TimeUnit.MILLISECONDS))
            Log.i(TAG, "Tor mode: routing via HTTP bridge 127.0.0.1:$bridgePort")
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
