package com.umoja.secure.transport

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * HTTP client wrapper for talking to the Umoja backend.
 *
 * Phase 1 dev: base URL points at the host Mac from the emulator
 * (10.0.2.2:8080). In production, base URL points at the Tor onion
 * service and the transport layer is Tor, not clearnet HTTP.
 *
 * TLS and Tor transport are wired in a later task. For Phase 1, the dev
 * backend speaks plain HTTP behind a network security config that allows
 * cleartext only to 10.0.2.2 and localhost.
 */
class HttpClient(baseUrl: String) {

    companion object {
        const val DEV_BASE_URL = "http://10.0.2.2:8080"
        private val JSON = "application/json; charset=utf-8".toMediaType()
        private const val CONNECT_TIMEOUT_SECONDS = 15L
        private const val READ_TIMEOUT_SECONDS = 30L
        private const val WRITE_TIMEOUT_SECONDS = 30L
    }

    private val baseUrl: String = baseUrl.trimEnd('/')
    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .readTimeout(READ_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .writeTimeout(WRITE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .build()

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
            throw HttpException("network_error", e)
        }
    }
}

data class HttpResult(val code: Int, val body: String)

class HttpException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
