package com.umoja.secure.transport

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for MatrixApi.
 *
 * No real network. The transport is injected as a lambda
 * (production wires HttpClient::get); tests wire a fake returning a
 * constructed HttpResult. Same pattern as IdentityChangeControllerTest
 * — lambda injection over interface extraction (see MatrixApi KDoc).
 *
 * The load-bearing test is `fetch returns null on 404` — the "no
 * matrix yet" case that AppRoot wiring treats as no-op per registry
 * §B TASK-P1-037. Every other path throws; that one returns null.
 */
class MatrixApiTest {

    private fun apiReturning(result: HttpResult): MatrixApi = MatrixApi { _ -> result }

    private fun apiThrowing(e: Exception): MatrixApi = MatrixApi { _ ->
        throw e
    }

    private fun validMatrixJson(): String =
        """{"canonical_utf8":"{\"domain\":\"umoja.authorization-matrix.v1\",\"matrix\":{}}","signature_base64url":"${"A".repeat(86)}"}"""

    @Test
    fun `fetch returns RemoteMatrix on 200`() {
        val api = apiReturning(HttpResult(200, validMatrixJson()))
        val rm = runBlocking { api.fetch("test-token") }
        assertEquals(
            """{"domain":"umoja.authorization-matrix.v1","matrix":{}}""",
            rm?.canonicalUtf8,
        )
        assertEquals("A".repeat(86), rm?.signatureBase64url)
    }

    @Test
    fun `fetch returns null on 404`() {
        val api = apiReturning(
            HttpResult(404, """{"error":"matrix_not_found"}"""),
        )
        assertNull(runBlocking { api.fetch("test-token") })
    }

    @Test
    fun `fetch throws on 401 with error code from body`() {
        val api = apiReturning(
            HttpResult(401, """{"error":"unauthorized"}"""),
        )
        val e = assertThrows(MatrixApiException::class.java) {
            runBlocking { api.fetch("test-token") }
        }
        assertEquals("unauthorized", e.code)
        assertEquals(401, e.httpCode)
    }

    @Test
    fun `fetch throws invalid_response on malformed JSON`() {
        val api = apiReturning(HttpResult(200, "not-json"))
        val e = assertThrows(MatrixApiException::class.java) {
            runBlocking { api.fetch("test-token") }
        }
        assertEquals("invalid_response", e.code)
    }

    @Test
    fun `fetch throws network_error on HttpException from fetchFn`() {
        val api = apiThrowing(HttpException("boom"))
        val e = assertThrows(MatrixApiException::class.java) {
            runBlocking { api.fetch("test-token") }
        }
        assertEquals("network_error", e.code)
        assertTrue(e.cause is HttpException)
    }
}
