package com.umoja.secure.transport

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for [shouldRetryAfter401]. The retry-with-fresh-bearer flow
 * itself (challenge -> verify -> retry) is verified at the emulator
 * layer in TASK-P1-040-E -- mocking OkHttp here would require
 * mockwebserver, which is not on the classpath.
 *
 * Registry §B's TEST-SESSION-* names cover the state machine's
 * reauth contract (TASK-P1-040-B). These TEST-INTERCEPTOR-* names
 * cover the interceptor's decision rule, which is 040-D's
 * contribution.
 *
 * TASK-P1-040-D.
 */
class HttpClientRetryTest {

    @Test
    fun `TEST-INTERCEPTOR-NON-401-NO-RETRY`() {
        assertFalse(shouldRetryAfter401("/me", 200, hasHandler = true))
        assertFalse(shouldRetryAfter401("/me/matrix", 404, hasHandler = true))
        assertFalse(shouldRetryAfter401("/envelopes", 500, hasHandler = true))
    }

    @Test
    fun `TEST-INTERCEPTOR-401-NO-HANDLER-NO-RETRY`() {
        assertFalse(shouldRetryAfter401("/me", 401, hasHandler = false))
    }

    @Test
    fun `TEST-INTERCEPTOR-401-WITH-HANDLER-RETRY`() {
        assertTrue(shouldRetryAfter401("/me", 401, hasHandler = true))
    }

    @Test
    fun `TEST-INTERCEPTOR-AUTH-PATHS-EXCLUDED`() {
        assertFalse(shouldRetryAfter401("/auth/challenge", 401, hasHandler = true))
        assertFalse(shouldRetryAfter401("/auth/verify", 401, hasHandler = true))
        assertFalse(shouldRetryAfter401("/auth/logout", 401, hasHandler = true))
    }

    @Test
    fun `TEST-INTERCEPTOR-ENROLLMENT-EXCLUDED`() {
        assertFalse(shouldRetryAfter401("/enrollment", 401, hasHandler = true))
    }

    @Test
    fun `TEST-INTERCEPTOR-SESSION-ENDPOINTS-RETRY`() {
        assertTrue(shouldRetryAfter401("/me", 401, hasHandler = true))
        assertTrue(shouldRetryAfter401("/me/matrix", 401, hasHandler = true))
        assertTrue(shouldRetryAfter401("/me/contacts", 401, hasHandler = true))
    }

    @Test
    fun `TEST-INTERCEPTOR-DATA-ENDPOINTS-RETRY`() {
        assertTrue(shouldRetryAfter401("/envelopes", 401, hasHandler = true))
        assertTrue(shouldRetryAfter401("/envelopes/pending", 401, hasHandler = true))
        assertTrue(shouldRetryAfter401("/prekeys/943fbeeb", 401, hasHandler = true))
        assertTrue(shouldRetryAfter401("/identity-change-notices", 401, hasHandler = true))
        assertTrue(shouldRetryAfter401("/admin/devices", 401, hasHandler = true))
        assertTrue(shouldRetryAfter401("/contacts", 401, hasHandler = true))
    }
}
