package com.umoja.secure.ui.admin

import com.umoja.secure.transport.AdminApi
import com.umoja.secure.transport.AdminApiException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for [AdminScreenState] -- the plain-class state holder
 * extracted from AdminScreen in Session Z-2, commit 2804427.
 *
 * No Compose runtime, no Android context, no real backend. Every
 * backend call is an injected lambda; tests fake them synchronously
 * and assert on MutableStateFlow values after each method runs.
 *
 * Coroutine framework: runBlocking. kotlinx-coroutines-test is not
 * on the classpath (only kotlinx-coroutines-core:1.10.2). This is
 * the same precedent as IdentityChangeControllerTest (Session K)
 * and SessionStateManagerTest (Session R-2). AdminScreenState uses
 * withContext(Dispatchers.IO) internally, so a real dispatcher runs;
 * the injected lambdas are synchronous so no artificial delay is
 * introduced.
 *
 * Test shape mirrors MatrixApiTest (lambda injection, JUnit4,
 * backtick method names, per-group sections) with IdentityChange-
 * ControllerTest's runBlocking + error-path conventions.
 *
 * Coverage groups (22 tests):
 *   load()                      -- 4 tests
 *   loadBundle(json)            -- 3 tests
 *   createTokenForScannedDevice -- 5 tests
 *   authorize()                 -- 4 tests
 *   buildMatrix()               -- 5 tests
 *   setStatusMessage()          -- 1 test
 */
class AdminScreenStateTest {

    // ============================================================
    // Fixtures
    // ============================================================

    private fun validBundleJson(): String = """
        {"domain":"umoja.enrollment-request.v1",
         "device_id":"11111111-2222-4333-8444-555555555555",
         "pub_device_auth_key":"${"A".repeat(43)}",
         "pub_messaging_identity_key":"${"B".repeat(43)}",
         "pub_wipe_confirmation_key":"${"C".repeat(43)}"}
    """.trimIndent()

    private fun device(
        id: String = "d1",
        status: String = "active",
    ) = AdminApi.DeviceEntry(
        deviceId = id,
        label = "label-$id",
        role = "user",
        status = status,
        enrolledAt = "2026-01-01T00:00:00Z",
        lastSeenAt = null,
        revokedAt = null,
    )

    private fun contact(
        owner: String = "d1",
        contact: String = "d2",
        status: String = "active",
    ) = AdminApi.ContactEntry(
        ownerDeviceId = owner,
        contactDeviceId = contact,
        ownerLabel = "label-$owner",
        contactLabel = "label-$contact",
        status = status,
        verificationLevel = "directory",
        authorizedAt = "2026-01-01T00:00:00Z",
        revokedAt = null,
    )

    private fun token() = AdminApi.CreatedToken(
        tokenId = "tok-1",
        token = "secret-token",
        expiresAt = "2026-12-31T00:00:00Z",
    )

    private fun stateWith(
        sessionToken: String? = "test-token",
        listDevicesFn: suspend (String) -> List<AdminApi.DeviceEntry> = { emptyList() },
        listContactsFn: suspend (String) -> List<AdminApi.ContactEntry> = { emptyList() },
        createTokenFn: suspend (AdminApi.CreateTokenRequest, String) -> AdminApi.CreatedToken =
            { _, _ -> token() },
        authorizeContactFn: suspend (String, String, String) -> Unit = { _, _, _ -> },
    ) = AdminScreenState(
        sessionToken = sessionToken,
        listDevicesFn = listDevicesFn,
        listContactsFn = listContactsFn,
        createTokenFn = createTokenFn,
        authorizeContactFn = authorizeContactFn,
    )

    // ============================================================
    // load()
    // ============================================================

    @Test
    fun `load sets error when sessionToken is null`() = runBlocking {
        val s = stateWith(sessionToken = null)
        s.load()
        assertEquals("Not authenticated", s.error.value)
        assertFalse(s.loading.value)
    }

    @Test
    fun `load populates devices and filters contacts to active only`() = runBlocking {
        val s = stateWith(
            listDevicesFn = { listOf(device("d1"), device("d2")) },
            listContactsFn = {
                listOf(
                    contact("d1", "d2", "active"),
                    contact("d3", "d4", "revoked"),
                )
            },
        )
        s.load()
        assertEquals(2, s.devices.value.size)
        assertEquals(1, s.contacts.value.size)
        assertEquals("d1", s.contacts.value[0].ownerDeviceId)
        assertFalse(s.loading.value)
        assertNull(s.error.value)
    }

    @Test
    fun `load sets error code on AdminApiException`() = runBlocking {
        val s = stateWith(
            listDevicesFn = { throw AdminApiException("forbidden") },
        )
        s.load()
        assertEquals("forbidden", s.error.value)
        assertFalse(s.loading.value)
    }

    @Test
    fun `load clears previous error on successful second call`() = runBlocking {
        var shouldFail = true
        val s = stateWith(
            listDevicesFn = {
                if (shouldFail) throw AdminApiException("boom") else listOf(device("d1"))
            },
        )
        s.load()
        assertEquals("boom", s.error.value)
        shouldFail = false
        s.load()
        assertNull(s.error.value)
        assertEquals(1, s.devices.value.size)
    }

    // ============================================================
    // loadBundle()
    // ============================================================

    @Test
    fun `loadBundle populates scannedBundle on valid JSON`() {
        val s = stateWith()
        s.loadBundle(validBundleJson())
        assertNotNull(s.scannedBundle.value)
        assertEquals("11111111-2222-4333-8444-555555555555", s.scannedBundle.value?.deviceId)
        assertEquals("A".repeat(43), s.scannedBundle.value?.pubDeviceAuthKey)
        assertNull(s.error.value)
    }

    @Test
    fun `loadBundle clears prior createdToken and error`() = runBlocking {
        val s = stateWith()
        s.loadBundle(validBundleJson())
        s.createTokenForScannedDevice()
        assertNotNull(s.createdToken.value)
        s.loadBundle(validBundleJson())
        assertNull(s.createdToken.value)
        assertNull(s.error.value)
    }

    @Test
    fun `loadBundle sets error on malformed JSON`() {
        val s = stateWith()
        s.loadBundle("not-json")
        assertNotNull(s.error.value)
        assertTrue(s.error.value?.startsWith("QR parse failed:") ?: false)
        assertNull(s.scannedBundle.value)
    }

    // ============================================================
    // createTokenForScannedDevice()
    // ============================================================

    @Test
    fun `createToken sets error when sessionToken is null`() = runBlocking {
        val s = stateWith(sessionToken = null)
        s.createTokenForScannedDevice()
        assertEquals("Not authenticated", s.error.value)
    }

    @Test
    fun `createToken sets error when no scanned bundle`() = runBlocking {
        val s = stateWith()
        s.createTokenForScannedDevice()
        assertEquals("No scanned device", s.error.value)
    }

    @Test
    fun `createToken populates createdToken and statusMessage on success`() = runBlocking {
        val s = stateWith()
        s.loadBundle(validBundleJson())
        s.createTokenForScannedDevice()
        assertNotNull(s.createdToken.value)
        assertEquals("secret-token", s.createdToken.value?.token)
        assertEquals("Token created", s.statusMessage.value)
        assertNull(s.error.value)
    }

    @Test
    fun `createToken passes boundPublicKey from bundle`() = runBlocking {
        var captured: AdminApi.CreateTokenRequest? = null
        val s = stateWith(
            createTokenFn = { req, _ ->
                captured = req
                token()
            },
        )
        s.loadBundle(validBundleJson())
        s.createTokenForScannedDevice()
        assertEquals("A".repeat(43), captured?.boundPublicKey)
        assertEquals("user", captured?.role)
    }

    @Test
    fun `createToken sets error on AdminApiException`() = runBlocking {
        val s = stateWith(
            createTokenFn = { _, _ -> throw AdminApiException("invalid_token") },
        )
        s.loadBundle(validBundleJson())
        s.createTokenForScannedDevice()
        assertEquals("invalid_token", s.error.value)
        assertNull(s.createdToken.value)
    }

    // ============================================================
    // authorize()
    // ============================================================

    @Test
    fun `authorize sets error when sessionToken is null`() = runBlocking {
        val s = stateWith(sessionToken = null)
        s.authorize("owner", "contact")
        assertEquals("Not authenticated", s.error.value)
    }

    @Test
    fun `authorize sets statusMessage and calls load on success`() = runBlocking {
        var listCalls = 0
        val s = stateWith(
            listDevicesFn = {
                listCalls++
                emptyList()
            },
            listContactsFn = { emptyList() },
        )
        s.authorize("owner", "contact")
        assertEquals("Contact authorized", s.statusMessage.value)
        assertEquals(1, listCalls)
    }

    @Test
    fun `authorize trims owner and contact IDs before calling backend`() = runBlocking {
        var capturedOwner = ""
        var capturedContact = ""
        val s = stateWith(
            authorizeContactFn = { o, c, _ ->
                capturedOwner = o
                capturedContact = c
            },
        )
        s.authorize("  owner  ", "  contact  ")
        assertEquals("owner", capturedOwner)
        assertEquals("contact", capturedContact)
    }

    @Test
    fun `authorize sets error on AdminApiException`() = runBlocking {
        val s = stateWith(
            authorizeContactFn = { _, _, _ -> throw AdminApiException("already_authorized") },
        )
        s.authorize("owner", "contact")
        assertEquals("already_authorized", s.error.value)
        assertNull(s.statusMessage.value)
    }

    // ============================================================
    // buildMatrix()
    // ============================================================

    @Test
    fun `buildMatrix sets error on non-numeric version`() {
        val s = stateWith()
        s.loadBundle(validBundleJson())
        s.buildMatrix(clearance = "", versionStr = "abc", permittedContacts = emptyList())
        assertEquals("version must be a positive integer", s.error.value)
    }

    @Test
    fun `buildMatrix sets error on version below 1`() {
        val s = stateWith()
        s.loadBundle(validBundleJson())
        s.buildMatrix(clearance = "", versionStr = "0", permittedContacts = emptyList())
        assertEquals("version must be a positive integer", s.error.value)
    }

    @Test
    fun `buildMatrix sets error when no scanned bundle`() {
        val s = stateWith()
        s.buildMatrix(clearance = "", versionStr = "1", permittedContacts = emptyList())
        assertEquals("No scanned device", s.error.value)
    }

    @Test
    fun `buildMatrix populates wrapper hash and statusMessage on success`() {
        val s = stateWith()
        s.loadBundle(validBundleJson())
        s.buildMatrix(
            clearance = "SECRET",
            versionStr = "1",
            permittedContacts = emptyList(),
        )
        assertNotNull(s.builtWrapperJson.value)
        assertNotNull(s.builtHash.value)
        assertEquals("Matrix built - review hash and content", s.statusMessage.value)
        assertNull(s.error.value)
        assertEquals(43, s.builtHash.value?.length)
    }

    @Test
    fun `buildMatrix clears prior error on success`() {
        val s = stateWith()
        s.loadBundle(validBundleJson())
        s.buildMatrix(clearance = "", versionStr = "abc", permittedContacts = emptyList())
        assertNotNull(s.error.value)
        s.buildMatrix(clearance = "SECRET", versionStr = "1", permittedContacts = emptyList())
        assertNull(s.error.value)
    }

    // ============================================================
    // setStatusMessage()
    // ============================================================

    @Test
    fun `setStatusMessage updates statusMessage`() {
        val s = stateWith()
        assertNull(s.statusMessage.value)
        s.setStatusMessage("hello")
        assertEquals("hello", s.statusMessage.value)
    }
}
