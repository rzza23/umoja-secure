package com.umoja.secure.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Tests for the authorization-matrix schema validator.
 *
 * Shape only — not signing, not canonicalization. Mirrors the TS suite
 * in backend/src/crypto/matrix-schema.test.ts.
 *
 * Task: TASK-P1-026
 * ADR:  §4 (schema)
 */
class AuthorizationMatrixTest {

    private val keyA = "A".repeat(43)
    private val keyB = "B".repeat(43)
    private val keyC = "C".repeat(43)

    private fun validMatrix(): Map<String, Any?> = linkedMapOf(
        "version" to 1,
        "device_id" to "device-001",
        "pub_device_auth_key" to keyA,
        "pub_messaging_identity_key" to keyB,
        "pub_wipe_confirmation_key" to keyC,
        "clearance" to "standard",
        "permitted_contacts" to listOf("device-002"),
        "issued_at" to "2026-10-14T00:00:00Z",
    )

    // ---------- accepts ----------

    @Test
    fun `accepts a fully valid matrix`() {
        val m = AuthorizationMatrix.fromJsonMap(validMatrix())
        assertEquals(1, m.version)
        assertEquals("device-001", m.deviceId)
        assertEquals(keyA, m.pubDeviceAuthKey)
        assertEquals(listOf("device-002"), m.permittedContacts)
        assertEquals("2026-10-14T00:00:00Z", m.issuedAt)
    }

    @Test
    fun `accepts empty permitted_contacts`() {
        val m = AuthorizationMatrix.fromJsonMap(validMatrix() + ("permitted_contacts" to emptyList<String>()))
        assertEquals(emptyList<String>(), m.permittedContacts)
    }

    @Test
    fun `accepts issued_at with fractional seconds`() {
        val m = AuthorizationMatrix.fromJsonMap(validMatrix() + ("issued_at" to "2026-10-14T00:00:00.123Z"))
        assertEquals("2026-10-14T00:00:00.123Z", m.issuedAt)
    }

    @Test
    fun `accepts high version number`() {
        val m = AuthorizationMatrix.fromJsonMap(validMatrix() + ("version" to 999_999))
        assertEquals(999_999, m.version)
    }

    // ---------- rejects ----------

    @Test
    fun `rejects missing version`() {
        val m = validMatrix() - "version"
        assertThrows(IllegalArgumentException::class.java) { AuthorizationMatrix.fromJsonMap(m) }
    }

    @Test
    fun `rejects non-integer version`() {
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationMatrix.fromJsonMap(validMatrix() + ("version" to 1.5))
        }
    }

    @Test
    fun `rejects zero version`() {
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationMatrix.fromJsonMap(validMatrix() + ("version" to 0))
        }
    }

    @Test
    fun `rejects negative version`() {
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationMatrix.fromJsonMap(validMatrix() + ("version" to -1))
        }
    }

    @Test
    fun `rejects empty device_id`() {
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationMatrix.fromJsonMap(validMatrix() + ("device_id" to ""))
        }
    }

    @Test
    fun `rejects non-base64url pub_device_auth_key`() {
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationMatrix.fromJsonMap(validMatrix() + ("pub_device_auth_key" to "has spaces"))
        }
    }

    @Test
    fun `rejects pub_device_auth_key with wrong length`() {
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationMatrix.fromJsonMap(validMatrix() + ("pub_device_auth_key" to "AAAA"))
        }
    }

    @Test
    fun `rejects non-list permitted_contacts`() {
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationMatrix.fromJsonMap(validMatrix() + ("permitted_contacts" to "not-a-list"))
        }
    }

    @Test
    fun `rejects non-string entry in permitted_contacts`() {
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationMatrix.fromJsonMap(validMatrix() + ("permitted_contacts" to listOf(1)))
        }
    }

    @Test
    fun `rejects issued_at without trailing Z`() {
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationMatrix.fromJsonMap(validMatrix() + ("issued_at" to "2026-10-14T00:00:00+00:00"))
        }
    }

    @Test
    fun `rejects issued_at not a timestamp`() {
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationMatrix.fromJsonMap(validMatrix() + ("issued_at" to "yesterday"))
        }
    }

    @Test
    fun `rejects empty clearance`() {
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationMatrix.fromJsonMap(validMatrix() + ("clearance" to ""))
        }
    }

    // ---------- signed matrix ----------

    @Test
    fun `accepts a fully valid signed matrix`() {
        val signed = linkedMapOf<String, Any?>(
            "domain" to SignedMatrix.DOMAIN,
            "matrix" to validMatrix(),
        )
        val parsed = SignedMatrix.fromJsonMap(signed)
        assertEquals(SignedMatrix.DOMAIN, parsed.domain)
        assertEquals("device-001", parsed.matrix.deviceId)
    }

    @Test
    fun `rejects wrong domain`() {
        val signed = linkedMapOf<String, Any?>(
            "domain" to "umoja.something-else.v1",
            "matrix" to validMatrix(),
        )
        assertThrows(IllegalArgumentException::class.java) { SignedMatrix.fromJsonMap(signed) }
    }

    @Test
    fun `rejects missing domain`() {
        val signed = linkedMapOf<String, Any?>("matrix" to validMatrix())
        assertThrows(IllegalArgumentException::class.java) { SignedMatrix.fromJsonMap(signed) }
    }

    @Test
    fun `rejects missing matrix`() {
        val signed = linkedMapOf<String, Any?>("domain" to SignedMatrix.DOMAIN)
        assertThrows(IllegalArgumentException::class.java) { SignedMatrix.fromJsonMap(signed) }
    }

    @Test
    fun `rejects nested matrix that fails its own validation`() {
        val signed = linkedMapOf<String, Any?>(
            "domain" to SignedMatrix.DOMAIN,
            "matrix" to linkedMapOf<String, Any?>("version" to -1),
        )
        assertThrows(IllegalArgumentException::class.java) { SignedMatrix.fromJsonMap(signed) }
    }

    // ---------- round-trip ----------

    @Test
    fun `toJsonMap and fromJsonMap round-trip`() {
        val m = AuthorizationMatrix.fromJsonMap(validMatrix())
        val round = AuthorizationMatrix.fromJsonMap(m.toJsonMap())
        assertEquals(m, round)
    }

    @Test
    fun `SignedMatrix toJsonMap and fromJsonMap round-trip`() {
        val s = SignedMatrix(SignedMatrix.DOMAIN, AuthorizationMatrix.fromJsonMap(validMatrix()))
        val round = SignedMatrix.fromJsonMap(s.toJsonMap())
        assertEquals(s, round)
    }
}
