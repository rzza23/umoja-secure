package com.umoja.secure.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the identity-change-ack schema validator.
 *
 * Shape only — not signing, not canonicalization. Mirrors
 * backend/src/crypto/identity-change-ack.test.ts except for the
 * "non-object wrapper" case, which is enforced by Kotlin's type
 * signature (`fromJsonMap(m: Map<String, Any?>)`) rather than runtime
 * validation — structurally impossible to call with a non-map.
 *
 * Task: TASK-P1-030 030e-c
 * ADR: ADR-IDENTITY-CHANGE-001 §3
 */
class IdentityChangeAckTest {

    private val validHash = "A".repeat(43)
    private val validDeviceId = "11111111-1111-1111-1111-111111111111"

    private fun validAck(): Map<String, Any?> = linkedMapOf(
        "notice_hash" to validHash,
        "acking_device_id" to validDeviceId,
        "decision" to "accept",
        "issued_at" to "2026-10-17T12:00:00Z",
    )

    private fun validWrapper(): Map<String, Any?> = linkedMapOf(
        "domain" to SignedIdentityChangeAck.DOMAIN,
        "ack" to validAck(),
    )

    // ---------- accepts ----------

    @Test
    fun `accepts a well-formed ack`() {
        val ack = IdentityChangeAck.fromJsonMap(validAck())
        assertEquals(validHash, ack.noticeHash)
        assertEquals(validDeviceId, ack.ackingDeviceId)
        assertEquals("accept", ack.decision)
        assertEquals("2026-10-17T12:00:00Z", ack.issuedAt)
    }

    @Test
    fun `accepts decision reject`() {
        val m = validAck() + ("decision" to "reject")
        assertEquals("reject", IdentityChangeAck.fromJsonMap(m).decision)
    }

    @Test
    fun `accepts issued_at with fractional seconds`() {
        val m = validAck() + ("issued_at" to "2026-10-17T12:00:00.123Z")
        assertEquals(
            "2026-10-17T12:00:00.123Z",
            IdentityChangeAck.fromJsonMap(m).issuedAt,
        )
    }

    // ---------- rejects ----------

    @Test
    fun `rejects wrong domain`() {
        val m = validWrapper() + ("domain" to "umoja.replacement-notice.v1")
        assertThrows(IllegalArgumentException::class.java) {
            SignedIdentityChangeAck.fromJsonMap(m)
        }
    }

    @Test
    fun `rejects missing ack object`() {
        val m = mapOf<String, Any?>("domain" to SignedIdentityChangeAck.DOMAIN)
        assertThrows(IllegalArgumentException::class.java) {
            SignedIdentityChangeAck.fromJsonMap(m)
        }
    }

    @Test
    fun `rejects decision not in accept or reject`() {
        val m = validAck() + ("decision" to "maybe")
        assertThrows(IllegalArgumentException::class.java) {
            IdentityChangeAck.fromJsonMap(m)
        }
    }

    @Test
    fun `rejects notice_hash not 43-char base64url`() {
        val badValues = listOf(
            "",
            "short",
            "A".repeat(44),
            "A".repeat(42),
            "A".repeat(43) + "=",
        )
        for (bad in badValues) {
            val m = validAck() + ("notice_hash" to bad)
            assertThrows(
                "notice_hash=$bad should reject",
                IllegalArgumentException::class.java,
            ) { IdentityChangeAck.fromJsonMap(m) }
        }
    }

    @Test
    fun `rejects issued_at without trailing Z`() {
        val m = validAck() + ("issued_at" to "2026-10-17T12:00:00")
        assertThrows(IllegalArgumentException::class.java) {
            IdentityChangeAck.fromJsonMap(m)
        }
    }

    // ---------- round-trip ----------

    @Test
    fun `toJsonMap produces snake_case wire keys and round-trips`() {
        val ack = IdentityChangeAck.fromJsonMap(validAck())
        val wire = ack.toJsonMap()
        assertEquals(validHash, wire["notice_hash"])
        assertEquals(validDeviceId, wire["acking_device_id"])
        assertEquals("accept", wire["decision"])
        assertEquals("2026-10-17T12:00:00Z", wire["issued_at"])

        val wrapper = SignedIdentityChangeAck(
            domain = SignedIdentityChangeAck.DOMAIN,
            ack = ack,
        )
        val wrapperWire = wrapper.toJsonMap()
        assertEquals(SignedIdentityChangeAck.DOMAIN, wrapperWire["domain"])
        assertTrue(wrapperWire["ack"] is Map<*, *>)

        val reparsed = SignedIdentityChangeAck.fromJsonMap(wrapperWire)
        assertEquals(ack, reparsed.ack)
    }
}
