package com.umoja.secure.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Tests for MatrixBuilder — turns a scanned provisioning bundle plus
 * admin input into the unsigned authorization-matrix wrapper.
 *
 * The builder is where TEST-PROVSCHEMA-001 is actually enforceable.
 * The schema layer cannot detect a swap between pub_device_auth_key and
 * pub_messaging_identity_key — both are 32 bytes of base64url,
 * indistinguishable by inspection. These tests prove field identity is
 * preserved end to end.
 *
 * Task: TASK-P1-025
 * ADR:  §4, §5
 */
class MatrixBuilderTest {

    private val keyA = "A".repeat(43)
    private val keyB = "B".repeat(43)
    private val keyC = "C".repeat(43)
    private val deviceId = "11111111-2222-4333-8444-555555555555"
    private val issuedAt = "2026-10-14T18:30:00Z"

    private fun bundle(): ProvisioningBundle = ProvisioningBundle(
        deviceId = deviceId,
        pubDeviceAuthKey = keyA,
        pubMessagingIdentityKey = keyB,
        pubWipeConfirmationKey = keyC,
    )

    // ---------- TEST-PROVSCHEMA-001-builder ----------

    @Test
    fun `TEST-PROVSCHEMA-001-builder — fields land in the correct slots`() {
        // Sanity: the three inputs are distinct.
        assertNotEquals(keyA, keyB)
        assertNotEquals(keyB, keyC)
        assertNotEquals(keyA, keyC)

        val signed = MatrixBuilder.build(
            bundle = bundle(),
            clearance = "standard",
            permittedContacts = listOf("device-002"),
            version = 1,
            issuedAt = issuedAt,
        )
        val m = signed.matrix
        assertEquals(deviceId, m.deviceId)
        assertEquals(keyA, m.pubDeviceAuthKey)
        assertEquals(keyB, m.pubMessagingIdentityKey)
        assertEquals(keyC, m.pubWipeConfirmationKey)
    }

    @Test
    fun `TEST-PROVSCHEMA-001-builder-negative — swapped inputs produce a different matrix`() {
        val normal = MatrixBuilder.build(bundle(), "standard", emptyList(), 1, issuedAt)
        val swapped = MatrixBuilder.build(
            bundle().copy(
                pubDeviceAuthKey = keyB,
                pubMessagingIdentityKey = keyA,
            ),
            "standard", emptyList(), 1, issuedAt,
        )
        assertNotEquals(normal.matrix.pubDeviceAuthKey, swapped.matrix.pubDeviceAuthKey)
        assertNotEquals(normal.matrix.pubMessagingIdentityKey, swapped.matrix.pubMessagingIdentityKey)
    }

    @Test
    fun `TEST-PROVSCHEMA-001-builder-negative — swapped inputs produce different canonical bytes`() {
        val normal = MatrixBuilder.build(bundle(), "standard", emptyList(), 1, issuedAt)
        val swapped = MatrixBuilder.build(
            bundle().copy(
                pubDeviceAuthKey = keyB,
                pubMessagingIdentityKey = keyA,
            ),
            "standard", emptyList(), 1, issuedAt,
        )
        val bytesN = jcsCanonicalize(normal.toJsonMap())
        val bytesS = jcsCanonicalize(swapped.toJsonMap())
        assertFalse(bytesN.contentEquals(bytesS))
    }

    // ---------- wrapper shape ----------

    @Test
    fun `wrapper carries the matrix domain`() {
        val signed = MatrixBuilder.build(bundle(), "standard", emptyList(), 1, issuedAt)
        assertEquals(SignedMatrix.DOMAIN, signed.domain)
    }

    @Test
    fun `wrapper nested map carries all eight matrix fields`() {
        val signed = MatrixBuilder.build(
            bundle(), "standard", listOf("device-003", "device-002"), 5, issuedAt,
        )
        @Suppress("UNCHECKED_CAST")
        val inner = signed.toJsonMap()["matrix"] as Map<String, Any?>
        assertEquals(
            setOf(
                "version", "device_id",
                "pub_device_auth_key", "pub_messaging_identity_key",
                "pub_wipe_confirmation_key", "clearance",
                "permitted_contacts", "issued_at",
            ),
            inner.keys,
        )
        assertEquals(5, inner["version"])
        // The builder sorts permitted_contacts for deterministic bytes.
        assertEquals(listOf("device-002", "device-003"), inner["permitted_contacts"])
    }

    // ---------- JCS stability ----------

    @Test
    fun `JCS canonical bytes are stable across two calls`() {
        val signed = MatrixBuilder.build(bundle(), "standard", emptyList(), 1, issuedAt)
        val b1 = jcsCanonicalize(signed.toJsonMap())
        val b2 = jcsCanonicalize(signed.toJsonMap())
        assertEquals(b1.toList(), b2.toList())
    }

    // ---------- schema rejection through the builder ----------

    @Test
    fun `rejects zero version`() {
        assertThrows(IllegalArgumentException::class.java) {
            MatrixBuilder.build(bundle(), "standard", emptyList(), 0, issuedAt)
        }
    }

    @Test
    fun `rejects empty clearance`() {
        assertThrows(IllegalArgumentException::class.java) {
            MatrixBuilder.build(bundle(), "", emptyList(), 1, issuedAt)
        }
    }

    @Test
    fun `rejects non-ISO issued_at`() {
        assertThrows(IllegalArgumentException::class.java) {
            MatrixBuilder.build(bundle(), "standard", emptyList(), 1, "yesterday")
        }
    }
}
