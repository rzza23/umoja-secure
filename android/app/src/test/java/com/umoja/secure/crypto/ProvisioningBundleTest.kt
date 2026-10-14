package com.umoja.secure.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Tests for the enrollment QR payload parser.
 *
 * Wire format per owner ruling 2026-10-14 (ADR §7 amendment). The
 * payload is not canonicalized and not signed in Phase 1.
 *
 * Task: TASK-P1-025
 */
class ProvisioningBundleTest {

    private val keyA = "A".repeat(43)
    private val keyB = "B".repeat(43)
    private val keyC = "C".repeat(43)
    private val deviceId = "11111111-2222-4333-8444-555555555555"

    private fun validMap(): Map<String, Any?> = linkedMapOf(
        "domain" to ProvisioningBundle.DOMAIN,
        "device_id" to deviceId,
        "pub_device_auth_key" to keyA,
        "pub_messaging_identity_key" to keyB,
        "pub_wipe_confirmation_key" to keyC,
    )

    // ---------- accepts ----------

    @Test
    fun `accepts a fully valid bundle`() {
        val b = ProvisioningBundle.fromJsonMap(validMap())
        assertEquals(deviceId, b.deviceId)
        assertEquals(keyA, b.pubDeviceAuthKey)
        assertEquals(keyB, b.pubMessagingIdentityKey)
        assertEquals(keyC, b.pubWipeConfirmationKey)
    }

    @Test
    fun `accepts a device_id at max length (64)`() {
        val id64 = "a".repeat(64)
        val b = ProvisioningBundle.fromJsonMap(validMap() + ("device_id" to id64))
        assertEquals(id64, b.deviceId)
    }

    @Test
    fun `accepts a non-UUID device_id`() {
        // The validator must not hard-require UUID format. UUID v4 is
        // the generator's recommendation, not a validator rule.
        val b = ProvisioningBundle.fromJsonMap(validMap() + ("device_id" to "device-007"))
        assertEquals("device-007", b.deviceId)
    }

    // ---------- rejects ----------

    @Test
    fun `rejects wrong domain`() {
        assertThrows(IllegalArgumentException::class.java) {
            ProvisioningBundle.fromJsonMap(validMap() + ("domain" to "umoja.something-else.v1"))
        }
    }

    @Test
    fun `rejects missing domain`() {
        assertThrows(IllegalArgumentException::class.java) {
            ProvisioningBundle.fromJsonMap(validMap() - "domain")
        }
    }

    @Test
    fun `rejects missing device_id`() {
        assertThrows(IllegalArgumentException::class.java) {
            ProvisioningBundle.fromJsonMap(validMap() - "device_id")
        }
    }

    @Test
    fun `rejects empty device_id`() {
        assertThrows(IllegalArgumentException::class.java) {
            ProvisioningBundle.fromJsonMap(validMap() + ("device_id" to ""))
        }
    }

    @Test
    fun `rejects device_id with non-printable-ASCII`() {
        assertThrows(IllegalArgumentException::class.java) {
            ProvisioningBundle.fromJsonMap(validMap() + ("device_id" to "has\ttab"))
        }
    }

    @Test
    fun `rejects device_id longer than 64 chars`() {
        assertThrows(IllegalArgumentException::class.java) {
            ProvisioningBundle.fromJsonMap(validMap() + ("device_id" to "a".repeat(65)))
        }
    }

    @Test
    fun `rejects null device_id`() {
        assertThrows(IllegalArgumentException::class.java) {
            ProvisioningBundle.fromJsonMap(validMap() + ("device_id" to null))
        }
    }

    @Test
    fun `rejects missing pub_device_auth_key`() {
        assertThrows(IllegalArgumentException::class.java) {
            ProvisioningBundle.fromJsonMap(validMap() - "pub_device_auth_key")
        }
    }

    @Test
    fun `rejects non-base64url pub_device_auth_key`() {
        assertThrows(IllegalArgumentException::class.java) {
            ProvisioningBundle.fromJsonMap(validMap() + ("pub_device_auth_key" to "has spaces"))
        }
    }

    @Test
    fun `rejects pub_device_auth_key with wrong length`() {
        assertThrows(IllegalArgumentException::class.java) {
            ProvisioningBundle.fromJsonMap(validMap() + ("pub_device_auth_key" to "AAAA"))
        }
    }

    @Test
    fun `rejects extra field`() {
        assertThrows(IllegalArgumentException::class.java) {
            ProvisioningBundle.fromJsonMap(validMap() + ("unexpected" to "value"))
        }
    }

    // ---------- parse ----------

    @Test
    fun `parse accepts valid JSON`() {
        val json = "{" +
            "\"domain\":\"${ProvisioningBundle.DOMAIN}\"," +
            "\"device_id\":\"$deviceId\"," +
            "\"pub_device_auth_key\":\"$keyA\"," +
            "\"pub_messaging_identity_key\":\"$keyB\"," +
            "\"pub_wipe_confirmation_key\":\"$keyC\"" +
            "}"
        val b = ProvisioningBundle.parse(json)
        assertEquals(deviceId, b.deviceId)
        assertEquals(keyA, b.pubDeviceAuthKey)
    }

    @Test
    fun `parse rejects malformed JSON`() {
        assertThrows(IllegalArgumentException::class.java) {
            ProvisioningBundle.parse("not-json")
        }
    }
}
