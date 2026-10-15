package com.umoja.secure.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM tests for [EnrollmentQrPayload.build].
 *
 * Producer/consumer interop: every payload the builder accepts must be
 * parseable by [ProvisioningBundle.parse] with field values preserved.
 * A builder that produces valid-looking JSON the parser rejects is
 * still a bug, and this suite catches it.
 */
class EnrollmentQrPayloadTest {

    private fun key(c: Char): String = c.toString().repeat(43)
    private val validDeviceId = "11111111-2222-4333-8444-555555555555"

    @Test
    fun buildProducesValidPayloadThatRoundTripsThroughParser() {
        val json = EnrollmentQrPayload.build(
            deviceId = validDeviceId,
            pubDeviceAuthKey = key('A'),
            pubMessagingIdentityKey = key('B'),
            pubWipeConfirmationKey = key('C'),
        )
        val parsed = ProvisioningBundle.parse(json)
        assertEquals(validDeviceId, parsed.deviceId)
        assertEquals(key('A'), parsed.pubDeviceAuthKey)
        assertEquals(key('B'), parsed.pubMessagingIdentityKey)
        assertEquals(key('C'), parsed.pubWipeConfirmationKey)
    }

    @Test
    fun buildIsDeterministicForSameInputs() {
        val a = EnrollmentQrPayload.build(validDeviceId, key('A'), key('B'), key('C'))
        val b = EnrollmentQrPayload.build(validDeviceId, key('A'), key('B'), key('C'))
        assertEquals("same input must produce byte-identical output", a, b)
    }

    @Test
    fun buildEmitsCorrectDomain() {
        val json = EnrollmentQrPayload.build(validDeviceId, key('A'), key('B'), key('C'))
        assertTrue(
            "payload must contain the domain field",
            json.contains("\"domain\":\"umoja.enrollment-request.v1\""),
        )
    }

    @Test
    fun buildPreservesFieldOrder() {
        // Not load-bearing for the parser, but stable for reproducibility.
        val json = EnrollmentQrPayload.build(validDeviceId, key('A'), key('B'), key('C'))
        val iDomain = json.indexOf("\"domain\"")
        val iDeviceId = json.indexOf("\"device_id\"")
        val iAuth = json.indexOf("\"pub_device_auth_key\"")
        val iMsg = json.indexOf("\"pub_messaging_identity_key\"")
        val iWipe = json.indexOf("\"pub_wipe_confirmation_key\"")
        assertTrue("domain before device_id", iDomain in 0 until iDeviceId)
        assertTrue("device_id before auth", iDeviceId < iAuth)
        assertTrue("auth before msg", iAuth < iMsg)
        assertTrue("msg before wipe", iMsg < iWipe)
    }

    @Test(expected = IllegalArgumentException::class)
    fun buildRejectsDeviceIdWithNonPrintableChars() {
        EnrollmentQrPayload.build(
            deviceId = "has\u0007bell",
            pubDeviceAuthKey = key('A'),
            pubMessagingIdentityKey = key('B'),
            pubWipeConfirmationKey = key('C'),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun buildRejectsEmptyDeviceId() {
        EnrollmentQrPayload.build(
            deviceId = "",
            pubDeviceAuthKey = key('A'),
            pubMessagingIdentityKey = key('B'),
            pubWipeConfirmationKey = key('C'),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun buildRejectsDeviceIdOverMaxLength() {
        EnrollmentQrPayload.build(
            deviceId = "a".repeat(65),
            pubDeviceAuthKey = key('A'),
            pubMessagingIdentityKey = key('B'),
            pubWipeConfirmationKey = key('C'),
        )
    }

    @Test
    fun buildAcceptsDeviceIdAtMaxLength() {
        val id = "a".repeat(64)
        val json = EnrollmentQrPayload.build(id, key('A'), key('B'), key('C'))
        val parsed = ProvisioningBundle.parse(json)
        assertEquals(id, parsed.deviceId)
    }

    @Test(expected = IllegalArgumentException::class)
    fun buildRejectsShortPubKey() {
        EnrollmentQrPayload.build(
            deviceId = validDeviceId,
            pubDeviceAuthKey = "AAAA",
            pubMessagingIdentityKey = key('B'),
            pubWipeConfirmationKey = key('C'),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun buildRejectsPubKeyWithPadding() {
        // '=' padding is not valid base64url no-pad.
        EnrollmentQrPayload.build(
            deviceId = validDeviceId,
            pubDeviceAuthKey = key('A'),
            pubMessagingIdentityKey = key('B'),
            pubWipeConfirmationKey = "=" + key('C').substring(1),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun buildRejectsPubKeyWithPlusSlash() {
        // Classic base64 chars + and / are not base64url.
        EnrollmentQrPayload.build(
            deviceId = validDeviceId,
            pubDeviceAuthKey = "+".repeat(43),
            pubMessagingIdentityKey = key('B'),
            pubWipeConfirmationKey = key('C'),
        )
    }

    @Test
    fun buildRoundTripsAllThreeDistinctKeys() {
        val auth = key('A')
        val msg = key('B')
        val wipe = key('C')
        val json = EnrollmentQrPayload.build(validDeviceId, auth, msg, wipe)
        val parsed = ProvisioningBundle.parse(json)
        assertEquals(auth, parsed.pubDeviceAuthKey)
        assertEquals(msg, parsed.pubMessagingIdentityKey)
        assertEquals(wipe, parsed.pubWipeConfirmationKey)
    }
}
