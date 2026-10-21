package com.umoja.secure.crypto

import com.umoja.secure.storage.KeyValueStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.time.Instant
import java.util.Base64

class RecoveryNoticeStoreTest {

    private class InMemoryStore : KeyValueStore {
        private val m = mutableMapOf<String, String>()
        override fun get(key: String) = m[key]
        override fun put(key: String, value: String) { m[key] = value }
        override fun remove(key: String) { m.remove(key) }
        override fun has(key: String) = m.containsKey(key)
    }

    private val recoveryKeyPair: KeyPair =
        KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    private val initialCurrentKeyPair: KeyPair =
        KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    private val newKeyPair: KeyPair =
        KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    private val initialCurrentB64: String = rawB64u(initialCurrentKeyPair)
    private val newKeyB64: String = rawB64u(newKeyPair)
    private val initialCurrentFingerprint: String =
        ProvisioningKeys.fingerprintOf(initialCurrentKeyPair.public)

    private val nowMillis: Long = 1_700_000_000_000L

    private fun store(kv: InMemoryStore) = RecoveryNoticeStore(
        store = kv,
        recoveryPubkey = recoveryKeyPair.public,
        failureLog = null,
    )

    private fun seededKv(): InMemoryStore = InMemoryStore().also {
        it.put(ProvisioningKeys.STORAGE_KEY_CURRENT_PROVISIONING_PUBKEY, initialCurrentB64)
    }

    private fun makeRotation(v: Int, newKey: String = newKeyB64, overlapSec: Int = 3600,
                             effectiveAtMillis: Long = nowMillis):
        Pair<SignedKeyRotationNotice, String> {
        val notice = KeyRotationNotice(
            newProvisioningKey = newKey,
            overlapWindowSeconds = overlapSec,
            effectiveAt = Instant.ofEpochMilli(effectiveAtMillis).toString(),
            nonce = uuid(v, 1),
            eventId = uuid(v, 2),
            recoveryKeyVersion = v,
        )
        val signed = SignedKeyRotationNotice(domain = SignedKeyRotationNotice.DOMAIN, notice = notice)
        val sig = RecoveryNoticeSigner.signKeyRotation(signed, recoveryKeyPair.private)
        return signed to sig
    }

    private fun makeRevocation(v: Int, revokedFingerprint: String,
                               newKey: String = newKeyB64,
                               effectiveAtMillis: Long = nowMillis):
        Pair<SignedKeyRevocationNotice, String> {
        val notice = KeyRevocationNotice(
            revokedProvisioningKeyId = revokedFingerprint,
            newProvisioningKey = newKey,
            effectiveAt = Instant.ofEpochMilli(effectiveAtMillis).toString(),
            nonce = uuid(v, 3),
            eventId = uuid(v, 4),
            recoveryKeyVersion = v,
        )
        val signed = SignedKeyRevocationNotice(domain = SignedKeyRevocationNotice.DOMAIN, notice = notice)
        val sig = RecoveryNoticeSigner.signKeyRevocation(signed, recoveryKeyPair.private)
        return signed to sig
    }

    private fun rawB64u(kp: KeyPair): String {
        val spki = kp.public.encoded  // 44 bytes; strip 12-byte prefix
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(spki.copyOfRange(12, 44))
    }

    private fun uuid(v: Int, suffix: Int): String =
        "00000000-0000-4000-8000-%08d%04d".format(v, suffix)

    // ---- key_rotation ----

    @Test fun `TEST-ROTATION-ACCEPT-CURRENT-KEY-MATRIX`() {
        val kv = seededKv()
        val trusted = ProvisioningKeys.currentTrustedProvisioningKeys(kv, nowMillis)
        assertEquals(1, trusted.size)
        assertTrue(trusted.contains(initialCurrentKeyPair.public))
    }

    @Test fun `TEST-ROTATION-ACCEPT-PREVIOUS-KEY-DURING-OVERLAP`() {
        val kv = seededKv()
        val s = store(kv)
        val (signed, sig) = makeRotation(v = 1, overlapSec = 3600)
        assertEquals(RecoveryNoticeStore.ApplyResult.Accepted(1), s.recordKeyRotation(signed, sig))

        val midOverlap = nowMillis + 1_800_000L
        val trusted = ProvisioningKeys.currentTrustedProvisioningKeys(kv, midOverlap)
        assertEquals(2, trusted.size)
        assertTrue(trusted.contains(initialCurrentKeyPair.public))
        assertTrue(trusted.contains(newKeyPair.public))
    }

    @Test fun `TEST-ROTATION-REJECT-PREVIOUS-KEY-AFTER-OVERLAP`() {
        val kv = seededKv()
        val s = store(kv)
        val (signed, sig) = makeRotation(v = 1, overlapSec = 3600)
        s.recordKeyRotation(signed, sig)

        val afterOverlap = nowMillis + 7_200_000L
        val trusted = ProvisioningKeys.currentTrustedProvisioningKeys(kv, afterOverlap)
        assertEquals(1, trusted.size)
        assertFalse(trusted.contains(initialCurrentKeyPair.public))
        assertTrue(trusted.contains(newKeyPair.public))
    }

    @Test fun `TEST-ROTATION-REJECT-BAD-SIGNATURE`() {
        val kv = seededKv()
        val s = store(kv)
        val (signed, _) = makeRotation(v = 1)
        val result = s.recordKeyRotation(signed, "AAAA")
        assertTrue(result is RecoveryNoticeStore.ApplyResult.Rejected)
        assertEquals(RecoveryNoticeStore.RejectReason.BAD_SIGNATURE,
            (result as RecoveryNoticeStore.ApplyResult.Rejected).reason)
        assertNull(kv.get(ProvisioningKeys.STORAGE_KEY_HIGHEST_RECOVERY_KEY_VERSION))
        assertEquals(initialCurrentB64, kv.get(ProvisioningKeys.STORAGE_KEY_CURRENT_PROVISIONING_PUBKEY))
    }

    // ---- key_revocation ----

    @Test fun `TEST-REVOCATION-ACCEPT-AFTER-RECOVERY-KEY-SIGNED-NOTICE`() {
        val kv = seededKv()
        val s = store(kv)
        val (signed, sig) = makeRevocation(v = 1, revokedFingerprint = initialCurrentFingerprint)
        assertEquals(RecoveryNoticeStore.ApplyResult.Accepted(1), s.recordKeyRevocation(signed, sig))
        assertTrue(kv.get(ProvisioningKeys.STORAGE_KEY_REVOKED_PROVISIONING_KEY_FINGERPRINTS)
            ?.contains(initialCurrentFingerprint) == true)
    }

    @Test fun `TEST-REVOCATION-REJECT-MATRIX-AFTER-REVOCATION`() {
        val kv = seededKv()
        val s = store(kv)
        val (signed, sig) = makeRevocation(v = 1, revokedFingerprint = initialCurrentFingerprint)
        s.recordKeyRevocation(signed, sig)

        val trusted = ProvisioningKeys.currentTrustedProvisioningKeys(kv, nowMillis)
        assertTrue("empty trusted set after current key revoked", trusted.isEmpty())
    }

    @Test fun `TEST-REVOCATION-ROLLBACK-REJECTED`() {
        val kv = seededKv()
        val s = store(kv)
        val (ok, okSig) = makeRevocation(v = 5,
            revokedFingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        assertEquals(RecoveryNoticeStore.ApplyResult.Accepted(5), s.recordKeyRevocation(ok, okSig))

        val (rollback, rollbackSig) = makeRevocation(v = 4,
            revokedFingerprint = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
        val result = s.recordKeyRevocation(rollback, rollbackSig)
        assertTrue(result is RecoveryNoticeStore.ApplyResult.Rejected)
        assertEquals(RecoveryNoticeStore.RejectReason.OUT_OF_ORDER,
            (result as RecoveryNoticeStore.ApplyResult.Rejected).reason)
    }

    // ---- moved from P1-035 v0.12 (TEST-RECKEY-007..010) ----

    @Test fun `TEST-RECKEY-007 post-revocation matrix signed by revoked key rejected`() {
        val kv = seededKv()
        val s = store(kv)
        val (signed, sig) = makeRevocation(v = 1, revokedFingerprint = initialCurrentFingerprint)
        s.recordKeyRevocation(signed, sig)
        assertFalse(ProvisioningKeys.currentTrustedProvisioningKeys(kv, nowMillis)
            .contains(initialCurrentKeyPair.public))
    }

    @Test fun `TEST-RECKEY-008 new matrix signed by new provisioning key accepted`() {
        val kv = seededKv()
        val s = store(kv)
        val (signed, sig) = makeRotation(v = 1)
        s.recordKeyRotation(signed, sig)
        assertTrue(ProvisioningKeys.currentTrustedProvisioningKeys(kv, nowMillis)
            .contains(newKeyPair.public))
    }

    @Test fun `TEST-RECKEY-009 out-of-order recovery notice rejected`() {
        val kv = seededKv()
        val s = store(kv)
        val (first, firstSig) = makeRotation(v = 5)
        s.recordKeyRotation(first, firstSig)
        val (stale, staleSig) = makeRotation(v = 4, newKey = initialCurrentB64)
        val result = s.recordKeyRotation(stale, staleSig)
        assertTrue(result is RecoveryNoticeStore.ApplyResult.Rejected)
        assertEquals(RecoveryNoticeStore.RejectReason.OUT_OF_ORDER,
            (result as RecoveryNoticeStore.ApplyResult.Rejected).reason)
    }

    @Test fun `TEST-RECKEY-010 conflicting same-version notices second rejected`() {
        val kv = seededKv()
        val s = store(kv)
        val (first, firstSig) = makeRotation(v = 1)
        assertEquals(RecoveryNoticeStore.ApplyResult.Accepted(1), s.recordKeyRotation(first, firstSig))

        val (conflict, conflictSig) = makeRotation(v = 1, newKey = initialCurrentB64)
        val result = s.recordKeyRotation(conflict, conflictSig)
        assertTrue(result is RecoveryNoticeStore.ApplyResult.Rejected)
        assertEquals(RecoveryNoticeStore.RejectReason.OUT_OF_ORDER,
            (result as RecoveryNoticeStore.ApplyResult.Rejected).reason)
    }

    @Test fun `TEST-NOTICE-STORE-CLEAR`() {
        val kv = seededKv()
        val s = store(kv)
        val (rot, rotSig) = makeRotation(v = 1)
        s.recordKeyRotation(rot, rotSig)
        assertEquals("1", kv.get(ProvisioningKeys.STORAGE_KEY_HIGHEST_RECOVERY_KEY_VERSION))

        s.clear()
        assertNull(kv.get(ProvisioningKeys.STORAGE_KEY_CURRENT_PROVISIONING_PUBKEY))
        assertNull(kv.get(ProvisioningKeys.STORAGE_KEY_PREVIOUS_PROVISIONING_PUBKEY))
        assertNull(kv.get(ProvisioningKeys.STORAGE_KEY_PREVIOUS_PROVISIONING_PUBKEY_OVERLAP_ENDS_AT_MILLIS))
        assertNull(kv.get(ProvisioningKeys.STORAGE_KEY_HIGHEST_RECOVERY_KEY_VERSION))
        assertNull(kv.get(ProvisioningKeys.STORAGE_KEY_REVOKED_PROVISIONING_KEY_FINGERPRINTS))

        val trusted = ProvisioningKeys.currentTrustedProvisioningKeys(kv, nowMillis)
        assertEquals("cleared store falls back to BuildConfig default",
            1, trusted.size)
    }
}