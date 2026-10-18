package com.umoja.secure.crypto

import com.umoja.secure.storage.KeyValueStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Behaviour tests for [VerificationFailureStore].
 *
 * End-to-end wiring tests (where MatrixStore.accept calls record())
 * live in [MatrixStoreTest] and [ReplacementNoticeStoreTest] as
 * registry §B's TEST-DIAG-VERIFICATION-FAILURE-LOGGED and
 * TEST-DIAG-VERIFICATION-LOG-CLEARED-ON-WIPE. These tests exercise
 * the store in isolation — one class, one concern.
 */
class VerificationFailureStoreTest {

    private class InMemoryStore : KeyValueStore {
        val map = mutableMapOf<String, String>()
        override fun put(key: String, value: String) { map[key] = value }
        override fun get(key: String): String? = map[key]
        override fun remove(key: String) { map.remove(key) }
        override fun has(key: String): Boolean = map.containsKey(key)
    }

    private fun sample(reason: String = "signature"): ByteArray =
        "sample-canonical-bytes".toByteArray()

    @Test
    fun `record appends entry with expected fields`() {
        val store = VerificationFailureStore(InMemoryStore())
        store.record(
            VerificationFailureStore.ArtifactType.MATRIX,
            "signature",
            sample(),
        )
        val entries = store.entries()
        assertEquals(1, entries.size)
        val e = entries[0]
        assertEquals(VerificationFailureStore.ArtifactType.MATRIX, e.artifactType)
        assertEquals("signature", e.reason)
        assertEquals(8, e.canonicalTruncated.length)
        assertTrue(e.timestampMs > 0L)
    }

    @Test
    fun `record trims to MAX_ENTRIES oldest-first`() {
        val store = VerificationFailureStore(InMemoryStore())
        repeat(25) { i ->
            store.record(
                VerificationFailureStore.ArtifactType.MATRIX,
                "reason-$i",
                sample(),
            )
        }
        val entries = store.entries()
        assertEquals(VerificationFailureStore.MAX_ENTRIES, entries.size)
        // Oldest kept should be reason-5 (0..24 => last 20 = indices 5..24)
        assertEquals("reason-5", entries.first().reason)
        assertEquals("reason-24", entries.last().reason)
    }

    @Test
    fun `entries returns empty on fresh store`() {
        val store = VerificationFailureStore(InMemoryStore())
        assertEquals(0, store.entries().size)
    }

    @Test
    fun `clear removes all entries`() {
        val store = VerificationFailureStore(InMemoryStore())
        store.record(VerificationFailureStore.ArtifactType.MATRIX, "sig", sample())
        store.record(VerificationFailureStore.ArtifactType.NOTICE, "sig", sample())
        assertEquals(2, store.entries().size)
        store.clear()
        assertEquals(0, store.entries().size)
    }

    @Test
    fun `clearOf MATRIX removes only matrix entries`() {
        val store = VerificationFailureStore(InMemoryStore())
        store.record(VerificationFailureStore.ArtifactType.MATRIX, "sig", sample())
        store.record(VerificationFailureStore.ArtifactType.NOTICE, "sig", sample())
        store.record(VerificationFailureStore.ArtifactType.ACK, "no_session", ByteArray(0))
        store.clearOf(VerificationFailureStore.ArtifactType.MATRIX)
        val entries = store.entries()
        assertEquals(2, entries.size)
        assertTrue(entries.all { it.artifactType != VerificationFailureStore.ArtifactType.MATRIX })
    }

    @Test
    fun `clearOf NOTICE preserves MATRIX and ACK`() {
        val store = VerificationFailureStore(InMemoryStore())
        store.record(VerificationFailureStore.ArtifactType.MATRIX, "sig", sample())
        store.record(VerificationFailureStore.ArtifactType.NOTICE, "sig", sample())
        store.record(VerificationFailureStore.ArtifactType.ACK, "no_session", ByteArray(0))
        store.clearOf(VerificationFailureStore.ArtifactType.NOTICE)
        val entries = store.entries()
        assertEquals(2, entries.size)
        assertTrue(entries.all { it.artifactType != VerificationFailureStore.ArtifactType.NOTICE })
    }

    @Test
    fun `clearOf on absent type does not error`() {
        val store = VerificationFailureStore(InMemoryStore())
        store.record(VerificationFailureStore.ArtifactType.MATRIX, "sig", sample())
        store.clearOf(VerificationFailureStore.ArtifactType.ACK)
        assertEquals(1, store.entries().size)
    }

    @Test
    fun `empty canonical bytes yields empty fingerprint`() {
        val store = VerificationFailureStore(InMemoryStore())
        store.record(VerificationFailureStore.ArtifactType.ACK, "no_session", ByteArray(0))
        val e = store.entries().single()
        assertEquals("", e.canonicalTruncated)
    }

    @Test
    fun `malformed JSON in store returns empty list defensively`() {
        val backing = InMemoryStore()
        backing.put(VerificationFailureStore.KEY, "not-json-at-all")
        val store = VerificationFailureStore(backing)
        assertEquals(0, store.entries().size)
    }

    @Test
    fun `subsequent record after malformed recovers cleanly`() {
        val backing = InMemoryStore()
        backing.put(VerificationFailureStore.KEY, "[{\"ts\": broken}]")
        val store = VerificationFailureStore(backing)
        store.record(VerificationFailureStore.ArtifactType.MATRIX, "sig", sample())
        val entries = store.entries()
        // Bad row skipped, new row preserved.
        assertEquals(1, entries.size)
        assertEquals("sig", entries[0].reason)
    }
}
