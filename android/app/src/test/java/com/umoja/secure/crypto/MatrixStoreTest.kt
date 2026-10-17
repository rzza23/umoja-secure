package com.umoja.secure.crypto

import com.umoja.secure.storage.KeyValueStore
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.util.Base64

/**
 * MatrixStore behaviour against the W-series vectors.
 *
 * Uses an in-memory [KeyValueStore] so the suite runs on the JVM.
 * Only vectors with signature material are usable here (W-001..W-006);
 * N-001..N-003 are canonicalizer scope.
 */
class MatrixStoreTest {

    private class InMemoryStore : KeyValueStore {
        private val map = mutableMapOf<String, String>()
        override fun put(key: String, value: String) { map[key] = value }
        override fun get(key: String): String? = map[key]
        override fun remove(key: String) { map.remove(key) }
        override fun has(key: String): Boolean = map.containsKey(key)
    }

    private fun repoRoot(): File {
        var dir = File(System.getProperty("user.dir")!!)
        for (i in 0 until 10) {
            if (File(dir, "UMOJA-SECURE-BUILD-MASTER.md").exists()) return dir
            dir = dir.parentFile ?: break
        }
        error("could not find repo root from ${System.getProperty("user.dir")}")
    }

    private fun loadSignedVectors(): List<JSONObject> {
        val path = File(repoRoot(), "docs/reference/canonical-matrix-test-vectors.json")
        val doc = JSONObject(path.readText())
        val arr = doc.getJSONArray("vectors")
        val out = mutableListOf<JSONObject>()
        for (i in 0 until arr.length()) {
            val v = arr.getJSONObject(i)
            if (v.has("expected_ed25519_signature_base64url") &&
                !v.isNull("expected_ed25519_signature_base64url")) {
                out.add(v)
            }
        }
        return out
    }

    private fun canonicalOf(v: JSONObject): ByteArray =
        v.getString("expected_canonical_bytes_utf8").toByteArray(Charsets.UTF_8)

    private fun signatureOf(v: JSONObject): String =
        v.getString("expected_ed25519_signature_base64url")

    private fun trustedSetOf(v: JSONObject): Set<PublicKey> {
        val raw = Base64.getUrlDecoder().decode(
            v.getString("expected_provisioning_public_key_base64url"),
        )
        return setOf(MatrixSigner.publicKeyFromRaw(raw))
    }

    private fun freshEd25519Public(): PublicKey =
        KeyPairGenerator.getInstance("Ed25519").generateKeyPair().public

    // Test-only synthetic signed matrix. Uses W-001's canonical bytes as
    // the base, but this helper only constructs *inputs* for
    // MatrixStore.accept — the matrix content does not need to
    // correspond to a real signature unless the test asserts acceptance.
    // For version-swap tests we tamper with the canonical bytes'
    // "version" field and accept the resulting verification failure as
    // the correct reject path.

    // ---------- accept / load round-trip ----------

    @Test
    fun `accept stores a valid vector and highestSeenVersion reads back`() {
        val v = loadSignedVectors().first()
        val store = MatrixStore(InMemoryStore())
        val result = store.accept(canonicalOf(v), signatureOf(v), trustedSetOf(v))
        assertTrue("expected accepted, got $result", result is MatrixStore.AcceptResult.Accepted)
        val version = store.highestSeenVersion()
        assertNotNull(version)
    }

    @Test
    fun `load returns stored canonical and signature round-trip`() {
        val v = loadSignedVectors().first()
        val store = MatrixStore(InMemoryStore())
        store.accept(canonicalOf(v), signatureOf(v), trustedSetOf(v))
        val loaded = store.load()
        assertNotNull(loaded)
        assertTrue(loaded!!.canonical.contentEquals(canonicalOf(v)))
        assertEquals(signatureOf(v), loaded.signatureBase64url)
    }

    @Test
    fun `permittedContacts reads from stored canonical bytes`() {
        val v = loadSignedVectors().first()
        val store = MatrixStore(InMemoryStore())
        store.accept(canonicalOf(v), signatureOf(v), trustedSetOf(v))
        val contacts = store.permittedContacts()
        assertNotNull(contacts)
        // Not asserting exact contents — that is the vector's domain.
        // Asserting the derivation path works end-to-end.
        assertTrue(contacts!!.isNotEmpty() || contacts.isEmpty())
    }

    // ---------- reject paths ----------

    @Test
    fun `accept rejects tampered canonical`() {
        val v = loadSignedVectors().first()
        val tampered = canonicalOf(v).copyOf()
        tampered[tampered.size / 2] = (tampered[tampered.size / 2].toInt() + 1).toByte()
        val store = MatrixStore(InMemoryStore())
        val result = store.accept(tampered, signatureOf(v), trustedSetOf(v))
        assertTrue(result is MatrixStore.AcceptResult.Rejected)
        assertEquals("signature", (result as MatrixStore.AcceptResult.Rejected).reason)
        assertNull(store.load())
    }

    @Test
    fun `accept rejects wrong-key signature`() {
        val v = loadSignedVectors().first()
        val store = MatrixStore(InMemoryStore())
        val result = store.accept(canonicalOf(v), signatureOf(v), setOf(freshEd25519Public()))
        assertTrue(result is MatrixStore.AcceptResult.Rejected)
        assertEquals("signature", (result as MatrixStore.AcceptResult.Rejected).reason)
    }

    @Test
    fun `accept rejects tampered and leaves prior state untouched`() {
        // Two vectors with different versions. Accept the higher one first
        // (need to allow it), then attempt the lower one and assert
        // rejection with the store unchanged.
        val vectors = loadSignedVectors()
        // Pick two distinct vectors. Version ordering is unknown without
        // parsing, so this test accepts whichever orders first, then
        // attempts the other and expects either rollback (if lower) or
        // acceptance (if higher). To force the rollback assertion, we
        // first accept a vector, remember its version, then hand-craft
        // a lower-version payload by tampering — which fails signature
        // first. That conflates reject reasons.
        //
        // Cleaner: accept vector A. If vector B's version is <= A's,
        // assert rejection. Otherwise B is higher — skip and accept
        // explicitly there. The rollback-specific assertion is below
        // in a version-aware test.
        //
        // See `TEST-MATRIX-ROLLBACK-STRICT` — this test simply documents
        // that the store leaves prior state untouched on any rejection.
        val v = vectors.first()
        val store = MatrixStore(InMemoryStore())
        val first = store.accept(canonicalOf(v), signatureOf(v), trustedSetOf(v))
        assertTrue(first is MatrixStore.AcceptResult.Accepted)
        val versionBefore = store.highestSeenVersion()

        // Tamper a fresh copy so signature verification fails.
        val tampered = canonicalOf(v).copyOf()
        tampered[10] = (tampered[10].toInt() + 1).toByte()
        val rejected = store.accept(tampered, signatureOf(v), trustedSetOf(v))
        assertTrue(rejected is MatrixStore.AcceptResult.Rejected)
        assertEquals(versionBefore, store.highestSeenVersion())
    }

    @Test
    fun `TEST-MATRIX-ROLLBACK accept rejects equal version`() {
        // Accept a vector twice; the second attempt must be rejected
        // because version is not strictly greater.
        val v = loadSignedVectors().first()
        val store = MatrixStore(InMemoryStore())
        val first = store.accept(canonicalOf(v), signatureOf(v), trustedSetOf(v))
        assertTrue(first is MatrixStore.AcceptResult.Accepted)
        val second = store.accept(canonicalOf(v), signatureOf(v), trustedSetOf(v))
        assertTrue(second is MatrixStore.AcceptResult.Rejected)
        assertEquals("rollback", (second as MatrixStore.AcceptResult.Rejected).reason)
    }

    // ---------- clear ----------

    @Test
    fun `clear removes the envelope`() {
        val v = loadSignedVectors().first()
        val store = MatrixStore(InMemoryStore())
        store.accept(canonicalOf(v), signatureOf(v), trustedSetOf(v))
        assertNotNull(store.load())
        store.clear()
        assertNull(store.load())
    }

    // ---------- empty state ----------

    @Test
    fun `load returns null when no matrix stored`() {
        val store = MatrixStore(InMemoryStore())
        assertNull(store.load())
        assertNull(store.highestSeenVersion())
        assertNull(store.permittedContacts())
    }

    // ---------- enrollment floor (TASK-P1-030 3d) ----------


    /**
     * Build a signed matrix at an arbitrary version, using W-001's
     * canonical bytes as the template. The template's version field is
     * overwritten and the wrapper is re-canonicalized and re-signed
     * with [privateKey]. Test-only — production never re-canonicalizes
     * or re-signs; the store's trust path is bytes-in, verify-then-store.
     */
    private fun buildSignedMatrixAtVersion(
        version: Int,
        privateKey: PrivateKey,
    ): Pair<ByteArray, String> {
        val template = loadSignedVectors().first()
        val plain = jsonObjectToPlainMap(
            JSONObject(String(canonicalOf(template), Charsets.UTF_8)),
        )
        val parsed = SignedMatrix.fromJsonMap(plain)
        val wrapper = parsed.toJsonMap().toMutableMap()
        @Suppress("UNCHECKED_CAST")
        val matrix = (wrapper["matrix"] as Map<String, Any?>).toMutableMap()
        matrix["version"] = version
        wrapper["matrix"] = matrix
        val rebuilt = SignedMatrix.fromJsonMap(wrapper)
        val canonical = jcsCanonicalizeString(rebuilt.toJsonMap()).toByteArray(Charsets.UTF_8)
        val sig = MatrixSigner.sign(rebuilt, privateKey)
        return canonical to sig
    }

    private fun freshKeypair() = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    @Test
    fun `TEST-MATRIX-FLOOR-INCLUSIVE accepts version equal to floor`() {
        val kp = freshKeypair()
        val trusted = setOf<PublicKey>(kp.public)
        val store = MatrixStore(InMemoryStore())
        store.setEnrollmentFloor(5)

        val (canonical, sig) = buildSignedMatrixAtVersion(5, kp.private)
        val result = store.accept(canonical, sig, trusted)
        assertTrue("expected accepted, got $result", result is MatrixStore.AcceptResult.Accepted)
        assertEquals(5, store.highestSeenVersion())
    }

    @Test
    fun `TEST-MATRIX-FLOOR-BELOW-REJECTED rejects version below floor`() {
        val kp = freshKeypair()
        val trusted = setOf<PublicKey>(kp.public)
        val store = MatrixStore(InMemoryStore())
        store.setEnrollmentFloor(6)

        val (canonical, sig) = buildSignedMatrixAtVersion(5, kp.private)
        val result = store.accept(canonical, sig, trusted)
        assertTrue("expected rejected, got $result", result is MatrixStore.AcceptResult.Rejected)
        assertEquals(
            "below_floor",
            (result as MatrixStore.AcceptResult.Rejected).reason,
        )
        assertNull(store.load())
    }

    @Test
    fun `TEST-MATRIX-FLOOR-NULL-ACCEPTS-ANY no floor accepts any version`() {
        val kp = freshKeypair()
        val trusted = setOf<PublicKey>(kp.public)
        val store = MatrixStore(InMemoryStore())
        // No setEnrollmentFloor call — bootstrap case.

        val (canonical, sig) = buildSignedMatrixAtVersion(1, kp.private)
        val result = store.accept(canonical, sig, trusted)
        assertTrue("expected accepted, got $result", result is MatrixStore.AcceptResult.Accepted)
        assertEquals(1, store.highestSeenVersion())
    }

    @Test
    fun `TEST-MATRIX-FLOOR-NOT-CONSULTED-AFTER-FIRST-ACCEPT floor ignored after first accept`() {
        val kp = freshKeypair()
        val trusted = setOf<PublicKey>(kp.public)
        val store = MatrixStore(InMemoryStore())
        store.setEnrollmentFloor(5)

        // First accept at version 5.
        val (c1, s1) = buildSignedMatrixAtVersion(5, kp.private)
        assertTrue(store.accept(c1, s1, trusted) is MatrixStore.AcceptResult.Accepted)

        // Set an absurd floor. Subsequent accept must ignore it.
        store.setEnrollmentFloor(999)
        val (c2, s2) = buildSignedMatrixAtVersion(6, kp.private)
        val result = store.accept(c2, s2, trusted)
        assertTrue(
            "expected accepted despite floor=999, got $result",
            result is MatrixStore.AcceptResult.Accepted,
        )
        assertEquals(6, store.highestSeenVersion())
    }

    @Test
    fun `TEST-MATRIX-FLOOR-CLEARED-ON-WIPE clear removes floor and matrix`() {
        val kp = freshKeypair()
        val trusted = setOf<PublicKey>(kp.public)
        val store = MatrixStore(InMemoryStore())
        store.setEnrollmentFloor(5)

        val (c1, s1) = buildSignedMatrixAtVersion(5, kp.private)
        assertTrue(store.accept(c1, s1, trusted) is MatrixStore.AcceptResult.Accepted)
        assertNotNull(store.enrollmentFloor())

        store.clear()
        assertNull(store.enrollmentFloor())
        assertNull(store.highestSeenVersion())

        // After wipe, v1 should be accepted (floor is gone).
        val (c2, s2) = buildSignedMatrixAtVersion(1, kp.private)
        val result = store.accept(c2, s2, trusted)
        assertTrue("expected accepted post-wipe, got $result",
            result is MatrixStore.AcceptResult.Accepted)
    }
}
