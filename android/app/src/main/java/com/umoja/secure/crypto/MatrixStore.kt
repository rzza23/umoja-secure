package com.umoja.secure.crypto

import com.umoja.secure.storage.KeyValueStore
import org.json.JSONArray
import org.json.JSONObject
import java.security.PublicKey
import java.util.Base64

/**
 * Persistent store for the verified authorization matrix.
 *
 * **Storage shape.** A single JSON envelope under one key:
 *
 *   {"canonical": "<base64url>", "signature": "<base64url>"}
 *
 * The canonical bytes are stored exactly as received — verification on
 * read is hash-then-verify against the same bytes, never a
 * re-canonicalization. This insulates stored matrices from future
 * changes to the canonicalizer: a drifted canonicalizer would fail new
 * receipts, not silently invalidate stored ones.
 *
 * **Parse is convenience, not trust.** [StoredMatrix.signed] is parsed
 * from [StoredMatrix.canonical] for field access. The trust anchor is
 * the canonical bytes plus signature, verified by [MatrixVerifier].
 * If [AuthorizationMatrix.fromJsonMap] is ever widened to accept a
 * broader shape, no parse-based bypass exists — the stored bytes are
 * still verified against the signature.
 *
 * **Anti-rollback.** [accept] enforces `version > highestSeenVersion()`
 * after verification and before persistence. This rule lives here, not
 * in [MatrixVerifier], so the verifier stays stateless and callers
 * cannot bypass the check by calling verify directly.
 *
 * **highestSeenVersion is derived**, not stored separately. It is
 * `load()?.signed?.matrix?.version`. Separate storage would invite a
 * crash-window inconsistency: write matrix, crash before writing
 * version, accept a rollback on next launch.
 *
 * Task: TASK-P1-026
 * Build Master: §3.6, §3.7, §3.8
 * ADR: §3, §4, §7.1.4
 */
class MatrixStore(private val store: KeyValueStore) {

    companion object {
        /** SecureStorage key holding the JSON envelope. */
        const val KEY: String = "provisioning.matrix.envelope"
    }

    /** Raw canonical bytes plus signature, plus the parsed form. */
    data class StoredMatrix(
        val canonical: ByteArray,
        val signatureBase64url: String,
        val signed: SignedMatrix,
    )

    /** Result of [accept]. */
    sealed class AcceptResult {
        data class Accepted(val version: Int) : AcceptResult()
        data class Rejected(val reason: String) : AcceptResult()
    }

    /**
     * Verify, enforce anti-rollback, and persist.
     *
     * Returns [AcceptResult.Rejected] with reason `"signature"` if
     * verification fails, `"malformed"` if the signed content does not
     * parse, `"rollback"` if the version is not strictly greater than
     * the highest already stored. Persists only on acceptance.
     */
    fun accept(
        canonical: ByteArray,
        signatureBase64url: String,
        trustedKeys: Set<PublicKey>,
    ): AcceptResult {
        if (!MatrixVerifier.verify(canonical, signatureBase64url, trustedKeys)) {
            return AcceptResult.Rejected("signature")
        }
        val parsed = try {
            parseSigned(canonical)
        } catch (_: Exception) {
            return AcceptResult.Rejected("malformed")
        }
        val current = highestSeenVersion()
        if (current != null && parsed.matrix.version <= current) {
            return AcceptResult.Rejected("rollback")
        }
        store.put(KEY, encodeEnvelope(canonical, signatureBase64url))
        return AcceptResult.Accepted(parsed.matrix.version)
    }

    /** Read the stored envelope, if any. */
    fun load(): StoredMatrix? {
        val raw = store.get(KEY) ?: return null
        val (canonical, sig) = try {
            decodeEnvelope(raw)
        } catch (_: Exception) {
            return null
        }
        val parsed = try {
            parseSigned(canonical)
        } catch (_: Exception) {
            return null
        }
        return StoredMatrix(canonical, sig, parsed)
    }

    /** The stored matrix's version, or null if none stored. */
    fun highestSeenVersion(): Int? = load()?.signed?.matrix?.version

    /** The stored matrix's permitted contacts, or null if none stored. */
    fun permittedContacts(): List<String>? = load()?.signed?.matrix?.permittedContacts

    /** Remove the stored matrix. Only the duress-wipe flow should call. */
    fun clear() {
        store.remove(KEY)
    }

    // ---------- envelope encoding ----------

    private fun encodeEnvelope(canonical: ByteArray, sig: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding().encodeToString(canonical)
        return JSONObject()
            .put("canonical", enc)
            .put("signature", sig)
            .toString()
    }

    private fun decodeEnvelope(raw: String): Pair<ByteArray, String> {
        val jo = JSONObject(raw)
        val enc = jo.getString("canonical")
        val sig = jo.getString("signature")
        return Base64.getUrlDecoder().decode(enc) to sig
    }

    // ---------- parse ----------

    private fun parseSigned(canonical: ByteArray): SignedMatrix {
        val text = String(canonical, Charsets.UTF_8)
        val map = jsonObjectToPlainMap(JSONObject(text))
        return SignedMatrix.fromJsonMap(map)
    }

    private fun jsonObjectToPlainMap(jo: JSONObject): Map<String, Any?> {
        val out = linkedMapOf<String, Any?>()
        for (key in jo.keys()) {
            out[key] = jsonValueToPlain(jo.get(key))
        }
        return out
    }

    private fun jsonValueToPlain(v: Any?): Any? = when (v) {
        null, JSONObject.NULL -> null
        is JSONObject -> jsonObjectToPlainMap(v)
        is JSONArray -> (0 until v.length()).map { jsonValueToPlain(v.get(it)) }
        else -> v
    }
}
