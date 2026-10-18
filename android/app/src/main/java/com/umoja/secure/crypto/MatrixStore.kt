package com.umoja.secure.crypto

import com.umoja.secure.storage.KeyValueStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
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

    /**
     * Write-notification, not a data cache. Bumped after every successful
     * [accept] and [clear]. UI observers use it to re-derive state
     * (e.g. ChatScreen's send-gate banner) rather than caching the
     * matrix contents. Same pattern as
     * [com.umoja.secure.crypto.IdentityChangeController.version].
     *
     * TASK-P1-038 D-1: without this signal, ChatScreen's composition-time
     * derivation goes stale when AppRoot's async matrix fetch completes
     * after the chat is already open. The initial-fetch race is not
     * hypothetical — it fires on every cold start where the user
     * navigates into chat before the fetch round-trip completes.
     */
    private val _version = MutableStateFlow(0L)
    val version: StateFlow<Long> = _version.asStateFlow()

    companion object {
        /** SecureStorage key holding the JSON envelope. */
        const val KEY: String = "provisioning.matrix.envelope"

        /** SecureStorage key holding the enrollment floor (if any). */
        const val KEY_ENROLLMENT_FLOOR: String =
            "provisioning.matrix.enrollment_floor"
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
     * parse, `"rollback"` if a matrix is already stored and the new
     * version is not strictly greater, `"below_floor"` if no matrix is
     * yet stored and the new version is below the enrollment floor.
     * Persists only on acceptance.
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
        if (current != null) {
            if (parsed.matrix.version <= current) {
                return AcceptResult.Rejected("rollback")
            }
        } else {
            val floor = enrollmentFloor()
            if (floor != null && parsed.matrix.version < floor) {
                return AcceptResult.Rejected("below_floor")
            }
        }
        store.put(KEY, encodeEnvelope(canonical, signatureBase64url))
        _version.value = _version.value + 1
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

    /**
     * Set the enrollment floor for the next [accept] on this device.
     *
     * Floor is store-owned policy, not a caller-supplied argument, so
     * the floor cannot be bypassed by an [accept] caller that fails to
     * pass it. Called by the enrollment flow (MainActivity.enrollDevice)
     * with the value from the 030c enrollment response.
     *
     * A null floor means "no floor": accept any valid version. This is
     * the bootstrap case for the first device in a fresh org.
     *
     * Per §3.7 step 1, the floor is inclusive: a matrix with
     * `version == floor` is accepted. See [accept].
     */
    fun setEnrollmentFloor(floor: Int?) {
        if (floor == null) {
            store.remove(KEY_ENROLLMENT_FLOOR)
        } else {
            store.put(KEY_ENROLLMENT_FLOOR, floor.toString())
        }
    }

    /**
     * Read the stored enrollment floor, if any. Consumed by the first
     * [accept] only; subsequent accepts use [highestSeenVersion].
     */
    fun enrollmentFloor(): Int? =
        store.get(KEY_ENROLLMENT_FLOOR)?.toIntOrNull()

    /**
     * Remove the stored matrix and enrollment floor. Only the
     * duress-wipe flow should call. The floor is part of the wipe — a
     * wiped device re-enrolls and receives a fresh floor via
     * [setEnrollmentFloor].
     */
    fun clear() {
        store.remove(KEY)
        store.remove(KEY_ENROLLMENT_FLOOR)
        _version.value = _version.value + 1
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


}
