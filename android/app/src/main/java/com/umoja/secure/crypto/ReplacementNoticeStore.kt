package com.umoja.secure.crypto

import com.umoja.secure.storage.KeyValueStore
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.security.PublicKey
import java.time.Instant
import java.util.Base64

/** Decision on a replacement notice: accept or reject the continuity. */
enum class AckDecision { ACCEPT, REJECT }

/**
 * Persistent store for incoming replacement notices and local ack state.
 *
 * Discovery is separate from unblock. This store holds the local state
 * that drives both: `pendingNotices()` is what the UI surfaces,
 * `blockStateFor(toDeviceId)` is what the send path consults. Both are
 * derived from the same stored list.
 *
 * **Storage shape.** A single JSON envelope under [KEY]:
 *
 *   {"notices": [{notice_hash, canonical_b64u, signature_b64u,
 *                 from_device_id, to_device_id, issued_at,
 *                 state, acked_at}, ...]}
 *
 * A single key, not one key per notice — [KeyValueStore] has no
 * `allKeys()` in its public surface, so per-notice keys would require
 * an interface change. Per-notice keys would be preferable at scale;
 * for Phase 1 notice counts (a handful per device) the list is fine.
 *
 * **Verify on write, trust on read.** [recordNotice] verifies the
 * incoming signature against [trustedKeys] before storing. Later reads
 * ([pendingNotices], [blockStateFor]) do not re-verify — the trust
 * anchor is the moment of receipt. Mirrors [MatrixStore]'s contract.
 *
 * **Q3 ruling — rejection blocks permanently for that specific notice.**
 * [blockStateFor] returns the state of the *newest* notice (by
 * `issued_at`) for the given target device. A later notice from the
 * admin supersedes an earlier one — the recovery path for a rejected
 * continuity is a new notice, not a re-decision on the old one.
 *
 * **Signing without a PrivateKey.** The ack signer takes a
 * `(ByteArray) -> ByteArray` function, not a [java.security.PrivateKey]
 * — the device auth key is Keystore-backed and non-exportable. Production
 * wires `deviceKeyManager.sign(digest)`; tests wire a BouncyCastle-backed
 * lambda. Two custody models, two entry points, no convenience overload.
 *
 * Task: TASK-P1-030 030e-c 3b
 * ADR: ADR-IDENTITY-CHANGE-001 §3, §5, §7
 */
class ReplacementNoticeStore(
    private val store: KeyValueStore,
    private val signingFn: (ByteArray) -> ByteArray,
    private val ackingDeviceId: String,
) {

    companion object {
        const val KEY: String = "identity_change.notices"
    }

    enum class State { PENDING, ACKED_ACCEPT, ACKED_REJECT }

    data class StoredNotice(
        val noticeHash: String,
        val canonicalB64u: String,
        val signatureB64u: String,
        val fromDeviceId: String,
        val toDeviceId: String,
        val issuedAt: String,
        val state: State,
        val ackedAt: String?,
    )

    sealed class RecordResult {
        data class Pending(val noticeHash: String) : RecordResult()
        data class AlreadyAcked(val noticeHash: String, val decision: String) : RecordResult()
        data class AlreadyRejected(val noticeHash: String) : RecordResult()
        data class Invalid(val reason: String) : RecordResult()
    }

    sealed class BlockState {
        object Unblocked : BlockState()
        data class Blocked(val reason: Reason) : BlockState()
        enum class Reason { PENDING, REJECTED }
    }

    data class SignedAck(
        val wrapper: SignedIdentityChangeAck,
        val canonicalUtf8: String,
        val signatureBase64url: String,
    )

    /**
     * Verify, parse, and store an incoming replacement notice.
     *
     * Order: signature verification first (trust gate), parse second
     * (extract fields), persist third. A record that has not been
     * verified never reaches the store.
     *
     * Idempotent with respect to already-stored notices: same
     * `notice_hash` returns the current local state without
     * re-prompting. This is what makes the polling loop safe.
     */
    fun recordNotice(
        canonical: ByteArray,
        signatureBase64url: String,
        trustedKeys: Set<PublicKey>,
    ): RecordResult {
        if (!ReplacementNoticeVerifier.verify(canonical, signatureBase64url, trustedKeys)) {
            return RecordResult.Invalid("signature")
        }
        val parsed = try {
            SignedReplacementNotice.fromJsonMap(
                jsonObjectToPlainMap(JSONObject(String(canonical, Charsets.UTF_8))),
            )
        } catch (_: Exception) {
            return RecordResult.Invalid("malformed")
        }
        val noticeHash = sha256B64u(canonical)
        val existing = loadAll().firstOrNull { it.noticeHash == noticeHash }
        if (existing != null) {
            return when (existing.state) {
                State.PENDING -> RecordResult.Pending(noticeHash)
                State.ACKED_ACCEPT -> RecordResult.AlreadyAcked(noticeHash, "accept")
                State.ACKED_REJECT -> RecordResult.AlreadyRejected(noticeHash)
            }
        }
        val stored = StoredNotice(
            noticeHash = noticeHash,
            canonicalB64u = Base64.getUrlEncoder().withoutPadding().encodeToString(canonical),
            signatureB64u = signatureBase64url,
            fromDeviceId = parsed.notice.fromDeviceId,
            toDeviceId = parsed.notice.toDeviceId,
            issuedAt = parsed.notice.issuedAt,
            state = State.PENDING,
            ackedAt = null,
        )
        saveAll(loadAll() + stored)
        return RecordResult.Pending(noticeHash)
    }

    /** Notices awaiting local ack. */
    fun pendingNotices(): List<StoredNotice> = loadAll().filter { it.state == State.PENDING }

    /**
     * All stored notices, any state. Used by consumers that need to
     * derive policy from the full history — [IdentityChangeController.gateFor]
     * needs ACKED_REJECT visibility to answer "is this peer's continuity
     * blocked?", which [pendingNotices] (PENDING only) cannot serve.
     *
     * Not a wider trust surface: every returned notice was verified at
     * [recordNotice] time and has not been re-verified since — same
     * trust model as [pendingNotices] and [blockStateFor].
     */
    fun allNotices(): List<StoredNotice> = loadAll()

    /**
     * Block state for a target device. Newest notice wins (Q3).
     *
     * No matching notice → Unblocked.
     * Newest PENDING → Blocked(PENDING).
     * Newest ACKED_ACCEPT → Unblocked (peer accepted the continuity).
     * Newest ACKED_REJECT → Blocked(REJECTED).
     */
    fun blockStateFor(toDeviceId: String): BlockState {
        val matching = loadAll().filter { it.toDeviceId == toDeviceId }
        if (matching.isEmpty()) return BlockState.Unblocked
        val newest = matching.maxByOrNull { it.issuedAt } ?: return BlockState.Unblocked
        return when (newest.state) {
            State.PENDING -> BlockState.Blocked(BlockState.Reason.PENDING)
            State.ACKED_ACCEPT -> BlockState.Unblocked
            State.ACKED_REJECT -> BlockState.Blocked(BlockState.Reason.REJECTED)
        }
    }

    /**
     * Build and sign an ack for [noticeHash]. Does NOT persist — the
     * caller posts the returned artifact, then calls [markAcked] only
     * on successful HTTP POST. A failed POST leaves the state PENDING,
     * the banner stays, the user can retry.
     *
     * Idempotent at the backend on replay: PK
     * `(notice_hash, acking_device_id)` DO NOTHING, so a crash between
     * POST and [markAcked] recovers on re-ack. See backend acks.ts.
     */
    fun ack(noticeHash: String, decision: AckDecision): SignedAck {
        val decisionStr = when (decision) {
            AckDecision.ACCEPT -> "accept"
            AckDecision.REJECT -> "reject"
        }
        val wrapper = SignedIdentityChangeAck(
            domain = SignedIdentityChangeAck.DOMAIN,
            ack = IdentityChangeAck(
                noticeHash = noticeHash,
                ackingDeviceId = ackingDeviceId,
                decision = decisionStr,
                issuedAt = Instant.now().toString(),
            ),
        )
        val canonicalUtf8 = jcsCanonicalizeString(wrapper.toJsonMap())
        val signature = IdentityChangeAckSigner.signWithDeviceKey(wrapper, signingFn)
        return SignedAck(wrapper, canonicalUtf8, signature)
    }

    /**
     * Persist the state transition after a successful POST. No-op if
     * the notice isn't found or isn't PENDING — recovery is by
     * re-polling, not by resurrecting deleted state.
     */
    fun markAcked(noticeHash: String, decision: AckDecision) {
        val notices = loadAll().toMutableList()
        val idx = notices.indexOfFirst { it.noticeHash == noticeHash }
        if (idx < 0) return
        val current = notices[idx]
        if (current.state != State.PENDING) return
        val newState = when (decision) {
            AckDecision.ACCEPT -> State.ACKED_ACCEPT
            AckDecision.REJECT -> State.ACKED_REJECT
        }
        notices[idx] = current.copy(
            state = newState,
            ackedAt = Instant.now().toString(),
        )
        saveAll(notices)
    }

    /** Remove all stored notices and ack state. Only the duress-wipe flow should call. */
    fun clear() {
        store.remove(KEY)
    }

    // ---------- persistence ----------

    private fun loadAll(): List<StoredNotice> {
        val raw = store.get(KEY) ?: return emptyList()
        return try {
            val arr = JSONObject(raw).getJSONArray("notices")
            (0 until arr.length()).map { i -> parseStored(arr.getJSONObject(i)) }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun saveAll(notices: List<StoredNotice>) {
        val arr = JSONArray()
        for (n in notices) arr.put(serializeStored(n))
        store.put(KEY, JSONObject().put("notices", arr).toString())
    }

    private fun parseStored(jo: JSONObject): StoredNotice = StoredNotice(
        noticeHash = jo.getString("notice_hash"),
        canonicalB64u = jo.getString("canonical_b64u"),
        signatureB64u = jo.getString("signature_b64u"),
        fromDeviceId = jo.getString("from_device_id"),
        toDeviceId = jo.getString("to_device_id"),
        issuedAt = jo.getString("issued_at"),
        state = when (jo.getString("state")) {
            "pending" -> State.PENDING
            "acked_accept" -> State.ACKED_ACCEPT
            "acked_reject" -> State.ACKED_REJECT
            else -> throw IllegalArgumentException("unknown state")
        },
        ackedAt = if (jo.isNull("acked_at")) null else jo.getString("acked_at"),
    )

    private fun serializeStored(n: StoredNotice): JSONObject = JSONObject().apply {
        put("notice_hash", n.noticeHash)
        put("canonical_b64u", n.canonicalB64u)
        put("signature_b64u", n.signatureB64u)
        put("from_device_id", n.fromDeviceId)
        put("to_device_id", n.toDeviceId)
        put("issued_at", n.issuedAt)
        put("state", when (n.state) {
            State.PENDING -> "pending"
            State.ACKED_ACCEPT -> "acked_accept"
            State.ACKED_REJECT -> "acked_reject"
        })
        put("acked_at", n.ackedAt ?: JSONObject.NULL)
    }

    private fun sha256B64u(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(bytes))
}
