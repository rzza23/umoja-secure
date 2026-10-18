package com.umoja.secure.crypto

import com.umoja.secure.storage.KeyValueStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.util.Base64

/**
 * Local, user-visible log of verification failures.
 *
 * Records the fact that a verification attempt was rejected so the
 * operator can investigate "did my peer receive this" from
 * `DiagnosticsScreen`. Deliberately scoped: no backend, no telemetry,
 * no server-side audit extension (TASK-P1-041 §B non-goals).
 *
 * **Three write sites** (wired by callers, not by this class):
 *  - [MatrixStore.accept] on `AcceptResult.Rejected`
 *  - [ReplacementNoticeStore.recordNotice] on `RecordResult.Invalid`
 *  - [IdentityChangeController.ackAndPost] on `AckResult.Failure`
 *
 * Failures are recorded via a `recordFailure` callback passed into
 * those classes' constructors. That callback defaults to `null` (no
 * recording) so existing tests and construction sites compile
 * unchanged. Production wires it to an instance of this store.
 * Matches the lambda-injection precedent from
 * [com.umoja.secure.crypto.IdentityChangeController] (Session K).
 *
 * **Filtered clear, not full clear.** ADR registry §B:
 * "matrix-store wipe clears matrix-failure log; notice-store wipe
 * clears notice-failure log." So [clearOf] is the operative method —
 * `MatrixStore.clear()` calls `clearOf(MATRIX)`, `ReplacementNoticeStore.clear()`
 * calls `clearOf(NOTICE)`. Full [clear] is provided for the (hypothetical)
 * case of a full-wipe operation; not currently called in production.
 *
 * **Bounded size.** [MAX_ENTRIES] = 20. Older entries age out when the
 * limit is reached. Not configurable at runtime for Phase 1 — the log
 * is debug-only and 20 is enough for "the last few failures." If a
 * future operator needs more, add a `DiagnosticsScreen` control; do
 * not silently grow the constant.
 *
 * **Threading.** All four public methods are `@Synchronized`. Multiple
 * verification sites can fail concurrently: `MatrixStore.accept` from
 * `LaunchedEffect` on Main, `ReplacementNoticeStore.recordNotice` from
 * `refresh()` on Dispatchers.IO, `IdentityChangeController.ackAndPost`
 * from IO. A synchronized block per method serializes writes without
 * the complexity of a coroutine Mutex (these are non-suspend methods;
 * no suspension points to worry about).
 *
 * **Storage shape.** Single JSON envelope under [KEY], matching
 * [MatrixStore] and [ReplacementNoticeStore]'s pattern. One key for
 * the whole log, one `KeyValueStore` read per `entries()` call. The
 * store interface has no `allKeys()`; per-entry keys would need an
 * interface change (Session J's reasoning for [ReplacementNoticeStore]).
 *
 * **Truncated canonical bytes.** Display fingerprint is the first 8
 * base64url chars of the canonical bytes — matches the
 * `noticeHash.take(8)` / `envelopeId.take(8)` convention used in
 * `ChatScreen`'s AckDialog and DiagnosticsScreen's envelope display.
 * For ACK failures (where the failing artifact is the POST, not the
 * notice), the recorded bytes are the *notice* the ack targets; the
 * fingerprint is the notice's hash prefix. Empty bytes truncate to
 * empty string; the reason code is the primary signal in that case.
 *
 * Task: TASK-P1-041
 * Registry: US-TASK-P1-001 §B
 */
class VerificationFailureStore(private val store: KeyValueStore) {

    /**
     * Write-notification, not a data cache. Bumped after every
     * [record], [clear], and [clearOf]. The DiagnosticsScreen collects
     * it via collectAsState and re-derives the entry list on each
     * tick, matching the pattern established for [MatrixStore] in
     * Session P D-1 and [IdentityChangeController] in Session K.
     */
    private val _version = MutableStateFlow(0L)
    val version: StateFlow<Long> = _version.asStateFlow()

    enum class ArtifactType {
        MATRIX,
        NOTICE,
        ACK,
    }

    data class FailureEntry(
        val timestampMs: Long,
        val artifactType: ArtifactType,
        val reason: String,
        val canonicalTruncated: String,
    )

    /**
     * Append a failure entry. Called from [MatrixStore.accept],
     * [ReplacementNoticeStore.recordNotice], and
     * [IdentityChangeController.ackAndPost] on their respective
     * rejection paths. Trims to [MAX_ENTRIES] on each call — the
     * write is O(MAX_ENTRIES) which is 20, negligible for a debug-
     * only log.
     */
    @Synchronized
    fun record(artifactType: ArtifactType, reason: String, canonicalBytes: ByteArray) {
        val fingerprint = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(canonicalBytes).take(8)
        val entry = FailureEntry(
            timestampMs = System.currentTimeMillis(),
            artifactType = artifactType,
            reason = reason,
            canonicalTruncated = fingerprint,
        )
        val next = (loadAll() + entry).takeLast(MAX_ENTRIES)
        saveAll(next)
        _version.value = _version.value + 1
    }

    /** All recorded entries, oldest first. */
    @Synchronized
    fun entries(): List<FailureEntry> = loadAll()

    /** Remove every recorded entry. Not called in Phase 1 production paths. */
    @Synchronized
    fun clear() {
        store.remove(KEY)
        _version.value = _version.value + 1
    }

    /**
     * Remove entries for one artifact type. This is the operative
     * clear: [MatrixStore.clear] calls `clearOf(MATRIX)` and
     * [ReplacementNoticeStore.clear] calls `clearOf(NOTICE)` so
     * wiping one store does not wipe the other's failure history.
     */
    @Synchronized
    fun clearOf(type: ArtifactType) {
        val remaining = loadAll().filter { it.artifactType != type }
        if (remaining.isEmpty()) {
            store.remove(KEY)
        } else {
            saveAll(remaining)
        }
        _version.value = _version.value + 1
    }

    private fun loadAll(): List<FailureEntry> {
        val raw = store.get(KEY) ?: return emptyList()
        return try {
            val arr = JSONArray(raw)
            (0 until arr.length()).mapNotNull { i ->
                try {
                    val o = arr.getJSONObject(i)
                    FailureEntry(
                        timestampMs = o.getLong("ts"),
                        artifactType = ArtifactType.valueOf(o.getString("type")),
                        reason = o.getString("reason"),
                        canonicalTruncated = o.getString("trunc"),
                    )
                } catch (_: Exception) {
                    // Skip malformed entries; do not fail the whole log
                    // on one bad row (defensive against future storage
                    // shape changes or partial writes).
                    null
                }
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun saveAll(entries: List<FailureEntry>) {
        val arr = JSONArray()
        entries.forEach { e ->
            arr.put(JSONObject().apply {
                put("ts", e.timestampMs)
                put("type", e.artifactType.name)
                put("reason", e.reason)
                put("trunc", e.canonicalTruncated)
            })
        }
        store.put(KEY, arr.toString())
    }

    companion object {
        const val KEY = "verification.failure.log"
        const val MAX_ENTRIES = 20
    }
}
