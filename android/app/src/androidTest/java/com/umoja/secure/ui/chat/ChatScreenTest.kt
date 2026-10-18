package com.umoja.secure.ui.chat

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import com.umoja.secure.crypto.IdentityChangeController
import com.umoja.secure.crypto.MatrixStore
import com.umoja.secure.crypto.ReplacementNoticeStore
import com.umoja.secure.messaging.MessagingService
import com.umoja.secure.storage.KeyValueStore
import com.umoja.secure.storage.local.Message
import com.umoja.secure.storage.local.MessageDirection
import com.umoja.secure.storage.local.MessageStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import java.util.Base64

/**
 * Compose tests for [ChatScreen] -- the last arc deliverable
 * (Session D). Refactors in sessions A (AdminScreenState) and C
 * (ChatViewModel injectable) enabled these tests; before session C
 * this file could not exist because ChatViewModel was a
 * `Context`-bound final class with no injection seam.
 *
 * Rule: [createComposeRule] -- ChatScreen's only Activity-scoped call
 * is `SecureScreen()`, which casts `LocalView.current.context as?
 * Activity` null-safely (see its KDoc). In Compose test, the cast
 * yields a ComponentActivity; FLAG_SECURE is applied silently and
 * the composition renders normally.
 *
 * Fixtures are seeded through the same [KeyValueStore] surface the
 * production stores read from. No real crypto keys, no network, no
 * disk. Notice-signature verification is bypassed by writing the
 * envelope JSON directly to the store -- the tests exercise the
 * rendering paths (banner states, composer gating, message list,
 * AckDialog open) not the signature-verification path (covered by
 * ReplacementNoticeStoreTest and IdentityChangeControllerTest).
 *
 * Coverage groups (11 tests):
 *   unauthorized peer  -- 3 tests
 *   authorized peer    -- 3 tests
 *   identity banner    -- 4 tests (pending, tap-opens-dialog,
 *                        rejected, both banners)
 *   message list       -- 2 tests (empty, bubbles)
 *   send action        -- 1 test (fires sendMessageFn)
 *
 * Deliberately NOT covered: `ackAndPost` sign->POST->markAcked
 * (needs a Keystore-backed signer; covered by controller tests at
 * the JVM layer), full send end-to-end (needs real backend; covered
 * by C's emulator walk).
 */
class ChatScreenTest {

    @get:Rule
    val composeRule = createComposeRule()

    // ============================================================
    // Fake KeyValueStore
    // ============================================================

    private class FakeKv : KeyValueStore {
        private val map = mutableMapOf<String, String>()
        override fun put(key: String, value: String) { map[key] = value }
        override fun get(key: String): String? = map[key]
        override fun remove(key: String) { map.remove(key) }
        override fun has(key: String): Boolean = map.containsKey(key)
    }

    // ============================================================
    // Matrix fixture: writes a well-formed envelope to MatrixStore.KEY
    // ============================================================

    private fun seedAuthorizedMatrix(kv: FakeKv, permitted: List<String>) {
        val matrixJson = JSONObject().apply {
            put("version", 1)
            put("device_id", "test-device-0001")
            put("pub_device_auth_key", "A".repeat(43))
            put("pub_messaging_identity_key", "B".repeat(43))
            put("pub_wipe_confirmation_key", "C".repeat(43))
            put("clearance", "SECRET")
            put("permitted_contacts", JSONArray(permitted))
            put("issued_at", "2026-10-18T20:00:00.000Z")
        }
        val wrapper = JSONObject().apply {
            put("domain", "umoja.authorization-matrix.v1")
            put("matrix", matrixJson)
        }
        val canonicalBytes = wrapper.toString().toByteArray(Charsets.UTF_8)
        val canonicalB64u = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(canonicalBytes)
        val envelope = JSONObject().apply {
            put("canonical", canonicalB64u)
            put("signature", "A".repeat(86))
        }
        kv.put(MatrixStore.KEY, envelope.toString())
    }

    // ============================================================
    // Notice fixture: writes a notices array to ReplacementNoticeStore.KEY
    // ============================================================

    private fun seedNotice(
        kv: FakeKv,
        toDeviceId: String,
        state: String,  // "pending" | "acked_accept" | "acked_reject"
        issuedAt: String = "2026-10-18T19:00:00.000Z",
    ) {
        val notice = JSONObject().apply {
            put("notice_hash", "abcdef0123456789abcdef0123456789")
            put("canonical_b64u", "fake-canonical")
            put("signature_b64u", "fake-signature")
            put("from_device_id", "old-device-0001")
            put("to_device_id", toDeviceId)
            put("issued_at", issuedAt)
            put("state", state)
            put("acked_at", JSONObject.NULL)
        }
        val existing = kv.get(ReplacementNoticeStore.KEY)
        val root = if (existing == null) JSONObject().put("notices", JSONArray())
                   else JSONObject(existing)
        root.getJSONArray("notices").put(notice)
        kv.put(ReplacementNoticeStore.KEY, root.toString())
    }

    // ============================================================
    // Fake dependencies
    // ============================================================

    private fun fakeViewModel(
        messages: List<Message> = emptyList(),
        onSend: (String, String) -> Unit = { _, _ -> },
    ): ChatViewModel = ChatViewModel(
        listMessagesFn = { messages },
        sendMessageFn = { peer, text ->
            onSend(peer, text)
            MessagingService.SendOutcome.Success("env-test", wasPreKey = false)
        },
        scope = CoroutineScope(Dispatchers.Unconfined),
    )

    private fun fakeController(kv: FakeKv): IdentityChangeController =
        IdentityChangeController(
            listNotices = { emptyList() },
            postAck = { _, _, _ ->
                com.umoja.secure.transport.IdentityChangeApi.AckResponse(
                    ackHash = "ack-test",
                    createdAt = "2026-10-18T20:00:00.000Z",
                )
            },
            store = ReplacementNoticeStore(
                store = kv,
                // Never invoked in these tests -- ackAndPost is not exercised
                // (test 8 taps "View" to open the dialog; it does not tap
                // "Acknowledge" to submit the ack). Identity passthrough satisfies
                // the constructor without involving crypto.
                signingFn = { digest -> digest },
                ackingDeviceId = "test-device-acking",
            ),
            sessionTokenProvider = { "test-token" },
            trustedKeys = emptySet(),
            failureLog = null,
        )

    private fun render(
        viewModel: ChatViewModel,
        controller: IdentityChangeController,
        matrixStore: MatrixStore,
        peerDeviceId: String = "p1",
    ) {
        composeRule.setContent {
            MaterialTheme {
                ChatScreen(
                    peerDeviceId = peerDeviceId,
                    peerLabel = "Peer One",
                    onBack = {},
                    viewModel = viewModel,
                    identityChangeController = controller,
                    matrixStore = matrixStore,
                )
            }
        }
    }

    private fun msg(text: String): Message = Message(
        id = "m-${text.hashCode()}",
        envelopeId = null,
        peerDeviceId = "p1",
        direction = MessageDirection.OUT,
        plaintext = text,
        createdAt = 0L,
        status = MessageStatus.SENT,
    )

    // ============================================================
    // Unauthorized peer (no matrix seeded)
    // ============================================================

    @Test
    fun unauthorized_peer_renders_not_authorized_banner() {
        val kv = FakeKv()
        render(fakeViewModel(), fakeController(kv), MatrixStore(kv))
        composeRule.onNodeWithText(
            "You are not authorized to message this device. " +
                "Contact your admin to resolve."
        ).assertExists()
    }

    @Test
    fun unauthorized_peer_composer_placeholder_is_sending_blocked() {
        val kv = FakeKv()
        render(fakeViewModel(), fakeController(kv), MatrixStore(kv))
        composeRule.onNodeWithText("Sending blocked").assertExists()
    }

    @Test
    fun unauthorized_peer_send_icon_is_disabled() {
        val kv = FakeKv()
        render(fakeViewModel(), fakeController(kv), MatrixStore(kv))
        composeRule.onNodeWithContentDescription("Send").assertIsNotEnabled()
    }

    // ============================================================
    // Authorized peer (matrix seeded with p1 in permitted_contacts)
    // ============================================================

    @Test
    fun authorized_peer_has_no_not_authorized_banner() {
        val kv = FakeKv()
        seedAuthorizedMatrix(kv, listOf("p1", "p2"))
        render(fakeViewModel(), fakeController(kv), MatrixStore(kv))
        composeRule.onNodeWithText(
            "You are not authorized to message this device. " +
                "Contact your admin to resolve."
        ).assertDoesNotExist()
    }

    @Test
    fun authorized_peer_composer_placeholder_is_message() {
        val kv = FakeKv()
        seedAuthorizedMatrix(kv, listOf("p1"))
        render(fakeViewModel(), fakeController(kv), MatrixStore(kv))
        composeRule.onNodeWithText("Message...").assertExists()
    }

    @Test
    fun authorized_peer_send_icon_enabled_after_text_entry() {
        val kv = FakeKv()
        seedAuthorizedMatrix(kv, listOf("p1"))
        render(fakeViewModel(), fakeController(kv), MatrixStore(kv))
        composeRule.onNode(hasSetTextAction()).performTextInput("hello")
        composeRule.onNodeWithContentDescription("Send").assertIsEnabled()
    }

    // ============================================================
    // Identity-change banner states
    // ============================================================

    @Test
    fun pending_notice_renders_identity_banner() {
        val kv = FakeKv()
        seedAuthorizedMatrix(kv, listOf("p1"))
        seedNotice(kv, toDeviceId = "p1", state = "pending")
        render(fakeViewModel(), fakeController(kv), MatrixStore(kv))
        composeRule.onNodeWithText(
            "Device replacement awaiting your acknowledgment"
        ).assertExists()
    }

    @Test
    fun pending_notice_banner_tap_opens_ack_dialog() {
        val kv = FakeKv()
        seedAuthorizedMatrix(kv, listOf("p1"))
        seedNotice(kv, toDeviceId = "p1", state = "pending")
        render(fakeViewModel(), fakeController(kv), MatrixStore(kv))
        // "View" text is only rendered when the notice is PENDING
        composeRule.onNodeWithText("View").performClick()
        composeRule.onNodeWithText("Device replacement").assertExists()
    }

    @Test
    fun rejected_notice_renders_error_banner() {
        val kv = FakeKv()
        seedAuthorizedMatrix(kv, listOf("p1"))
        seedNotice(kv, toDeviceId = "p1", state = "acked_reject")
        render(fakeViewModel(), fakeController(kv), MatrixStore(kv))
        composeRule.onNodeWithText(
            "You rejected the replacement of this device. Sending is blocked. " +
                "Contact your admin to resolve."
        ).assertExists()
    }

    @Test
    fun rejected_notice_has_no_view_affordance() {
        // Q3 ruling: rejected is not tappable (admin must issue new notice)
        val kv = FakeKv()
        seedAuthorizedMatrix(kv, listOf("p1"))
        seedNotice(kv, toDeviceId = "p1", state = "acked_reject")
        render(fakeViewModel(), fakeController(kv), MatrixStore(kv))
        composeRule.onNodeWithText("View").assertDoesNotExist()
    }

    @Test
    fun unauthorized_and_pending_notice_render_both_banners() {
        val kv = FakeKv()
        // No matrix seed -> not authorized
        seedNotice(kv, toDeviceId = "p1", state = "pending")
        render(fakeViewModel(), fakeController(kv), MatrixStore(kv))
        composeRule.onNodeWithText(
            "You are not authorized to message this device. " +
                "Contact your admin to resolve."
        ).assertExists()
        composeRule.onNodeWithText(
            "Device replacement awaiting your acknowledgment"
        ).assertExists()
    }

    // ============================================================
    // Message list
    // ============================================================

    @Test
    fun empty_messages_renders_empty_state() {
        val kv = FakeKv()
        seedAuthorizedMatrix(kv, listOf("p1"))
        render(fakeViewModel(messages = emptyList()), fakeController(kv), MatrixStore(kv))
        composeRule.onNodeWithText("No messages yet. Say hi.").assertExists()
    }

    @Test
    fun messages_render_as_bubbles() {
        val kv = FakeKv()
        seedAuthorizedMatrix(kv, listOf("p1"))
        val msgs = listOf(msg("first message"), msg("second message"))
        render(fakeViewModel(messages = msgs), fakeController(kv), MatrixStore(kv))
        composeRule.onNodeWithText("first message").assertExists()
        composeRule.onNodeWithText("second message").assertExists()
    }

    // ============================================================
    // Send action
    // ============================================================

    @Test
    fun send_fires_sendMessageFn_with_peer_and_text() {
        val kv = FakeKv()
        seedAuthorizedMatrix(kv, listOf("p1"))
        var capturedPeer: String? = null
        var capturedText: String? = null
        val vm = fakeViewModel(onSend = { p, t ->
            capturedPeer = p
            capturedText = t
        })
        render(vm, fakeController(kv), MatrixStore(kv))
        composeRule.onNode(hasSetTextAction()).performTextInput("hello world")
        composeRule.onNodeWithContentDescription("Send").performClick()
        composeRule.waitForIdle()
        assertEquals("p1", capturedPeer)
        assertEquals("hello world", capturedText)
    }
}
