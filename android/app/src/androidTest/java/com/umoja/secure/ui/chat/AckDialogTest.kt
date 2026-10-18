package com.umoja.secure.ui.chat

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import com.umoja.secure.crypto.ReplacementNoticeStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * Compose tests for [AckDialog] (TASK-P1-030e-c 3d-2's confirmation
 * UI). Security-relevant surface: the ack flow is how a user confirms
 * "device X is really now device Y." If the dialog renders the wrong
 * fields, the user confirms something they didn't see.
 *
 * Covers Session I's Q1-Q3 rulings at the UI layer:
 *   - Q1: dialog shows full notice (from/to IDs, issuedAt, notice
 *     hash prefix, signature-verified claim)
 *   - Q2: Acknowledge and Reject are the two confirmation affordances
 *   - Q3: Reject is available with no undo affordance (rejection
 *     blocks permanently for that notice_hash; admin issues a new
 *     notice to recover)
 *
 * Rule: [createComposeRule] -- pure composition, no Activity needed.
 * AckDialog is prop-driven (all 6 params), no remember state of its
 * own, so it's fully isolable.
 *
 * Pre-existing: 46 androidTest / 6 files, all under crypto/. This is
 * the first non-crypto androidTest and the first Compose test in the
 * project.
 */
class AckDialogTest {

    @get:Rule
    val composeRule = createComposeRule()

    private fun storedNotice(
        from: String = "11111111-1111-1111-1111-111111111111",
        to: String = "22222222-2222-2222-2222-222222222222",
        issuedAt: String = "2026-10-18T19:00:00.000Z",
        hash: String = "abcdef0123456789abcdef0123456789",
    ): ReplacementNoticeStore.StoredNotice =
        ReplacementNoticeStore.StoredNotice(
            noticeHash = hash,
            canonicalB64u = "fake-canonical-b64u",
            signatureB64u = "fake-signature-b64u",
            fromDeviceId = from,
            toDeviceId = to,
            issuedAt = issuedAt,
            state = ReplacementNoticeStore.State.PENDING,
            ackedAt = null,
        )

    private fun render(
        notice: ReplacementNoticeStore.StoredNotice = storedNotice(),
        ackInProgress: Boolean = false,
        ackError: String? = null,
        onAccept: () -> Unit = {},
        onReject: () -> Unit = {},
        onDismiss: () -> Unit = {},
    ) {
        composeRule.setContent {
            MaterialTheme {
                AckDialog(
                    notice = notice,
                    ackInProgress = ackInProgress,
                    ackError = ackError,
                    onAccept = onAccept,
                    onReject = onReject,
                    onDismiss = onDismiss,
                )
            }
        }
    }

    @Test
    fun dialog_renders_title() {
        render()
        composeRule.onNodeWithText("Device replacement").assertExists()
    }

    @Test
    fun dialog_renders_from_and_to_device_ids() {
        render(
            notice = storedNotice(
                from = "11111111-1111-1111-1111-111111111111",
                to = "22222222-2222-2222-2222-222222222222",
            )
        )
        composeRule.onNodeWithText("11111111-1111-1111-1111-111111111111").assertExists()
        composeRule.onNodeWithText("\u2192 22222222-2222-2222-2222-222222222222").assertExists()
    }

    @Test
    fun dialog_renders_issuedAt_verbatim() {
        render(
            notice = storedNotice(issuedAt = "2026-10-18T19:00:00.000Z"),
        )
        composeRule.onNodeWithText("Issued: 2026-10-18T19:00:00.000Z").assertExists()
    }

    @Test
    fun dialog_truncates_noticeHash_to_eight_chars_plus_ellipsis() {
        render(
            notice = storedNotice(hash = "abcdef0123456789abcdef0123456789"),
        )
        composeRule.onNodeWithText("Notice: abcdef01\u2026").assertExists()
    }

    @Test
    fun dialog_renders_signature_verified_claim() {
        render()
        composeRule.onNodeWithText(
            "Signature verified on receipt against pinned provisioning key."
        ).assertExists()
    }

    @Test
    fun dialog_renders_acknowledge_and_reject_buttons() {
        render()
        composeRule.onNodeWithText("Acknowledge").assertExists().assertIsEnabled()
        composeRule.onNodeWithText("Reject").assertExists().assertIsEnabled()
    }

    @Test
    fun acknowledge_click_invokes_onAccept() {
        var called = 0
        render(onAccept = { called += 1 })
        composeRule.onNodeWithText("Acknowledge").performClick()
        assertEquals(1, called)
    }

    @Test
    fun reject_click_invokes_onReject() {
        var called = 0
        render(onReject = { called += 1 })
        composeRule.onNodeWithText("Reject").performClick()
        assertEquals(1, called)
    }

    @Test
    fun ackInProgress_disables_both_buttons_and_shows_ellipsis_on_acknowledge() {
        render(ackInProgress = true)
        composeRule.onNodeWithText("Acknowledge").assertDoesNotExist()
        composeRule.onNodeWithText("\u2026").assertExists().assertIsNotEnabled()
        composeRule.onNodeWithText("Reject").assertExists().assertIsNotEnabled()
    }

    @Test
    fun ackError_renders_error_message() {
        render(ackError = "device_revoked")
        composeRule.onNodeWithText("Error: device_revoked").assertExists()
    }

    @Test
    fun noError_when_ackError_is_null() {
        render(ackError = null)
        composeRule.onNodeWithText("Error: device_revoked").assertDoesNotExist()
    }
}
