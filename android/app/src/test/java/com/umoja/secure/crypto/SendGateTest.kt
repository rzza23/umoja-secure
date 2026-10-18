package com.umoja.secure.crypto

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Registry-mandated cases (TASK-P1-038 §B Acceptance criteria):
 *   TEST-SEND-GATE-EXCLUDED-PEER
 *   TEST-SEND-GATE-PERMITTED-PEER
 *
 * Plus the two fail-closed edge cases that distinguish "gate works" from
 * "gate happens to be in the right shape when someone remembers to load
 * the matrix":
 *   TEST-SEND-GATE-NULL-MATRIX   -- no matrix yet (never enrolled / fetch failed)
 *   TEST-SEND-GATE-EMPTY-MATRIX  -- matrix accepted but has zero permitted contacts
 *
 * Emulator acceptance covers the integration path (MessagingService
 * receives [SendGate]'s verdict and short-circuits before envelope
 * queuing); these JVM tests pin the predicate.
 */
class SendGateTest {

    @Test
    fun `TEST-SEND-GATE-EXCLUDED-PEER peer not in permitted_contacts is rejected`() {
        val permitted = listOf("aaaa", "bbbb")
        assertFalse(SendGate.authorized(permitted, "cccc"))
    }

    @Test
    fun `TEST-SEND-GATE-PERMITTED-PEER peer in permitted_contacts is allowed`() {
        val permitted = listOf("aaaa", "bbbb")
        assertTrue(SendGate.authorized(permitted, "bbbb"))
    }

    @Test
    fun `TEST-SEND-GATE-NULL-MATRIX null permitted_contacts fails closed`() {
        assertFalse(SendGate.authorized(null, "aaaa"))
    }

    @Test
    fun `TEST-SEND-GATE-EMPTY-MATRIX empty permitted_contacts fails closed`() {
        assertFalse(SendGate.authorized(emptyList(), "aaaa"))
    }
}
