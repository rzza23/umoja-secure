package com.umoja.secure.ui.chat

import com.umoja.secure.messaging.MessagingService
import com.umoja.secure.storage.local.Message
import com.umoja.secure.storage.local.MessageDirection
import com.umoja.secure.storage.local.MessageStatus
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for [ChatViewModel] -- the state holder behind ChatScreen.
 *
 * First JVM tests for this class (Session C of the Compose-refactor arc,
 * the session that refactored ChatViewModel to be injectable). Prior to
 * the refactor, ChatViewModel was a `Context`-bound final class with
 * hardcoded [MessageStore]/[MessagingService] construction; it could
 * not be tested without an Android device.
 *
 * Coroutine framework: runBlocking + injected `Dispatchers.Unconfined`
 * scope + CompletableDeferred where callbacks need to signal completion.
 * kotlinx-coroutines-test is not on the classpath (see Session R-2's
 * SessionStateManagerTest precedent). Unconfined ensures the launched
 * body executes eagerly on the current thread, so `scope.launch { ... }`
 * inside `send` / `refresh` runs to the first suspension before the
 * caller resumes. The fakes are synchronous so this is deterministic
 * without real wall-clock delays.
 *
 * Coverage groups (10 tests):
 *   observe / refresh  -- 5 tests
 *   send               -- 5 tests
 *
 * The production factory `create(context)` is not tested here -- it
 * requires Android Context and only wires the two lambdas + scope.
 * Emulator smoke test covers it (hit send, tap Back, verify delivery).
 */
class ChatViewModelTest {

    private fun msg(
        id: String = "m1",
        peer: String = "p1",
        text: String = "hi",
    ): Message = Message(
        id = id,
        envelopeId = null,
        peerDeviceId = peer,
        direction = MessageDirection.OUT,
        plaintext = text,
        createdAt = 0L,
        status = MessageStatus.SENT,
    )

    private fun vm(
        listMessagesFn: suspend (String) -> List<Message> = { emptyList() },
        sendMessageFn: suspend (String, String) -> MessagingService.SendOutcome = { _, _ ->
            MessagingService.SendOutcome.Success("env-0", wasPreKey = false)
        },
    ): ChatViewModel = ChatViewModel(
        listMessagesFn = listMessagesFn,
        sendMessageFn = sendMessageFn,
        scope = CoroutineScope(Dispatchers.Unconfined),
    )

    // ============================================================
    // observe / refresh
    // ============================================================

    @Test
    fun `observe loads messages for the current peer`() = runBlocking {
        val m = vm(listMessagesFn = { listOf(msg(id = "a"), msg(id = "b")) })
        m.observe("p1")
        assertEquals(2, m.messages.value.size)
    }

    @Test
    fun `observe triggers exactly one list call`() = runBlocking {
        var calls = 0
        val m = vm(listMessagesFn = { calls++; emptyList() })
        m.observe("p1")
        assertEquals(1, calls)
    }

    @Test
    fun `refresh without observe is a no-op`() = runBlocking {
        var calls = 0
        val m = vm(listMessagesFn = { calls++; emptyList() })
        m.refresh()
        assertEquals(0, calls)
        assertTrue(m.messages.value.isEmpty())
    }

    @Test
    fun `observe switches to the new peer`() = runBlocking {
        val seen = mutableListOf<String>()
        val m = vm(listMessagesFn = { p -> seen.add(p); emptyList() })
        m.observe("p1")
        m.observe("p2")
        assertEquals(listOf("p1", "p2"), seen)
    }

    @Test
    fun `refresh re-queries the current peer`() = runBlocking {
        val seen = mutableListOf<String>()
        val m = vm(listMessagesFn = { p -> seen.add(p); emptyList() })
        m.observe("p1")
        m.refresh()
        assertEquals(listOf("p1", "p1"), seen)
    }

    // ============================================================
    // send
    // ============================================================

    @Test
    fun `send success fires onResult with null`() = runBlocking {
        val done = CompletableDeferred<String?>()
        val m = vm(sendMessageFn = { _, _ ->
            MessagingService.SendOutcome.Success("env-1", wasPreKey = false)
        })
        m.send("p1", "hello") { r -> done.complete(r) }
        assertNull(done.await())
    }

    @Test
    fun `send failure fires onResult with code`() = runBlocking {
        val done = CompletableDeferred<String?>()
        val m = vm(sendMessageFn = { _, _ ->
            MessagingService.SendOutcome.Failure("network_error")
        })
        m.send("p1", "hello") { r -> done.complete(r) }
        assertEquals("network_error", done.await())
    }

    @Test
    fun `send NotAuthorized fires onResult with not_authorized`() = runBlocking {
        val done = CompletableDeferred<String?>()
        val m = vm(sendMessageFn = { _, _ ->
            MessagingService.SendOutcome.NotAuthorized("p1")
        })
        m.send("p1", "hello") { r -> done.complete(r) }
        assertEquals("not_authorized", done.await())
    }

    @Test
    fun `send passes peer and plaintext to the lambda`() = runBlocking {
        var capturedPeer = ""
        var capturedText = ""
        val done = CompletableDeferred<Unit>()
        val m = vm(sendMessageFn = { p, t ->
            capturedPeer = p
            capturedText = t
            MessagingService.SendOutcome.Success("env-1", wasPreKey = false)
        })
        m.send("p1", "hello") { _ -> done.complete(Unit) }
        done.await()
        assertEquals("p1", capturedPeer)
        assertEquals("hello", capturedText)
    }

    @Test
    fun `send invokes sendMessageFn exactly once per call`() = runBlocking {
        var calls = 0
        val done = CompletableDeferred<Unit>()
        val m = vm(sendMessageFn = { _, _ ->
            calls++
            MessagingService.SendOutcome.Success("env-1", wasPreKey = false)
        })
        m.send("p1", "hello") { _ -> done.complete(Unit) }
        done.await()
        assertEquals(1, calls)
    }
}
