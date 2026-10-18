package com.umoja.secure.ui.chat

import android.content.Context
import com.umoja.secure.messaging.MessagingService
import com.umoja.secure.storage.local.Message
import com.umoja.secure.storage.local.MessageStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * View model for a single 1:1 chat.
 *
 * Exposes the message list as a StateFlow so Compose observes updates.
 * The backing store is not reactive; refresh() re-queries it. Callers
 * trigger refresh() when MessagingService.messagesVersion increments.
 *
 * **Injected lambdas for testability (Session C).** The two data-access
 * operations (listMessages, sendMessage) and the coroutine scope are
 * constructor-injected. Production uses the [create] factory below,
 * which wires the real [MessageStore] + [MessagingService] and the
 * same `CoroutineScope(Dispatchers.IO + SupervisorJob())` this class
 * previously constructed inline. Tests inject synchronous fakes + an
 * `Unconfined` scope. The public surface (messages, observe, refresh,
 * send) is unchanged from the pre-refactor shape -- ChatScreen's call
 * sites compile unchanged.
 *
 * **Fire-and-forget preserved.** [send] launches on the injected scope
 * and returns before the network round-trip completes. Production's
 * scope is independent of any Compose composition, so a user who taps
 * send and immediately navigates away still delivers the message.
 * Emulator smoke test: hit send, tap Back, verify peer receives.
 */
class ChatViewModel(
    private val listMessagesFn: suspend (String) -> List<Message>,
    private val sendMessageFn: suspend (String, String) -> MessagingService.SendOutcome,
    private val scope: CoroutineScope,
) {
    private val _messages = MutableStateFlow<List<Message>>(emptyList())
    val messages: StateFlow<List<Message>> = _messages.asStateFlow()

    private var currentPeerId: String? = null

    /** Bind to a peer and load its messages. */
    fun observe(peerDeviceId: String) {
        currentPeerId = peerDeviceId
        refresh()
    }

    /** Re-query the local message store for the current peer. */
    fun refresh() {
        val peer = currentPeerId ?: return
        scope.launch {
            _messages.value = listMessagesFn(peer)
        }
    }

    /**
     * Send a message. onResult is invoked with null on success or an error
     * code on failure. The message list refreshes automatically via
     * MessagingService.messagesVersion once the outgoing message is stored.
     */
    fun send(peerDeviceId: String, plaintext: String, onResult: (String?) -> Unit) {
        scope.launch {
            val outcome = sendMessageFn(peerDeviceId, plaintext)
            val errorCode = when (outcome) {
                is MessagingService.SendOutcome.Success -> null
                is MessagingService.SendOutcome.Failure -> outcome.code
                is MessagingService.SendOutcome.NotAuthorized -> "not_authorized"
            }
            onResult(errorCode)
        }
    }

    companion object {
        /**
         * Production factory. Wires the real data sources and the same
         * scope shape the previous (context-only) constructor used.
         * Callers that previously did `ChatViewModel(context)` should
         * call `ChatViewModel.create(context)`.
         */
        fun create(context: Context): ChatViewModel = ChatViewModel(
            listMessagesFn = { peer -> MessageStore(context).listMessages(peer) },
            sendMessageFn = { peer, text ->
                MessagingService(context).sendMessage(peer, text)
            },
            scope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
        )
    }
}
