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
 */
class ChatViewModel(private val context: Context) {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

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
            val list = MessageStore(context).listMessages(peer)
            _messages.value = list
        }
    }

    /**
     * Send a message. onResult is invoked with null on success or an error
     * code on failure. The message list refreshes automatically via
     * MessagingService.messagesVersion once the outgoing message is stored.
     */
    fun send(peerDeviceId: String, plaintext: String, onResult: (String?) -> Unit) {
        scope.launch {
            val outcome = MessagingService(context).sendMessage(peerDeviceId, plaintext)
            val errorCode = when (outcome) {
                is MessagingService.SendOutcome.Success -> null
                is MessagingService.SendOutcome.Failure -> outcome.code
                is MessagingService.SendOutcome.NotAuthorized -> "not_authorized"
            }
            onResult(errorCode)
        }
    }
}
