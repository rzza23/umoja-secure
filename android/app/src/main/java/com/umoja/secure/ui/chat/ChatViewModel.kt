package com.umoja.secure.ui.chat

import android.content.Context
import com.umoja.secure.messaging.MessagingService
import com.umoja.secure.storage.local.Message
import com.umoja.secure.storage.local.MessageStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Very small view model for a chat. Holds the currently loaded peer's
 * message list in memory. Kept intentionally simple — a full
 * ViewModel/LiveData setup will come when we do proper lifecycle work.
 */
class ChatViewModel(private val context: Context) {

    var currentMessages: List<Message> = emptyList()
        private set

    private val scope = CoroutineScope(Dispatchers.IO)

    fun loadMessages(peerDeviceId: String) {
        scope.launch {
            val list = withContext(Dispatchers.IO) {
                MessageStore(context).listMessages(peerDeviceId)
            }
            currentMessages = list
        }
    }

    /**
     * Send a message. onResult is invoked on completion with null on success
     * or an error code on failure. The caller is expected to refresh
     * currentMessages after this returns.
     */
    fun send(peerDeviceId: String, plaintext: String, onResult: (String?) -> Unit) {
        scope.launch {
            val outcome = MessagingService(context).sendMessage(peerDeviceId, plaintext)
            val errorCode = when (outcome) {
                is MessagingService.SendOutcome.Success -> null
                is MessagingService.SendOutcome.Failure -> outcome.code
            }
            // Reload the local list so the outgoing message appears
            val list = withContext(Dispatchers.IO) {
                MessageStore(context).listMessages(peerDeviceId)
            }
            currentMessages = list
            onResult(errorCode)
        }
    }
}
