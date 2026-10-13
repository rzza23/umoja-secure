package com.umoja.secure.ui.chat

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import com.umoja.secure.storage.local.Message
import com.umoja.secure.storage.local.MessageDirection
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ChatScreen(
    peerDeviceId: String,
    peerLabel: String,
    onBack: () -> Unit,
    viewModel: ChatViewModel,
) {
    // System back (gesture / hardware) should close the chat instead of
    // popping the whole activity.
    BackHandler(enabled = true) { onBack() }

    var input by remember { mutableStateOf("") }
    var messages by remember { mutableStateOf<List<Message>>(emptyList()) }
    var sending by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<String?>(null) }

    val listState = rememberLazyListState()

    LaunchedEffect(peerDeviceId, messages.size) {
        viewModel.loadMessages(peerDeviceId)
        messages = viewModel.currentMessages
    }

    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    Column(Modifier.fillMaxSize()) {
        // Header
        Surface(
            color = MaterialTheme.colorScheme.surface,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(horizontal = 8.dp, vertical = 12.dp),
            ) {
                TextButton(onClick = onBack) { Text("Back") }
                Spacer(Modifier.widthIn(min = 4.dp))
                Column {
                    Text(peerLabel, style = MaterialTheme.typography.titleMedium)
                    Text(
                        peerDeviceId.take(16) + "...",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        // Messages
        Box(Modifier.weight(1f).fillMaxWidth()) {
            if (messages.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        "No messages yet. Say hi.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize().padding(horizontal = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    items(messages, key = { it.id }) { m -> MessageBubble(m) }
                    item { Spacer(Modifier.height(12.dp)) }
                }
            }
        }

        status?.let {
            Text(
                it,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(horizontal = 16.dp),
            )
        }

        // Composer
        Surface(color = MaterialTheme.colorScheme.surface) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth().padding(8.dp),
            ) {
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it },
                    placeholder = { Text("Message...") },
                    enabled = !sending,
                    maxLines = 4,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                    keyboardActions = KeyboardActions(onSend = {
                        if (input.isNotBlank() && !sending) {
                            val text = input.trim()
                            input = ""
                            sending = true
                            status = null
                            viewModel.send(peerDeviceId, text) { result ->
                                sending = false
                                if (result != null) status = "Error: $result"
                                messages = viewModel.currentMessages
                            }
                        }
                    }),
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.widthIn(min = 8.dp))
                IconButton(
                    onClick = {
                        if (input.isNotBlank() && !sending) {
                            val text = input.trim()
                            input = ""
                            sending = true
                            status = null
                            viewModel.send(peerDeviceId, text) { result ->
                                sending = false
                                if (result != null) status = "Error: $result"
                                messages = viewModel.currentMessages
                            }
                        }
                    },
                    enabled = input.isNotBlank() && !sending,
                ) {
                    Icon(
                        Icons.AutoMirrored.Filled.Send,
                        contentDescription = "Send",
                        tint = MaterialTheme.colorScheme.primary,
                    )
                }
            }
        }
    }
}

@Composable
private fun MessageBubble(m: Message) {
    val isOut = m.direction == MessageDirection.OUT
    val bubbleColor = if (isOut) MaterialTheme.colorScheme.primaryContainer
                      else MaterialTheme.colorScheme.surfaceVariant
    val textColor = if (isOut) MaterialTheme.colorScheme.onPrimaryContainer
                    else MaterialTheme.colorScheme.onSurfaceVariant

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = if (isOut) Arrangement.End else Arrangement.Start,
    ) {
        Surface(
            color = bubbleColor,
            shape = RoundedCornerShape(18.dp),
            modifier = Modifier.widthIn(max = 280.dp),
        ) {
            Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
                Text(m.plaintext, style = MaterialTheme.typography.bodyLarge, color = textColor)
                Spacer(Modifier.height(2.dp))
                Text(
                    formatTime(m.createdAt),
                    style = MaterialTheme.typography.labelSmall,
                    color = textColor.copy(alpha = 0.7f),
                )
            }
        }
    }
}

private fun formatTime(epochMs: Long): String =
    SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(epochMs))
