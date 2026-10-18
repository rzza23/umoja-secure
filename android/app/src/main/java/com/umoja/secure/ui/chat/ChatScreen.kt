package com.umoja.secure.ui.chat

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
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
import androidx.compose.material3.AlertDialog
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
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import com.umoja.secure.crypto.AckDecision
import com.umoja.secure.crypto.IdentityChangeController
import com.umoja.secure.crypto.MatrixStore
import com.umoja.secure.crypto.ReplacementNoticeStore
import com.umoja.secure.crypto.SendGate
import com.umoja.secure.messaging.MessagingService
import com.umoja.secure.storage.local.Message
import com.umoja.secure.storage.local.MessageDirection
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ChatScreen(
    peerDeviceId: String,
    peerLabel: String,
    onBack: () -> Unit,
    viewModel: ChatViewModel,
    identityChangeController: IdentityChangeController,
    matrixStore: MatrixStore,
) {
    BackHandler(enabled = true) { onBack() }

    val scope = rememberCoroutineScope()

    var input by remember { mutableStateOf("") }
    var sending by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<String?>(null) }
    var showDialog by remember { mutableStateOf(false) }
    var ackInProgress by remember { mutableStateOf(false) }
    var ackError by remember { mutableStateOf<String?>(null) }

    val listState = rememberLazyListState()
    val messages by viewModel.messages.collectAsState()
    val messagesVersion by MessagingService.messagesVersion.collectAsState()

    val version by identityChangeController.version.collectAsState()
    val gateState: IdentityChangeController.GateState =
        remember(version, peerDeviceId) { identityChangeController.gateFor(peerDeviceId) }
    val isIdentityBlocked = gateState is IdentityChangeController.GateState.Blocked
    // Authorization gate (TASK-P1-038 C, D-1). Derived via SendGate
    // (tested predicate, not an inline check). Keyed on
    // matrixStore.version so that AppRoot's async matrix fetch — which
    // completes after the chat may already be composed on cold start —
    // propagates a re-derivation when it lands in MatrixStore.accept().
    //
    // Without the version key this was a real bug, not a trade-off:
    // the initial fetch runs inside a LaunchedEffect(screen, deviceId)
    // in AppRoot. A user navigating into chat before that fetch
    // completes composes with the stale matrix, computes
    // isAuthorized=false, and — because neither peerDeviceId nor
    // matrixStore changes when the fetch eventually lands — never
    // re-derives. The banner stayed visible until ChatScreen was
    // unmounted and re-composed. Caught in emulator acceptance of
    // Case 2 (authorized peer still showed banner).
    //
    // Same version-flow idiom as IdentityChangeController.version
    // (Session K, eea1af7): write-notification, not a data cache.
    val matrixVersion by matrixStore.version.collectAsState()
    val isAuthorized = remember(peerDeviceId, matrixVersion) {
        SendGate.authorized(matrixStore.permittedContacts(), peerDeviceId)
    }
    val isBlocked = isIdentityBlocked || !isAuthorized

    LaunchedEffect(peerDeviceId) {
        viewModel.observe(peerDeviceId)
    }
    LaunchedEffect(peerDeviceId) {
        identityChangeController.refresh()
    }
    LaunchedEffect(messagesVersion) {
        viewModel.refresh()
    }
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    val sendNow: () -> Unit = {
        if (input.isNotBlank() && !sending && !isBlocked) {
            val text = input.trim()
            input = ""
            sending = true
            status = null
            viewModel.send(peerDeviceId, text) { result ->
                sending = false
                if (result != null) status = "Error: $result"
            }
        }
    }

    Column(Modifier.fillMaxSize()) {
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

        (gateState as? IdentityChangeController.GateState.Blocked)?.let { blocked ->
            IdentityChangeBanner(
                state = blocked,
                onOpenDetails = { showDialog = true },
            )
        }

        if (!isAuthorized) {
            NotAuthorizedBanner()
        }

        Surface(color = MaterialTheme.colorScheme.surface) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth().padding(8.dp),
            ) {
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it },
                    placeholder = {
                        Text(if (isBlocked) "Sending blocked" else "Message...")
                    },
                    enabled = !sending && !isBlocked,
                    maxLines = 4,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                    keyboardActions = KeyboardActions(onSend = { sendNow() }),
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.widthIn(min = 8.dp))
                IconButton(
                    onClick = sendNow,
                    enabled = input.isNotBlank() && !sending && !isBlocked,
                ) {
                    Icon(
                        Icons.AutoMirrored.Filled.Send,
                        contentDescription = "Send",
                        tint = if (isBlocked) MaterialTheme.colorScheme.onSurfaceVariant
                               else MaterialTheme.colorScheme.primary,
                    )
                }
            }
        }
    }

    val pendingNotice = (gateState as? IdentityChangeController.GateState.Blocked)
        ?.takeIf { it.reason == IdentityChangeController.GateState.Reason.PENDING }
        ?.notice
    if (showDialog && pendingNotice != null) {
        val pn = pendingNotice
        val submitAck: (AckDecision) -> Unit = { decision ->
            ackError = null
            ackInProgress = true
            scope.launch {
                val result = identityChangeController.ackAndPost(pn, decision)
                ackInProgress = false
                val r = result.getOrNull()
                if (r is IdentityChangeController.AckResult.Success) {
                    showDialog = false
                } else {
                    ackError = (r as? IdentityChangeController.AckResult.Failure)
                        ?.code ?: "unknown"
                }
            }
        }
        AckDialog(
            notice = pn,
            ackInProgress = ackInProgress,
            ackError = ackError,
            onAccept = { submitAck(AckDecision.ACCEPT) },
            onReject = { submitAck(AckDecision.REJECT) },
            onDismiss = { if (!ackInProgress) showDialog = false },
        )
    }
}

@Composable
private fun IdentityChangeBanner(
    state: IdentityChangeController.GateState.Blocked,
    onOpenDetails: () -> Unit,
) {
    val isPending = state.reason == IdentityChangeController.GateState.Reason.PENDING
    val message = if (isPending) {
        "Device replacement awaiting your acknowledgment"
    } else {
        "You rejected the replacement of this device. Sending is blocked. " +
            "Contact your admin to resolve."
    }
    val container = if (isPending) MaterialTheme.colorScheme.tertiaryContainer
                    else MaterialTheme.colorScheme.errorContainer

    Surface(
        color = container,
        modifier = Modifier
            .fillMaxWidth()
            .then(if (isPending) Modifier.clickable { onOpenDetails() } else Modifier),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
        ) {
            Text(
                message,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.weight(1f),
            )
            if (isPending) {
                Spacer(Modifier.widthIn(min = 8.dp))
                Text(
                    "View",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }
    }
}

@Composable
private fun NotAuthorizedBanner() {
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
        ) {
            Text(
                "You are not authorized to message this device. " +
                    "Contact your admin to resolve.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun AckDialog(
    notice: ReplacementNoticeStore.StoredNotice,
    ackInProgress: Boolean,
    ackError: String?,
    onAccept: () -> Unit,
    onReject: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Device replacement") },
        text = {
            Column {
                Text("Device was replaced:", style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(6.dp))
                Text(
                    notice.fromDeviceId,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    "→ " + notice.toDeviceId,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                )
                Spacer(Modifier.height(10.dp))
                Text(
                    "Issued: ${notice.issuedAt}",
                    style = MaterialTheme.typography.labelSmall,
                )
                Text(
                    "Notice: ${notice.noticeHash.take(8)}…",
                    style = MaterialTheme.typography.labelSmall,
                )
                Spacer(Modifier.height(10.dp))
                Text(
                    "Signature verified on receipt against pinned provisioning key.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                ackError?.let {
                    Spacer(Modifier.height(10.dp))
                    Text(
                        "Error: $it",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onAccept, enabled = !ackInProgress) {
                Text(if (ackInProgress) "…" else "Acknowledge")
            }
        },
        dismissButton = {
            TextButton(onClick = onReject, enabled = !ackInProgress) {
                Text("Reject")
            }
        },
    )
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
