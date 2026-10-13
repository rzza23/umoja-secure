package com.umoja.secure.ui.diagnostics

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.umoja.secure.auth.PreKeyUploader
import com.umoja.secure.auth.SessionManager
import com.umoja.secure.messaging.MessagingService
import com.umoja.secure.storage.SecureStorage
import com.umoja.secure.transport.WebSocketClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun DiagnosticsScreen(
    wsState: WebSocketClient.State,
    envelopesReceived: Int,
    onConnectWs: () -> Unit,
    onDisconnectWs: () -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var deviceId by remember { mutableStateOf<String?>(null) }
    var sessionExpiresAt by remember { mutableStateOf<String?>(null) }
    var prekeyStatusText by remember { mutableStateOf<String?>(null) }
    var status by remember { mutableStateOf<String?>(null) }
    var isBusy by remember { mutableStateOf(false) }
    var peerDeviceIdInput by remember { mutableStateOf("") }
    var sentMessageInput by remember { mutableStateOf("hello from Umoja") }
    var receivedMessagesText by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        val s = SecureStorage(context)
        deviceId = s.get("device_id")
        sessionExpiresAt = s.get("session_expires_at")
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("Back") }
            Spacer(Modifier.padding(horizontal = 4.dp))
            Text("Diagnostics", style = MaterialTheme.typography.headlineMedium)
        }
        Spacer(Modifier.height(16.dp))

        Text("Device ID", style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(deviceId ?: "—", fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(8.dp))

        Text("Session expires", style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(sessionExpiresAt ?: "—", fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(8.dp))

        Text("WebSocket: ${wsLabel(wsState)}",
            style = MaterialTheme.typography.bodyMedium)
        Text("Envelopes received: $envelopesReceived",
            style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(16.dp))

        if (wsState is WebSocketClient.State.Ready ||
            wsState is WebSocketClient.State.Connecting ||
            wsState is WebSocketClient.State.Authenticating ||
            wsState is WebSocketClient.State.Reconnecting
        ) {
            OutlinedButton(onClick = onDisconnectWs, enabled = !isBusy,
                modifier = Modifier.fillMaxWidth()) {
                Text("Disconnect WebSocket")
            }
        } else {
            Button(onClick = onConnectWs, enabled = !isBusy,
                modifier = Modifier.fillMaxWidth()) {
                Text("Connect WebSocket")
            }
        }

        Spacer(Modifier.height(8.dp))
        Button(
            onClick = {
                isBusy = true
                status = null
                scope.launch {
                    val outcome = PreKeyUploader(context).uploadPreKeys()
                    withContext(Dispatchers.Main) {
                        isBusy = false
                        when (outcome) {
                            is PreKeyUploader.UploadOutcome.Success ->
                                prekeyStatusText = "Prekeys: ${outcome.total} unconsumed (uploaded ${outcome.stored})"
                            is PreKeyUploader.UploadOutcome.Failure ->
                                status = "Prekey upload error: ${outcome.code}"
                            PreKeyUploader.UploadOutcome.NotAuthenticated ->
                                status = "Not authenticated"
                        }
                    }
                }
            },
            enabled = !isBusy,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (isBusy) "Working..." else "Upload prekeys")
        }
        prekeyStatusText?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary)
        }

        Spacer(Modifier.height(24.dp))
        Text("Messaging", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))

        OutlinedTextField(
            value = peerDeviceIdInput,
            onValueChange = { peerDeviceIdInput = it },
            label = { Text("Peer device ID") },
            singleLine = true,
            enabled = !isBusy,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = sentMessageInput,
            onValueChange = { sentMessageInput = it },
            label = { Text("Message to send") },
            singleLine = true,
            enabled = !isBusy,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        Button(
            onClick = {
                isBusy = true
                status = null
                scope.launch {
                    val outcome = MessagingService(context).sendMessage(
                        peerDeviceIdInput.trim(),
                        sentMessageInput,
                    )
                    withContext(Dispatchers.Main) {
                        isBusy = false
                        status = when (outcome) {
                            is MessagingService.SendOutcome.Success ->
                                "Sent: ${outcome.envelopeId.take(8)}... (prekey=${outcome.wasPreKey})"
                            is MessagingService.SendOutcome.Failure ->
                                "Send error: ${outcome.code}"
                        }
                    }
                }
            },
            enabled = !isBusy && peerDeviceIdInput.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Send encrypted message")
        }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(
            onClick = {
                isBusy = true
                status = null
                scope.launch {
                    val outcome = MessagingService(context).receiveMessages()
                    withContext(Dispatchers.Main) {
                        isBusy = false
                        when (outcome) {
                            is MessagingService.ReceiveOutcome.Success -> {
                                val list = outcome.messages
                                receivedMessagesText = if (list.isEmpty()) "No pending messages."
                                else list.joinToString("\n") { "${it.senderDeviceId.take(8)}: ${it.plaintext}" }
                                status = "Received ${list.size} message(s)"
                            }
                            is MessagingService.ReceiveOutcome.Failure ->
                                status = "Receive error: ${outcome.code}"
                        }
                    }
                }
            },
            enabled = !isBusy,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Check messages")
        }

        receivedMessagesText?.let {
            Spacer(Modifier.height(12.dp))
            Text("Received:", style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(4.dp))
            Text(it, style = MaterialTheme.typography.bodySmall)
        }

        status?.let {
            Spacer(Modifier.height(12.dp))
            Text(it, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary)
        }

        Spacer(Modifier.height(24.dp))
    }
}

private fun wsLabel(state: WebSocketClient.State): String = when (state) {
    is WebSocketClient.State.Disconnected -> "Disconnected"
    is WebSocketClient.State.Connecting -> "Connecting"
    is WebSocketClient.State.Authenticating -> "Authenticating"
    is WebSocketClient.State.Ready -> "Ready"
    is WebSocketClient.State.Reconnecting -> "Reconnecting"
    is WebSocketClient.State.Failed -> "Failed: ${state.reason}"
    is WebSocketClient.State.Revoked -> "Revoked"
}
