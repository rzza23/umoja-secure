package com.umoja.secure.ui.diagnostics

import android.content.Context
import android.content.pm.ApplicationInfo
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
import com.umoja.secure.crypto.MatrixSigner
import com.umoja.secure.crypto.MatrixStore
import com.umoja.secure.crypto.ProvisioningKeys
import com.umoja.secure.messaging.MessagingService
import com.umoja.secure.storage.SecureStorage
import com.umoja.secure.transport.WebSocketClient
import com.umoja.secure.ui.common.SecureScreen
import java.util.Base64
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
    SecureScreen()
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
    var matrixCanonicalB64 by remember { mutableStateOf("") }
    var matrixSignatureB64 by remember { mutableStateOf("") }
    var matrixResult by remember { mutableStateOf<String?>(null) }
    var matrixReadBack by remember { mutableStateOf<String?>(null) }

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
                            is MessagingService.SendOutcome.NotAuthorized ->
                                "Send blocked: peer not in permitted contacts"
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

        val isDebug = (context.applicationInfo.flags and
            ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (isDebug) {
            Spacer(Modifier.height(24.dp))
            Text("Matrix (debug)", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))

            // Read back the current stored matrix on screen entry, so
            // TASK-P1-037 O-2 manual verification is "open Diagnostics,
            // see the version" without a paste+verify cycle. The
            // Verify-and-store button below still populates
            // matrixReadBack on success — this LaunchedEffect is the
            // initial state read. Keyed on Unit so it fires once per
            // composition (per navigation into Diagnostics).
            LaunchedEffect(Unit) {
                matrixReadBack = try {
                    val store = MatrixStore(SecureStorage(context))
                    "highestSeenVersion=" + store.highestSeenVersion() +
                        " contacts=" + (store.permittedContacts()?.size ?: "null")
                } catch (e: Exception) {
                    "read-back failed: " + e.message
                }
            }

            OutlinedTextField(
                value = matrixCanonicalB64,
                onValueChange = { matrixCanonicalB64 = it },
                label = { Text("canonical_b64 (JCS bytes, base64url no-pad)") },
                enabled = !isBusy,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = matrixSignatureB64,
                onValueChange = { matrixSignatureB64 = it },
                label = { Text("signature_b64 (Ed25519, base64url no-pad)") },
                enabled = !isBusy,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = {
                    isBusy = true
                    matrixResult = null
                    matrixReadBack = null
                    scope.launch {
                        val outcome = verifyAndStoreMatrix(
                            context,
                            matrixCanonicalB64.trim(),
                            matrixSignatureB64.trim(),
                        )
                        withContext(Dispatchers.Main) {
                            isBusy = false
                            matrixResult = outcome.first
                            matrixReadBack = outcome.second
                        }
                    }
                },
                enabled = !isBusy &&
                    matrixCanonicalB64.isNotBlank() &&
                    matrixSignatureB64.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Verify and store")
            }
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = {
                    MatrixStore(SecureStorage(context)).clear()
                    matrixResult = "Cleared"
                    matrixReadBack = null
                },
                enabled = !isBusy,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Clear stored matrix")
            }

            matrixResult?.let {
                Spacer(Modifier.height(8.dp))
                Text(it, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary)
            }
            matrixReadBack?.let {
                Spacer(Modifier.height(4.dp))
                Text(it, fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall)
            }
        }

        Spacer(Modifier.height(24.dp))
    }
}

private suspend fun verifyAndStoreMatrix(
    context: Context,
    canonicalB64: String,
    signatureB64: String,
): Pair<String, String?> = withContext(Dispatchers.IO) {
    try {
        val canonical = Base64.getUrlDecoder().decode(canonicalB64)
        val store = MatrixStore(SecureStorage(context))
        val rawPub = Base64.getUrlDecoder()
            .decode(ProvisioningKeys.CURRENT_PROVISIONING_PUBKEY_B64U)
        val pub = MatrixSigner.publicKeyFromRaw(rawPub)
        val result = store.accept(canonical, signatureB64, setOf(pub))
        val resultText = when (result) {
            is MatrixStore.AcceptResult.Accepted ->
                "Accepted(version=${result.version})"
            is MatrixStore.AcceptResult.Rejected ->
                "Rejected(${result.reason})"
        }
        val readBack = try {
            val v = store.highestSeenVersion()
            val contacts = store.permittedContacts()
            "highestSeenVersion=$v contacts=${contacts?.size ?: "null"}"
        } catch (e: Exception) {
            "read-back failed: ${e.message}"
        }
        resultText to readBack
    } catch (e: Exception) {
        "error: ${e.message}" to null
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
