package com.umoja.secure

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.umoja.secure.auth.PreKeyUploader
import com.umoja.secure.messaging.MessagingService
import com.umoja.secure.auth.SessionManager
import com.umoja.secure.crypto.DeviceIdentity
import com.umoja.secure.crypto.DeviceKeyManager
import com.umoja.secure.storage.SecureStorage
import com.umoja.secure.transport.EnrollmentApi
import com.umoja.secure.transport.EnrollmentException
import com.umoja.secure.transport.EnrollmentRequest
import com.umoja.secure.transport.HttpClient
import com.umoja.secure.transport.WebSocketClient
import com.umoja.secure.ui.admin.AdminScreen
import com.umoja.secure.ui.theme.UmojaSecureTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            UmojaSecureTheme {
                var showAdmin by remember { mutableStateOf(false) }
                if (showAdmin) {
                    AdminScreen(onBack = { showAdmin = false })
                } else {
                    Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                        HomeScreen(
                            onOpenAdmin = { showAdmin = true },
                            modifier = Modifier.padding(innerPadding),
                        )
                    }
                }
            }
        }
    }
}

private sealed class EnrollUiOutcome {
    data class Success(val deviceId: String) : EnrollUiOutcome()
    data class Failure(val code: String) : EnrollUiOutcome()
}

@Composable
fun HomeScreen(
    onOpenAdmin: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var deviceId by remember { mutableStateOf<String?>(null) }
    var sessionExpiresAt by remember { mutableStateOf<String?>(null) }
    var prekeyStatusText by remember { mutableStateOf<String?>(null) }
    var status by remember { mutableStateOf<String?>(null) }
    var isBusy by remember { mutableStateOf(false) }
    var showAbout by remember { mutableStateOf(false) }
    var envelopesReceived by remember { mutableStateOf(0) }
    var peerDeviceIdInput by remember { mutableStateOf("") }
    var sentMessageInput by remember { mutableStateOf("hello from Umoja") }
    var receivedMessagesText by remember { mutableStateOf<String?>(null) }

    val app = context.applicationContext as UmojaApplication
    val wsState by app.webSocketClient.state.collectAsState()

    // Observe incoming envelopes and decrypt them as they arrive.
    LaunchedEffect(Unit) {
        app.webSocketClient.envelopes.collect { frame ->
            envelopesReceived += 1
            val svc = MessagingService(context)
            val msg = svc.decryptWebSocketFrame(frame)
            if (msg != null) {
                val prefix = if (receivedMessagesText.isNullOrEmpty()) "" else "\n"
                receivedMessagesText = (receivedMessagesText ?: "") +
                    prefix + "${msg.senderDeviceId.take(8)}: ${msg.plaintext}"
                status = "Decrypted incoming message"
            }
        }
    }

    var tokenInput by remember { mutableStateOf("") }
    var labelInput by remember { mutableStateOf("Android device") }

    var role by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        val storage = SecureStorage(context)
        deviceId = storage.get("device_id")
        sessionExpiresAt = storage.get("session_expires_at")
        role = storage.get("session_role") ?: storage.get("role")
    }

    // Re-read role whenever the session changes. Makes the admin button
    // appear immediately after an admin authenticates.
    LaunchedEffect(sessionExpiresAt) {
        val storage = SecureStorage(context)
        role = storage.get("session_role")
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = stringResource(R.string.app_name),
            style = MaterialTheme.typography.headlineMedium,
        )
        Spacer(modifier = Modifier.height(24.dp))

        when {
            deviceId == null -> EnrollmentForm(
                tokenInput = tokenInput,
                onTokenChange = { tokenInput = it },
                labelInput = labelInput,
                onLabelChange = { labelInput = it },
                isBusy = isBusy,
                onEnroll = {
                    isBusy = true
                    status = null
                    scope.launch {
                        val outcome = enrollDevice(context, tokenInput, labelInput)
                        withContext(Dispatchers.Main) {
                            isBusy = false
                            when (outcome) {
                                is EnrollUiOutcome.Success -> {
                                    deviceId = outcome.deviceId
                                    status = "Enrolled"
                                }
                                is EnrollUiOutcome.Failure -> {
                                    status = "Error: ${outcome.code}"
                                }
                            }
                        }
                    }
                },
            )

            sessionExpiresAt == null -> AuthenticatePanel(
                deviceId = deviceId!!,
                isBusy = isBusy,
                onAuthenticate = {
                    isBusy = true
                    status = null
                    scope.launch {
                        val manager = SessionManager(context)
                        val outcome = manager.authenticate()
                        withContext(Dispatchers.Main) {
                            isBusy = false
                            when (outcome) {
                                is SessionManager.AuthOutcome.Success -> {
                                    sessionExpiresAt = outcome.expiresAt
                                    status = "Authenticated"
                                }
                                is SessionManager.AuthOutcome.Failure -> {
                                    status = "Auth error: ${outcome.code}"
                                }
                                SessionManager.AuthOutcome.NotEnrolled -> {
                                    deviceId = null
                                    status = "Device not enrolled"
                                }
                            }
                        }
                    }
                },
            )

            else -> AuthenticatedPanel(
                deviceId = deviceId!!,
                expiresAt = sessionExpiresAt!!,
                role = role,
                onOpenAdmin = onOpenAdmin,
                prekeyStatus = prekeyStatusText,
                wsState = wsState,
                envelopesReceived = envelopesReceived,
                peerDeviceId = peerDeviceIdInput,
                onPeerDeviceIdChange = { peerDeviceIdInput = it },
                messageInput = sentMessageInput,
                onMessageInputChange = { sentMessageInput = it },
                receivedMessages = receivedMessagesText,
                isBusy = isBusy,
                onSendMessage = {
                    isBusy = true
                    status = null
                    scope.launch {
                        val svc = MessagingService(context)
                        val outcome = svc.sendMessage(peerDeviceIdInput.trim(), sentMessageInput)
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
                onCheckMessages = {
                    isBusy = true
                    status = null
                    scope.launch {
                        val svc = MessagingService(context)
                        val outcome = svc.receiveMessages()
                        withContext(Dispatchers.Main) {
                            isBusy = false
                            when (outcome) {
                                is MessagingService.ReceiveOutcome.Success -> {
                                    val list = outcome.messages
                                    receivedMessagesText = if (list.isEmpty()) {
                                        "No pending messages."
                                    } else {
                                        list.joinToString("\n") { m ->
                                            "${m.senderDeviceId.take(8)}: ${m.plaintext}"
                                        }
                                    }
                                    status = "Received ${list.size} message(s)"
                                }
                                is MessagingService.ReceiveOutcome.Failure -> {
                                    status = "Receive error: ${outcome.code}"
                                }
                            }
                        }
                    }
                },
                onConnectWs = {
                    val storage = SecureStorage(context)
                    val token = storage.get("session_token")
                    if (token != null) {
                        app.webSocketClient.connect(token)
                    } else {
                        status = "No session token"
                    }
                },
                onDisconnectWs = {
                    app.webSocketClient.disconnect()
                },
                onUploadPrekeys = {
                    isBusy = true
                    status = null
                    scope.launch {
                        val uploader = PreKeyUploader(context)
                        val outcome = uploader.uploadPreKeys()
                        withContext(Dispatchers.Main) {
                            isBusy = false
                            when (outcome) {
                                is PreKeyUploader.UploadOutcome.Success -> {
                                    prekeyStatusText =
                                        "Prekeys: ${outcome.total} unconsumed (uploaded ${outcome.stored})"
                                    status = "Prekeys uploaded"
                                }
                                is PreKeyUploader.UploadOutcome.Failure -> {
                                    status = "Prekey upload error: ${outcome.code}"
                                }
                                PreKeyUploader.UploadOutcome.NotAuthenticated -> {
                                    sessionExpiresAt = null
                                    status = "Session expired — authenticate again"
                                }
                            }
                        }
                    }
                },
                onLogout = {
                    isBusy = true
                    status = null
                    scope.launch {
                        val manager = SessionManager(context)
                        manager.clearSession()
                        withContext(Dispatchers.Main) {
                            isBusy = false
                            sessionExpiresAt = null
                            status = "Logged out"
                        }
                    }
                },
            )
        }

        status?.let {
            Spacer(modifier = Modifier.height(16.dp))
            Text(text = it, style = MaterialTheme.typography.bodySmall)
        }

        Spacer(modifier = Modifier.height(24.dp))
        TextButton(onClick = { showAbout = true }) {
            Text("About")
        }
    }

    if (showAbout) {
        AboutDialog(onClose = { showAbout = false })
    }
}

@Composable
private fun EnrollmentForm(
    tokenInput: String,
    onTokenChange: (String) -> Unit,
    labelInput: String,
    onLabelChange: (String) -> Unit,
    isBusy: Boolean,
    onEnroll: () -> Unit,
) {
    Text(
        text = stringResource(R.string.home_status_not_enrolled),
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.error,
    )
    Spacer(modifier = Modifier.height(24.dp))
    OutlinedTextField(
        value = tokenInput,
        onValueChange = onTokenChange,
        label = { Text("Enrollment token") },
        enabled = !isBusy,
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    Spacer(modifier = Modifier.height(12.dp))
    OutlinedTextField(
        value = labelInput,
        onValueChange = onLabelChange,
        label = { Text("Device label") },
        enabled = !isBusy,
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    Spacer(modifier = Modifier.height(24.dp))
    Button(
        onClick = onEnroll,
        enabled = !isBusy && tokenInput.isNotBlank(),
    ) {
        Text(if (isBusy) "Enrolling..." else stringResource(R.string.home_enroll_button))
    }
}

@Composable
private fun AuthenticatePanel(
    deviceId: String,
    isBusy: Boolean,
    onAuthenticate: () -> Unit,
) {
    Text(
        text = stringResource(R.string.home_status_enrolled),
        style = MaterialTheme.typography.titleMedium,
    )
    Spacer(modifier = Modifier.height(8.dp))
    Text(
        text = "Device ID: $deviceId",
        style = MaterialTheme.typography.bodySmall,
    )
    Spacer(modifier = Modifier.height(24.dp))
    Button(onClick = onAuthenticate, enabled = !isBusy) {
        Text(if (isBusy) "Authenticating..." else "Authenticate")
    }
}

@Composable
private fun AuthenticatedPanel(
    deviceId: String,
    expiresAt: String,
    role: String?,
    onOpenAdmin: () -> Unit,
    prekeyStatus: String?,
    wsState: WebSocketClient.State,
    envelopesReceived: Int,
    peerDeviceId: String,
    onPeerDeviceIdChange: (String) -> Unit,
    messageInput: String,
    onMessageInputChange: (String) -> Unit,
    receivedMessages: String?,
    isBusy: Boolean,
    onSendMessage: () -> Unit,
    onCheckMessages: () -> Unit,
    onConnectWs: () -> Unit,
    onDisconnectWs: () -> Unit,
    onUploadPrekeys: () -> Unit,
    onLogout: () -> Unit,
) {
    Text(
        text = "Authenticated",
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.primary,
    )
    if (role == "admin" || role == "owner") {
        Spacer(modifier = Modifier.height(8.dp))
        Button(onClick = onOpenAdmin, enabled = !isBusy) {
            Text("Open admin panel")
        }
    }
    Spacer(modifier = Modifier.height(8.dp))
    Text(
        text = "Device ID: $deviceId",
        style = MaterialTheme.typography.bodySmall,
    )
    Spacer(modifier = Modifier.height(4.dp))
    Text(
        text = "Session expires: $expiresAt",
        style = MaterialTheme.typography.bodySmall,
    )
    prekeyStatus?.let {
        Spacer(modifier = Modifier.height(4.dp))
        Text(text = it, style = MaterialTheme.typography.bodySmall)
    }
    Spacer(modifier = Modifier.height(8.dp))
    Text(
        text = "WebSocket: ${wsStateLabel(wsState)}",
        style = MaterialTheme.typography.bodySmall,
    )
    Spacer(modifier = Modifier.height(4.dp))
    Text(
        text = "Envelopes received: $envelopesReceived",
        style = MaterialTheme.typography.bodySmall,
    )
    Spacer(modifier = Modifier.height(24.dp))

    val isConnected = wsState is WebSocketClient.State.Ready ||
        wsState is WebSocketClient.State.Connecting ||
        wsState is WebSocketClient.State.Authenticating ||
        wsState is WebSocketClient.State.Reconnecting

    if (isConnected) {
        OutlinedButton(onClick = onDisconnectWs, enabled = !isBusy) {
            Text("Disconnect WebSocket")
        }
    } else {
        Button(onClick = onConnectWs, enabled = !isBusy) {
            Text("Connect WebSocket")
        }
    }

    Spacer(modifier = Modifier.height(8.dp))
    Button(onClick = onUploadPrekeys, enabled = !isBusy) {
        Text(if (isBusy) "Working..." else "Upload prekeys")
    }
    Spacer(modifier = Modifier.height(24.dp))
    Text("Messaging", style = MaterialTheme.typography.titleSmall)
    Spacer(modifier = Modifier.height(8.dp))

    OutlinedTextField(
        value = peerDeviceId,
        onValueChange = onPeerDeviceIdChange,
        label = { Text("Peer device ID") },
        enabled = !isBusy,
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    Spacer(modifier = Modifier.height(8.dp))

    OutlinedTextField(
        value = messageInput,
        onValueChange = onMessageInputChange,
        label = { Text("Message to send") },
        enabled = !isBusy,
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    Spacer(modifier = Modifier.height(8.dp))

    Button(
        onClick = onSendMessage,
        enabled = !isBusy && peerDeviceId.isNotBlank() && messageInput.isNotBlank(),
    ) {
        Text(if (isBusy) "Working..." else "Send encrypted message")
    }
    Spacer(modifier = Modifier.height(8.dp))
    OutlinedButton(onClick = onCheckMessages, enabled = !isBusy) {
        Text("Check messages")
    }

    receivedMessages?.let {
        Spacer(modifier = Modifier.height(12.dp))
        Text("Received:", style = MaterialTheme.typography.titleSmall)
        Spacer(modifier = Modifier.height(4.dp))
        Text(it, style = MaterialTheme.typography.bodySmall)
    }

    Spacer(modifier = Modifier.height(24.dp))
    OutlinedButton(onClick = onLogout, enabled = !isBusy) {
        Text("Log out")
    }
}

private fun wsStateLabel(state: WebSocketClient.State): String = when (state) {
    is WebSocketClient.State.Disconnected -> "Disconnected"
    is WebSocketClient.State.Connecting -> "Connecting"
    is WebSocketClient.State.Authenticating -> "Authenticating"
    is WebSocketClient.State.Ready -> "Ready"
    is WebSocketClient.State.Reconnecting -> "Reconnecting"
    is WebSocketClient.State.Failed -> "Failed: ${state.reason}"
    is WebSocketClient.State.Revoked -> "Revoked"
}

@Composable
private fun AboutDialog(onClose: () -> Unit) {
    val sourceUrl = stringResource(R.string.about_source_url)
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(stringResource(R.string.about_title)) },
        text = {
            Column {
                Text("Umoja Secure")
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    stringResource(R.string.about_license_summary),
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text("Source code:", style = MaterialTheme.typography.bodySmall)
                Text(sourceUrl, style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = {
            TextButton(onClick = onClose) {
                Text("Close")
            }
        },
    )
}

private suspend fun enrollDevice(
    context: Context,
    token: String,
    label: String,
): EnrollUiOutcome = withContext(Dispatchers.IO) {
    try {
        val keyManager = DeviceKeyManager(context = context)
        val keyInfo = keyManager.ensureKeyPair()
        val publicKeyB64 = DeviceIdentity.encodePublicKey(keyInfo.spkiEncoded)

        val http = HttpClient(HttpClient.DEV_BASE_URL)
        val api = EnrollmentApi(http)
        val response = api.enroll(
            EnrollmentRequest(
                token = token,
                devicePublicKey = publicKeyB64,
                label = label,
            ),
        )

        val storage = SecureStorage(context)
        storage.put("device_id", response.deviceId)
        storage.put("org_id", response.orgId)
        storage.put("role", response.role)

        EnrollUiOutcome.Success(response.deviceId)
    } catch (e: EnrollmentException) {
        EnrollUiOutcome.Failure(e.code)
    } catch (e: Exception) {
        EnrollUiOutcome.Failure("unexpected_error")
    }
}
