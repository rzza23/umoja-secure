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
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.umoja.secure.auth.PreKeyUploader
import com.umoja.secure.auth.SessionManager
import com.umoja.secure.crypto.DeviceIdentity
import com.umoja.secure.crypto.DeviceKeyManager
import com.umoja.secure.storage.SecureStorage
import com.umoja.secure.transport.EnrollmentApi
import com.umoja.secure.transport.EnrollmentException
import com.umoja.secure.transport.EnrollmentRequest
import com.umoja.secure.transport.HttpClient
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
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    HomeScreen(modifier = Modifier.padding(innerPadding))
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
fun HomeScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var deviceId by remember { mutableStateOf<String?>(null) }
    var sessionExpiresAt by remember { mutableStateOf<String?>(null) }
    var prekeyStatusText by remember { mutableStateOf<String?>(null) }
    var status by remember { mutableStateOf<String?>(null) }
    var isBusy by remember { mutableStateOf(false) }

    var tokenInput by remember { mutableStateOf("") }
    var labelInput by remember { mutableStateOf("Android device") }

    LaunchedEffect(Unit) {
        val storage = SecureStorage(context)
        deviceId = storage.get("device_id")
        sessionExpiresAt = storage.get("session_expires_at")
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
                prekeyStatus = prekeyStatusText,
                isBusy = isBusy,
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
    prekeyStatus: String?,
    isBusy: Boolean,
    onUploadPrekeys: () -> Unit,
    onLogout: () -> Unit,
) {
    Text(
        text = "Authenticated",
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.primary,
    )
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
    Spacer(modifier = Modifier.height(24.dp))
    Button(onClick = onUploadPrekeys, enabled = !isBusy) {
        Text(if (isBusy) "Working..." else "Upload prekeys")
    }
    Spacer(modifier = Modifier.height(8.dp))
    OutlinedButton(onClick = onLogout, enabled = !isBusy) {
        Text("Log out")
    }
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
