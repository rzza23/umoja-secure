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
                    EnrollmentScreen(modifier = Modifier.padding(innerPadding))
                }
            }
        }
    }
}

private sealed class EnrollmentOutcome {
    data class Success(val deviceId: String) : EnrollmentOutcome()
    data class Failure(val code: String) : EnrollmentOutcome()
}

@Composable
fun EnrollmentScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var tokenInput by remember { mutableStateOf("") }
    var labelInput by remember { mutableStateOf("Android device") }
    var status by remember { mutableStateOf<String?>(null) }
    var enrolledDeviceId by remember { mutableStateOf<String?>(null) }
    var isEnrolling by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        val storage = SecureStorage(context)
        enrolledDeviceId = storage.get("device_id")
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

        if (enrolledDeviceId != null) {
            Text(
                text = stringResource(R.string.home_status_enrolled),
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "Device ID: $enrolledDeviceId",
                style = MaterialTheme.typography.bodySmall,
            )
        } else {
            Text(
                text = stringResource(R.string.home_status_not_enrolled),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.error,
            )

            Spacer(modifier = Modifier.height(24.dp))

            OutlinedTextField(
                value = tokenInput,
                onValueChange = { tokenInput = it },
                label = { Text("Enrollment token") },
                enabled = !isEnrolling,
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = labelInput,
                onValueChange = { labelInput = it },
                label = { Text("Device label") },
                enabled = !isEnrolling,
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = {
                    isEnrolling = true
                    status = null
                    scope.launch {
                        val outcome = enrollDevice(context, tokenInput, labelInput)
                        withContext(Dispatchers.Main) {
                            isEnrolling = false
                            when (outcome) {
                                is EnrollmentOutcome.Success -> {
                                    enrolledDeviceId = outcome.deviceId
                                    status = "Enrolled: ${outcome.deviceId}"
                                }
                                is EnrollmentOutcome.Failure -> {
                                    status = "Error: ${outcome.code}"
                                }
                            }
                        }
                    }
                },
                enabled = !isEnrolling && tokenInput.isNotBlank(),
            ) {
                Text(
                    if (isEnrolling) "Enrolling..."
                    else stringResource(R.string.home_enroll_button)
                )
            }
        }

        status?.let {
            Spacer(modifier = Modifier.height(16.dp))
            Text(text = it, style = MaterialTheme.typography.bodySmall)
        }
    }
}

private suspend fun enrollDevice(
    context: Context,
    token: String,
    label: String,
): EnrollmentOutcome = withContext(Dispatchers.IO) {
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

        EnrollmentOutcome.Success(response.deviceId)
    } catch (e: EnrollmentException) {
        EnrollmentOutcome.Failure(e.code)
    } catch (e: Exception) {
        EnrollmentOutcome.Failure("unexpected_error")
    }
}
