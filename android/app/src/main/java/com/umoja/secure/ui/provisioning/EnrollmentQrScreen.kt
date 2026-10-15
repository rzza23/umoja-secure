package com.umoja.secure.ui.provisioning

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.Image
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
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.BarcodeEncoder
import com.umoja.secure.crypto.DeviceIdStore
import com.umoja.secure.crypto.DeviceIdentity
import com.umoja.secure.crypto.DeviceKeyManager
import com.umoja.secure.crypto.EnrollmentQrPayload
import com.umoja.secure.crypto.SignalIdentityStore
import com.umoja.secure.crypto.WipeConfirmationKeyManager
import com.umoja.secure.storage.SecureStorage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Enrolling-device QR screen for TASK-P1-019.
 *
 * Renders the amended umoja.enrollment-request.v1 payload (see handoff 3)
 * as a QR the admin scans. Also exposes the JSON as copy-to-clipboard and
 * as inline monospace text, so the admin has a manual fallback when
 * camera scanning is unavailable on either side.
 *
 * device_id is generated on first entry and persisted via SecureStorage.
 * Never regenerated for the lifetime of the cryptographic entity it
 * identifies. A duress wipe destroys it — that is correct behavior
 * (see DeviceIdStore KDoc).
 *
 * All three keys are fetched via their canonical accessors:
 *   - pub_device_auth_key:       DeviceKeyManager.ensureKeyPair -> DeviceIdentity.encodePublicKey
 *   - pub_messaging_identity_key: SignalIdentityStore.messagingIdentityKeyBase64Url
 *   - pub_wipe_confirmation_key:  WipeConfirmationKeyManager.ensureKeyPair -> publicKeyBase64Url
 *
 * ensureKeyPair() is called for both DeviceKeyManager and
 * WipeConfirmationKeyManager because either key may be absent on a fresh
 * install. Generating them here is the same code path the enrollment
 * flow uses; no separate key material is created.
 */
@Composable
fun EnrollmentQrScreen(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current

    var payload by remember { mutableStateOf<String?>(null) }
    var deviceIdDisplay by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var isBusy by remember { mutableStateOf(true) }
    var copied by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        val result = withContext(Dispatchers.IO) {
            runCatching {
                val deviceId = DeviceIdStore(SecureStorage(context)).getOrCreate()

                val deviceKeyMgr = DeviceKeyManager(context)
                deviceKeyMgr.ensureKeyPair()
                val spki = deviceKeyMgr.publicKey()
                    ?: error("device authentication key unavailable after ensureKeyPair")
                val authB64u = DeviceIdentity.encodePublicKey(spki)

                val messagingB64u = SignalIdentityStore(context).messagingIdentityKeyBase64Url()

                val wipeMgr = WipeConfirmationKeyManager(context)
                wipeMgr.ensureKeyPair()
                val wipeB64u = wipeMgr.publicKeyBase64Url()
                    ?: error("wipe-confirmation key unavailable after ensureKeyPair")

                val json = EnrollmentQrPayload.build(
                    deviceId = deviceId,
                    pubDeviceAuthKey = authB64u,
                    pubMessagingIdentityKey = messagingB64u,
                    pubWipeConfirmationKey = wipeB64u,
                )
                Pair(deviceId, json)
            }
        }
        result.fold(
            onSuccess = { pair ->
                deviceIdDisplay = pair.first
                payload = pair.second
                isBusy = false
            },
            onFailure = { e ->
                error = e.message ?: e::class.simpleName ?: "unknown error"
                isBusy = false
            },
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("Back") }
            Spacer(Modifier.padding(horizontal = 4.dp))
            Text("Enrollment QR", style = MaterialTheme.typography.headlineMedium)
        }
        Spacer(Modifier.height(16.dp))

        when {
            isBusy -> {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center,
                ) {
                    CircularProgressIndicator()
                }
            }

            error != null -> {
                Text(
                    "Error generating QR: $error",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            payload != null -> {
                val json = payload!!

                Text(
                    "Device ID",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    deviceIdDisplay ?: "\u2014",
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.height(16.dp))

                val qrBitmap = remember(json) {
                    BarcodeEncoder().encodeBitmap(
                        json,
                        BarcodeFormat.QR_CODE,
                        640,
                        640,
                    )
                }
                Image(
                    bitmap = qrBitmap.asImageBitmap(),
                    contentDescription = "Enrollment QR code",
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(16.dp))

                Button(
                    onClick = {
                        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        cm.setPrimaryClip(ClipData.newPlainText("enrollment-payload", json))
                        copied = true
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Copy JSON payload")
                }
                if (copied) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Copied to clipboard.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }

                Spacer(Modifier.height(24.dp))
                Text(
                    "Payload (manual fallback)",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    json,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}
