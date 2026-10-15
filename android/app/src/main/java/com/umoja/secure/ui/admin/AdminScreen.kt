package com.umoja.secure.ui.admin

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.umoja.secure.crypto.MatrixBuilder
import com.umoja.secure.crypto.ProvisioningBundle
import com.umoja.secure.crypto.jcsCanonicalizeString
import com.umoja.secure.storage.SecureStorage
import com.umoja.secure.transport.AdminApi
import com.umoja.secure.transport.AdminApiException
import com.umoja.secure.transport.HttpClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun AdminScreen(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // Make the system back button behave like the on-screen Back button.
    BackHandler { onBack() }

    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    var statusMessage by remember { mutableStateOf<String?>(null) }
    var devices by remember { mutableStateOf<List<AdminApi.DeviceEntry>>(emptyList()) }
    var contacts by remember { mutableStateOf<List<AdminApi.ContactEntry>>(emptyList()) }
    var ownerDeviceId by remember { mutableStateOf("") }
    var contactDeviceId by remember { mutableStateOf("") }

    var scannedBundle by remember { mutableStateOf<ProvisioningBundle?>(null) }
    var createdToken by remember { mutableStateOf<AdminApi.CreatedToken?>(null) }
    var provisionClearance by remember { mutableStateOf("") }
    var provisionVersion by remember { mutableStateOf("1") }
    var provisionContacts by remember { mutableStateOf<Set<String>>(emptySet()) }
    var builtWrapperJson by remember { mutableStateOf<String?>(null) }
    var builtHash by remember { mutableStateOf<String?>(null) }

    val api = remember { AdminApi(HttpClient(HttpClient.DEV_BASE_URL)) }
    val storage = remember { SecureStorage(context) }
    val sessionToken = remember { storage.get("session_token") }
    val clipboard = LocalClipboardManager.current
    val scanLauncher = rememberLauncherForActivityResult(contract = ScanContract()) { result ->
        val contents = result.contents
        if (contents != null) {
            try {
                scannedBundle = ProvisioningBundle.parse(contents)
                createdToken = null
                error = null
            } catch (e: IllegalArgumentException) {
                error = "QR parse failed: ${e.message}"
            }
        }
    }

    suspend fun load() {
        if (sessionToken == null) {
            error = "Not authenticated"
            loading = false
            return
        }
        loading = true
        error = null
        try {
            val d = withContext(Dispatchers.IO) { api.listDevices(sessionToken) }
            val c = withContext(Dispatchers.IO) { api.listContacts(sessionToken) }
            devices = d
            contacts = c.filter { it.status == "active" }
        } catch (e: AdminApiException) {
            error = e.code
        } finally {
            loading = false
        }
    }

    LaunchedEffect(Unit) { load() }

    Column(modifier.fillMaxSize().padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = {
                android.util.Log.d("UmojaNavigation", "Admin Back button tapped")
                onBack()
            }) { Text("Back") }
            Spacer(Modifier.width(8.dp))
            Text("Admin", style = MaterialTheme.typography.headlineSmall)
        }
        Spacer(Modifier.height(12.dp))

        if (loading) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
            return@Column
        }

        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.fillMaxSize(),
        ) {
            error?.let {
                item { Text("Error: $it", color = MaterialTheme.colorScheme.error) }
            }
            statusMessage?.let {
                item { Text(it, color = MaterialTheme.colorScheme.primary) }
            }

            item { Text("Devices (${devices.size})", style = MaterialTheme.typography.titleMedium) }
            items(devices.size) { i ->
                val d = devices[i]
                Card { Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text(d.label, style = MaterialTheme.typography.titleSmall)
                    Text(d.deviceId, style = MaterialTheme.typography.bodySmall)
                    Text("${d.role} / ${d.status}", style = MaterialTheme.typography.bodySmall)
                } }
            }

            item {
                Spacer(Modifier.height(8.dp))
                Text("Provision new device", style = MaterialTheme.typography.titleMedium)
            }
            item {
                Column {
                    var debugPasteText by remember { mutableStateOf("") }
                    val isDebug = (context.applicationInfo.flags and
                        android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0

                    Button(onClick = {
                        val options = ScanOptions().apply {
                            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                            setPrompt("Scan device enrollment QR")
                            setBeepEnabled(false)
                            setOrientationLocked(false)
                        }
                        scanLauncher.launch(options)
                    }) { Text("Scan device QR") }

                    if (isDebug) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "Debug: paste QR payload",
                            style = MaterialTheme.typography.labelSmall,
                        )
                        OutlinedTextField(
                            value = debugPasteText,
                            onValueChange = { debugPasteText = it },
                            label = { Text("Enrollment JSON") },
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Spacer(Modifier.height(4.dp))
                        Row {
                            Button(onClick = {
                                try {
                                    scannedBundle = ProvisioningBundle.parse(debugPasteText)
                                    createdToken = null
                                    error = null
                                } catch (e: IllegalArgumentException) {
                                    error = "QR parse failed: ${e.message}"
                                }
                            }) { Text("Load JSON") }
                            Spacer(Modifier.width(8.dp))
                            TextButton(onClick = { debugPasteText = "" }) { Text("Clear") }
                        }
                    }

                    scannedBundle?.let { b ->
                        Spacer(Modifier.height(8.dp))
                        Card { Column(Modifier.fillMaxWidth().padding(12.dp)) {
                            Text("Scanned device", style = MaterialTheme.typography.titleSmall)
                            Text("device_id: ${b.deviceId}", style = MaterialTheme.typography.bodySmall)
                            Text("auth: ${b.pubDeviceAuthKey.take(12)}...", style = MaterialTheme.typography.bodySmall)
                            Text("msg: ${b.pubMessagingIdentityKey.take(12)}...", style = MaterialTheme.typography.bodySmall)
                            Text("wipe: ${b.pubWipeConfirmationKey.take(12)}...", style = MaterialTheme.typography.bodySmall)
                            Spacer(Modifier.height(8.dp))
                            Button(onClick = {
                                val tok = sessionToken ?: return@Button
                                scope.launch {
                                    error = null
                                    statusMessage = null
                                    try {
                                        val t = withContext(Dispatchers.IO) {
                                            api.createEnrollmentToken(
                                                AdminApi.CreateTokenRequest(
                                                    role = "user",
                                                    boundPublicKey = b.pubDeviceAuthKey,
                                                ),
                                                tok,
                                            )
                                        }
                                        createdToken = t
                                        statusMessage = "Token created"
                                    } catch (e: AdminApiException) {
                                        error = e.code
                                    }
                                }
                            }) { Text("Create enrollment token for this device") }
                            createdToken?.let { t ->
                                Spacer(Modifier.height(8.dp))
                                Text("Token (shown once)", style = MaterialTheme.typography.labelSmall)
                                Text(t.token, style = MaterialTheme.typography.bodySmall)
                                Text("Expires: ${t.expiresAt}", style = MaterialTheme.typography.bodySmall)
                                Spacer(Modifier.height(8.dp))
                                Button(onClick = {
                                    clipboard.setText(AnnotatedString(t.token))
                                    statusMessage = "Token copied"
                                }) { Text("Copy token") }
                            }
                        } }
                    }
                }
            }
            scannedBundle?.let { b ->
                item {
                    Column {
                        OutlinedTextField(
                            value = provisionClearance,
                            onValueChange = { provisionClearance = it },
                            label = { Text("Clearance") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = provisionVersion,
                            onValueChange = { s -> provisionVersion = s.filter { it.isDigit() } },
                            label = { Text("Matrix version") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Text(
                            "Matrix version. Must be higher than any previously issued matrix. " +
                                "Devices reject matrices with version <= their stored version. " +
                                "Use 1 for the first matrix.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
                item {
                    Column {
                        Text(
                            "Permitted contacts (${provisionContacts.size})",
                            style = MaterialTheme.typography.titleSmall,
                        )
                        devices.filter { it.status == "active" && it.deviceId != b.deviceId }.forEach { d ->
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(
                                    checked = provisionContacts.contains(d.deviceId),
                                    onCheckedChange = { checked ->
                                        provisionContacts = if (checked) {
                                            provisionContacts + d.deviceId
                                        } else {
                                            provisionContacts - d.deviceId
                                        }
                                    },
                                )
                                Text(
                                    "${d.label} (${d.deviceId.take(8)})",
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                        }
                    }
                }
                item {
                    Button(onClick = {
                        error = null
                        statusMessage = null
                        val v = provisionVersion.toIntOrNull()
                        if (v == null || v < 1) {
                            error = "version must be a positive integer"
                        } else {
                            try {
                                val signed = MatrixBuilder.build(
                                    bundle = b,
                                    clearance = provisionClearance.trim(),
                                    permittedContacts = provisionContacts.toList(),
                                    version = v,
                                )
                                val wrapperStr = jcsCanonicalizeString(signed.toJsonMap())
                                val digest = java.security.MessageDigest.getInstance("SHA-256")
                                    .digest(wrapperStr.toByteArray(Charsets.UTF_8))
                                val hashB64 = java.util.Base64.getUrlEncoder()
                                    .withoutPadding()
                                    .encodeToString(digest)
                                builtWrapperJson = wrapperStr
                                builtHash = hashB64
                                statusMessage = "Matrix built - review hash and content"
                            } catch (e: IllegalArgumentException) {
                                error = "Build failed: ${e.message}"
                            }
                        }
                    }) { Text("Build matrix") }
                }
                builtWrapperJson?.let { w ->
                    item {
                        Card { Column(Modifier.fillMaxWidth().padding(12.dp)) {
                            Text("Unsigned wrapper (JCS-canonical)", style = MaterialTheme.typography.labelSmall)
                            Text(w, style = MaterialTheme.typography.bodySmall)
                        } }
                    }
                }
                builtHash?.let { h ->
                    item {
                        Card { Column(Modifier.fillMaxWidth().padding(12.dp)) {
                            Text("SHA-256 (base64url, no pad)", style = MaterialTheme.typography.labelSmall)
                            Text(h, style = MaterialTheme.typography.bodySmall)
                            Spacer(Modifier.height(8.dp))
                            Row {
                                Button(onClick = {
                                    clipboard.setText(AnnotatedString(builtWrapperJson ?: ""))
                                    statusMessage = "Wrapper copied"
                                }) { Text("Copy wrapper") }
                                Spacer(Modifier.width(8.dp))
                                Button(onClick = {
                                    clipboard.setText(AnnotatedString(h))
                                    statusMessage = "Hash copied"
                                }) { Text("Copy hash") }
                            }
                        } }
                    }
                }
            }

            item {
                Spacer(Modifier.height(8.dp))
                Text("Authorize a contact pair", style = MaterialTheme.typography.titleMedium)
            }
            item {
                Column {
                    OutlinedTextField(
                        value = ownerDeviceId,
                        onValueChange = { ownerDeviceId = it },
                        label = { Text("Owner device ID") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = contactDeviceId,
                        onValueChange = { contactDeviceId = it },
                        label = { Text("Contact device ID") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(8.dp))
                    Button(onClick = {
                        val tok = sessionToken ?: return@Button
                        scope.launch {
                            error = null
                            statusMessage = null
                            try {
                                withContext(Dispatchers.IO) {
                                    api.authorizeContact(
                                        ownerDeviceId.trim(),
                                        contactDeviceId.trim(),
                                        tok,
                                    )
                                }
                                statusMessage = "Contact authorized"
                                load()
                            } catch (e: AdminApiException) {
                                error = e.code
                            }
                        }
                    }) { Text("Authorize") }
                }
            }

            item {
                Spacer(Modifier.height(8.dp))
                Text("Active contacts (${contacts.size})", style = MaterialTheme.typography.titleMedium)
            }
            items(contacts.size) { i ->
                val c = contacts[i]
                Card { Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text("${c.ownerLabel} -> ${c.contactLabel}", style = MaterialTheme.typography.titleSmall)
                    Text(
                        "${c.ownerDeviceId.take(8)} -> ${c.contactDeviceId.take(8)}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Text(c.verificationLevel, style = MaterialTheme.typography.bodySmall)
                } }
            }
        }
    }
}
