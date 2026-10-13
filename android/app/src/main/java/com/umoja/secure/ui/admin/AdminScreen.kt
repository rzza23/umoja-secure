package com.umoja.secure.ui.admin

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
import androidx.compose.ui.unit.dp
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

    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    var statusMessage by remember { mutableStateOf<String?>(null) }
    var devices by remember { mutableStateOf<List<AdminApi.DeviceEntry>>(emptyList()) }
    var contacts by remember { mutableStateOf<List<AdminApi.ContactEntry>>(emptyList()) }
    var createdToken by remember { mutableStateOf<AdminApi.CreatedToken?>(null) }

    var newTokenRole by remember { mutableStateOf("user") }
    var newTokenLabel by remember { mutableStateOf("") }
    var ownerDeviceId by remember { mutableStateOf("") }
    var contactDeviceId by remember { mutableStateOf("") }

    val api = remember { AdminApi(HttpClient(HttpClient.DEV_BASE_URL)) }
    val storage = remember { SecureStorage(context) }
    val sessionToken = remember { storage.get("session_token") }

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
            TextButton(onClick = onBack) { Text("Back") }
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
                Text("Create enrollment token", style = MaterialTheme.typography.titleMedium)
            }
            item {
                Column {
                    OutlinedTextField(
                        value = newTokenRole,
                        onValueChange = { newTokenRole = it },
                        label = { Text("Role (user / admin / owner / auditor)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = newTokenLabel,
                        onValueChange = { newTokenLabel = it },
                        label = { Text("Label hint") },
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
                                val t = withContext(Dispatchers.IO) {
                                    api.createEnrollmentToken(
                                        AdminApi.CreateTokenRequest(
                                            role = newTokenRole.trim(),
                                            labelHint = newTokenLabel.trim().ifBlank { null },
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
                    }) { Text("Create token") }

                    createdToken?.let { t ->
                        Spacer(Modifier.height(8.dp))
                        Card { Column(Modifier.fillMaxWidth().padding(12.dp)) {
                            Text("Token (shown once)", style = MaterialTheme.typography.labelSmall)
                            Text(t.token, style = MaterialTheme.typography.bodySmall)
                            Text("Expires: ${t.expiresAt}", style = MaterialTheme.typography.bodySmall)
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
