package com.umoja.secure.ui.navigation

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import com.umoja.secure.ui.chat.ChatScreen
import com.umoja.secure.ui.chat.ChatViewModel
import com.umoja.secure.crypto.IdentityChangeController
import com.umoja.secure.ui.contacts.ContactsScreen
import com.umoja.secure.ui.conversations.ConversationsScreen
import com.umoja.secure.ui.provisioning.EnrollmentQrScreen
import com.umoja.secure.ui.settings.SettingsScreen

enum class Tab(val label: String, val icon: ImageVector) {
    Conversations("Conversations", Icons.Filled.Email),
    Contacts("Contacts", Icons.Filled.Person),
    Settings("Settings", Icons.Filled.Settings),
}

private data class OpenChat(val peerDeviceId: String, val peerLabel: String)

@Composable
fun MainNavigation(
    onLogout: () -> Unit,
    onOpenAdmin: (() -> Unit)?,
    onOpenDiagnostics: () -> Unit,
    selectedTab: Tab,
    onSelectTab: (Tab) -> Unit,
    identityChangeController: IdentityChangeController,
) {
    var openChat by remember { mutableStateOf<OpenChat?>(null) }
    var openEnrollmentQr by remember { mutableStateOf(false) }

    val context = LocalContext.current
    val chatViewModel = remember { ChatViewModel(context) }

    // If a chat is open, show it full-screen instead of the tabbed shell.
    if (openEnrollmentQr) {
        EnrollmentQrScreen(
            onBack = { openEnrollmentQr = false },
            modifier = Modifier.fillMaxSize(),
        )
        return
    }

    val activeChat = openChat
    if (activeChat != null) {
        ChatScreen(
            peerDeviceId = activeChat.peerDeviceId,
            peerLabel = activeChat.peerLabel,
            onBack = { openChat = null },
            viewModel = chatViewModel,
            identityChangeController = identityChangeController,
        )
        return
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { tab ->
                    NavigationBarItem(
                        selected = selectedTab == tab,
                        onClick = { onSelectTab(tab) },
                        icon = { Icon(tab.icon, contentDescription = tab.label) },
                        label = { Text(tab.label) },
                    )
                }
            }
        },
    ) { innerPadding ->
        val contentModifier = Modifier.padding(innerPadding)
        when (selectedTab) {
            Tab.Conversations -> ConversationsScreen(
                onOpenChat = { id, label -> openChat = OpenChat(id, label) },
                modifier = contentModifier,
            )
            Tab.Contacts -> ContactsScreen(
                onOpenChat = { id, label -> openChat = OpenChat(id, label) },
                modifier = contentModifier,
            )
            Tab.Settings -> SettingsScreen(
                onLogout = onLogout,
                onOpenAdmin = onOpenAdmin,
                onOpenDiagnostics = onOpenDiagnostics,
                onOpenEnrollmentQr = { openEnrollmentQr = true },
                modifier = contentModifier,
            )
        }
    }
}
