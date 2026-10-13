package com.umoja.secure.ui.contacts

import android.content.Context
import com.umoja.secure.storage.SecureStorage
import com.umoja.secure.transport.ContactEntry
import com.umoja.secure.transport.ContactsApi
import com.umoja.secure.transport.ContactsApiException
import com.umoja.secure.transport.HttpClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Loads the authorized contact list from the backend.
 *
 * The backend is the source of truth for authorization. The client
 * displays only what the backend permits — this is the enforcement
 * boundary in the current Phase 1 model.
 */
class ContactsViewModel(private val context: Context) {

    sealed class State {
        object Loading : State()
        data class Ready(val contacts: List<ContactEntry>) : State()
        data class Error(val code: String) : State()
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val _state = MutableStateFlow<State>(State.Loading)
    val state: StateFlow<State> = _state.asStateFlow()

    fun refresh() {
        _state.value = State.Loading
        scope.launch {
            val storage = SecureStorage(context)
            val token = storage.get("session_token")
            if (token == null) {
                _state.value = State.Error("not_authenticated")
                return@launch
            }
            try {
                val api = ContactsApi(HttpClient(HttpClient.DEV_BASE_URL))
                val list = api.list(token)
                _state.value = State.Ready(list)
            } catch (e: ContactsApiException) {
                _state.value = State.Error(e.code)
            } catch (e: Exception) {
                _state.value = State.Error("unexpected_error")
            }
        }
    }
}
