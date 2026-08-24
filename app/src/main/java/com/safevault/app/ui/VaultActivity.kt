package com.safevault.app.ui

import android.content.Intent
import android.os.Bundle
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.widget.SearchView
import androidx.core.view.isVisible
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.safevault.app.R
import com.safevault.app.data.VaultEntry
import com.safevault.app.data.VaultRepository
import com.safevault.app.databinding.ActivityVaultBinding
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch

class VaultActivity : SecureActivity() {

    private lateinit var binding: ActivityVaultBinding
    private lateinit var adapter: VaultListAdapter
    private lateinit var repository: VaultRepository
    private val query = MutableStateFlow("")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (isFinishing) return

        binding = ActivityVaultBinding.inflate(layoutInflater)
        setContentView(binding.root)
        repository = VaultRepository(this)

        adapter = VaultListAdapter(
            onClick = { entry -> openEntry(entry.id) },
            onLongClick = { entry -> confirmDelete(entry) },
            onFavoriteToggle = { entry ->
                lifecycleScope.launch { repository.setFavorite(entry.id, !entry.favorite) }
            }
        )
        binding.recycler.layoutManager = LinearLayoutManager(this)
        binding.recycler.adapter = adapter

        binding.fabAdd.setOnClickListener {
            startActivity(Intent(this, EntryEditActivity::class.java))
        }
        binding.btnSecurity.setOnClickListener {
            startActivity(Intent(this, SecurityActivity::class.java))
        }
        binding.btnLock.setOnClickListener { lockVault() }

        binding.searchView.setOnQueryTextListener(object : SearchView.OnQueryTextListener {
            override fun onQueryTextSubmit(q: String?) = false
            override fun onQueryTextChange(q: String?): Boolean {
                query.value = q.orEmpty()
                return true
            }
        })

        observeVault()

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            // Backing out of the vault list means leaving the vault, so lock it
            // rather than dropping the user onto whatever was behind the app.
            override fun handleOnBackPressed() = lockVault()
        })
    }

    private fun observeVault() {
        val favoritesLabel = getString(R.string.favorites)
        lifecycleScope.launch {
            repository.observeAll()
                .combine(query) { entries, q -> entries.filter { it.matches(q) } }
                .collect { entries ->
                    adapter.submitList(VaultListAdapter.build(entries, favoritesLabel))
                    binding.emptyStateContainer.isVisible = entries.isEmpty()
                    binding.tvEmpty.setText(
                        if (query.value.isBlank()) R.string.empty_vault else R.string.empty_search
                    )
                }
        }
    }

    /** Search covers the non-secret columns only — no decryption per keystroke. */
    private fun VaultEntry.matches(q: String): Boolean {
        if (q.isBlank()) return true
        return title.contains(q, ignoreCase = true) ||
            serviceName.contains(q, ignoreCase = true) ||
            website.contains(q, ignoreCase = true)
    }

    private fun openEntry(id: Long) {
        lifecycleScope.launch { repository.markUsed(id) }
        startActivity(
            Intent(this, EntryEditActivity::class.java)
                .putExtra(EntryEditActivity.EXTRA_ID, id)
        )
    }

    private fun confirmDelete(entry: VaultEntry) {
        AlertDialog.Builder(this)
            .setTitle(R.string.delete_entry)
            .setMessage(getString(R.string.delete_confirm, entry.title))
            .setPositiveButton(R.string.delete) { _, _ ->
                lifecycleScope.launch { repository.delete(entry) }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}
