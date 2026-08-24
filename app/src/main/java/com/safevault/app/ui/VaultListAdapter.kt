package com.safevault.app.ui

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.view.isVisible
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.safevault.app.R
import com.safevault.app.data.VaultEntry
import com.safevault.app.databinding.ItemEntryBinding
import com.safevault.app.databinding.ItemServiceHeaderBinding
import com.safevault.app.security.PasswordHealth
import java.util.Locale

/** One row of the vault list: either a service heading or a credential. */
sealed interface VaultListItem {
    data class Header(val label: String, val count: Int) : VaultListItem
    data class Credential(
        val entry: VaultEntry,
        val reused: Boolean
    ) : VaultListItem
}

/**
 * Renders credentials grouped under their service, which is the product's
 * headline difference from a flat list: two Gmail accounts sit together under one
 * "Gmail" heading instead of being two unrelated rows that happen to sort next to
 * each other.
 */
class VaultListAdapter(
    private val onClick: (VaultEntry) -> Unit,
    private val onLongClick: (VaultEntry) -> Unit,
    private val onFavoriteToggle: (VaultEntry) -> Unit
) : ListAdapter<VaultListItem, RecyclerView.ViewHolder>(DIFF) {

    companion object {
        private const val TYPE_HEADER = 0
        private const val TYPE_ENTRY = 1

        private val DIFF = object : DiffUtil.ItemCallback<VaultListItem>() {
            override fun areItemsTheSame(a: VaultListItem, b: VaultListItem) = when {
                a is VaultListItem.Header && b is VaultListItem.Header -> a.label == b.label
                a is VaultListItem.Credential && b is VaultListItem.Credential ->
                    a.entry.id == b.entry.id
                else -> false
            }

            override fun areContentsTheSame(a: VaultListItem, b: VaultListItem) = a == b
        }

        /**
         * Groups entries by service and marks reuse.
         *
         * Favourites are lifted into their own group at the top — the roadmap's
         * "fast retrieval" goal is better served by the handful of accounts someone
         * actually opens than by alphabetical purity.
         */
        fun build(entries: List<VaultEntry>, favoritesLabel: String): List<VaultListItem> {
            if (entries.isEmpty()) return emptyList()

            val reusedHashes = entries
                .filter { it.reuseHash.isNotEmpty() }
                .groupingBy { it.reuseHash }
                .eachCount()
                .filterValues { it > 1 }
                .keys

            val items = mutableListOf<VaultListItem>()

            val favorites = entries.filter { it.favorite }
            if (favorites.isNotEmpty()) {
                items += VaultListItem.Header(favoritesLabel, favorites.size)
                favorites.sortedBy { it.title.lowercase(Locale.getDefault()) }
                    .forEach { items += VaultListItem.Credential(it, it.reuseHash in reusedHashes) }
            }

            entries.groupBy { it.groupLabel }
                .toSortedMap(String.CASE_INSENSITIVE_ORDER)
                .forEach { (service, group) ->
                    items += VaultListItem.Header(service, group.size)
                    group.sortedBy { it.title.lowercase(Locale.getDefault()) }
                        .forEach {
                            items += VaultListItem.Credential(it, it.reuseHash in reusedHashes)
                        }
                }
            return items
        }
    }

    override fun getItemViewType(position: Int) = when (getItem(position)) {
        is VaultListItem.Header -> TYPE_HEADER
        is VaultListItem.Credential -> TYPE_ENTRY
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        val inflater = LayoutInflater.from(parent.context)
        return if (viewType == TYPE_HEADER) {
            HeaderVH(ItemServiceHeaderBinding.inflate(inflater, parent, false))
        } else {
            EntryVH(ItemEntryBinding.inflate(inflater, parent, false))
        }
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        when (val item = getItem(position)) {
            is VaultListItem.Header -> (holder as HeaderVH).bind(item)
            is VaultListItem.Credential -> (holder as EntryVH).bind(item)
        }
    }

    inner class HeaderVH(private val binding: ItemServiceHeaderBinding) :
        RecyclerView.ViewHolder(binding.root) {
        fun bind(item: VaultListItem.Header) {
            binding.tvHeader.text = item.label
            binding.tvHeaderCount.text = binding.root.resources
                .getQuantityString(R.plurals.account_count, item.count, item.count)
        }
    }

    inner class EntryVH(private val binding: ItemEntryBinding) :
        RecyclerView.ViewHolder(binding.root) {
        fun bind(item: VaultListItem.Credential) = with(binding) {
            val entry = item.entry
            tvTitle.text = entry.title
            tvWebsite.text = entry.website.ifBlank { "—" }
            tvInitial.text = entry.groupLabel.take(1).uppercase(Locale.getDefault())

            val badge = when {
                item.reused -> root.context.getString(R.string.badge_reused)
                entry.strengthScore in 1..PasswordHealth.SCORE_WEAK ->
                    root.context.getString(R.string.badge_weak)
                else -> null
            }
            tvHealthBadge.isVisible = badge != null
            tvHealthBadge.text = badge

            btnFavorite.setImageResource(
                if (entry.favorite) R.drawable.ic_star_filled else R.drawable.ic_star
            )
            btnFavorite.imageTintList = androidx.core.content.ContextCompat.getColorStateList(
                root.context,
                if (entry.favorite) R.color.primary else R.color.on_surface_variant
            )
            btnFavorite.setOnClickListener { onFavoriteToggle(entry) }

            root.setOnClickListener { onClick(entry) }
            root.setOnLongClickListener { onLongClick(entry); true }
        }
    }
}
