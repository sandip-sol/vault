package com.safevault.app.data

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * A service the user has an account with — "Google", "GitHub", the bank.
 *
 * Until Phase 3 a service was nothing but a free-text column on the credential
 * row, which was adequate while grouping was the only thing it had to do. It
 * stops being adequate for autofill: filling requires knowing that this service
 * *is* `com.google.android.gm` and `mail.google.com` and `accounts.google.com`,
 * and one text column cannot hold three answers. The bindings live in
 * [UriBinding]; this row is what they hang off.
 *
 * [name] is unique and case-insensitive because it is also the grouping key the
 * list renders. Two services differing only in case would split one user's
 * accounts across two headers and, worse, across two sets of bindings.
 */
@Entity(
    tableName = "services",
    indices = [Index(value = ["name"], unique = true)]
)
data class VaultService(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,

    /**
     * Display name and grouping key.
     *
     * NOCASE is on the column, not just the index: in SQLite an index inherits
     * its column's collation, so declaring it here is what actually makes
     * "GitHub" and "github" the same service rather than two.
     */
    @ColumnInfo(collate = ColumnInfo.NOCASE)
    val name: String,

    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis()
)
