package com.safevault.app.data

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * One thing a service can be recognised by: a web host, or an Android package.
 *
 * Autofill asks "who is this request from?" and gets either a package name (a
 * native app) or a web domain (a browser tab). A service accumulates several of
 * both over its life, which is the whole reason this is a table and not a
 * column.
 *
 * [value] is stored already normalised — see
 * [com.safevault.app.autofill.UriNormalizer] — so matching is a comparison and
 * never a parse. Storing raw user input here would move parsing to the fill
 * path, where a mistake becomes "filled the wrong site's password".
 *
 * Rows are deleted with their service: a binding without a service can only
 * match nothing, and leaving it behind would let a recycled service id inherit
 * another service's bindings.
 */
@Entity(
    tableName = "uri_bindings",
    foreignKeys = [
        ForeignKey(
            entity = VaultService::class,
            parentColumns = ["id"],
            childColumns = ["serviceId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [
        Index("serviceId"),
        Index("value"),
        // One binding per (service, kind, value): re-saving a login should not
        // grow the table, and duplicates would produce duplicate datasets.
        Index(value = ["serviceId", "kind", "value"], unique = true)
    ]
)
data class UriBinding(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,

    val serviceId: Long,

    /** One of [KIND_WEB] or [KIND_ANDROID_APP]. */
    val kind: Int,

    /** Normalised host or package name. Never raw user input. */
    val value: String,

    /** One of the SOURCE_* constants — how this binding came to exist. */
    val source: Int = SOURCE_MANUAL,

    val createdAt: Long = System.currentTimeMillis()
) {
    companion object {
        /** A web origin: the normalised host, no scheme, no port, no path. */
        const val KIND_WEB = 0

        /** An Android application id, e.g. `com.google.android.gm`. */
        const val KIND_ANDROID_APP = 1

        /** Entered or edited by the user. */
        const val SOURCE_MANUAL = 0

        /** Derived from the entry's `website` column by the 2 -> 3 migration. */
        const val SOURCE_MIGRATION = 1

        /** Learned from an autofill save/update prompt the user accepted. */
        const val SOURCE_AUTOFILL = 2

        /** Derived from an imported CSV row's URL column. */
        const val SOURCE_IMPORT = 3
    }
}
