package com.safevault.app.backup

import android.content.Context
import android.net.Uri
import com.safevault.app.data.ServiceBackfill
import com.safevault.app.data.VaultRepository
import com.safevault.app.security.VaultKeyManager
import com.safevault.app.security.VaultPrefs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.crypto.SecretKey

/**
 * Export, verify and restore of encrypted backups.
 *
 * Files move through the Storage Access Framework, so the user picks the
 * destination and the app needs no storage permission and no network. Where the
 * file ends up — local, SD card, a cloud provider's document picker — is the
 * user's choice, and everything written is ciphertext either way.
 */
class BackupManager(context: Context) {

    private val appContext = context.applicationContext
    private val repository = VaultRepository(appContext)
    private val keys = VaultKeyManager(appContext)
    private val prefs = VaultPrefs(appContext)

    sealed interface ExportResult {
        data class Success(val entries: Int, val verified: Boolean) : ExportResult
        data class Failed(val reason: String) : ExportResult
    }

    sealed interface RestoreResult {
        data class Success(val entries: Int) : RestoreResult
        data object WrongPassphrase : RestoreResult
        data class Failed(val reason: String) : RestoreResult
    }

    /**
     * Writes an encrypted backup, then immediately reads it back and decrypts it.
     * An export that cannot be reopened is reported as unverified rather than
     * being quietly counted as a backup — the roadmap treats an unrestorable
     * backup as a release blocker, so it should never be shown as a green tick.
     */
    suspend fun export(
        destination: Uri,
        passphrase: CharArray,
        dek: SecretKey
    ): ExportResult = withContext(Dispatchers.IO) {
        try {
            val entries = repository.getAll()
            val services = repository.allServices()
            val bytes = BackupPackage.write(
                passphrase = passphrase,
                dek = dek,
                vaultCreatedAt = prefs.vaultCreatedAt,
                entries = entries,
                services = services,
                // Bindings ride along so a restored vault autofills immediately
                // rather than relearning every site the user has already taught it.
                bindings = repository.allBindings(),
                passkeys = repository.allPasskeys()
            )
            appContext.contentResolver.openOutputStream(destination, "wt")
                ?.use { it.write(bytes) }
                ?: return@withContext ExportResult.Failed("Could not open the chosen file")

            val verified = verify(destination, passphrase, entries.size)
            if (verified) prefs.lastBackupAt = System.currentTimeMillis()
            ExportResult.Success(entries.size, verified)
        } catch (e: Exception) {
            ExportResult.Failed(e.message ?: "Export failed")
        }
    }

    /** Re-opens a written backup to prove it decrypts and holds every record. */
    private fun verify(source: Uri, passphrase: CharArray, expected: Int): Boolean = try {
        val bytes = read(source)
        val contents = BackupPackage.open(bytes, passphrase)
        contents != null && contents.entries.size == expected
    } catch (e: Exception) {
        false
    }

    suspend fun inspect(source: Uri): BackupPackage.Header = withContext(Dispatchers.IO) {
        BackupPackage.readHeader(read(source))
    }

    /**
     * Replaces the local vault with the backup's contents.
     *
     * The recovered DEK is re-wrapped under [newMasterPassword] for this device,
     * which is why record ciphertext can be written back untouched. Biometrics are
     * cleared: the old device's Keystore key does not exist here and must not be
     * assumed to. Rows land in a single transaction, so a failure leaves the
     * previous vault intact rather than a partial merge.
     */
    suspend fun restore(
        source: Uri,
        passphrase: CharArray,
        newMasterPassword: CharArray
    ): RestoreResult = withContext(Dispatchers.IO) {
        try {
            val contents = BackupPackage.open(read(source), passphrase)
                ?: return@withContext RestoreResult.WrongPassphrase

            repository.replaceVault(
                contents.entries,
                contents.services,
                contents.bindings,
                contents.passkeys
            )
            // The restored vault's bindings came from the file, not from this
            // device's back-fill flag — re-arm it so a v1 backup, which carries
            // no bindings, still gets them derived from its `website` columns.
            ServiceBackfill.reset(appContext)
            ServiceBackfill.runIfNeeded(appContext)
            keys.adoptDek(
                dek = contents.dek,
                masterPassword = newMasterPassword,
                createdAt = contents.vaultCreatedAt.takeIf { it > 0 }
            )
            RestoreResult.Success(contents.entries.size)
        } catch (e: BackupPackage.MalformedBackupException) {
            RestoreResult.Failed(e.message ?: "Backup file is not readable")
        } catch (e: Exception) {
            RestoreResult.Failed(e.message ?: "Restore failed")
        }
    }

    private fun read(source: Uri): ByteArray =
        appContext.contentResolver.openInputStream(source)?.use { it.readBytes() }
            ?: throw BackupPackage.MalformedBackupException("Could not open the chosen file")

    fun suggestedFileName(): String {
        val stamp = android.text.format.DateFormat.format("yyyyMMdd-HHmm", System.currentTimeMillis())
        return "safevault-$stamp.${BackupPackage.FILE_EXTENSION}"
    }
}
