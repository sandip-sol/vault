# 🔐 Safe Vault — offline-first credential vault for Android

A password manager that works with no account and no network. Credentials are
encrypted with **AES-256-GCM** under a random vault key that is itself wrapped by
your master password — and the app declares no `INTERNET` permission, so Network
Lock is enforced by Android rather than promised by the code.

See [ROADMAP.md](ROADMAP.md) for architecture rationale, phase plan and open gaps.

## Features

| Feature | Details |
|---|---|
| 🔑 No account | Create a vault and start saving credentials offline, in seconds |
| 🧅 Envelope encryption | Records are encrypted under a random DEK; the DEK is wrapped by your password. Changing the master password re-wraps one key instead of re-encrypting the vault |
| 🔒 AES-256-GCM | Username, password and notes each sealed with a random IV and per-field associated data |
| 🧂 PBKDF2 | 210,000 iterations (SHA-256) for unlock, 310,000 for backups; parameters are versioned |
| 👆 Biometric unlock | The vault key is sealed by an Android Keystore key that requires a Class 3 biometric for every use. A new fingerprint enrollment invalidates it automatically |
| 🗂 Service grouping | Several accounts under one service (Personal + Work Gmail) group together |
| ⭐ Favourites & recents | Both pinned above the service list for fast retrieval |
| 🩺 Password health | Weak and reused passwords flagged locally — reuse is detected via a vault-keyed HMAC, never a stored hash of your password |
| 💾 Encrypted backup | One passphrase-protected file, verified by re-reading it after every export |
| ♻️ Restore | Recovers the vault key and re-wraps it for the new device; records are never re-encrypted |
| 🔍 Search | Filters on non-secret metadata only — no decryption per keystroke |
| 🎲 Generator | Passwords (length and character classes) and passphrases (1024-word list, exactly 10 bits per word), with live entropy and session-only history |
| 📥 CSV import | Chrome, Bitwarden, LastPass, 1Password, Keeper or any CSV with a header — columns detected automatically |
| 📋 Clipboard | Flagged sensitive, and cleared after 30s if untouched |
| ⏱️ Auto-lock | Process-wide, configurable 30s–5m |
| 🚫 Screenshot blocking | `FLAG_SECURE` on every screen |
| 🚫 No backup exfiltration | `allowBackup=false` plus data-extraction rules excluding cloud backup and device transfer |

## Security design

```
master password ──PBKDF2(210k, salt)──▶ password KEK ─┐
                                                      │ AES-GCM wrap
Android Keystore key                                  ▼
(user-auth required,                        ┌───────────────────┐
 Class 3 biometric) ──── AES-GCM wrap ─────▶│     Vault DEK     │ random AES-256
                                            └───────────────────┘
                                                      │ AES-GCM + per-field AAD
                                                      ▼
                                            entries.db (ciphertext)
```

- The master password is **never stored**. A wrong password is detected by the GCM
  auth tag on the wrapped key failing — there is no separate verifier to leak.
- The DEK never exists on disk unwrapped. Biometric unlock stores it sealed by a
  Keystore key that will not operate without a fresh biometric match.
- Payloads carry a schema version and are bound to their column, so a ciphertext
  cannot be moved from `password` into `username`.
- Backups carry the DEK sealed under a separate passphrase, which is why restore
  can re-wrap one key rather than re-encrypt every record.

## Project structure

```
app/src/main/java/com/safevault/app/
├── SafeVaultApp.kt      process-wide auto-lock clock
├── backup/              BackupPackage (file format), BackupManager (export/restore)
├── data/                VaultEntry, VaultDao, VaultDatabase, VaultRepository
├── importer/            CsvImport (parsing + column detection)
├── security/            CryptoManager, KeyDerivation, VaultKeyManager,
│                        BiometricKeyGuard, VaultPrefs, SessionManager,
│                        PasswordHealth, LegacyVaultMigration
└── ui/                  Unlock / Vault / EntryEdit / Security / Restore /
                         Generator / Import activities, VaultListAdapter,
                         SecureClipboard, PasswordGenerator, PassphraseGenerator
```

## Build & run

Android Studio (Koala or newer), or from the command line:

```bash
./gradlew assembleDebug        # APK at app/build/outputs/apk/debug/
./gradlew testDebugUnitTest    # 76 JVM tests
```

AGP 8.5.2, Kotlin 1.9.24, min SDK 24 / target SDK 34. Biometric unlock needs a
**Class 3 (strong)** biometric enrolled; weaker sensors cannot back a Keystore key,
so the option stays disabled on those devices.

### Installing from WSL to a Windows-hosted emulator

WSL's `adb` cannot see an emulator running on the Windows host. Use the Windows
`adb.exe` and a path it can read:

```bash
cp app/build/outputs/apk/debug/app-debug.apk /mnt/c/temp/safevault.apk
"/mnt/c/Users/$USER/AppData/Local/Android/Sdk/platform-tools/adb.exe" \
  install -r 'C:\temp\safevault.apk'
```

## Usage

1. **First launch** → create a master password (min 8 chars), or restore from a
   backup file. ⚠️ The master password cannot be recovered.
2. Tap **+** to add an entry. The **Service** field groups accounts together, so
   "Personal" and "Work" both under `Gmail` appear as one group of two.
3. Tap an entry to view or edit; **long-press to delete**; tap the ⭐ to favourite.
4. The **key icon** opens the Generator: passwords or passphrases, with a live
   entropy read-out. Nothing generated there is saved.
5. The **shield icon** opens Security: password health, encrypted backup and
   restore, CSV import, biometric unlock, auto-lock timing and master password
   change.

### Importing from another password manager

Security → **Import from CSV**. Columns are detected automatically for Chrome,
Bitwarden, LastPass, 1Password and Keeper, and for any CSV with a recognisable
header row. Import adds to your vault rather than replacing it.

⚠️ An export from another manager is an unencrypted list of every password you
own. Delete it as soon as the import finishes — the app will remind you.

## Upgrading an existing vault

Vaults created before the envelope hierarchy are migrated at the next unlock. The
migration re-seals every record under the new key and encrypts notes that were
previously stored in plaintext. It is ordered so that an interruption at any point
leaves the vault openable and the migration resumable.

## Known gaps

Tracked in [ROADMAP.md](ROADMAP.md) §9. In short: no instrumentation tests, the
legacy migration is verified by hand rather than automatically, and autofill
(the fix for clipboard exposure) is the next phase.
