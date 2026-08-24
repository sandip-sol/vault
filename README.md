# 🔐 Safe Vault — ID & Password Manager for Android

A secure, offline password vault app written in **Kotlin**. All credentials are
encrypted with **AES-256-GCM** using a key derived from your master password —
nothing ever leaves the device, and no network permission is even requested.

## Features

| Feature | Details |
|---|---|
| 🔑 Master password | Set once on first launch; verified with an encrypted token, never stored |
| 🔒 AES-256-GCM encryption | Usernames & passwords encrypted per-field with random IVs |
| 🧂 PBKDF2 key derivation | 210,000 iterations of PBKDF2-HmacSHA256 with a random salt |
| 👆 Biometric unlock | Optional fingerprint/face unlock (toggle from the vault screen) |
| 🗄️ Room database | Local SQLite storage — ciphertext only for sensitive columns |
| 🔍 Search | Live filtering by title or website |
| 🎲 Password generator | One-tap 16-char strong password |
| 📋 Safe clipboard copy | Marked sensitive so Android 13+ hides it from clipboard previews |
| ⏱️ Auto-lock | Vault locks after 60s in background, on back press, or via the lock button |
| 🚫 Screenshot blocking | `FLAG_SECURE` on every screen; content hidden in Recents |
| 🚫 No backups | `allowBackup=false` so encrypted data isn't exfiltrated via ADB backup |

## Security design

```
Master password ──PBKDF2(210k, salt)──▶ AES-256 key (RAM only while unlocked)
                                             │
        entries.db  ◀── AES-GCM encrypt ─────┘
   (title/site plaintext for display; username/password = ciphertext)

Salt + verifier token ──▶ EncryptedSharedPreferences (Android Keystore master key)
```

- The master password itself is **never persisted**. A verifier token encrypted
  with the derived key confirms correctness (GCM auth-tag failure = wrong password).
- Biometric unlock caches the derived key in a *separate* Keystore-backed
  encrypted prefs file, cleared instantly if you disable biometrics.
- 3 failed unlock attempts triggers a 5-second cooldown.

## Project structure

```
app/src/main/java/com/safevault/app/
├── data/          VaultEntry (entity), VaultDao, VaultDatabase (Room)
├── security/      CryptoManager (AES/PBKDF2), VaultPrefs, SessionKeyHolder
└── ui/            UnlockActivity, VaultActivity, EntryEditActivity,
                   EntryAdapter, BiometricKeyStore
```

## Build & run

1. Open the `SafeVault` folder in **Android Studio** (Koala or newer).
2. Let Gradle sync (AGP 8.5.2, Kotlin 1.9.24, min SDK 24 / target SDK 34).
3. Run on a device or emulator (API 24+). Biometric unlock needs enrolled
   fingerprints/face on the device.

Or from the command line (with the Android SDK installed):

```bash
cd SafeVault
gradle wrapper            # generate the wrapper once
./gradlew assembleDebug   # APK at app/build/outputs/apk/debug/
```

## Usage

1. **First launch** → create a master password (min 8 chars). ⚠️ It cannot be
   recovered — losing it means losing the vault.
2. Tap **+** to add an entry: title, website, ID/username, password, notes.
3. Tap an entry to view/edit; **long-press to delete**.
4. Use the **fingerprint icon** in the top bar to enable biometric unlock,
   and the **lock icon** to lock immediately.
