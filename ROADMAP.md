# SafeVault — Implementation Roadmap

Working roadmap for the offline-first Android credential vault, mapped onto this
codebase. It translates the product PRD (`offline_first_android_credential_vault_roadmap.md`)
into concrete phases, files and exit criteria.

The PRD is the *what and why*; this document is the *where and when*. Where the two
disagree, the PRD wins on product intent and this document wins on sequencing,
because sequencing is constrained by what is already built.

---

## 1. Where the code actually is

SafeVault is a working local vault: master password, AES-256-GCM records, Room
storage, biometric unlock, search, generator, auto-lock, `FLAG_SECURE`. In PRD terms
that is most of **Phase 1** plus scattered pieces of Phase 2.

The current state after this round of work:

| PRD phase | Scope | State |
|---|---|---|
| Phase 0 — Product & security definition | Threat model, key hierarchy, data model | **Done** (this document + §3 below) |
| Phase 1 — Local vault foundation | Envelope keys, encrypted CRUD, session, migration | **Done** |
| Phase 2 — Consumer MVP UX | Grouping, multi-account, favourites, generator, health | **Mostly done** — import, recents surface outstanding |
| Phase 3 — Android autofill | `AutofillService`, save/update prompts | **Not started** |
| Phase 4 — Portable backup | Encrypted export, restore, verification | **Done** (ahead of PRD order — see §2) |
| Phase 5 — Passkeys + Credential Provider | Android 14+ provider | **Not started** |
| Phase 6 — Optional connected backup | Network policy, remote backup | **Not started** (deliberately) |
| Phase 7 — Sync & security intelligence | E2EE sync, breach checks | **Not started** |

---

## 2. Why backup was built before autofill

The PRD orders autofill (Phase 3) before portable backup (Phase 4). This codebase
did them the other way round, for one reason: **backup is a property of the key
hierarchy, not a feature bolted on later.**

The PRD says as much in its own MVP success condition — *"the local data model and
key hierarchy are designed so encrypted export/restore can be added without
migration pain."* The original code did not satisfy that. It derived the record
encryption key directly from the master password, which means:

- changing the master password requires decrypting and re-encrypting every record;
- a backup cannot carry a key, only plaintext, so restore must re-encrypt everything;
- every future unlock method needs its own copy of the same derived key.

Fixing that is the envelope hierarchy in §3. Once the DEK exists, export and restore
are a few hundred lines, and they were written immediately to prove the hierarchy
works. Autofill is next and is unaffected by the reordering — it depends on the
session and repository, both of which are now stable.

---

## 3. Security architecture as built

### Key hierarchy

```
                     master password
                            │
              PBKDF2-HMAC-SHA256, 210k iters, 16-byte salt
                            │
                      password KEK ──────┐
                                         │ AES-GCM wrap
   Android Keystore key                  ▼
   (user-auth required,        ┌──────────────────┐
    Class 3 biometric,         │    Vault DEK     │  random AES-256
    invalidated on enroll)     │ never stored bare│
              │                └──────────────────┘
              │ AES-GCM wrap            │
              └─────────────────────────┤ AES-GCM, per-field AAD
                                        ▼
                              entries.db ciphertext
```

Implemented in:

| Concern | File |
|---|---|
| AEAD primitives, payload schema, AAD | [CryptoManager.kt](app/src/main/java/com/safevault/app/security/CryptoManager.kt) |
| Versioned KDF parameters | [KeyDerivation.kt](app/src/main/java/com/safevault/app/security/KeyDerivation.kt) |
| Envelope wrap/unwrap, password change | [VaultKeyManager.kt](app/src/main/java/com/safevault/app/security/VaultKeyManager.kt) |
| Keystore biometric key | [BiometricKeyGuard.kt](app/src/main/java/com/safevault/app/security/BiometricKeyGuard.kt) |
| Metadata storage | [VaultPrefs.kt](app/src/main/java/com/safevault/app/security/VaultPrefs.kt) |
| Session lifetime | [SessionManager.kt](app/src/main/java/com/safevault/app/security/SessionManager.kt) |
| v1 → v2 data migration | [LegacyVaultMigration.kt](app/src/main/java/com/safevault/app/security/LegacyVaultMigration.kt) |
| Crypto boundary for records | [VaultRepository.kt](app/src/main/java/com/safevault/app/data/VaultRepository.kt) |
| Backup format | [BackupPackage.kt](app/src/main/java/com/safevault/app/backup/BackupPackage.kt) |

### Payload schema

`"v2." + Base64(IV‖ciphertext‖tag)`, with GCM associated data naming the column the
value belongs to (`entry/password/v2`). A ciphertext moved between columns fails its
tag. Schema v1 (`Base64(IV‖ciphertext)`, no AAD) is still readable so existing vaults
migrate; it is never written.

### Defects this round closed

| Defect | Why it mattered | Fix |
|---|---|---|
| Record key derived straight from the master password | Password change = full re-encrypt; no portable backup | Envelope hierarchy, DEK wrapped not derived |
| Biometric unlock cached the **raw AES key** in `EncryptedSharedPreferences` | Anything that could read app storage had the vault key; the fingerprint prompt gated nothing cryptographically | Keystore key with `setUserAuthenticationRequired(true)`, unlocked through a `CryptoObject` |
| Biometric accepted Class 2 (weak) authenticators | A Class 2 match cannot authorise a Keystore key, so the gate was decorative | `BIOMETRIC_STRONG` only |
| `notes` stored in plaintext | README claimed encryption at rest; notes are where people put recovery codes | `encryptedNotes` column, sealed like every other secret |
| No payload versioning or AAD | Crypto format could never change; blobs were swappable between fields | Version prefix + per-field AAD |
| Auto-lock timed per-activity | Opening the editor looked like leaving the app; unresumed screens never checked | Process lifecycle observer in [SafeVaultApp.kt](app/src/main/java/com/safevault/app/SafeVaultApp.kt) |
| Clipboard never cleared | Secrets sat in the clipboard indefinitely | 30s clear-if-unchanged in [SecureClipboard.kt](app/src/main/java/com/safevault/app/ui/SecureClipboard.kt) |
| No DB migration path | Any schema change would have dropped the vault | Room migration 1→2 + resumable content migration |

### Threat model position

| Threat | Position |
|---|---|
| Lost unlocked phone | Process-wide auto-lock (configurable 30s–5m), `FLAG_SECURE`, re-auth on resume |
| App storage read by another app / root | Records are ciphertext; DEK is wrapped; biometric envelope needs the Keystore |
| Device backup exfiltration | `allowBackup=false` plus `dataExtractionRules` excluding cloud backup and device transfer |
| Clipboard snooping | Sensitive flag + timed clear. **Partial** — a keyboard reading a live clipboard still wins. Autofill (Phase 3) is the real fix |
| New fingerprint enrolled by an attacker | `setInvalidatedByBiometricEnrollment(true)` destroys the key; vault falls back to password |
| Backup file stolen | Single GCM tag over DEK + all records, keyed by a 310k-iteration PBKDF2 of a separate passphrase |
| Network exfiltration | No `INTERNET` permission in the manifest — enforced by the OS, not by app code |
| Rooted device | Not defended. Documented, not promised against |

---

## 4. Data model as built

[VaultEntry.kt](app/src/main/java/com/safevault/app/data/VaultEntry.kt) collapses the
PRD's Service / Account / CredentialSecret / SecurityMeta entities into one row with a
`serviceName` grouping key. That is a deliberate simplification for the current scale:
grouping is a list-building concern, and a separate `services` table buys referential
tidiness at the cost of joins and migrations nothing yet needs.

The split becomes worth doing when a service acquires attributes of its own — an icon,
multiple URI bindings, an Android package association. That is a Phase 3 requirement
(autofill has to match packages and origins to services), so **the entity split is
scheduled as the first task of Phase 3**, not deferred indefinitely.

| PRD entity | Current representation |
|---|---|
| Service | `serviceName` column + `groupLabel` |
| Account | The row itself |
| CredentialSecret | `encryptedUsername` / `encryptedPassword` / `encryptedNotes` + `payloadSchema` |
| UriBinding | `website` only — **insufficient for autofill**, split in Phase 3 |
| SecurityMeta | `strengthScore`, `reuseHash`, `passwordUpdatedAt` |
| VaultMeta | `VaultPrefs` (KDF params, wrapped DEK, backup state) |
| AuditLocal | Not built — `lastBackupAt` is the only event recorded |

`reuseHash` is HMAC-SHA256 of the password keyed by a subkey of the DEK, truncated to
128 bits. Reuse is detectable by grouping equal hashes; the value is meaningless
without the vault key, and cannot be compared across vaults.

---

## 5. Backup format

```json
{
  "format": "safevault.backup",
  "version": 1,
  "createdAt": 1787573864394,
  "entryCount": 3,
  "kdf": { "version": 1, "algorithm": "PBKDF2WithHmacSHA256",
           "iterations": 310000, "salt": "…" },
  "payload": "v2.…"
}
```

The header is cleartext because restore must read the KDF parameters before it can
ask for a passphrase, and must be able to say *"this backup holds 3 entries"* before
the user commits. Nothing in the header is vault content.

The payload holds the **DEK and every record** under one GCM tag. Carrying the DEK is
what lets restore re-wrap one key for the new device rather than re-encrypting the
vault, and the single tag means a truncated or edited file fails as a unit — the
PRD's *"verify authentication tag before importing any records"* is structural rather
than a check someone has to remember to write.

No Keystore material is ever exported. The biometric envelope is device-bound; a
restored vault re-enrols.

**Verified on-device:** export → uninstall (wiping vault and Keystore) → reinstall →
restore with a new master password → all records decrypt. That is the PRD's recovery
drill, run against a real emulator, not a unit test.

---

## 6. What is deliberately not built

| Not built | Reason |
|---|---|
| `INTERNET` permission | The PRD notes INTERNET is a *normal* permission the user cannot revoke, so an in-app network switch is a promise, not a control. Omitting it makes Network Lock an OS-enforced property of the build. Adding any connected feature means declaring it — a visible, reviewable decision |
| `NetworkPolicy` abstraction | Nothing to police while the permission is absent. Introduce it in Phase 6 together with the permission, not before |
| Argon2id | The PRD prefers a memory-hard KDF. Adding it means vendoring a native dependency into a security-critical build; PBKDF2 at 210k/310k is the interim position and `KdfParams.version` exists so the change is a DEK re-wrap, not a vault rebuild |
| Analytics | None, opt-in or otherwise |
| Multiple vaults, sharing, TOTP | Post-MVP in the PRD, and none are blocked by current decisions |

---

## 7. Phase 3 — Android autofill (next)

Exit criterion: filling credentials into Chrome and a representative app matrix, with
a locked vault demanding authentication before releasing a dataset.

1. **Split Service and UriBinding out of `VaultEntry`.** Autofill matches on Android
   package names and web origins; one free-text `website` column cannot express
   "this service is `com.google.android.gm` *and* `mail.google.com` *and*
   `accounts.google.com`". Room migration 2→3.
2. **`AutofillService` implementation** — dataset construction from non-secret
   metadata, `FillResponse` with an authentication `IntentSender` when
   `SessionManager` is locked.
3. **Authentication handoff** — a locked vault presents an unlock action, never
   plaintext. Reuse `UnlockActivity` in a result-returning mode.
4. **Save / update prompts** — `SaveInfo` on submitted forms, mapped to an existing
   service where one matches.
5. **Inline suggestions** (API 30+) where the keyboard supports them.
6. **`minSdk` decision.** Autofill needs API 26; the app is currently 24. Either
   raise to 26 or gate the service with `@RequiresApi`. **Recommendation: raise to
   26** — API 24/25 is a rounding error of live devices and gating adds a permanent
   branch to a security-sensitive path.
7. **Compatibility matrix testing** — Chrome, a WebView app, a native login form.

Distinct risk worth stating up front: autofill is the first feature that hands
secrets to *another process*. Dataset construction must never include a secret the
user has not authenticated for, and the service must not be usable to enumerate the
vault while locked.

---

## 8. Later phases

**Phase 5 — Passkeys / Credential Provider (Android 14+).** `CredentialProviderService`
alongside the autofill service. Passkey private keys are a new secret type in the DEK
hierarchy — they encrypt like any other payload, but need their own AAD context and a
schema bump. Depends on the Phase 3 entity split.

**Phase 6 — Optional connected backup.** The first phase that declares `INTERNET`.
Prerequisites: `NetworkPolicy` boundary with `DENY_ALL` default; an explicit consent
screen; automated tests asserting no request is issued in Network Lock; the privacy
dashboard from PRD §15. The backup format already produces ciphertext suitable for
upload unchanged — the server never needs a key.

**Phase 7 — Sync.** Not startable until device identity and conflict resolution are
designed. The PRD is right that this must not be attempted before backup and the
device key model are mature.

---

## 9. Testing status

34 JVM tests, all passing (`./gradlew testDebugUnitTest`):

| Suite | Covers |
|---|---|
| `CryptoManagerTest` | Round trip, IV uniqueness, wrong key, cross-field AAD rejection, tamper detection, key wrapping, schema detection |
| `KeyDerivationTest` | Determinism, salt freshness, key length, backup work factor |
| `BackupPackageTest` | Round trip, header readability, no plaintext in file, wrong passphrase, tamper, truncation, foreign file, unknown version, count mismatch |
| `PasswordHealthTest` | Scoring, common-password and sequence detection, reuse-hash keying |
| `PasswordGeneratorTest` | Length, class coverage, ambiguous-character exclusion, uniqueness |

**Gaps, in priority order:**

1. **No instrumentation tests.** Biometric enrolment, `KeyPermanentlyInvalidatedException`
   handling, process death, and the Room migration all run only on-device and were
   verified by hand. The migration especially deserves an automated test — a silent
   record drop is a release blocker by the PRD's own list.
2. **`LegacyVaultMigration` has no automated coverage.** Its resumability argument is
   sound on paper and untested in code. Needs a test that interrupts between the two
   commits and asserts the vault still opens.
3. **No fuzz/corruption suite** beyond the hand-written backup cases.
4. **No compatibility matrix** — one emulator (Pixel 6, API 34) is not a matrix.

---

## 10. Release blockers (from PRD §14, current status)

| Blocker | Status |
|---|---|
| Plaintext credential in logs, crash reports, backups or temp files | **Clear** — backup file verified free of entry plaintext; nothing logs secrets |
| Network request during Network Lock | **Structurally impossible** — no `INTERNET` permission |
| Backup that cannot be restored on a clean device | **Verified** — full uninstall/restore drill passes |
| Autofill path exposing a locked credential | **N/A** — not built yet; the gating requirement is written into §7 |
| Migration that can silently drop or corrupt records | **Designed against, not yet proven** — see testing gap 2 |
| Cloud feature where server compromise reveals plaintext | **N/A** — no server |

Independent security review remains a release requirement before any connected
feature, per the PRD's closing note. Nothing in this round substitutes for it.
