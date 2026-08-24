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
storage, biometric unlock, search, generator, auto-lock, `FLAG_SECURE`, encrypted
backup/restore, Android Autofill, an Android 14+ Credential Provider, and optional
connected backup behind a deny-by-default network policy. In PRD terms, Phases 1
through 6 are now implemented.

The current state after this round of work:

| PRD phase | Scope | State |
|---|---|---|
| Phase 0 — Product & security definition | Threat model, key hierarchy, data model | **Done** (this document + §3 below) |
| Phase 1 — Local vault foundation | Envelope keys, encrypted CRUD, session, migration | **Done** |
| Phase 2 — Consumer MVP UX | Grouping, multi-account, favourites, recents, generator, health, import | **Done** |
| Phase 3 — Android autofill | `AutofillService`, save/update prompts | **Done** (device matrix still needed before release) |
| Phase 4 — Portable backup | Encrypted export, restore, verification | **Done** (ahead of PRD order — see §2) |
| Phase 5 — Passkeys + Credential Provider | Android 14+ provider | **Done** (device matrix still needed before release) |
| Phase 6 — Optional connected backup | Network policy, remote backup | **Done** |
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
works. Autofill followed that work and reused the same stable session and repository
boundaries.

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
| Network boundary | [NetworkPolicy.kt](app/src/main/java/com/safevault/app/security/NetworkPolicy.kt) |

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
| Network exfiltration | `INTERNET` exists for Phase 6, but `NetworkPolicy` defaults to `DENY_ALL`; the only allowed capability is a user-consented HTTPS connected-backup upload |
| Rooted device | Not defended. Documented, not promised against |

---

## 4. Data model as built

[VaultEntry.kt](app/src/main/java/com/safevault/app/data/VaultEntry.kt) collapses the
PRD's Service / Account / CredentialSecret / SecurityMeta entities into one row with a
`serviceName` grouping key. That is a deliberate simplification for the current scale:
grouping is a list-building concern, and a separate `services` table buys referential
tidiness at the cost of joins and migrations nothing yet needs.

The split became worth doing when a service acquired attributes of its own — multiple
URI bindings and Android package associations for Autofill. Schema v3 promotes
services and bindings into first-class rows while keeping `serviceName` denormalised
on entries for fast list rendering and search.

| PRD entity | Current representation |
|---|---|
| Service | `services` row + denormalised `serviceName` / `groupLabel` |
| Account | The row itself |
| CredentialSecret | `encryptedUsername` / `encryptedPassword` / `encryptedNotes` + `payloadSchema` |
| UriBinding | `uri_bindings` rows for web hosts and Android package names |
| PasskeyCredential | `passkeys` row: RP ID / credential ID metadata, encrypted user handle and ES256 private key |
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
  "version": 2,
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

The payload holds the **DEK, every record, services, URI bindings and passkeys** under one GCM
tag. Carrying the DEK is what lets restore re-wrap one key for the new device rather
than re-encrypting the vault, and the single tag means a truncated or edited file
fails as a unit — the PRD's *"verify authentication tag before importing any
records"* is structural rather than a check someone has to remember to write. Format
v1 backups remain readable; restore rebuilds service rows from each entry's
denormalised `serviceName` and imports no bindings because v1 never knew them.

No Keystore material is ever exported. The biometric envelope is device-bound; a
restored vault re-enrols.

**Verified on-device:** export → uninstall (wiping vault and Keystore) → reinstall →
restore with a new master password → all records decrypt. That is the PRD's recovery
drill, run against a real emulator, not a unit test.

---

## 6. What is deliberately not built

| Not built | Reason |
|---|---|
| Argon2id | The PRD prefers a memory-hard KDF. Adding it means vendoring a native dependency into a security-critical build; PBKDF2 at 210k/310k is the interim position and `KdfParams.version` exists so the change is a DEK re-wrap, not a vault rebuild |
| Analytics | None, opt-in or otherwise |
| Multiple vaults, sharing, TOTP | Post-MVP in the PRD, and none are blocked by current decisions |

---

## 6a. Phase 2 as completed

The PRD's Phase 2 backlog, item by item:

| Backlog item | Where |
|---|---|
| Home with search, recent and favourites | Recent and Favourites are shortcut groups above the service list, in [VaultListAdapter.kt](app/src/main/java/com/safevault/app/ui/VaultListAdapter.kt) |
| Add credential with service detection / manual entry | Service field with autocomplete from existing services |
| Multiple accounts per service | `serviceName` grouping |
| Password **and passphrase** generator | [GeneratorActivity.kt](app/src/main/java/com/safevault/app/ui/GeneratorActivity.kt), [PassphraseGenerator.kt](app/src/main/java/com/safevault/app/ui/PassphraseGenerator.kt) |
| Copy/reveal behaviour with timers and state feedback | [SecureClipboard.kt](app/src/main/java/com/safevault/app/ui/SecureClipboard.kt), 30s clear-if-unchanged |
| Import from CSV / other managers, with warnings and cleanup guidance | [CsvImport.kt](app/src/main/java/com/safevault/app/importer/CsvImport.kt), [ImportActivity.kt](app/src/main/java/com/safevault/app/ui/ImportActivity.kt) |
| Local password-health checks | `strengthScore` and vault-keyed `reuseHash` |

Three decisions worth recording:

**Recent is gated.** It appears only when the vault holds at least 5 entries and at
least 2 have been opened. Below that the whole list fits on screen and a Recent
group would just repeat what the user can already see.

**The passphrase wordlist is exactly 1024 words.** A power of two makes the entropy
arithmetic exact and checkable — 10 bits per word, so six words is 60 bits and
nobody has to trust a rounded claim. Words are 3–7 letters, and the list is asserted
distinct and lowercase-ASCII by test, because a duplicate would silently reduce
entropy below the figure the UI displays.

**Generator history is session-only.** It lives in the activity, is never written to
the database, and dies with the screen. A generator that persisted its output would
quietly become a second, unencrypted copy of the passwords the vault exists to
protect.

Import deliberately *adds* rather than replaces — restore is the operation that
replaces — and it ends on a blocking dialog about deleting the CSV, since that
plaintext file is the one part of the flow the app cannot clean up itself.

## 7. Phase 3 — Android autofill as completed

Implementation exit criterion met in code: an `AutofillService` can fill matching
credentials, a locked vault returns only an authentication response, and submitted
credentials can be saved or used to update an existing account. Release evidence still
needs the compatibility matrix in §9.

1. **Split Service and UriBinding out of `VaultEntry`.** Implemented with
   [VaultService.kt](app/src/main/java/com/safevault/app/data/VaultService.kt),
   [UriBinding.kt](app/src/main/java/com/safevault/app/data/UriBinding.kt), schema
   v3, and Room migration 2→3. Existing `website` values are back-filled into
   bindings by [ServiceBackfill.kt](app/src/main/java/com/safevault/app/data/ServiceBackfill.kt)
   after database open so URL parsing stays in one Kotlin implementation.
2. **`AutofillService` implementation.** [SafeVaultAutofillService.kt](app/src/main/java/com/safevault/app/autofill/SafeVaultAutofillService.kt)
   parses form structures, refuses SafeVault's own package, constructs datasets
   only while the session is unlocked, and returns a locked authentication response
   before any database lookup.
3. **Authentication handoff.** [AutofillAuthActivity.kt](app/src/main/java/com/safevault/app/autofill/AutofillAuthActivity.kt)
   reuses [UnlockActivity.kt](app/src/main/java/com/safevault/app/ui/UnlockActivity.kt)
   in result mode, then returns an authenticated `FillResponse`.
4. **Save / update prompts.** `SaveInfo` is included on locked, unlocked and
   post-auth responses. [AutofillSaveActivity.kt](app/src/main/java/com/safevault/app/autofill/AutofillSaveActivity.kt)
   maps the submitted target to an existing service when possible, updates an
   exact username match, and learns a web/package binding from the accepted save.
   Change-password forms prefer a submitted `NEW_PASSWORD` field over the current
   password field.
5. **Inline suggestions.** [InlinePresentations.kt](app/src/main/java/com/safevault/app/autofill/InlinePresentations.kt)
   builds API 30+ inline presentations where the keyboard advertises a supported
   spec; presentations show only title/username, never a password.
6. **`minSdk` decision.** Raised to API 26, avoiding a permanent compatibility
   branch inside the autofill path.
7. **Compatibility matrix testing.** Still pending on device/emulator: Chrome,
   a WebView app, and a native login form.

Distinct risk worth stating up front: autofill is the first feature that hands
secrets to *another process*. Dataset construction must never include a secret the
user has not authenticated for, and the service must not be usable to enumerate the
vault while locked.

---

## 7a. Phase 5 — Credential Provider as completed

Implementation exit criterion met in code: Android 14+ Credential Manager can bind
to SafeVault as a provider, request passwords and passkeys, and save new password or
passkey credentials through the same unlocked-session and DEK boundary as the rest of
the vault. Release evidence still needs a device matrix with Chrome / app-backed
Credential Manager callers.

1. **Passkey storage.** [PasskeyCredential.kt](app/src/main/java/com/safevault/app/data/PasskeyCredential.kt)
   adds `passkeys` as schema v4. RP ID and credential ID are lookup metadata;
   user handle and ES256 private key are encrypted under passkey-specific AAD in
   [VaultRepository.kt](app/src/main/java/com/safevault/app/data/VaultRepository.kt).
2. **Provider service.** [SafeVaultCredentialProviderService.kt](app/src/main/java/com/safevault/app/credential/SafeVaultCredentialProviderService.kt)
   is exported only behind `BIND_CREDENTIAL_PROVIDER_SERVICE`, declares password and
   public-key capabilities in [credential_provider.xml](app/src/main/res/xml/credential_provider.xml),
   and returns only an authentication action while locked.
3. **Credential Manager handoff.** [SafeVaultCredentialAuthActivity.kt](app/src/main/java/com/safevault/app/credential/SafeVaultCredentialAuthActivity.kt)
   reuses [UnlockActivity.kt](app/src/main/java/com/safevault/app/ui/UnlockActivity.kt)
   before returning the populated begin response. [SafeVaultCredentialGetActivity.kt](app/src/main/java/com/safevault/app/credential/SafeVaultCredentialGetActivity.kt)
   re-checks the session at selection time and unlocks again if the sheet outlived
   the session.
4. **Create flows.** [SafeVaultCredentialCreateActivity.kt](app/src/main/java/com/safevault/app/credential/SafeVaultCredentialCreateActivity.kt)
   saves `CreatePasswordRequest` as normal credential rows and
   `CreatePublicKeyCredentialRequest` as passkey rows, then returns Credential
   Manager responses.
5. **WebAuthn construction.** [WebAuthn.kt](app/src/main/java/com/safevault/app/credential/WebAuthn.kt)
   generates P-256 keys, COSE public keys, none-format attestation objects and
   assertion responses locally. No network permission is introduced.
6. **Backups.** [BackupPackage.kt](app/src/main/java/com/safevault/app/backup/BackupPackage.kt)
   bumps the backup format to v3 so passkeys ride inside the same sealed payload as
   entries, services and bindings. v1/v2 backups still restore with no passkeys.

---

## 8. Phase 6 — Optional connected backup as completed

Phase 6 is the first phase that declares `INTERNET`, and that remains the review
point it was meant to be. The app now has a `NetworkPolicy` boundary whose default
settings are `DENY_ALL`; connected backup is the only named network capability.

1. **Network boundary.** [NetworkPolicy.kt](app/src/main/java/com/safevault/app/security/NetworkPolicy.kt)
   requires `CONNECTED_BACKUP_ONLY`, a recorded consent timestamp and a valid HTTPS
   endpoint before an upload is allowed. [ConnectedBackup.kt](app/src/main/java/com/safevault/app/backup/ConnectedBackup.kt)
   checks that policy before it calls the uploader, which keeps the "no request
   during Network Lock" invariant testable without opening a socket.
2. **Connected backup upload.** [ConnectedBackupManager.kt](app/src/main/java/com/safevault/app/backup/ConnectedBackupManager.kt)
   builds the same backup package used by local export, verifies it can be opened
   with the passphrase, then POSTs it to the configured endpoint. The server
   receives the clear restore header plus sealed payload, never the master password,
   backup passphrase, unwrapped DEK or plaintext entries.
3. **Consent and privacy dashboard.** [SecurityActivity.kt](app/src/main/java/com/safevault/app/ui/SecurityActivity.kt)
   adds an explicit consent dialog, HTTPS endpoint setup, manual upload, disable
   action and a privacy status panel that switches between Network Lock and
   "connected backup only."
4. **Tests.** `NetworkPolicyTest` covers deny-by-default, consent and HTTPS
   requirements. `ConnectedBackupCoordinatorTest` asserts the uploader is not
   called while Network Lock is on.

## 8a. Later phases

**Phase 7 — Sync.** Not startable until device identity and conflict resolution are
designed. The PRD is right that this must not be attempted before backup and the
device key model are mature.

---

## 9. Testing status

136 JVM tests, all passing (`./gradlew testDebugUnitTest`):

| Suite | Covers |
|---|---|
| `CryptoManagerTest` | Round trip, IV uniqueness, wrong key, cross-field AAD rejection, tamper detection, key wrapping, schema detection |
| `KeyDerivationTest` | Determinism, salt freshness, key length, backup work factor |
| `BackupPackageTest` | Round trip, header readability, no plaintext in file, wrong passphrase, tamper, truncation, foreign file, unknown version, count mismatch, passkey carriage |
| `PasswordHealthTest` | Scoring, common-password and sequence detection, reuse-hash keying |
| `PasswordGeneratorTest` | Length, class coverage and exclusion, clamping, entropy, ambiguous characters, uniqueness |
| `PassphraseGeneratorTest` | Wordlist size/distinctness/charset, word count, separator, capitalisation, appended number, exact entropy |
| `CsvImportTest` | Quoted fields, doubled quotes, embedded newlines, CRLF, BOM; Chrome/Bitwarden/LastPass column detection, exact-over-substring matching; skipped-row accounting, host extraction |
| `FieldClassifierTest` | Autofill hint precedence, browser/native password detection, new-password detection, and negative cases for search, OTP and card fields |
| `UriNormalizerTest` | Host/package normalisation, public-suffix guardrails, phishing-lookalike rejection, exact/subdomain matching |
| `SaveCandidateTest` | Save-path password choice, including change-password forms preferring the new password |
| `VaultDatabaseMigrationTest` | Schema 2→3 and 3→4 migrations, service collapse, orphan prevention, binding/passkey constraints and cascade behaviour |
| `WebAuthnTest` | Passkey attestation JSON construction and assertion signature verification |
| `NetworkPolicyTest` / `ConnectedBackupCoordinatorTest` | Deny-by-default network policy, consent/HTTPS gates and no uploader call during Network Lock |

**Gaps, in priority order:**

1. **No instrumentation tests.** Biometric enrolment, `KeyPermanentlyInvalidatedException`
   handling, process death, and the Autofill platform contract still need device
   tests.
2. **No Autofill compatibility matrix evidence.** The service needs manual or
   instrumented validation in Chrome, a WebView app and a native login form before
   release.
3. **No Credential Provider compatibility matrix evidence.** Password and passkey
   create/get flows need Android 14+ device validation against Chrome and native
   Credential Manager callers before release.
4. **`LegacyVaultMigration` has no automated coverage.** Its resumability argument is
   sound on paper and untested in code. Needs a test that interrupts between the two
   commits and asserts the vault still opens.
5. **No fuzz/corruption suite** beyond the hand-written backup cases.

---

## 10. Release blockers (from PRD §14, current status)

| Blocker | Status |
|---|---|
| Plaintext credential in logs, crash reports, backups or temp files | **Clear** — backup file verified free of entry plaintext; nothing logs secrets |
| Network request during Network Lock | **Tested in code** — `NetworkPolicy` defaults to `DENY_ALL`, and the connected-backup coordinator does not call its uploader while blocked |
| Backup that cannot be restored on a clean device | **Verified** — full uninstall/restore drill passes |
| Autofill path exposing a locked credential | **Designed against in code** — locked fill responses do not query the vault; device matrix still pending |
| Migration that can silently drop or corrupt records | **Partly proven** — schema 2→3 is JVM-tested; legacy content migration still lacks automated interruption coverage |
| Cloud feature where server compromise reveals plaintext | **Designed against** — connected backup uploads the existing sealed backup package; the endpoint gets no key or passphrase |

Independent security review remains a release requirement for the connected-backup
boundary and any future sync feature, per the PRD's closing note. Nothing in this
round substitutes for it.
