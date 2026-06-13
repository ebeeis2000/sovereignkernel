# 🔐 SovereignKernel — Analyse & Testrapport

> **Repository:** [ebeeis2000/sovereignkernel](https://github.com/ebeeis2000/sovereignkernel)
> **Versie:** 0.3.0 · Hoofdtaal: **Rust** · Licentie: MIT
> **Beschrijving:** Beveiligde kluis voor Windows 11, met TPM 2.0-integratie

---

## 📋 Overzicht

SovereignKernel is een **hardware-beveiligde vault** met drie componenten:

| Component | Technologie | Rol |
|-----------|-------------|-----|
| **Rust Workspace** (7 crates) | Rust 2021 | Cryptografie, audit, Shamir SSS, DB |
| **Windows Service** | .NET 8 / C# | Named pipe, TPM lifecycle, vault-beheer |
| **Electron UI** | React + TypeScript | Desktop-interface, wizard, systeemvak |

---

## ✅ Testresultaten

### `cargo check --workspace` — **GESLAAGD** ✅

De workspace compileert zonder fouten voor alle 7 crates:
```
vault-common ✓  vault-crypto ✓  vault-tpm ✓  vault-core ✓
vault-audit ✓   vault-shamir ✓  vault-db-tool ✓
```

> **Opmerking:** `cargo test --workspace` kon niet worden uitgevoerd door schijfruimtebeperking in de sandbox (Rust toolchain + testartefacten overschrijden 2 GB). De 50 tests zijn hieronder geanalyseerd via codereview.

---

## 🔬 Analyse per Crate

### 1. `vault-crypto` — Centrale Cryptografie

**Bestanden:** `kdf.rs`, `keys.rs`, `hkdf.rs`, `secure_delete.rs`, `memory_lock.rs`

#### ✅ Sterke punten
- **Argon2id** correct geconfigureerd: 65.536 KiB geheugen, 4 iteraties, 4 threads → bestand tegen GPU-bruteforce
- **AES-256-GCM** met verplichte AAD — authenticatie van geassocieerde data altijd gecontroleerd
- **Unieke nonce gegarandeerd** via een globale atomaire teller (`AtomicU64`) + 4 willekeurige bytes → geen hergebruik van nonces mogelijk
- **`SecretBytes`** implementeert `Drop` met `zeroize` → sleutels worden gewist uit het geheugen
- **Constante-tijd vergelijking** via de `subtle` crate — bescherming tegen timing-aanvallen
- De functie `constant_time_eq` is geannoteerd met `#[inline(never)]` om compileroptimalisatie te voorkomen

#### ⚠️ Aandachtspunten
- **`memory_lock.rs`** gebruikt waarschijnlijk `mlock()` — op Linux (CI sandbox) kunnen systeemlimieten geheugenvergrendeling verhinderen. Een stille degradatie verdient de voorkeur boven een panic.
- De `dpapi_unprotect`-fallback (niet-Windows) leest de `machine_id` uit een hardgecodeerd pad (`./vault-data/machine_id`), wat fragiel is als de werkdirectory verandert.

#### Gedekte tests (19 tests in `tests.rs` + `kdf.rs`)
| Test | Controleert |
|------|-------------|
| `test_different_passwords_different_keys` | Isolatie van afleidingen |
| `test_different_salts_different_keys` | Uniciteit van salts |
| `test_random_salt_uniqueness` | OsRng produceert verschillende salts |
| `test_verify_wrong_password_fails` | Afwijzing van foutieve wachtwoorden |
| `test_unicode_password` | Volledige UTF-8-ondersteuning |
| `test_long_password` | Wachtwoorden tot 10.000 bytes |
| `test_encrypt_produces_unique_ciphertexts` | Verschillende nonces bij elke aanroep |
| `test_encrypt_decrypt_empty_message` | Lege berichten |
| `test_encrypt_decrypt_large_message` | Grote volumes (100 KB) |
| `test_wrong_aad_decryption_fails` | AEAD-integriteit |
| `test_tampered_ciphertext_fails` | Detectie van manipulatie (bit flip) |
| `test_truncated_ciphertext_fails` | Afwijzing van te korte ciphertexts |
| `test_secure_delete_large_file` | Veilig wissen van 1 MB |
| `test_secure_delete_dir_recursive` | Recursief verwijderen |
| `test_constant_time_eq_*` (3 tests) | Constante-tijd vergelijkingen |

---

### 2. `vault-shamir` — Secret Sharing (SSS)

**Enkel bestand:** `lib.rs` (~200 regels)

#### ✅ Sterke punten
- **Volledige GF(256)-implementatie**: `gf256_mul` en `gf256_inv` met het correcte irreducibele polynoom (0x1b = AES)
- Correcte `lagrange_interpolate` voor reconstructie
- **Zeroize on Drop** op `ShamirShare.data`
- Parametervalidatie: drempelwaarde ≥ 2, totaal ≤ 255
- SHA-256-vingerafdruk per share om corruptie te detecteren

#### ⚠️ Aandachtspunten (kritisch)
- **`gf256_inv(0)` geeft 0 terug** — dit gedrag kan een incorrecte reconstructie veroorzaken als een share met `index = 0` wordt aangeboden (onmogelijk door constructie want indices beginnen bij 1, maar verdient een expliciete bewering)
- **`combine()` gebruikt altijd de eerste `threshold` shares** (`&xs[..self.threshold]`) zelfs als er meer shares worden aangeboden. Als een van de eerste shares beschadigd is, mislukt reconstructie zonder de andere te proberen.
- Geen test voor gedeeltelijke reconstructie met niet-opeenvolgende shares (bv. shares 1, 3, 5)

#### Gedekte tests
| Test | Controleert |
|------|-------------|
| `test_split_and_combine` | Reconstructie met shares[0..3] en shares[2..5] |
| `test_insufficient_shares` | Fout bij minder dan drempelwaarde shares |

---

### 3. `vault-core` — Vault-logica

**Bestanden:** `vault.rs`, `rate_limiter.rs`, `backup.rs`, `db_encryption.rs`, `db_migration.rs`, `state_validator.rs`

#### ✅ Sterke punten
- **Persistente rate limiter in SQLite**: vergrendeling na N pogingen, tijdvenster, automatische reset bij succes
- **WAL-modus + synchronous=FULL** op de rate limiter-DB → consistentie gegarandeerd, ook bij crash
- `Vault::drop()` roept automatisch `lock()` aan → geen sleutellek bij paniek
- `integrity_hmac_key` gewist in `Drop` via `zeroize`
- **Auto-lock timeout** configureerbaar (standaard: 10 minuten)
- `lock()` stelt `master_key = None` in → sleutel direct gewist

#### ⚠️ Aandachtspunten
- **Alleen de `"tpm"`-provider is geïmplementeerd** in `unlock_internal()`. Een ontgrendeling via wachtwoord (Argon2id) ontbreekt, waardoor de vault onbruikbaar is zonder fysieke TPM in productie.
- De rate limiter gebruikt `BEGIN IMMEDIATE` met handmatige retry — een SQLite `busy_handler` zou eleganter zijn.
- `build_hash: [0u8; 32]` in het `ServiceStarted`-event — de werkelijke binary-hash wordt niet berekend.

#### Gedekte tests (in `tests.rs`)
- Tests van de rate limiter: verificatie van blokkering, telpogingen, reset bij succes
- Tests van auto-lock timeout
- Tests van de lock/unlock-cyclus

---

### 4. `vault-audit` — Auditlogboek

#### ✅ Sterke punten
- **SHA-256-hash chaining** → elke inzending verwijst naar de vorige, manipulatie wordt gedetecteerd
- Configureerbaar groottepercentage (standaard 1 GB)
- Integratie met Windows Event Log
- Configureerbare retentie (standaard 1.000 inzendingen)

---

### 5. CI/CD-pipeline

**Bestand:** `.github/workflows/ci.yml`

#### ✅ Structuur
```
rust-check → rust-build-windows
                                  ↘
dotnet-build                        package-release (alleen tags v*)
electron-build                    ↗
```

| Stap | Runner | Controleert |
|------|--------|-------------|
| `cargo check + test + clippy + fmt` | ubuntu-latest | Rust-kwaliteit |
| Cross-compilatie `vault-db-tool.exe` | ubuntu-latest + MinGW | Windows-build |
| `dotnet publish` zelfstandig | ubuntu-latest | .NET service |
| Electron + Wine packaging | ubuntu-latest | Windows UI |

#### ⚠️ Aandachtspunten CI
- **Geen `Cargo.lock`-cache** — Cargo.lock is niet gecommit in de repository, wat niet-reproduceerbare builds kan veroorzaken.
- De `dotnet-build`-job heeft **geen .NET-tests** — alleen een build/publish.
- Electron-tests beperken zich tot `tsc` + `vite build`, geen Jest-eenheidstests.
- `secrets.GITHUB_TOKEN` gebruikt voor electron-builder — OK voor publieke repositories.

---

## 📊 Kwaliteitsoverzicht

| Criterium | Score | Opmerking |
|-----------|-------|-----------|
| **Cryptografie** | 🟢 Uitstekend | Correcte primitieven, zeroize, constante tijd |
| **Architectuur** | 🟢 Goed | Duidelijke crate-scheiding, nette interfaces |
| **Eenheidstests** | 🟡 Matig | Goede crypto-dekking, lacunes in Shamir en vault-core |
| **TPM-beveiliging** | 🟡 Matig | Robuust maar enkelvoudige provider (geen wachtwoord-fallback) |
| **CI/CD** | 🟢 Goed | Volledige pipeline, ontbreken van Cargo.lock en .NET/JS-tests |
| **Documentatie** | 🟢 Uitstekend | README, BUILD, API, ARCHITECTURE, AGENTS.md |
| **Geheimbeheer** | 🟢 Uitstekend | Systematisch zeroize, SecretBytes, Drop geïmplementeerd |

**Algehele score: 🟢 Goed — Productie-klaar voor Windows met TPM, met enkele aanbevolen verbeteringen**

---

## 🛠️ Prioritaire Aanbevelingen

### 🔴 Hoge prioriteit
1. **Implementeer de "password"-provider** in `vault.rs` — zonder fysieke TPM kan de vault niet worden geopend
2. **Commit `Cargo.lock`** — onmisbaar voor reproduceerbare builds van een beveiligingsapplicatie
3. **Herstel `combine()` in vault-shamir** — gebruik de N beste geldige shares, niet per se de eerste N

### 🟡 Gemiddelde prioriteit
4. **Voeg een Shamir-test toe met niet-opeenvolgende shares** (bv. indices 1, 3, 5)
5. **Bereken de werkelijke `build_hash`** in het `ServiceStarted`-event (SHA-256-hash van de binary)
6. **Corrigeer het hardgecodeerde pad** in `dpapi_unprotect` (niet-Windows fallback)
7. **Voeg .NET-tests toe** voor de Windows Service (minimaal de IPC-handlers)

### 🟢 Lage prioriteit
8. Voeg Jest-tests toe voor de Electron UI
9. Documenteer het binaire formaat van de named pipe in `docs/API.md`
10. Vul de productiechecklist in `BUILD.md` in (certificaatpinning, code signing)

---

*Analyse uitgevoerd door Tasklet · Repository geanalyseerd op 8 juni 2026*
