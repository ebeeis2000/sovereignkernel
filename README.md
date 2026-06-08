# SovereignKernel Vault

[![CI](https://github.com/ebeeis2000/sovereignkernel/actions/workflows/ci.yml/badge.svg)](https://github.com/ebeeis2000/sovereignkernel/actions/workflows/ci.yml)

**Hardware-backed security vault voor Windows 11** met TPM 2.0 integratie, Argon2id key derivation, Shamir secret sharing, tamper-evident audit logging en encrypted database opslag.

## Kenmerken

- **Argon2id** key derivation (65MB geheugen-hard, GPU-resistent)
- **AES-256-GCM** voor alle data-at-rest en in-transit encryptie
- **TPM 2.0** hardware-backed key sealing met PCR policy
- **X25519 + HKDF** voor IPC channel key agreement
- **Shamir (3-of-5)** secret sharing voor noodherstel
- **Tamper-evident** SHA-256 hash-chained audit logging
- **Anti-tamper**: SHA256 self-hash verificatie bij elke opstart
- **Auto-lock**: Automatisch vergrendelen na inactiviteit
- **Secure delete**: 3-pass overwrite bij verwijdering van gevoelige data
- **Windows Event Log**: Alle beveiligingsgebeurtenissen gelogd

## Architectuur

```
┌─────────────────┐     ┌──────────────────────┐     ┌────────────────┐
│  Electron UI    │────▶│  Windows Service      │────▶│  Rust Core     │
│  (React + Tray) │     │  (Named Pipe + Auth)  │     │  (7 crates)    │
└─────────────────┘     └──────────────────────┘     └────────────────┘
                              │                             │
                              ▼                             ▼
                        Windows Event Log            TPM 2.0 / SQLCipher
```

Zie [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) voor het volledige diagram.

## Componenten

| Component | Technologie | Functie |
|-----------|-------------|---------|
| **Rust Workspace** | Rust 2021 (7 crates) | Cryptografie, audit, Shamir SSS, backup, database |
| **Windows Service** | .NET 8 (C#) | Named pipe server, TPM communicatie, vault lifecycle |
| **Electron UI** | React + TypeScript | Desktop interface, setup wizard, system tray |
| **Installer** | PowerShell + NSIS | Geautomatiseerde deployment |

## Installatie

### Optie 1: PowerShell (snel)

```powershell
# Administrator PowerShell
.\scripts\Install-SovereignKernel.ps1
```

### Optie 2: NSIS Installer (GUI)

Download `SovereignKernel-Setup.exe` van [Releases](https://github.com/ebeeis2000/sovereignkernel/releases) en dubbelklik.

### Optie 3: Handmatig

```powershell
# Service registreren
sc.exe create SovereignKernelVault binPath="C:\SovereignKernel\bin\SovereignKernelVault.exe --service" start=auto
sc.exe failure SovereignKernelVault reset=86400 actions=restart/5000/restart/10000/restart/30000
sc.exe start SovereignKernelVault

# UI starten
.\SovereignKernel-UI\SovereignKernel.exe
```

## Ontwikkeling

### Vereisten

- Rust 1.75+ (stable)
- .NET 8.0 SDK
- Node.js 20+
- MinGW (cross-compile): `sudo apt install gcc-mingw-w64-x86-64`

### Bouwen

```bash
# Rust: check + test
cargo check --workspace
cargo test --workspace

# Windows EXE (cross-compile)
cargo build --release --target x86_64-pc-windows-gnu -p vault-db-tool

# .NET Service
cd windows-service
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true

# Electron UI
cd electron-ui
npm ci && npm run build
npx electron-builder --win --dir
```

### Tests

```bash
cargo test --workspace        # 50 tests
cargo clippy --workspace      # Lint
cargo fmt --all -- --check    # Format
```

## API

De vault communiceert via een named pipe (`\\.\pipe\SovereignKernelVault`) met AES-256-GCM encrypted frames.

Commando's: `status`, `health`, `version`, `unlock`, `lock`, `rotate`, `shamir_status`, `backup`

Zie [docs/API.md](docs/API.md) voor volledige documentatie.

## Beveiliging

Rapporteer kwetsbaarheden via het [Security Policy](SECURITY.md).

## CI/CD

GitHub Actions pipeline:
1. **Rust Check & Test** — clippy, fmt, tests
2. **Rust Build Windows** — cross-compile vault-db-tool.exe
3. **.NET Build** — self-contained SovereignKernelVault.exe
4. **Electron Build** — SovereignKernel.exe
5. **Release** — automatisch bij git tag `v*`

## Bijdragen

Zie [CONTRIBUTING.md](CONTRIBUTING.md) voor richtlijnen.

## Licentie

MIT — Zie [LICENSE](LICENSE)
