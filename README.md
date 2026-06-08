# SovereignKernel Vault

**Hardware-backed security vault voor Windows 11** met TPM 2.0 integratie, Shamir secret sharing, tamper-evident audit logging en encrypted database opslag.

## Componenten

| Component | Technologie | Functie |
|-----------|-------------|---------|
| **Rust Workspace** | Rust 2021 | Cryptografie, audit, Shamir SSS, database tools |
| **Windows Service** | .NET 8 (C#) | Named pipe server, TPM communicatie, vault lifecycle |
| **Electron UI** | React + TypeScript | Desktop management interface |
| **Installer** | PowerShell | Geautomatiseerde deployment |

## Quick Start

```powershell
# 1. Service bouwen
cd windows-service
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true

# 2. Console mode starten
.\bin\Release\net8.0-windows\win-x64\publish\SovereignKernelVault.exe --console --no-tpm

# 3. Rust tools bouwen
cd ..
cargo build --release
```

## Beveiliging

- **AES-256-GCM** voor alle data-at-rest encryptie
- **X25519 + HKDF** voor IPC channel key agreement
- **SHA-256 hash chain** voor tamper-evident audit logging
- **Shamir (3-of-5)** secret sharing voor key recovery
- **TPM 2.0** hardware-backed key sealing en PCR validation
- **SQLCipher** (PBKDF2-SHA512, 256K iteraties) voor database encryptie
- **Rate limiting** met exponential backoff tegen brute-force

## Licentie

MIT OR Apache-2.0

## Build Instructies

Zie [BUILD.md](./BUILD.md) voor volledige compilatie-instructies.
