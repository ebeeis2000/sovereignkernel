# SovereignKernel — Build Instructies (Windows 11)

## Vereisten

### Minimale Software

| Tool | Versie | Download |
|------|--------|----------|
| **Rust** | 1.75+ | https://rustup.rs |
| **.NET SDK** | 8.0+ | https://dotnet.microsoft.com/download/dotnet/8.0 |
| **Node.js** | 20 LTS | https://nodejs.org |
| **Visual Studio Build Tools** | 2022 | https://visualstudio.microsoft.com/downloads/ |
| **Git** | Latest | https://git-scm.com |

### Windows-specifiek

```powershell
# Installeer Rust (in PowerShell als Administrator)
winget install Rustlang.Rustup

# Installeer .NET 8 SDK
winget install Microsoft.DotNet.SDK.8

# Installeer Node.js 20
winget install OpenJS.NodeJS.LTS

# Rust target voor Windows
rustup target add x86_64-pc-windows-msvc
```

---

## Stap 1: Rust Workspace Compileren

```powershell
cd sovereignkernel

# Debug build (snel, voor ontwikkeling)
cargo build

# Release build (geoptimaliseerd)
cargo build --release

# Tests uitvoeren
cargo test
```

De `vault-db-tool` binary staat na compilatie in:
- Debug: `target/debug/vault-db-tool.exe`
- Release: `target/release/vault-db-tool.exe`

### Met TPM-ondersteuning

```powershell
# TPM feature activeren (vereist TPM2 TSS libraries)
cargo build --release --features "vault-tpm/tpm"
```

> **Let op**: TPM-compilatie vereist de `tpm2-tss` development libraries. Zonder hardware TPM kun je het project prima compileren zonder de `tpm` feature.

---

## Stap 2: Windows Service (.NET) Compileren

```powershell
cd windows-service

# Build + publish als single-file EXE
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true

# Output locatie:
# bin/Release/net8.0-windows/win-x64/publish/SovereignKernelVault.exe
```

### Service Installeren

```powershell
# Als Administrator:
sc.exe create SovereignKernelVault binPath= "C:\Program Files\SovereignKernel\SovereignKernelVault.exe --service" start= delayed-auto
sc.exe description SovereignKernelVault "SovereignKernel Vault - Hardware-backed security service"
sc.exe start SovereignKernelVault
```

### Console-modus (voor development/debugging)

```powershell
.\SovereignKernelVault.exe --console
.\SovereignKernelVault.exe --console --no-tpm  # zonder TPM
.\SovereignKernelVault.exe --console --data-path "D:\vault-data"
```

---

## Stap 3: Electron UI Compileren (optioneel)

```powershell
cd electron-ui

# Dependencies installeren
npm install

# Development server
npm run dev

# Productie build (Windows installer)
npm run build
npm run package  # Maakt .exe installer
```

---

## Volledige Build Script (alles-in-een)

Sla dit op als `build-all.ps1`:

```powershell
#Requires -Version 7.0
param(
    [switch]$Release,
    [switch]$SkipElectron,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

Write-Host "=== SovereignKernel Build ===" -ForegroundColor Cyan

# 1. Rust
Write-Host "`n[1/3] Rust workspace..." -ForegroundColor Yellow
Push-Location $root
if ($Release) { cargo build --release } else { cargo build }
if (-not $SkipTests) { cargo test }
Pop-Location

# 2. .NET Service
Write-Host "`n[2/3] Windows Service..." -ForegroundColor Yellow
Push-Location "$root\windows-service"
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
Pop-Location

# 3. Electron (optioneel)
if (-not $SkipElectron) {
    Write-Host "`n[3/3] Electron UI..." -ForegroundColor Yellow
    Push-Location "$root\electron-ui"
    if (Test-Path "node_modules") { npm run build } else { npm install; npm run build }
    Pop-Location
}

Write-Host "`n=== Build Compleet ===" -ForegroundColor Green
Write-Host "Service EXE: $root\windows-service\bin\Release\net8.0-windows\win-x64\publish\SovereignKernelVault.exe"
Write-Host "DB Tool EXE: $root\target\$(if($Release){'release'}else{'debug'})\vault-db-tool.exe"
```

---

## Architectuur Overzicht

```
┌─────────────────────────────────────────────────────┐
│                  Electron UI (.exe)                  │
│         React + TypeScript + Vite                    │
└─────────────────────┬───────────────────────────────┘
                      │ Named Pipe (X25519 encrypted)
┌─────────────────────▼───────────────────────────────┐
│          Windows Service (.exe) — .NET 8             │
│   ┌─────────────┐  ┌──────────────┐  ┌──────────┐  │
│   │ Pipe Server │  │ TPM Manager  │  │ Rate Lim │  │
│   └─────────────┘  └──────────────┘  └──────────┘  │
└─────────────────────┬───────────────────────────────┘
                      │ FFI / subprocess
┌─────────────────────▼───────────────────────────────┐
│            Rust Core Libraries                       │
│  vault-crypto │ vault-audit │ vault-shamir │ vault-core │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│              TPM 2.0 Hardware                        │
└─────────────────────────────────────────────────────┘
```

---

## Productie Checklist

- [ ] Certificate pins invullen in `auto-updater.ts` (regel 488-490)
- [ ] Code signing certificaat configureren
- [ ] `CARGO_PKG_VERSION` verifiëren voor release
- [ ] Installer PowerShell script testen op schone VM
- [ ] TPM provisioning valideren op target hardware
- [ ] Security audit laten uitvoeren op X25519 handshake

---

## Troubleshooting

### "linker `link.exe` not found"
Installeer Visual Studio Build Tools met C++ workload:
```powershell
winget install Microsoft.VisualStudio.2022.BuildTools --override "--add Microsoft.VisualStudio.Workload.VCTools"
```

### "rusqlite build fails"
De `bundled` feature compileert SQLite vanuit source. Zorg dat een C-compiler beschikbaar is (MSVC via VS Build Tools).

### "TPM not available"
Zonder TPM hardware werkt de service in software-only mode (`--no-tpm`). Voor development is dit voldoende.
