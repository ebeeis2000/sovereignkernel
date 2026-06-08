# Bijdragen aan SovereignKernel

## Vereisten

- Rust 1.75+ (stable)
- .NET 8.0 SDK
- Node.js 20+
- MinGW (voor Windows cross-compile): `sudo apt install gcc-mingw-w64-x86-64`
- Wine (voor Electron packaging): `sudo apt install wine64`

## Ontwikkelomgeving opzetten

```bash
# Clone
git clone https://github.com/ebeeis2000/sovereignkernel.git
cd sovereignkernel

# Rust: check + test
cargo check --workspace
cargo test --workspace

# .NET: build
cd windows-service
dotnet build -c Debug
cd ..

# Electron: install + build
cd electron-ui
npm install
npm run build
cd ..
```

## Code Standaarden

### Rust
- `cargo fmt` — automatisch formatteren (verplicht)
- `cargo clippy -- -D warnings` — geen warnings toegestaan
- Alle secrets: `zeroize` derive of handmatig in `Drop`
- Geen `unwrap()` in productie-code — gebruik `?` of expliciete error handling
- Constant-time vergelijkingen voor security-gevoelige data

### C# (.NET)
- Gebruik `sealed` voor niet-overervbare klassen
- Alle IPC handlers: timeout + cancellation token
- Event Log voor security-relevante events
- Geen `catch {}` zonder logging

### TypeScript
- Strict mode (`"strict": true`)
- `contextIsolation: true` in Electron
- Geen `any` types
- Sequence numbers op alle IPC berichten

## Commit Conventions

```
feat: nieuwe functionaliteit
fix: bugfix
security: beveiligingsverbetering
docs: documentatie
test: tests toevoegen/verbeteren
refactor: code herstructurering
ci: CI/CD wijzigingen
```

## Pull Request Proces

1. Fork de repository
2. Maak een feature branch: `git checkout -b feature/mijn-feature`
3. Commit je wijzigingen
4. Zorg dat alle tests slagen: `cargo test --workspace`
5. Zorg dat clippy clean is: `cargo clippy --workspace -- -D warnings`
6. Open een Pull Request

## Security Issues

Rapporteer beveiligingsproblemen **NIET** via GitHub Issues.
Zie [SECURITY.md](SECURITY.md) voor het responsible disclosure proces.

## Architectuur

Zie [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) voor het volledige architectuuroverzicht.

## Licentie

Door bij te dragen ga je akkoord dat je bijdragen worden gelicentieerd onder dezelfde licentie als het project (MIT OR Apache-2.0).
