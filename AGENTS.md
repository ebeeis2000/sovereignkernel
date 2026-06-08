# AGENTS

This repository is a Windows security vault project with three main components:
- `crates/` — Rust workspace with cryptography, TPM support, audit logging, Shamir secret sharing, and database tooling
- `windows-service/` — .NET 8 Windows service for named-pipe IPC, TPM lifecycle, and vault management
- `electron-ui/` — Electron + React desktop UI with secure IPC and packaging

## What agents should know

- The codebase is security-sensitive. Prefer safe handling of secrets, explicit error propagation, and auditing behavior.
- Use existing documentation rather than duplicating it. Key references:
  - `README.md`
  - `CONTRIBUTING.md`
  - `docs/ARCHITECTURE.md`
  - `docs/API.md`
  - `SECURITY.md`
- The CI pipeline is defined in `.github/workflows/ci.yml`.

## Build and test commands

### Rust
- `cargo check --workspace`
- `cargo test --workspace`
- `cargo clippy --workspace -- -D warnings`
- `cargo fmt --all -- --check`

### .NET Windows service
- `dotnet restore windows-service/SovereignKernelService.csproj`
- `dotnet build windows-service/SovereignKernelService.csproj -c Release --no-restore`
- `dotnet publish windows-service/SovereignKernelService.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o ./publish`

### Electron UI
- `cd electron-ui && npm ci`
- `cd electron-ui && npx tsc -p tsconfig.main.json`
- `cd electron-ui && npx vite build`
- `cd electron-ui && CSC_IDENTITY_AUTO_DISCOVERY=false npx electron-builder --win --dir`

## Conventions

### Rust
- `cargo fmt` is required
- `cargo clippy -- -D warnings` must pass
- Avoid `unwrap()` in production code; use `?` or explicit error handling
- Use `zeroize` for secrets and constant-time comparisons for sensitive data

### C# / .NET
- Prefer `sealed` for classes that are not intended to be extended
- All IPC handlers should use timeout and cancellation tokens
- Log security-relevant events to Windows Event Log
- Avoid empty `catch {}` blocks

### TypeScript / Electron
- Use strict TypeScript mode
- `contextIsolation: true` in Electron security-sensitive code
- Avoid `any`
- Maintain explicit sequence numbers on IPC messages where applicable

## Repo layout

- `crates/` — core Rust implementation and toolbox
- `windows-service/` — service host, TPM integration, Windows-specific runtime
- `electron-ui/` — UI, React renderer, Electron packaging
- `scripts/` — installer and deployment scripts
- `docs/` — architecture and API reference

## Security and release notes

- Treat the project as a security product: cryptography, key sealing, audit logs, and TPM state are all critical.
- Follow the reporting process in `SECURITY.md` for vulnerabilities.
- Release packaging is triggered only for git tags starting with `v` in CI.

## When to ask for clarification

- If a change touches IPC, authentication, or cryptographic data flow, confirm the expected threat model and state transitions.
- If a build needs a new dependency, verify where it belongs: Rust workspace, Windows service, or Electron UI.
- If a fix affects secure storage, keep the review focused on secret handling, persistence, and auditing.
