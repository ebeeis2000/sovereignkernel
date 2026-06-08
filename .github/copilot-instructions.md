# Copilot Instructions for SovereignKernel

This repository is a security-focused Windows vault project. It combines:
- `crates/` — Rust workspace for cryptography, audit, TPM, Shamir secret sharing, and database tooling
- `windows-service/` — .NET 8 Windows service for named-pipe IPC, TPM lifecycle, and vault management
- `electron-ui/` — Electron + React UI with secure IPC, packaging, and Windows desktop logic

## Key priorities

- Treat the codebase as security-critical. Changes must preserve confidentiality, integrity, and auditability.
- Avoid insecure defaults, unsafe exception handling, or poorly constrained IPC flows.
- Prefer explicit error handling and avoid `unwrap()` in Rust; do not add unguarded `catch {}` blocks in C#.
- In Electron, maintain `contextIsolation: true`, avoid `any`, and keep IPC boundaries explicit.
- Keep secrets zeroized and use constant-time comparisons for sensitive data.

## Useful references

- `README.md` — project overview and build instructions
- `CONTRIBUTING.md` — conventions for Rust, C#, TypeScript, and commit style
- `docs/ARCHITECTURE.md` — architecture diagram and component relationships
- `docs/API.md` — named pipe API documentation
- `.github/workflows/ci.yml` — CI build/test/release steps
- `AGENTS.md` — additional agent guidance for repo layout and conventions

## Recommended commands

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

## When editing code

- Confirm the affected component before applying changes: Rust, Windows service, or Electron UI.
- If a change touches IPC, cryptographic state, key management, or audit logging, ask for the expected threat model and required invariants.
- For dependency changes, verify the impact on all build pipelines and language boundaries.
- When adding tests, target both unit-level behavior and the relevant security property.

## Do not

- Do not suggest or implement unreviewed cryptographic protocols.
- Do not bypass existing formatting, linting, or CI rules.
- Do not alter release packaging expectations without checking `.github/workflows/ci.yml` and the tagged release flow.
