# SovereignKernel Vault — Pipe API Reference

## Transport

- **Endpoint:** `\\.\pipe\SovereignKernelVault`
- **Protocol:** Length-prefixed frames (4-byte big-endian header)
- **Encryption:** AES-256-GCM after X25519 handshake
- **Max message:** 1 MB
- **Max concurrent:** 10 connections
- **Timeout:** 30 seconds per request

## Handshake (per verbinding)

```
Client → Server: ClientHello { client_random[32], client_eph_pub[32] }
Server → Client: ServerHello { server_random[32], server_eph_pub[32] }
                 (Both derive: shared_secret = X25519(eph_priv, peer_eph_pub))
                 (Both derive: master_key = HKDF(shared_secret, client_random || server_random))
Client → Server: ClientFinish { HMAC-SHA256(master_key, transcript) }
Server → Client: ServerFinish { HMAC-SHA256(master_key, transcript) }
```

Na handshake: alle berichten AES-256-GCM encrypted met session keys.

---

## Commando's

### `status`

Vraag de huidige vault status op.

**Request:**
```json
{ "command": "status" }
```

**Response:**
```json
{
  "ok": true,
  "status": "locked" | "unlocked",
  "tpm": "available" | "unavailable" | "error",
  "requests": 1234,
  "rejected": 5
}
```

---

### `health`

Uitgebreide health-check voor monitoring.

**Request:**
```json
{ "command": "health" }
```

**Response:**
```json
{
  "ok": true,
  "uptime_seconds": 86400,
  "memory_mb": 45,
  "working_set_mb": 120,
  "threads": 12,
  "requests_total": 5000,
  "requests_rejected": 23,
  "gc_gen0": 150,
  "gc_gen1": 30,
  "gc_gen2": 5,
  "data_path": "C:\\ProgramData\\SovereignKernel\\Data"
}
```

---

### `version`

Versie-informatie opvragen.

**Request:**
```json
{ "command": "version" }
```

**Response:**
```json
{
  "ok": true,
  "version": "0.3.0",
  "protocol": 1
}
```

---

### `unlock`

Ontgrendel de vault met een provider.

**Request:**
```json
{
  "command": "unlock",
  "provider": "password" | "tpm" | "shamir",
  "data": "<provider-specifieke data>"
}
```

**Provider data:**
- `password`: het wachtwoord als string
- `tpm`: leeg (gebruikt hardware key)
- `shamir`: array van shares `["share1_hex", "share2_hex", "share3_hex"]`

**Response (succes):**
```json
{ "ok": true, "message": "Vault ontgrendeld" }
```

**Response (fout):**
```json
{
  "ok": false,
  "error": "Rate limit overschreden",
  "retry_after_seconds": 60,
  "remaining_attempts": 2
}
```

---

### `lock`

Vergrendel de vault onmiddellijk.

**Request:**
```json
{ "command": "lock" }
```

**Response:**
```json
{ "ok": true, "message": "Vault vergrendeld" }
```

---

### `rotate`

Start key rotation (genereert nieuwe session keys).

**Request:**
```json
{ "command": "rotate" }
```

**Response:**
```json
{ "ok": true, "message": "Key rotation gestart" }
```

---

### `shamir_status`

Status van Shamir secret sharing.

**Request:**
```json
{ "command": "shamir_status" }
```

**Response:**
```json
{
  "ok": true,
  "threshold": 3,
  "total": 5,
  "available": 0
}
```

---

### `backup`

Maak een backup van alle vault data.

**Request:**
```json
{ "command": "backup" }
```

**Response:**
```json
{
  "ok": true,
  "path": "C:\\ProgramData\\SovereignKernel\\Data\\backups\\vault_backup_20260608_120000",
  "files": 4
}
```

---

## Error Response Format

Alle fouten volgen hetzelfde formaat:

```json
{
  "ok": false,
  "error": "<Nederlands foutbericht>"
}
```

### Error codes in Windows Event Log

| Event ID | Type | Betekenis |
|----------|------|-----------|
| 1000 | Info | Service gestart/informatie |
| 1100 | Info | Service lifecycle event |
| 2001 | Info | Succesvolle unlock |
| 2002 | Warning | Mislukte unlock poging |
| 5000 | Warning | Beveiligingswaarschuwing |
| 5001 | Warning | Rate limit bereikt |
| 5010 | Warning | Crash recovery gedetecteerd |
| 9000 | Error | Algemene fout |
| 9001 | Error | Integriteitsschending |
| 9002 | Error | Integriteitscontrole uitvoerfout |
| 9999 | Error | Onafgevangen exceptie |

---

## CLI: vault-db-tool

```
USAGE:
    vault-db-tool <COMMAND>

COMMANDS:
    init       Initialiseer een nieuwe vault database
    status     Toon vault status
    backup     Maak een verified backup
    restore    Herstel vanuit backup
    migrate    Migreer onversleutelde database
    verify     Verifieer database integriteit
    help       Toon hulp

OPTIONS:
    --data-dir <PATH>    Data directory [default: ./vault-data]
    --verbose            Uitgebreide output
    --json               JSON output formaat
```
