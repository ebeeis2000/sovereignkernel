use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vault_common::{VaultError, VaultResult};
use vault_crypto::constant_time_eq;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEvent {
    VaultInitialized { tpm_available: bool, shamir_threshold: usize, shamir_total: usize },
    VaultUnlocked { provider: String, shamir_shares_used: Option<usize>, tpm_pcr_valid: Option<bool> },
    VaultLocked { reason: LockReason },
    TpmUnsealAttempt { pcr_valid: bool, counter_valid: bool, success: bool },
    TpmPcrMismatch { expected_pcr_hash: [u8; 32], actual_pcr_hash: [u8; 32], affected_pcrs: Vec<u8> },
    TpmCounterValidationFailed { stored_counter: u64, hardware_counter: u64 },
    TpmCounterIncremented { old_value: u64, new_value: u64 },
    KeyRotation { old_key_fingerprint: [u8; 32], new_key_fingerprint: [u8; 32] },
    ShamirSharesGenerated { threshold: usize, total: usize, share_fingerprints: Vec<[u8; 32]> },
    ShamirSharesCombined { shares_used: usize, threshold: usize },
    RecoveryInitiated { package_hash: [u8; 32], usb_serial: Option<String>, wots_verified: bool },
    RecoveryCompleted { vault_id: String, new_pcr_baseline: [u8; 32] },
    TpmProvisioned { tpm_manufacturer: String, ek_cert_thumbprint: [u8; 32] },
    TpmError { error_code: String, operation: String },
    FailedUnlockAttempt { reason: String, attempt_number: u32, provider: String },
    RateLimitExceeded { attempts_in_window: u32, lockout_duration_secs: u64 },
    ConfigurationChanged { changed_fields: Vec<String>, previous_hash: [u8; 32], new_hash: [u8; 32] },
    UnauthorizedAccessAttempt { source: String, method: String },
    ServiceStarted { version: String, build_hash: [u8; 32] },
    ServiceStopped { reason: String, uptime_seconds: u64 },
    AuditRateLimited { events_dropped: u64, window_seconds: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LockReason {
    Manual,
    AutoTimeout,
    SystemSuspend,
    TpmFailure,
    EmergencyShutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub entry_hash: [u8; 32],
    pub previous_hash: [u8; 32],
    pub timestamp: DateTime<Utc>,
    pub event: AuditEvent,
    pub session_id: [u8; 16],
    pub machine_id: [u8; 32],
    pub sequence_number: u64,
}

#[derive(Debug, Clone)]
pub struct TamperedEntry {
    pub sequence_number: u64,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct ChainVerificationResult {
    pub total_entries: u64,
    pub tampered_entries: Vec<TamperedEntry>,
    pub is_intact: bool,
    pub final_hash: [u8; 32],
}

impl ChainVerificationResult {
    pub fn tampered_count(&self) -> usize {
        self.tampered_entries.len()
    }

    pub fn integrity_percentage(&self) -> f64 {
        if self.total_entries == 0 {
            return 100.0;
        }
        (self.total_entries - self.tampered_entries.len() as u64) as f64
            / self.total_entries as f64
            * 100.0
    }
}

struct AuditState {
    last_entry_hash: [u8; 32],
    sequence_number: u64,
}

struct RateLimitState {
    window_start_secs: i64,
    events_in_window: u64,
    events_dropped_total: u64,
    last_drop_logged_at: i64,
}

pub struct AuditLogger {
    db: Mutex<rusqlite::Connection>,
    state: Mutex<AuditState>,
    session_id: [u8; 16],
    machine_id: [u8; 32],
    max_events_per_second: u64,
    max_database_size_bytes: u64,
    rate_limit: Mutex<RateLimitState>,
}

impl AuditLogger {
    pub fn new(
        db_path: &str,
        machine_id: [u8; 32],
        max_eps: Option<u64>,
        max_size: Option<u64>,
    ) -> VaultResult<Self> {
        let meps = max_eps.unwrap_or(1000);
        let msize = max_size.unwrap_or(1_073_741_824);
        let db = rusqlite::Connection::open(db_path)
            .map_err(|e| VaultError::Audit(format!("Database openen: {}", e)))?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_hash BLOB NOT NULL UNIQUE,
                previous_hash BLOB NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_json TEXT NOT NULL,
                session_id BLOB NOT NULL,
                machine_id BLOB NOT NULL,
                sequence_number INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_sequence ON audit_log(sequence_number);
            CREATE INDEX IF NOT EXISTS idx_audit_machine ON audit_log(machine_id);
            CREATE TABLE IF NOT EXISTS audit_archive_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                archived_at TEXT NOT NULL,
                entries_archived INTEGER NOT NULL,
                archive_hash BLOB NOT NULL
            );
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;",
        )
        .map_err(|e| VaultError::Audit(format!("Schema initialisatie: {}", e)))?;

        let mut sid = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut sid);

        let (last_hash, seq) = {
            let mut stmt = db
                .prepare("SELECT entry_hash, sequence_number FROM audit_log ORDER BY id DESC LIMIT 1")
                .map_err(|e| VaultError::Audit(e.to_string()))?;
            let mut rows = stmt.query([]).map_err(|e| VaultError::Audit(e.to_string()))?;
            match rows.next().map_err(|e| VaultError::Audit(e.to_string()))? {
                Some(row) => {
                    let h: Vec<u8> = row.get(0).map_err(|e| VaultError::Audit(e.to_string()))?;
                    let q: i64 = row.get(1).map_err(|e| VaultError::Audit(e.to_string()))?;
                    if h.len() != 32 {
                        return Err(VaultError::Audit("Corrupte hash lengte in database".into()));
                    }
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&h);
                    (a, q as u64 + 1)
                }
                None => ([0u8; 32], 1),
            }
        };

        Ok(Self {
            db: Mutex::new(db),
            state: Mutex::new(AuditState { last_entry_hash: last_hash, sequence_number: seq }),
            session_id: sid,
            machine_id,
            max_events_per_second: meps,
            max_database_size_bytes: msize,
            rate_limit: Mutex::new(RateLimitState {
                window_start_secs: Utc::now().timestamp(),
                events_in_window: 0,
                events_dropped_total: 0,
                last_drop_logged_at: 0,
            }),
        })
    }

    pub fn log(&self, event: AuditEvent) -> VaultResult<[u8; 32]> {
        {
            let mut rl = self.rate_limit.lock();
            let now = Utc::now().timestamp();
            if now - rl.window_start_secs >= 1 {
                rl.window_start_secs = now;
                rl.events_in_window = 0;
            }
            if rl.events_in_window >= self.max_events_per_second {
                rl.events_dropped_total += 1;
                if now - rl.last_drop_logged_at >= 10 {
                    rl.last_drop_logged_at = now;
                    let dropped = rl.events_dropped_total;
                    drop(rl);
                    let _ = self.log_internal(&AuditEvent::AuditRateLimited {
                        events_dropped: dropped,
                        window_seconds: 1,
                    });
                }
                return Err(VaultError::Audit("Rate limited".into()));
            }
            rl.events_in_window += 1;
        }
        self.enforce_size_cap()?;
        self.log_internal(&event)
    }

    fn log_internal(&self, event: &AuditEvent) -> VaultResult<[u8; 32]> {
        let ts = Utc::now();
        let et = Self::event_type_str(event);
        let ej = serde_json::to_string(event)
            .map_err(|e| VaultError::Audit(format!("JSON serialisatie: {}", e)))?;

        let mut st = self.state.lock();
        let ph = st.last_entry_hash;
        let sq = st.sequence_number;

        let mut h = Sha256::new();
        h.update(ph);
        h.update(ts.to_rfc3339().as_bytes());
        h.update(et.as_bytes());
        h.update(ej.as_bytes());
        h.update(self.session_id);
        h.update(self.machine_id);
        h.update(sq.to_le_bytes());
        let eh: [u8; 32] = h.finalize().into();

        {
            let db = self.db.lock();
            db.execute(
                "INSERT INTO audit_log (entry_hash, previous_hash, timestamp, event_type, event_json, session_id, machine_id, sequence_number) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                rusqlite::params![
                    eh.as_slice(),
                    ph.as_slice(),
                    ts.to_rfc3339(),
                    et,
                    ej,
                    self.session_id.as_slice(),
                    self.machine_id.as_slice(),
                    sq as i64
                ],
            )
            .map_err(|e| VaultError::Audit(format!("Invoegen mislukt: {}", e)))?;
        }

        st.last_entry_hash = eh;
        st.sequence_number = sq + 1;
        Ok(eh)
    }

    fn enforce_size_cap(&self) -> VaultResult<()> {
        let db = self.db.lock();
        let pc: i64 = db.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap_or(0);
        let ps: i64 = db.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap_or(4096);
        let current_size = (pc * ps) as u64;
        if current_size <= self.max_database_size_bytes {
            return Ok(());
        }

        tracing::warn!("Audit database limiet bereikt ({} bytes), archivering gestart...", current_size);

        let entries_to_archive: i64 = db
            .query_row("SELECT COUNT(*) FROM audit_log WHERE id IN (SELECT id FROM audit_log ORDER BY id ASC LIMIT 10000)", [], |r| r.get(0))
            .unwrap_or(0);

        let mut archive_hasher = Sha256::new();
        {
            let mut stmt = db.prepare("SELECT entry_hash FROM audit_log ORDER BY id ASC LIMIT 10000").ok();
            if let Some(ref mut s) = stmt {
                let mut rows = s.query([]).ok();
                if let Some(ref mut r) = rows {
                    while let Ok(Some(row)) = r.next() {
                        if let Ok(h) = row.get::<_, Vec<u8>>(0) {
                            archive_hasher.update(&h);
                        }
                    }
                }
            }
        }
        let archive_hash: [u8; 32] = archive_hasher.finalize().into();

        db.execute(
            "INSERT INTO audit_archive_log (archived_at, entries_archived, archive_hash) VALUES (?1, ?2, ?3)",
            rusqlite::params![
                chrono::Utc::now().to_rfc3339(),
                entries_to_archive,
                archive_hash.as_slice()
            ],
        ).ok();

        for _ in 0..10 {
            let del = db
                .execute(
                    "DELETE FROM audit_log WHERE id IN (SELECT id FROM audit_log ORDER BY id ASC LIMIT 1000)",
                    [],
                )
                .unwrap_or(0);
            if del < 1000 {
                break;
            }
        }
        db.execute_batch("PRAGMA incremental_vacuum(1000);").ok();
        tracing::info!("Audit archivering voltooid: {} entries gearchiveerd, hash={}", entries_to_archive, hex::encode(archive_hash));
        Ok(())
    }

    pub fn verify_chain(&self) -> VaultResult<ChainVerificationResult> {
        let db = self.db.lock();
        let mut s = db
            .prepare("SELECT entry_hash, previous_hash, timestamp, event_type, event_json, session_id, machine_id, sequence_number FROM audit_log ORDER BY id ASC")
            .map_err(|e| VaultError::Audit(e.to_string()))?;
        let mut r = s.query([]).map_err(|e| VaultError::Audit(e.to_string()))?;

        let mut ph = [0u8; 32];
        let mut expected_seq = 1u64;
        let mut total = 0u64;
        let mut tampered = Vec::new();

        while let Some(row) = r.next().map_err(|e| VaultError::Audit(e.to_string()))? {
            let eh: Vec<u8> = row.get(0).map_err(|e| VaultError::Audit(e.to_string()))?;
            let pv: Vec<u8> = row.get(1).map_err(|e| VaultError::Audit(e.to_string()))?;
            let ts: String = row.get(2).map_err(|e| VaultError::Audit(e.to_string()))?;
            let et: String = row.get(3).map_err(|e| VaultError::Audit(e.to_string()))?;
            let ej: String = row.get(4).map_err(|e| VaultError::Audit(e.to_string()))?;
            let sid: Vec<u8> = row.get(5).map_err(|e| VaultError::Audit(e.to_string()))?;
            let mid: Vec<u8> = row.get(6).map_err(|e| VaultError::Audit(e.to_string()))?;
            let sq: i64 = row.get(7).map_err(|e| VaultError::Audit(e.to_string()))?;

            if eh.len() != 32 || pv.len() != 32 {
                tampered.push(TamperedEntry { sequence_number: sq as u64, reason: "Corrupte hash lengte".into() });
                continue;
            }

            let mut eha = [0u8; 32];
            eha.copy_from_slice(&eh);

            if sq as u64 != expected_seq {
                tampered.push(TamperedEntry {
                    sequence_number: sq as u64,
                    reason: format!("Sequence mismatch: verwacht {}, gekregen {}", expected_seq, sq),
                });
            }
            if pv.as_slice() != ph.as_slice() {
                tampered.push(TamperedEntry { sequence_number: sq as u64, reason: "Hash-koppeling verbroken".into() });
            }

            let mut h = Sha256::new();
            h.update(ph);
            h.update(ts.as_bytes());
            h.update(et.as_bytes());
            h.update(ej.as_bytes());
            h.update(&sid);
            h.update(&mid);
            h.update(sq.to_le_bytes());
            let computed: [u8; 32] = h.finalize().into();

            if !constant_time_eq(&computed, &eha) {
                tampered.push(TamperedEntry { sequence_number: sq as u64, reason: "Hash mismatch".into() });
            }

            ph = eha;
            expected_seq += 1;
            total += 1;
        }

        Ok(ChainVerificationResult {
            total_entries: total,
            tampered_entries: tampered,
            is_intact: total > 0 || expected_seq == 1,
            final_hash: ph,
        })
    }

    pub fn export_chain(&self, since: Option<DateTime<Utc>>) -> VaultResult<Vec<AuditEntry>> {
        let db = self.db.lock();
        let query = if since.is_some() {
            "SELECT entry_hash, previous_hash, timestamp, event_json, session_id, machine_id, sequence_number FROM audit_log WHERE timestamp >= ?1 ORDER BY id ASC"
        } else {
            "SELECT entry_hash, previous_hash, timestamp, event_json, session_id, machine_id, sequence_number FROM audit_log ORDER BY id ASC"
        };
        let mut stmt = db.prepare(query).map_err(|e| VaultError::Audit(e.to_string()))?;
        let mut rows = if let Some(s) = since {
            stmt.query([s.to_rfc3339()]).map_err(|e| VaultError::Audit(e.to_string()))?
        } else {
            stmt.query([]).map_err(|e| VaultError::Audit(e.to_string()))?
        };

        let mut entries = Vec::new();
        while let Some(row) = rows.next().map_err(|e| VaultError::Audit(e.to_string()))? {
            let eh: Vec<u8> = row.get(0).map_err(|e| VaultError::Audit(e.to_string()))?;
            let ph: Vec<u8> = row.get(1).map_err(|e| VaultError::Audit(e.to_string()))?;
            let ts: String = row.get(2).map_err(|e| VaultError::Audit(e.to_string()))?;
            let ej: String = row.get(3).map_err(|e| VaultError::Audit(e.to_string()))?;
            let sid: Vec<u8> = row.get(4).map_err(|e| VaultError::Audit(e.to_string()))?;
            let mid: Vec<u8> = row.get(5).map_err(|e| VaultError::Audit(e.to_string()))?;
            let sq: i64 = row.get(6).map_err(|e| VaultError::Audit(e.to_string()))?;

            if eh.len() != 32 || ph.len() != 32 || sid.len() != 16 || mid.len() != 32 {
                return Err(VaultError::Audit("Ongeldige datalengte in database rij".into()));
            }

            let mut entry_hash = [0u8; 32]; entry_hash.copy_from_slice(&eh);
            let mut previous_hash = [0u8; 32]; previous_hash.copy_from_slice(&ph);
            let mut session_id = [0u8; 16]; session_id.copy_from_slice(&sid);
            let mut machine_id_arr = [0u8; 32]; machine_id_arr.copy_from_slice(&mid);

            let timestamp = DateTime::parse_from_rfc3339(&ts)
                .map_err(|e| VaultError::Audit(format!("Ongeldig timestamp: {}", e)))?
                .with_timezone(&Utc);
            let event: AuditEvent = serde_json::from_str(&ej)
                .map_err(|e| VaultError::Audit(format!("Event deserialisatie: {}", e)))?;

            entries.push(AuditEntry {
                entry_hash,
                previous_hash,
                timestamp,
                event,
                session_id,
                machine_id: machine_id_arr,
                sequence_number: sq as u64,
            });
        }
        Ok(entries)
    }

    pub fn rate_limit_stats(&self) -> (u64, u64) {
        let rl = self.rate_limit.lock();
        (rl.events_in_window, rl.events_dropped_total)
    }

    pub fn database_size_bytes(&self) -> VaultResult<u64> {
        let db = self.db.lock();
        let pc: i64 = db.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap_or(0);
        let ps: i64 = db.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap_or(4096);
        Ok((pc * ps) as u64)
    }

    fn event_type_str(event: &AuditEvent) -> &'static str {
        match event {
            AuditEvent::VaultInitialized { .. } => "VaultInitialized",
            AuditEvent::VaultUnlocked { .. } => "VaultUnlocked",
            AuditEvent::VaultLocked { .. } => "VaultLocked",
            AuditEvent::TpmUnsealAttempt { .. } => "TpmUnsealAttempt",
            AuditEvent::TpmPcrMismatch { .. } => "TpmPcrMismatch",
            AuditEvent::TpmCounterValidationFailed { .. } => "TpmCounterValidationFailed",
            AuditEvent::TpmCounterIncremented { .. } => "TpmCounterIncremented",
            AuditEvent::KeyRotation { .. } => "KeyRotation",
            AuditEvent::ShamirSharesGenerated { .. } => "ShamirSharesGenerated",
            AuditEvent::ShamirSharesCombined { .. } => "ShamirSharesCombined",
            AuditEvent::RecoveryInitiated { .. } => "RecoveryInitiated",
            AuditEvent::RecoveryCompleted { .. } => "RecoveryCompleted",
            AuditEvent::TpmProvisioned { .. } => "TpmProvisioned",
            AuditEvent::TpmError { .. } => "TpmError",
            AuditEvent::FailedUnlockAttempt { .. } => "FailedUnlockAttempt",
            AuditEvent::RateLimitExceeded { .. } => "RateLimitExceeded",
            AuditEvent::ConfigurationChanged { .. } => "ConfigurationChanged",
            AuditEvent::UnauthorizedAccessAttempt { .. } => "UnauthorizedAccessAttempt",
            AuditEvent::ServiceStarted { .. } => "ServiceStarted",
            AuditEvent::ServiceStopped { .. } => "ServiceStopped",
            AuditEvent::AuditRateLimited { .. } => "AuditRateLimited",
        }
    }
}
