use std::path::PathBuf;
use vault_common::{VaultError, VaultResult};

pub struct RateLimiter {
    pool: r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
    max_attempts: u32,
    window_seconds: i64,
    lockout_seconds: i64,
}

impl RateLimiter {
    pub fn new(
        db_path: PathBuf,
        max_attempts: u32,
        window_seconds: u64,
        lockout_seconds: u64,
    ) -> VaultResult<Self> {
        let mgr = r2d2_sqlite::SqliteConnectionManager::file(&db_path);
        let pool = r2d2::Pool::builder()
            .min_idle(Some(2))
            .max_size(8)
            .build(mgr)
            .map_err(|e| VaultError::Storage(format!("RateLimiter pool: {}", e)))?;

        {
            let conn = pool.get().map_err(|e| VaultError::Storage(format!("Pool init: {}", e)))?;
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;
                 PRAGMA busy_timeout=5000;
                 CREATE TABLE IF NOT EXISTS rate_limit_attempts (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     timestamp INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS rate_limit_lockout (
                     key TEXT PRIMARY KEY,
                     locked_until INTEGER NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS idx_attempts_ts ON rate_limit_attempts(timestamp);",
            )
            .map_err(|e| VaultError::Storage(format!("RateLimiter schema: {}", e)))?;
        }

        Ok(Self {
            pool,
            max_attempts,
            window_seconds: window_seconds as i64,
            lockout_seconds: lockout_seconds as i64,
        })
    }

    pub fn check(&self) -> VaultResult<()> {
        let c = self.pool.get().map_err(|e| VaultError::Internal(format!("Pool: {}", e)))?;
        let max_retries = 3u64;
        let mut attempt = 0u64;
        loop {
            match c.execute("BEGIN IMMEDIATE", []) {
                Ok(_) => break,
                Err(e) if attempt < max_retries && e.to_string().contains("database is locked") => {
                    attempt += 1;
                    std::thread::sleep(std::time::Duration::from_millis(100 * attempt));
                    continue;
                }
                Err(e) => return Err(VaultError::Storage(format!("BEGIN IMMEDIATE: {}", e))),
            }
        }

        let r = self.check_inner(&c);
        match &r {
            Ok(()) => { c.execute("COMMIT", []).ok(); }
            Err(_) => { c.execute("ROLLBACK", []).ok(); }
        }
        r
    }

    fn check_inner(&self, c: &rusqlite::Connection) -> VaultResult<()> {
        let now = chrono::Utc::now().timestamp();

        let locked: bool = c
            .query_row(
                "SELECT locked_until > ?1 FROM rate_limit_lockout WHERE key='global'",
                [now],
                |r| r.get(0),
            )
            .unwrap_or(false);

        if locked {
            let until: i64 = c
                .query_row(
                    "SELECT locked_until FROM rate_limit_lockout WHERE key='global'",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(now + self.lockout_seconds);
            return Err(VaultError::RateLimited {
                retry_after_seconds: (until - now).max(0) as u64,
                remaining_attempts: 0,
            });
        }

        c.execute("DELETE FROM rate_limit_lockout WHERE key='global' AND locked_until <= ?1", [now]).ok();
        c.execute("DELETE FROM rate_limit_attempts WHERE timestamp < ?1", [now - self.window_seconds]).ok();

        let count: i64 = c
            .query_row("SELECT COUNT(*) FROM rate_limit_attempts", [], |r| r.get(0))
            .unwrap_or(0);

        if count >= self.max_attempts as i64 {
            c.execute(
                "INSERT OR REPLACE INTO rate_limit_lockout VALUES ('global', ?1)",
                [now + self.lockout_seconds],
            ).ok();
            return Err(VaultError::RateLimited {
                retry_after_seconds: self.lockout_seconds as u64,
                remaining_attempts: 0,
            });
        }

        c.execute("INSERT INTO rate_limit_attempts (timestamp) VALUES (?1)", [now]).ok();
        Ok(())
    }

    pub fn record_success(&self) -> VaultResult<()> {
        let c = self.pool.get().map_err(|e| VaultError::Internal(format!("Pool: {}", e)))?;
        c.execute_batch("DELETE FROM rate_limit_attempts; DELETE FROM rate_limit_lockout WHERE key='global';")
            .map_err(|e| VaultError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn remaining_attempts(&self) -> VaultResult<u32> {
        let c = self.pool.get().map_err(|e| VaultError::Internal(format!("Pool: {}", e)))?;
        let now = chrono::Utc::now().timestamp();
        let locked: bool = c
            .query_row(
                "SELECT locked_until > ?1 FROM rate_limit_lockout WHERE key='global'",
                [now],
                |r| r.get(0),
            )
            .unwrap_or(false);
        if locked { return Ok(0); }
        let count: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM rate_limit_attempts WHERE timestamp >= ?1",
                [now - self.window_seconds],
                |r| r.get(0),
            )
            .unwrap_or(0);
        Ok(self.max_attempts.saturating_sub(count as u32))
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            max_attempts: self.max_attempts,
            window_seconds: self.window_seconds,
            lockout_seconds: self.lockout_seconds,
        }
    }
}
