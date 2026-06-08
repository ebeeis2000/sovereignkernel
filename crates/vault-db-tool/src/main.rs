use clap::{Parser, Subcommand};
use std::path::PathBuf;
use vault_audit::AuditLogger;
use vault_core::{DatabaseKey, needs_migration, migrate_to_encrypted};

#[derive(Parser)]
#[command(name = "vault-db-tool", version, about = "SovereignKernel Database Management Tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verificeer de integriteit van de audit chain
    VerifyAudit {
        #[arg(short, long)]
        db_path: PathBuf,
    },
    /// Migreer een plaintext database naar SQLCipher
    Migrate {
        #[arg(short, long)]
        db_path: PathBuf,
        #[arg(short, long)]
        key_hex: String,
    },
    /// Controleer of een database migratie nodig heeft
    CheckMigration {
        #[arg(short, long)]
        db_path: PathBuf,
    },
    /// Toon database statistieken
    Stats {
        #[arg(short, long)]
        db_path: PathBuf,
    },
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::VerifyAudit { db_path } => verify_audit(&db_path),
        Commands::Migrate { db_path, key_hex } => migrate_db(&db_path, &key_hex),
        Commands::CheckMigration { db_path } => check_migration(&db_path),
        Commands::Stats { db_path } => show_stats(&db_path),
    };

    if let Err(e) = result {
        eprintln!("FOUT: {}", e);
        std::process::exit(1);
    }
}

fn verify_audit(db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let path_str = db_path.to_str().ok_or("Ongeldig pad")?;
    let logger = AuditLogger::new(path_str, [0u8; 32], None, None)?;
    let result = logger.verify_chain()?;

    println!("=== Audit Chain Verificatie ===");
    println!("Totaal entries: {}", result.total_entries);
    println!("Integriteit: {:.2}%", result.integrity_percentage());
    println!("Status: {}", if result.is_intact { "INTACT" } else { "BESCHADIGD" });

    if !result.tampered_entries.is_empty() {
        println!("\nBeschadigde entries:");
        for entry in &result.tampered_entries {
            println!("  Sequence {}: {}", entry.sequence_number, entry.reason);
        }
    }

    Ok(())
}

fn migrate_db(db_path: &PathBuf, key_hex: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key_bytes = hex::decode(key_hex)?;
    if key_bytes.len() != 32 {
        return Err("Key moet 32 bytes (64 hex karakters) zijn".into());
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    let key = DatabaseKey::from_raw(key_arr);

    let result = migrate_to_encrypted(db_path, &key)?;
    println!("Migratie succesvol:");
    println!("  Tabellen: {}", result.tables_migrated);
    println!("  Rijen: {}", result.rows_migrated);
    println!("  Encrypted: {}", result.encrypted_path.display());
    Ok(())
}

fn check_migration(db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let needs = needs_migration(db_path)?;
    println!("Database: {}", db_path.display());
    println!("Migratie nodig: {}", if needs { "JA" } else { "NEE" });
    Ok(())
}

fn show_stats(db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let path_str = db_path.to_str().ok_or("Ongeldig pad")?;
    let logger = AuditLogger::new(path_str, [0u8; 32], None, None)?;
    let size = logger.database_size_bytes()?;
    let (events_window, events_dropped) = logger.rate_limit_stats();

    println!("=== Database Statistieken ===");
    println!("Pad: {}", db_path.display());
    println!("Grootte: {} bytes ({:.2} MB)", size, size as f64 / 1_048_576.0);
    println!("Events in huidig window: {}", events_window);
    println!("Totaal gedropt: {}", events_dropped);
    Ok(())
}
