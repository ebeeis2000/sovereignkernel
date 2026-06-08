using System.Diagnostics;

namespace SovereignKernel.Service;

public sealed class GracefulShutdown
{
    private readonly string _dataPath;
    private readonly CancellationTokenSource _cts;
    private bool _isShutdown;

    public GracefulShutdown(string dataPath, CancellationTokenSource cts)
    {
        _dataPath = dataPath;
        _cts = cts;
    }

    public async Task ExecuteAsync()
    {
        if (_isShutdown) return;
        _isShutdown = true;

        AuditEventLogger.LogServiceLifecycle("Shutdown geïnitieerd");

        try
        {
            _cts.Cancel();
            await FlushStateAsync();
            await CreateShutdownBackupAsync();
            AuditEventLogger.LogServiceLifecycle("Shutdown voltooid");
        }
        catch (Exception ex)
        {
            AuditEventLogger.LogError($"Shutdown fout: {ex.Message}");
        }
    }

    private Task FlushStateAsync()
    {
        string journalPath = Path.Combine(_dataPath, "shutdown.journal");
        try
        {
            File.WriteAllText(journalPath, $"clean_shutdown={DateTime.UtcNow:O}");
        }
        catch (Exception ex)
        {
            AuditEventLogger.LogError($"Journal schrijven mislukt: {ex.Message}");
        }
        return Task.CompletedTask;
    }

    private Task CreateShutdownBackupAsync()
    {
        try
        {
            string backupDir = Path.Combine(_dataPath, "backups", "shutdown");
            Directory.CreateDirectory(backupDir);

            string[] criticalFiles = { "vault.db", "tpm_state.json", "hmac_key.enc" };
            foreach (var file in criticalFiles)
            {
                string src = Path.Combine(_dataPath, file);
                if (File.Exists(src))
                {
                    string dst = Path.Combine(backupDir, file);
                    File.Copy(src, dst, overwrite: true);
                }
            }
        }
        catch (Exception ex)
        {
            AuditEventLogger.LogError($"Shutdown backup mislukt: {ex.Message}");
        }
        return Task.CompletedTask;
    }

    public bool WasCleanShutdown()
    {
        string journalPath = Path.Combine(_dataPath, "shutdown.journal");
        if (!File.Exists(journalPath)) return false;

        try
        {
            string content = File.ReadAllText(journalPath);
            if (!content.StartsWith("clean_shutdown=")) return false;

            File.Delete(journalPath);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public void RecoverFromCrash()
    {
        AuditEventLogger.LogSecurity("Crash recovery gedetecteerd — vorige sessie niet netjes afgesloten", 5010);

        string backupDir = Path.Combine(_dataPath, "backups", "shutdown");
        if (!Directory.Exists(backupDir)) return;

        string[] criticalFiles = { "vault.db", "tpm_state.json" };
        foreach (var file in criticalFiles)
        {
            string backupFile = Path.Combine(backupDir, file);
            string targetFile = Path.Combine(_dataPath, file);
            if (File.Exists(backupFile) && !File.Exists(targetFile))
            {
                File.Copy(backupFile, targetFile);
                AuditEventLogger.LogInfo($"Hersteld vanuit shutdown backup: {file}");
            }
        }
    }
}
