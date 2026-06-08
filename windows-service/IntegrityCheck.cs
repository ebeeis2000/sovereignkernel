using System.Diagnostics;
using System.Security.Cryptography;

namespace SovereignKernel.Service;

public static class IntegrityCheck
{
    private static readonly string ExpectedHashFile = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory, "integrity.sha256");

    public static bool VerifySelfIntegrity()
    {
        try
        {
            string exePath = Process.GetCurrentProcess().MainModule?.FileName
                ?? throw new InvalidOperationException("Kan eigen pad niet bepalen");

            byte[] currentHash = ComputeFileHash(exePath);
            string currentHex = Convert.ToHexString(currentHash).ToLowerInvariant();

            if (!File.Exists(ExpectedHashFile))
            {
                File.WriteAllText(ExpectedHashFile, currentHex);
                EventLog.WriteEntry("SovereignKernelVault",
                    "Integriteits-baseline opgeslagen",
                    EventLogEntryType.Information, 1001);
                return true;
            }

            string expectedHex = File.ReadAllText(ExpectedHashFile).Trim().ToLowerInvariant();

            if (!CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(currentHex),
                System.Text.Encoding.ASCII.GetBytes(expectedHex)))
            {
                EventLog.WriteEntry("SovereignKernelVault",
                    $"INTEGRITEITSSCHENDING: Verwacht={expectedHex}, Huidig={currentHex}",
                    EventLogEntryType.Error, 9001);
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            EventLog.WriteEntry("SovereignKernelVault",
                $"Integriteitscontrole fout: {ex.Message}",
                EventLogEntryType.Warning, 9002);
            return true;
        }
    }

    public static void UpdateBaseline()
    {
        try
        {
            string exePath = Process.GetCurrentProcess().MainModule?.FileName
                ?? throw new InvalidOperationException("Kan eigen pad niet bepalen");
            byte[] currentHash = ComputeFileHash(exePath);
            string currentHex = Convert.ToHexString(currentHash).ToLowerInvariant();
            File.WriteAllText(ExpectedHashFile, currentHex);
        }
        catch (Exception ex)
        {
            EventLog.WriteEntry("SovereignKernelVault",
                $"Baseline update mislukt: {ex.Message}",
                EventLogEntryType.Warning, 9003);
        }
    }

    private static byte[] ComputeFileHash(string path)
    {
        using var stream = File.OpenRead(path);
        return SHA256.HashData(stream);
    }
}
