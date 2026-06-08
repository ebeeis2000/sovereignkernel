using System.Diagnostics;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SovereignKernel.Service;

public sealed class Tpm2VaultService : WindowsServiceBase
{
    private readonly string _logPath;
    private readonly string _dataPath;
    private readonly bool _tpmEnabled;
    private HardenedPipeServer? _pipeServer;

    public Tpm2VaultService(string logPath, string dataPath, bool tpmEnabled)
        : base("SovereignKernelVault", 30)
    {
        _logPath = logPath;
        _dataPath = dataPath;
        _tpmEnabled = tpmEnabled;
    }

    protected override void OnServiceStarted()
    {
        Directory.CreateDirectory(_logPath);
        Directory.CreateDirectory(_dataPath);
        WriteLog("Service gestart");
        WriteLog($"TPM: {(_tpmEnabled ? "actief" : "uitgeschakeld")}");
    }

    protected override async Task RunAsync(CancellationToken ct)
    {
        _pipeServer = new HardenedPipeServer("SovereignKernelVault", _dataPath);
        await _pipeServer.RunAsync(ct);
    }

    protected override void OnServiceStopped()
    {
        WriteLog("Service gestopt");
    }

    private void WriteLog(string message)
    {
        try
        {
            string logFile = Path.Combine(_logPath, $"vault-{DateTime.Now:yyyy-MM-dd}.log");
            File.AppendAllText(logFile, $"[{DateTime.Now:HH:mm:ss.fff}] {message}{Environment.NewLine}");
        }
        catch { }
    }
}
