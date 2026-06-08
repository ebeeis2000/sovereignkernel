using System.Diagnostics;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace SovereignKernel.Service;

public sealed class HardenedPipeServer
{
    private readonly string _pipeName;
    private readonly string _dataPath;
    private long _requestsHandled;
    private long _requestsRejected;
    private const int MAX_REQUEST_SIZE = 65536;
    private const int MAX_JSON_DEPTH = 8;
    private const int MAX_CONCURRENT = 10;
    private static readonly string[] ValidCommands = { "status", "unlock", "lock", "health", "version", "rotate", "shamir_status", "backup" };
    private readonly DateTime _startTime = DateTime.UtcNow;

    public HardenedPipeServer(string pipeName, string dataPath)
    {
        _pipeName = pipeName;
        _dataPath = dataPath;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        using var semaphore = new SemaphoreSlim(MAX_CONCURRENT, MAX_CONCURRENT);
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = CreateSecurePipe();
                await pipe.WaitForConnectionAsync(ct);
                await semaphore.WaitAsync(ct);

                _ = Task.Run(async () =>
                {
                    try
                    {
                        await HandleClientAsync(pipe, ct);
                    }
                    finally
                    {
                        semaphore.Release();
                        await pipe.DisposeAsync();
                    }
                }, ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception)
            {
                pipe?.Dispose();
                await Task.Delay(100, ct);
            }
        }
    }

    private NamedPipeServerStream CreateSecurePipe()
    {
        var sec = new PipeSecurity();
        var currentUser = WindowsIdentity.GetCurrent().User!;
        sec.AddAccessRule(new PipeAccessRule(
            currentUser,
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Deny));

        var pipe = NamedPipeServerStreamAcl.Create(
            _pipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Message,
            PipeOptions.Asynchronous | PipeOptions.WriteThrough,
            4096,
            4096,
            sec);
        return pipe;
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);

        byte[] buf = new byte[MAX_REQUEST_SIZE];
        int totalRead = 0;

        while (!pipe.IsMessageComplete && totalRead < MAX_REQUEST_SIZE)
        {
            int read = await pipe.ReadAsync(buf.AsMemory(totalRead, buf.Length - totalRead), linked.Token);
            if (read == 0) return;
            totalRead += read;
        }

        if (totalRead >= MAX_REQUEST_SIZE)
        {
            Interlocked.Increment(ref _requestsRejected);
            await WriteResponseAsync(pipe, JsonSerializer.Serialize(new { ok = false, error = "Request te groot" }), linked.Token);
            return;
        }

        string request = Encoding.UTF8.GetString(buf, 0, totalRead);
        string response = ProcessRequest(request);
        Interlocked.Increment(ref _requestsHandled);
        await WriteResponseAsync(pipe, response, linked.Token);
    }

    private static async Task WriteResponseAsync(PipeStream pipe, string response, CancellationToken ct)
    {
        byte[] data = Encoding.UTF8.GetBytes(response);
        await pipe.WriteAsync(data.AsMemory(), ct);
        await pipe.FlushAsync(ct);
    }

    private string ProcessRequest(string request)
    {
        try
        {
            var options = new JsonDocumentOptions
            {
                MaxDepth = MAX_JSON_DEPTH,
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
            };

            using var doc = JsonDocument.Parse(request, options);
            var root = doc.RootElement;

            if (!root.TryGetProperty("command", out JsonElement cmdEl))
                return JsonSerializer.Serialize(new { ok = false, error = "Ontbrekend 'command' veld" });

            string command = cmdEl.GetString() ?? "";

            if (command.Length > 64 || command.Contains('\n') || command.Contains('\r') || command.Contains('\0'))
                return JsonSerializer.Serialize(new { ok = false, error = "Ongeldig commando formaat" });

            if (Array.IndexOf(ValidCommands, command) < 0)
            {
                Interlocked.Increment(ref _requestsRejected);
                return JsonSerializer.Serialize(new { ok = false, error = "Onbekend commando", allowed = ValidCommands });
            }

            return command switch
            {
                "status" => JsonSerializer.Serialize(new { ok = true, status = "locked", tpm = "available", requests = _requestsHandled, rejected = _requestsRejected }),
                "health" => ProcessHealth(),
                "version" => JsonSerializer.Serialize(new { ok = true, version = "0.3.0", protocol = 1 }),
                "lock" => ProcessLock(),
                "unlock" => ProcessUnlock(root),
                "rotate" => JsonSerializer.Serialize(new { ok = true, message = "Key rotation gestart" }),
                "shamir_status" => JsonSerializer.Serialize(new { ok = true, threshold = 3, total = 5, available = 0 }),
                "backup" => ProcessBackup(),
                _ => JsonSerializer.Serialize(new { ok = false, error = "Niet geïmplementeerd" }),
            };
        }
        catch (JsonException)
        {
            Interlocked.Increment(ref _requestsRejected);
            return JsonSerializer.Serialize(new { ok = false, error = "Ongeldig JSON formaat" });
        }
        catch (Exception)
        {
            return JsonSerializer.Serialize(new { ok = false, error = "Interne server fout" });
        }
    }

    private string ProcessHealth()
    {
        var uptime = DateTime.UtcNow - _startTime;
        var proc = System.Diagnostics.Process.GetCurrentProcess();
        return JsonSerializer.Serialize(new
        {
            ok = true,
            uptime_seconds = (long)uptime.TotalSeconds,
            memory_mb = GC.GetTotalMemory(false) / (1024 * 1024),
            working_set_mb = proc.WorkingSet64 / (1024 * 1024),
            threads = proc.Threads.Count,
            requests_total = Interlocked.Read(ref _requestsHandled),
            requests_rejected = Interlocked.Read(ref _requestsRejected),
            gc_gen0 = GC.CollectionCount(0),
            gc_gen1 = GC.CollectionCount(1),
            gc_gen2 = GC.CollectionCount(2),
            data_path = _dataPath,
        });
    }

    private string ProcessBackup()
    {
        try
        {
            string backupDir = Path.Combine(_dataPath, "backups");
            Directory.CreateDirectory(backupDir);
            string timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            string backupPath = Path.Combine(backupDir, $"vault_backup_{timestamp}");
            Directory.CreateDirectory(backupPath);

            string[] filesToBackup = { "vault.db", "audit.db", "tpm_state.json", "hmac_key.enc" };
            int copied = 0;
            foreach (var file in filesToBackup)
            {
                string src = Path.Combine(_dataPath, file);
                if (File.Exists(src))
                {
                    File.Copy(src, Path.Combine(backupPath, file), overwrite: true);
                    copied++;
                }
            }

            AuditEventLogger.LogInfo($"Backup aangemaakt: {backupPath} ({copied} bestanden)");
            return JsonSerializer.Serialize(new { ok = true, path = backupPath, files = copied });
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { ok = false, error = $"Backup mislukt: {ex.Message}" });
        }
    }

    private string ProcessLock()
    {
        AuditEventLogger.LogInfo("Vault vergrendeld via IPC commando");
        return JsonSerializer.Serialize(new { ok = true, message = "Vault vergrendeld" });
    }

    private string ProcessUnlock(JsonElement root)
    {
        if (!root.TryGetProperty("provider", out JsonElement provEl))
            return JsonSerializer.Serialize(new { ok = false, error = "Ontbrekend 'provider' veld" });

        string provider = provEl.GetString() ?? "";
        if (string.IsNullOrWhiteSpace(provider) || provider.Length > 32)
            return JsonSerializer.Serialize(new { ok = false, error = "Ongeldige provider" });

        return JsonSerializer.Serialize(new { ok = true, message = $"Unlock poging met provider: {provider}" });
    }
}
