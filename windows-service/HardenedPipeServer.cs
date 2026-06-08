using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace SovereignKernel.Service;

public sealed class HardenedPipeServer
{
    private readonly string _pipeName;
    private readonly string _dataPath;
    private long _requestsHandled;
    private readonly SemaphoreSlim _concurrencyLimiter = new(10, 10);

    public HardenedPipeServer(string pipeName, string dataPath)
    {
        _pipeName = pipeName;
        _dataPath = dataPath;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var ps = CreateSecurePipe();
                await ps.WaitForConnectionAsync(ct);

                _ = Task.Run(async () =>
                {
                    if (!await _concurrencyLimiter.WaitAsync(TimeSpan.FromSeconds(5), ct))
                    {
                        ps.Dispose();
                        return;
                    }

                    try
                    {
                        await HandleClientAsync(ps, ct);
                    }
                    finally
                    {
                        _concurrencyLimiter.Release();
                        ps.Dispose();
                    }
                }, ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[PIPE] Fout: {ex.Message}");
                await Task.Delay(1000, ct);
            }
        }
    }

    private NamedPipeServerStream CreateSecurePipe()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            _pipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Message,
            PipeOptions.Asynchronous | PipeOptions.WriteThrough,
            4096, 4096,
            security);
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);

        try
        {
            var buffer = new byte[4096];
            int read = await pipe.ReadAsync(buffer, linked.Token);
            if (read == 0) return;

            Interlocked.Increment(ref _requestsHandled);
            var request = Encoding.UTF8.GetString(buffer, 0, read);
            var response = ProcessRequest(request);
            var responseBytes = Encoding.UTF8.GetBytes(response);
            await pipe.WriteAsync(responseBytes, linked.Token);
            await pipe.FlushAsync(linked.Token);
        }
        catch (OperationCanceledException) { }
        catch (IOException) { }
    }

    private string ProcessRequest(string request)
    {
        try
        {
            using var doc = JsonDocument.Parse(request);
            var root = doc.RootElement;
            string command = root.GetProperty("command").GetString() ?? "";

            return command switch
            {
                "status" => JsonSerializer.Serialize(new { ok = true, status = "locked", tpm = "available", requests = _requestsHandled }),
                "unlock" => JsonSerializer.Serialize(new { ok = true, message = "Vault unlock initiated" }),
                "lock" => JsonSerializer.Serialize(new { ok = true, message = "Vault locked" }),
                "health" => JsonSerializer.Serialize(new { ok = true, uptime = Environment.TickCount64 / 1000, memory = GC.GetTotalMemory(false) }),
                _ => JsonSerializer.Serialize(new { ok = false, error = $"Onbekend commando: {command}" }),
            };
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { ok = false, error = ex.Message });
        }
    }
}
