using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ServiceProcess;

namespace SovereignKernel.Service;

public abstract class WindowsServiceBase : ServiceBase
{
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool SetProcessWorkingSetSize(IntPtr h, IntPtr min, IntPtr max);

    private CancellationTokenSource? _cts;
    private Task? _mainTask;
    private readonly int _stopTimeout;
    private volatile bool _running;

    protected WindowsServiceBase(string name, int stopTimeout = 30)
    {
        ServiceName = name;
        _stopTimeout = stopTimeout;
        CanStop = true;
        CanShutdown = true;
        CanHandlePowerEvent = true;
        AutoLog = true;
    }

    protected override void OnStart(string[] args)
    {
        _running = true;
        _cts = new CancellationTokenSource();

        try { SetProcessWorkingSetSize(GetCurrentProcess(), new IntPtr(-1), new IntPtr(-1)); } catch { }

        _mainTask = Task.Run(async () =>
        {
            while (_running && !_cts.Token.IsCancellationRequested)
            {
                try
                {
                    await RunAsync(_cts.Token);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    EventLog.WriteEntry(ServiceName, $"Crash: {ex.Message}", EventLogEntryType.Error, 9000);
                    await Task.Delay(5000, _cts.Token);
                }
            }
        });

        OnServiceStarted();
    }

    protected override void OnStop() => Shutdown(TimeSpan.FromSeconds(_stopTimeout)).GetAwaiter().GetResult();
    protected override void OnShutdown() { Shutdown(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult(); base.OnShutdown(); }

    protected abstract Task RunAsync(CancellationToken ct);
    protected virtual void OnServiceStarted() { }
    protected virtual void OnServiceStopped() { }

    private async Task Shutdown(TimeSpan timeout)
    {
        _running = false;
        _cts?.Cancel();
        if (_mainTask != null)
        {
            var completed = await Task.WhenAny(_mainTask, Task.Delay(timeout));
            if (completed != _mainTask)
                EventLog.WriteEntry(ServiceName, "Stop timeout", EventLogEntryType.Warning, 4000);
        }
        OnServiceStopped();
        _cts?.Dispose();
        _cts = null;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _cts?.Dispose();
        base.Dispose(disposing);
    }
}
