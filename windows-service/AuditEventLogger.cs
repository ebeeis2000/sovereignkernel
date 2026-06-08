using System.Diagnostics;

namespace SovereignKernel.Service;

public sealed class AuditEventLogger
{
    private const string SOURCE = "SovereignKernelVault";
    private const string LOG_NAME = "Application";
    private static bool _sourceChecked;

    private static void EnsureSource()
    {
        if (_sourceChecked) return;
        try
        {
            if (!EventLog.SourceExists(SOURCE))
                EventLog.CreateEventSource(SOURCE, LOG_NAME);
        }
        catch { }
        _sourceChecked = true;
    }

    public static void LogSecurity(string message, int eventId = 5000)
    {
        EnsureSource();
        try { EventLog.WriteEntry(SOURCE, message, EventLogEntryType.Warning, eventId); }
        catch { }
    }

    public static void LogInfo(string message, int eventId = 1000)
    {
        EnsureSource();
        try { EventLog.WriteEntry(SOURCE, message, EventLogEntryType.Information, eventId); }
        catch { }
    }

    public static void LogError(string message, int eventId = 9000)
    {
        EnsureSource();
        try { EventLog.WriteEntry(SOURCE, message, EventLogEntryType.Error, eventId); }
        catch { }
    }

    public static void LogUnlockAttempt(string provider, bool success)
    {
        string msg = success
            ? $"Vault ontgrendeld via provider: {provider}"
            : $"Mislukte ontgrendelpoging via provider: {provider}";
        int id = success ? 2001 : 2002;
        var type = success ? EventLogEntryType.Information : EventLogEntryType.Warning;
        EnsureSource();
        try { EventLog.WriteEntry(SOURCE, msg, type, id); }
        catch { }
    }

    public static void LogServiceLifecycle(string action)
    {
        LogInfo($"Service lifecycle: {action}", 1100);
    }

    public static void LogRateLimitTriggered(string context)
    {
        LogSecurity($"Rate limit bereikt: {context}", 5001);
    }

    public static void LogIntegrityViolation(string details)
    {
        LogError($"Integriteitsschending: {details}", 9001);
    }
}
