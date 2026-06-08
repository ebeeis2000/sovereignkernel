using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using SovereignKernel.Service;

namespace SovereignKernel;

internal static class Program
{
    [DllImport("kernel32.dll")]
    private static extern bool SetConsoleCtrlHandler(ConsoleHandler h, bool add);
    private delegate bool ConsoleHandler(CtrlType t);
    private enum CtrlType : uint { CTRL_C = 0, CTRL_BREAK = 1, CTRL_CLOSE = 2, CTRL_LOGOFF = 5, CTRL_SHUTDOWN = 6 }

    private static Tpm2VaultService? _svc;
    private static readonly ManualResetEventSlim _exit = new(false);

    internal static int Main(string[] args)
    {
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            EventLog.WriteEntry("SovereignKernelVault", $"Unhandled: {(e.ExceptionObject as Exception)?.Message}", EventLogEntryType.Error, 9999);

        string commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (string.IsNullOrEmpty(commonAppData)) commonAppData = @"C:\ProgramData";

        string logPath = commonAppData + @"\SovereignKernel\Logs";
        string dataPath = commonAppData + @"\SovereignKernel\Data";
        bool tpmEnabled = true;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "--service": return RunService(logPath, dataPath, tpmEnabled);
                case "--console": return RunConsole(logPath, dataPath, tpmEnabled);
                case "--log-path" when i + 1 < args.Length: logPath = args[++i]; break;
                case "--data-path" when i + 1 < args.Length: dataPath = args[++i]; break;
                case "--no-tpm": tpmEnabled = false; break;
            }
        }

        return args.Length == 0 || Environment.UserInteractive
            ? RunConsole(logPath, dataPath, tpmEnabled)
            : RunService(logPath, dataPath, tpmEnabled);
    }

    private static int RunService(string logPath, string dataPath, bool tpm)
    {
        _svc = new Tpm2VaultService(logPath, dataPath, tpm);
        ServiceBase.Run(_svc);
        return 0;
    }

    private static int RunConsole(string logPath, string dataPath, bool tpm)
    {
        SetConsoleCtrlHandler(_ => { _exit.Set(); return true; }, true);

        string version = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyFileVersionAttribute>()?.Version ?? "0.3.0";
        Console.WriteLine($"SovereignKernel Vault v{version}");
        Console.WriteLine($"Data: {dataPath}");
        Console.WriteLine($"Logs: {logPath}");
        Console.WriteLine($"TPM: {(tpm ? "Enabled" : "Disabled")}");
        Console.WriteLine("Druk Ctrl+C om te stoppen...");

        try
        {
            _svc = new Tpm2VaultService(logPath, dataPath, tpm);
            typeof(ServiceBase)
                .GetMethod("OnStart", BindingFlags.NonPublic | BindingFlags.Instance, null, new[] { typeof(string[]) }, null)
                ?.Invoke(_svc, new object[] { Array.Empty<string>() });

            _exit.Wait();

            typeof(ServiceBase)
                .GetMethod("OnStop", BindingFlags.NonPublic | BindingFlags.Instance)
                ?.Invoke(_svc, null);

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FATAL: {ex.Message}");
            return 1;
        }
    }
}
