namespace SovereignKernel.Service;

public sealed class LogRotation
{
    private readonly string _logDir;
    private readonly long _maxFileSizeBytes;
    private readonly int _maxFiles;
    private StreamWriter? _currentWriter;
    private string _currentFilePath = "";
    private long _currentFileSize;
    private readonly object _lock = new();

    public LogRotation(string logDir, long maxFileSizeMb = 10, int maxFiles = 10)
    {
        _logDir = logDir;
        _maxFileSizeBytes = maxFileSizeMb * 1024 * 1024;
        _maxFiles = maxFiles;
        Directory.CreateDirectory(_logDir);
        OpenNewLogFile();
    }

    public void Write(string level, string message)
    {
        string line = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff}] [{level}] {message}";

        lock (_lock)
        {
            if (_currentFileSize + line.Length > _maxFileSizeBytes)
            {
                RotateLog();
            }

            _currentWriter?.WriteLine(line);
            _currentWriter?.Flush();
            _currentFileSize += line.Length + Environment.NewLine.Length;
        }
    }

    public void Info(string message) => Write("INFO", message);
    public void Warn(string message) => Write("WARN", message);
    public void Error(string message) => Write("ERROR", message);
    public void Security(string message) => Write("SECURITY", message);

    private void OpenNewLogFile()
    {
        string timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        _currentFilePath = Path.Combine(_logDir, $"vault_{timestamp}.log");
        _currentWriter = new StreamWriter(_currentFilePath, append: true) { AutoFlush = false };
        _currentFileSize = new FileInfo(_currentFilePath).Exists ? new FileInfo(_currentFilePath).Length : 0;
    }

    private void RotateLog()
    {
        _currentWriter?.Flush();
        _currentWriter?.Close();
        _currentWriter?.Dispose();
        PruneOldLogs();
        OpenNewLogFile();
    }

    private void PruneOldLogs()
    {
        try
        {
            var logFiles = Directory.GetFiles(_logDir, "vault_*.log")
                .OrderByDescending(f => f)
                .ToArray();

            if (logFiles.Length > _maxFiles)
            {
                foreach (var old in logFiles.Skip(_maxFiles))
                {
                    try { File.Delete(old); }
                    catch { }
                }
            }
        }
        catch { }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            _currentWriter?.Flush();
            _currentWriter?.Close();
            _currentWriter?.Dispose();
            _currentWriter = null;
        }
    }
}
