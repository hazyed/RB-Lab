namespace RollbackGuard.Common.Diagnostics;

using RollbackGuard.Common.Runtime;

public static class StartupLog
{
    private static readonly object SyncRoot = new();
    private const long MaxLogBytes = 10 * 1024 * 1024; // 10 MB per log file

    public static void Write(string component, string message, Exception? ex = null)
    {
        Write(ResolveCategoryFromComponent(component), component, message, ex);
    }

    public static void WriteDetection(string component, string message, Exception? ex = null)
    {
        Write(LogCategory.Detection, component, message, ex);
    }

    public static void WriteBackup(string component, string message, Exception? ex = null)
    {
        Write(LogCategory.Backup, component, message, ex);
    }

    public static void WriteRollback(string component, string message, Exception? ex = null)
    {
        Write(LogCategory.Rollback, component, message, ex);
    }

    public static void WriteOther(string component, string message, Exception? ex = null)
    {
        Write(LogCategory.Other, component, message, ex);
    }

    public static void WriteSign(string component, string message, Exception? ex = null)
    {
        Write(LogCategory.Sign, component, message, ex);
    }

    public static string GetLogPath(LogCategory category)
    {
        return category switch
        {
            LogCategory.Detection => RuntimePaths.DetectionLogPath,
            LogCategory.Backup => RuntimePaths.BackupLogPath,
            LogCategory.Rollback => RuntimePaths.RollbackLogPath,
            LogCategory.Sign => RuntimePaths.SignLogPath,
            _ => RuntimePaths.OtherLogPath
        };
    }

    private static void Write(LogCategory category, string component, string message, Exception? ex)
    {
        _ = category;
        _ = component;
        _ = message;
        _ = ex;
        // disabled: no file logging to logs directory
    }

    private static void RotateIfNeeded(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return;
            }

            var info = new FileInfo(path);
            if (info.Length < MaxLogBytes)
            {
                return;
            }

            var archive = path + ".1";
            if (File.Exists(archive))
            {
                File.Delete(archive);
            }

            File.Move(path, archive);
        }
        catch
        {
            // rotation failure must not affect the main write
        }
    }

    private static LogCategory ResolveCategoryFromComponent(string component)
    {
        if (string.IsNullOrWhiteSpace(component))
        {
            return LogCategory.Other;
        }

        if (component.Equals("Rollback", StringComparison.OrdinalIgnoreCase))
        {
            return LogCategory.Rollback;
        }

        if (component.Equals("Backup", StringComparison.OrdinalIgnoreCase))
        {
            return LogCategory.Backup;
        }

        if (component.Equals("Detection", StringComparison.OrdinalIgnoreCase))
        {
            return LogCategory.Detection;
        }

        return LogCategory.Other;
    }
}

public enum LogCategory
{
    Detection = 1,
    Backup = 2,
    Rollback = 3,
    Other = 4,
    Sign = 5
}
