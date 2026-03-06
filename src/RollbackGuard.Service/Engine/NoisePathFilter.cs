using RollbackGuard.Common.Models;

namespace RollbackGuard.Service.Engine;

public static class NoisePathFilter
{
    private static readonly string[] DirectoryMarkers =
    [
        @"\temp\",
        @"\tmp\",
        @"\cache\",
        @"\webcache\",
        @"\code cache\",
        @"\gpucache\",
        @"\logs\",
        @"\log\",
        @"\service worker\database\",
        @"\crashpad\"
    ];

    private static readonly string[] FileNameMarkers =
    [
        "log",
        "log.old",
        "journal"
    ];

    private static readonly string[] ExtensionMarkers =
    [
        ".log",
        ".tmp",
        ".temp",
        ".etl",
        ".cache",
        ".journal",
        ".wal",
        ".ldb",
        ".jfm",
        ".sqlite-wal",
        ".sqlite-shm"
    ];

    public static bool IsIgnorableFileEvent(TelemetryEvent evt)
    {
        if (evt.Kind is not (EventKind.FileWrite or EventKind.FileDelete or EventKind.FileRename or EventKind.FileCreate))
        {
            return false;
        }

        return IsIgnorablePath(evt.TargetPath) || IsIgnorablePath(evt.SourcePath);
    }

    public static bool IsIgnorablePath(string? rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath))
        {
            return false;
        }

        var path = Normalize(rawPath);
        foreach (var marker in DirectoryMarkers)
        {
            if (path.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        var fileName = Path.GetFileName(path);
        foreach (var marker in FileNameMarkers)
        {
            if (fileName.Equals(marker, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        foreach (var ext in ExtensionMarkers)
        {
            if (path.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string Normalize(string value)
    {
        var path = value.Trim().TrimEnd('\0').Replace('/', '\\');
        if (path.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
        {
            return path[4..];
        }

        if (path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
        {
            return path[4..];
        }

        return path;
    }
}
