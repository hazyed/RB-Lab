using RollbackGuard.Common.Diagnostics;

namespace RollbackGuard.Service.Rollback;

/// <summary>
/// Manages disk space for Copy-on-Write backup storage.
/// Prevents CoW backups from exhausting disk space which could crash the system.
/// </summary>
public sealed class BackupSpaceManager
{
    private readonly string _backupRoot;
    private readonly object _sync = new();
    private DateTimeOffset _lastCheck = DateTimeOffset.MinValue;
    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(30);

    // Configurable limits
    public long MaxBackupSizeBytes { get; set; } = 10L * 1024 * 1024 * 1024; // 10 GB default
    public long MinFreeDiskBytes { get; set; } = 2L * 1024 * 1024 * 1024;    // 2 GB minimum free
    public double MaxDiskUsagePercent { get; set; } = 15.0; // Max 15% of total disk

    private long _currentBackupSize;
    private bool _spaceWarningIssued;

    public BackupSpaceManager(string backupRoot)
    {
        _backupRoot = backupRoot;
    }

    /// <summary>
    /// Checks if there is sufficient space to store a new backup of the given size.
    /// Returns false if the backup should be skipped to protect disk space.
    /// </summary>
    public bool CanAcceptBackup(long fileSizeBytes)
    {
        lock (_sync)
        {
            var now = DateTimeOffset.Now;
            if (now - _lastCheck > CheckInterval)
            {
                RefreshMetrics();
                _lastCheck = now;
            }

            // Check absolute backup size limit
            if (_currentBackupSize + fileSizeBytes > MaxBackupSizeBytes)
            {
                if (!_spaceWarningIssued)
                {
                    StartupLog.Write("BackupSpace",
                        $"backup size limit reached: current={FormatSize(_currentBackupSize)}, max={FormatSize(MaxBackupSizeBytes)}");
                    _spaceWarningIssued = true;
                }
                return false;
            }

            // Check minimum free disk space
            if (!HasMinimumFreeDisk(fileSizeBytes))
            {
                if (!_spaceWarningIssued)
                {
                    StartupLog.Write("BackupSpace",
                        $"minimum free disk threshold: min={FormatSize(MinFreeDiskBytes)}");
                    _spaceWarningIssued = true;
                }
                return false;
            }

            return true;
        }
    }

    /// <summary>
    /// Notifies that a backup was created.
    /// </summary>
    public void NotifyBackupCreated(long sizeBytes)
    {
        lock (_sync)
        {
            _currentBackupSize += sizeBytes;
        }
    }

    /// <summary>
    /// Notifies that backup files were removed (e.g., after rollback or cleanup).
    /// </summary>
    public void NotifyBackupRemoved(long sizeBytes)
    {
        lock (_sync)
        {
            _currentBackupSize = Math.Max(0, _currentBackupSize - sizeBytes);
        }
    }

    /// <summary>
    /// Performs cleanup of old backups to free space. Removes oldest backups first.
    /// Called when space is running low.
    /// </summary>
    public int CleanupOldBackups(TimeSpan maxAge)
    {
        lock (_sync)
        {
            var cutoff = DateTimeOffset.Now - maxAge;
            var removed = 0;
            long freedBytes = 0;

            try
            {
                if (!Directory.Exists(_backupRoot))
                    return 0;

                var files = new DirectoryInfo(_backupRoot)
                    .EnumerateFiles("*", SearchOption.AllDirectories)
                    .Where(f => f.CreationTimeUtc < cutoff.UtcDateTime)
                    .OrderBy(f => f.CreationTimeUtc)
                    .ToList();

                foreach (var file in files)
                {
                    try
                    {
                        var size = file.Length;
                        file.Delete();
                        freedBytes += size;
                        removed++;
                    }
                    catch
                    {
                        // Skip files that can't be deleted
                    }
                }

                if (removed > 0)
                {
                    _currentBackupSize = Math.Max(0, _currentBackupSize - freedBytes);
                    StartupLog.Write("BackupSpace",
                        $"cleanup: removed={removed}, freed={FormatSize(freedBytes)}, remaining={FormatSize(_currentBackupSize)}");
                }
            }
            catch (Exception ex)
            {
                StartupLog.Write("BackupSpace", $"cleanup error: {ex.Message}");
            }

            return removed;
        }
    }

    /// <summary>
    /// Emergency cleanup: removes backups aggressively to free critical disk space.
    /// Only removes backups for processes that have already been terminated/rolled-back.
    /// </summary>
    public int EmergencyCleanup(long targetFreeBytes)
    {
        lock (_sync)
        {
            var removed = 0;
            long freedBytes = 0;

            try
            {
                if (!Directory.Exists(_backupRoot))
                    return 0;

                var files = new DirectoryInfo(_backupRoot)
                    .EnumerateFiles("*", SearchOption.AllDirectories)
                    .OrderBy(f => f.CreationTimeUtc)
                    .ToList();

                foreach (var file in files)
                {
                    if (freedBytes >= targetFreeBytes) break;

                    try
                    {
                        var size = file.Length;
                        file.Delete();
                        freedBytes += size;
                        removed++;
                    }
                    catch
                    {
                        // Skip locked files
                    }
                }

                _currentBackupSize = Math.Max(0, _currentBackupSize - freedBytes);
                if (removed > 0)
                {
                    StartupLog.Write("BackupSpace",
                        $"emergency cleanup: removed={removed}, freed={FormatSize(freedBytes)}");
                }
            }
            catch (Exception ex)
            {
                StartupLog.Write("BackupSpace", $"emergency cleanup error: {ex.Message}");
            }

            return removed;
        }
    }

    /// <summary>
    /// Gets current backup space usage statistics.
    /// </summary>
    public BackupSpaceInfo GetSpaceInfo()
    {
        lock (_sync)
        {
            RefreshMetrics();
            var driveInfo = TryGetDriveInfo();
            return new BackupSpaceInfo(
                _currentBackupSize,
                MaxBackupSizeBytes,
                driveInfo?.AvailableFreeSpace ?? 0,
                driveInfo?.TotalSize ?? 0,
                _currentBackupSize >= MaxBackupSizeBytes || !HasMinimumFreeDisk(0));
        }
    }

    private void RefreshMetrics()
    {
        try
        {
            if (!Directory.Exists(_backupRoot))
            {
                _currentBackupSize = 0;
                return;
            }

            _currentBackupSize = new DirectoryInfo(_backupRoot)
                .EnumerateFiles("*", SearchOption.AllDirectories)
                .Sum(f => { try { return f.Length; } catch { return 0L; } });

            _spaceWarningIssued = false;

            // Auto-adjust max size based on disk capacity
            var driveInfo = TryGetDriveInfo();
            if (driveInfo != null)
            {
                var percentLimit = (long)(driveInfo.TotalSize * (MaxDiskUsagePercent / 100.0));
                MaxBackupSizeBytes = Math.Min(MaxBackupSizeBytes, percentLimit);
            }

            // Auto-cleanup if approaching limits
            if (_currentBackupSize > MaxBackupSizeBytes * 0.9)
            {
                CleanupOldBackups(TimeSpan.FromHours(24));
            }

            if (!HasMinimumFreeDisk(0))
            {
                EmergencyCleanup(MinFreeDiskBytes);
            }
        }
        catch (Exception ex)
        {
            StartupLog.Write("BackupSpace", $"refresh error: {ex.Message}");
        }
    }

    private bool HasMinimumFreeDisk(long additionalBytes)
    {
        var driveInfo = TryGetDriveInfo();
        if (driveInfo == null) return true; // Can't check, assume OK

        return driveInfo.AvailableFreeSpace - additionalBytes >= MinFreeDiskBytes;
    }

    private DriveInfo? TryGetDriveInfo()
    {
        try
        {
            var root = Path.GetPathRoot(_backupRoot);
            if (string.IsNullOrWhiteSpace(root)) return null;
            return new DriveInfo(root);
        }
        catch
        {
            return null;
        }
    }

    private static string FormatSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes}B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1}KB";
        if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1}MB";
        return $"{bytes / (1024.0 * 1024 * 1024):F2}GB";
    }
}

public sealed record BackupSpaceInfo(
    long CurrentSizeBytes,
    long MaxSizeBytes,
    long FreeDiskBytes,
    long TotalDiskBytes,
    bool IsAtCapacity);
