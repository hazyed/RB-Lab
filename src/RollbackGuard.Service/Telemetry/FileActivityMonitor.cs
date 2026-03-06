using System.Collections.Concurrent;
using System.Diagnostics;
using RollbackGuard.Service.Engine;
using RollbackGuard.Common.Models;
using RollbackGuard.Common.Runtime;

namespace RollbackGuard.Service.Telemetry;

public sealed class FileActivityMonitor : IDisposable
{
    private readonly PolicyConfig _policy;
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly ConcurrentQueue<TelemetryEvent> _queue = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentEventKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _attributionSync = new();
    private readonly HashSet<string> _allowList;
    private readonly HashSet<string> _terminationCandidates;
    private readonly List<string> _excludedRoots;
    private readonly FileProcessResolver _processResolver = new();
    private readonly TimeSpan _dedupeWindow = TimeSpan.FromMilliseconds(120);
    private readonly List<string> _monitoredRoots = [];
    private readonly List<string> _startupErrors = [];

    private DateTimeOffset _lastFallbackAttributionAt = DateTimeOffset.MinValue;
    private AttributionResult _lastFallbackAttribution = AttributionResult.Empty;

    public FileActivityMonitor(PolicyConfig policy)
    {
        _policy = policy;
        _allowList = new HashSet<string>(policy.AllowListProcesses.Select(NormalizeExeName), StringComparer.OrdinalIgnoreCase);
        _terminationCandidates = BuildTerminationCandidateSet(policy);
        _excludedRoots = BuildExcludedRoots();
        InitializeWatchers();
    }

    public int ActiveWatchers => _watchers.Count;

    public IReadOnlyList<string> MonitoredRoots => _monitoredRoots;

    public IReadOnlyList<string> StartupErrors => _startupErrors;

    public IReadOnlyList<TelemetryEvent> Drain(int maxCount)
    {
        var take = Math.Max(1, maxCount);
        var list = new List<TelemetryEvent>(take);
        while (list.Count < take && _queue.TryDequeue(out var item))
        {
            list.Add(item);
        }

        return list;
    }

    public void Dispose()
    {
        foreach (var watcher in _watchers)
        {
            watcher.Dispose();
        }

        _watchers.Clear();
    }

    private void InitializeWatchers()
    {
        foreach (var root in _policy.ProtectedFolders.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
            {
                continue;
            }

            try
            {
                var watcher = new FileSystemWatcher(root)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName |
                                   NotifyFilters.DirectoryName |
                                   NotifyFilters.LastWrite |
                                   NotifyFilters.Size |
                                   NotifyFilters.CreationTime,
                    InternalBufferSize = Math.Clamp(_policy.FileMonitorBufferKb, 16, 64) * 1024
                };

                watcher.Changed += (_, e) => HandleEvent(EventKind.FileWrite, e.FullPath, null);
                watcher.Created += (_, e) => HandleEvent(EventKind.FileWrite, e.FullPath, null);
                watcher.Deleted += (_, e) => HandleEvent(EventKind.FileDelete, e.FullPath, null);
                watcher.Renamed += (_, e) => HandleEvent(EventKind.FileRename, e.FullPath, e.OldFullPath);
                watcher.Error += (_, e) =>
                {
                    var message = e.GetException()?.Message ?? "file watcher overflow";
                    _startupErrors.Add($"watcher-error {root}: {message}");
                };

                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
                _monitoredRoots.Add(root);
            }
            catch (Exception ex)
            {
                _startupErrors.Add($"watcher-init failed {root}: {ex.Message}");
            }
        }
    }

    private void HandleEvent(EventKind kind, string? targetPath, string? sourcePath)
    {
        var target = NormalizePath(targetPath);
        if (string.IsNullOrWhiteSpace(target))
        {
            return;
        }

        if (ShouldIgnorePath(target))
        {
            return;
        }

        var source = NormalizePath(sourcePath);
        var now = DateTimeOffset.Now;
        if (IsDuplicate(kind, target, source, now))
        {
            return;
        }

        var process = ResolveAttribution(now, target, source);

        var telemetry = new TelemetryEvent(
            now,
            kind,
            process.ProcessPath,
            process.ProcessId,
            target,
            source,
            null,
            0,
            IsProtectedTarget(target),
            IsSuspiciousExtension(target),
            false,
            process.IsUnsigned);

        while (_queue.Count > 12000 && _queue.TryDequeue(out _))
        {
            // bounded queue
        }

        _queue.Enqueue(telemetry);
    }

    private AttributionResult ResolveAttribution(DateTimeOffset now, string targetPath, string sourcePath)
    {
        if (TryResolveFromPaths(now, targetPath, sourcePath, out var resolved))
        {
            return resolved;
        }

        return ResolveFallbackAttribution(now);
    }

    private bool TryResolveFromPaths(DateTimeOffset now, string targetPath, string sourcePath, out AttributionResult result)
    {
        result = AttributionResult.Empty;

        if (TryResolveFromSinglePath(now, targetPath, out result))
        {
            return true;
        }

        if (TryResolveFromSinglePath(now, sourcePath, out result))
        {
            return true;
        }

        return false;
    }

    private bool TryResolveFromSinglePath(DateTimeOffset now, string path, out AttributionResult result)
    {
        result = AttributionResult.Empty;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return false;
        }

        var candidates = _processResolver.Resolve(path);
        if (candidates.Count == 0)
        {
            return false;
        }

        var lookback = TimeSpan.FromMinutes(Math.Clamp(_policy.TerminationLookbackMinutes, 1, 120));
        FileProcessCandidate best = FileProcessCandidate.Empty;
        var bestScore = int.MinValue;

        foreach (var candidate in candidates)
        {
            if (candidate.ProcessId <= 0 || candidate.ProcessId == Environment.ProcessId)
            {
                continue;
            }

            var exeName = NormalizeExeName(string.IsNullOrWhiteSpace(candidate.ProcessPath)
                ? candidate.ProcessName
                : candidate.ProcessPath);

            var score = 0;
            if (_terminationCandidates.Contains(exeName))
            {
                score += 3;
            }

            if (_allowList.Contains(exeName))
            {
                score -= 2;
            }

            if (candidate.StartTime != DateTime.MinValue && now.LocalDateTime - candidate.StartTime <= lookback)
            {
                score += 2;
            }

            if (!string.IsNullOrWhiteSpace(candidate.ProcessPath) && IsUnsignedProcess(candidate.ProcessPath))
            {
                score += 1;
            }

            if (score > bestScore || (score == bestScore && candidate.StartTime > best.StartTime))
            {
                best = candidate;
                bestScore = score;
            }
        }

        if (best.ProcessId <= 0)
        {
            return false;
        }

        var processPath = string.IsNullOrWhiteSpace(best.ProcessPath)
            ? NormalizeExeName(best.ProcessName)
            : best.ProcessPath;

        result = new AttributionResult(
            best.ProcessId,
            processPath,
            IsUnsignedProcess(best.ProcessPath),
            best.StartTime);

        return true;
    }

    private AttributionResult ResolveFallbackAttribution(DateTimeOffset now)
    {
        lock (_attributionSync)
        {
            if (now - _lastFallbackAttributionAt < TimeSpan.FromMilliseconds(800))
            {
                return _lastFallbackAttribution;
            }

            _lastFallbackAttribution = DiscoverFallbackAttribution(now);
            _lastFallbackAttributionAt = now;
            return _lastFallbackAttribution;
        }
    }

    private AttributionResult DiscoverFallbackAttribution(DateTimeOffset now)
    {
        _ = now;
        // 禁用“最近启动进程”兜底归因，避免将无关进程误判为勒索源。
        return AttributionResult.Empty;
    }

    private bool ShouldIgnorePath(string path)
    {
        if (IsInExcludedRoots(path))
        {
            return true;
        }

        if (Directory.Exists(path))
        {
            return true;
        }

        var fileName = Path.GetFileName(path);
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return true;
        }

        if (fileName.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase) ||
            fileName.Equals("thumbs.db", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    private bool IsInExcludedRoots(string path)
    {
        return _excludedRoots.Any(root =>
            path.StartsWith(root, StringComparison.OrdinalIgnoreCase));
    }

    private List<string> BuildExcludedRoots()
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        AddRoot(RuntimePaths.DataRoot);
        AddRoot(RuntimePaths.RollbackRoot);
        AddRoot(RuntimePaths.LogsRoot);
        AddRoot(Path.GetDirectoryName(RuntimePaths.PolicyPath));
        AddRoot(Path.GetDirectoryName(RuntimePaths.StatusPath));
        AddRoot(Path.GetDirectoryName(RuntimePaths.IncidentLogPath));
        AddRoot(AppContext.BaseDirectory);

        return [.. roots];

        void AddRoot(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                return;
            }

            var normalized = NormalizePath(raw);
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                roots.Add(normalized.TrimEnd('\\'));
            }
        }
    }

    private bool IsDuplicate(EventKind kind, string targetPath, string sourcePath, DateTimeOffset now)
    {
        var key = $"{kind}|{targetPath}|{sourcePath}";
        if (_recentEventKeys.TryGetValue(key, out var last) && now - last <= _dedupeWindow)
        {
            return true;
        }

        _recentEventKeys[key] = now;

        if (_recentEventKeys.Count > 3000)
        {
            var expire = now - TimeSpan.FromSeconds(10);
            foreach (var pair in _recentEventKeys)
            {
                if (pair.Value < expire)
                {
                    _recentEventKeys.TryRemove(pair.Key, out _);
                }
            }
        }

        return false;
    }

    private bool IsProtectedTarget(string targetPath)
    {
        return _policy.ProtectedFolders.Any(folder =>
            targetPath.StartsWith(folder, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsSuspiciousExtension(string targetPath)
    {
        var ext = Path.GetExtension(targetPath);
        if (string.IsNullOrWhiteSpace(ext))
        {
            return false;
        }

        return _policy.SuspiciousExtensions.Any(item =>
            item.Equals(ext, StringComparison.OrdinalIgnoreCase));
    }

    private static string NormalizePath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        try
        {
            return Path.GetFullPath(value.Trim());
        }
        catch
        {
            return value.Trim();
        }
    }

    private static string TryGetProcessPath(Process process)
    {
        try
        {
            return process.MainModule?.FileName ?? NormalizeExeName(process.ProcessName);
        }
        catch
        {
            return NormalizeExeName(process.ProcessName);
        }
    }

    private static bool IsUnsignedProcess(string? processPath)
    {
        if (string.IsNullOrWhiteSpace(processPath) || !File.Exists(processPath))
        {
            return false;
        }

        return SignatureTrustEvaluator.TryGetTrust(processPath, out var trust) && !trust.IsSigned;
    }

    private static HashSet<string> BuildTerminationCandidateSet(PolicyConfig policy)
    {
        var source = policy.TerminationCandidateProcesses.Count > 0
            ? policy.TerminationCandidateProcesses
            :
            [
                "cmd.exe",
                "powershell.exe",
                "pwsh.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
                "python.exe",
                "node.exe",
                "rundll32.exe",
                "regsvr32.exe"
            ];

        return new HashSet<string>(source.Select(NormalizeExeName), StringComparer.OrdinalIgnoreCase);
    }

    private static string NormalizeExeName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var name = Path.GetFileName(value.Trim());
        if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            name += ".exe";
        }

        return name;
    }

    private readonly record struct AttributionResult(int ProcessId, string ProcessPath, bool IsUnsigned, DateTime StartTime)
    {
        public static AttributionResult Empty => new(0, string.Empty, false, DateTime.MinValue);
    }
}
