using System.Diagnostics;
using System.Runtime.InteropServices;

namespace RollbackGuard.Service.Infra;

public sealed class ProcessAttributionCache
{
    private sealed record CacheEntry(string ProcessPath, DateTimeOffset ExpiresAt, DateTimeOffset LastSeen);
    private sealed record PathEntry(int ProcessId, DateTimeOffset ExpiresAt, DateTimeOffset LastSeen);

    private readonly Dictionary<int, CacheEntry> _entries = [];
    private readonly Dictionary<string, PathEntry> _entriesByPath = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, PathEntry> _entriesByImage = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeSpan _entryTtl;
    private readonly int _maxEntries;
    private DateTimeOffset _lastPruneAt = DateTimeOffset.MinValue;

    public ProcessAttributionCache(TimeSpan? entryTtl = null, int maxEntries = 8192)
    {
        _entryTtl = entryTtl ?? TimeSpan.FromHours(2);
        _maxEntries = Math.Max(128, maxEntries);
    }

    public void Observe(int processId, string? processPath, DateTimeOffset timestamp)
    {
        if (processId <= 4)
        {
            return;
        }

        var normalizedPath = Normalize(processPath);
        if (string.IsNullOrWhiteSpace(normalizedPath))
        {
            return;
        }

        var expiresAt = timestamp.Add(_entryTtl);
        _entries[processId] = new CacheEntry(normalizedPath, expiresAt, timestamp);
        _entriesByPath[normalizedPath] = new PathEntry(processId, expiresAt, timestamp);

        var imageName = GetImageName(normalizedPath);
        if (!string.IsNullOrWhiteSpace(imageName))
        {
            _entriesByImage[imageName] = new PathEntry(processId, expiresAt, timestamp);
        }

        PruneIfNeeded(timestamp);
    }

    public string ResolvePath(int processId, string? processPathHint, DateTimeOffset timestamp)
    {
        var hint = Normalize(processPathHint);
        if (processId <= 4)
        {
            return hint;
        }

        if (!string.IsNullOrWhiteSpace(hint))
        {
            Observe(processId, hint, timestamp);
            return hint;
        }

        if (_entries.TryGetValue(processId, out var cached))
        {
            if (cached.ExpiresAt > timestamp)
            {
                _entries[processId] = cached with { LastSeen = timestamp };
                return cached.ProcessPath;
            }

            _entries.Remove(processId);
        }

        var livePath = TryReadLiveProcessPath(processId);
        if (!string.IsNullOrWhiteSpace(livePath))
        {
            Observe(processId, livePath, timestamp);
            return livePath;
        }

        return string.Empty;
    }

    public int ResolvePidByPath(string? processPathHint, DateTimeOffset timestamp)
    {
        var normalizedPath = Normalize(processPathHint);
        if (string.IsNullOrWhiteSpace(normalizedPath))
        {
            return 0;
        }

        if (_entriesByPath.TryGetValue(normalizedPath, out var byPath))
        {
            if (byPath.ExpiresAt > timestamp && byPath.ProcessId > 4)
            {
                _entriesByPath[normalizedPath] = byPath with { LastSeen = timestamp };
                return byPath.ProcessId;
            }

            _entriesByPath.Remove(normalizedPath);
        }

        var imageName = GetImageName(normalizedPath);
        if (!string.IsNullOrWhiteSpace(imageName) &&
            _entriesByImage.TryGetValue(imageName, out var byImage))
        {
            if (byImage.ExpiresAt > timestamp && byImage.ProcessId > 4)
            {
                _entriesByImage[imageName] = byImage with { LastSeen = timestamp };
                return byImage.ProcessId;
            }

            _entriesByImage.Remove(imageName);
        }

        return 0;
    }

    private void PruneIfNeeded(DateTimeOffset now)
    {
        if (_entries.Count == 0 && _entriesByPath.Count == 0 && _entriesByImage.Count == 0)
        {
            return;
        }

        var shouldPruneByInterval = (now - _lastPruneAt) >= TimeSpan.FromSeconds(30);
        if (!shouldPruneByInterval && _entries.Count <= _maxEntries)
        {
            return;
        }

        _lastPruneAt = now;

        var expiredKeys = _entries
            .Where(item => item.Value.ExpiresAt <= now)
            .Select(item => item.Key)
            .ToArray();

        foreach (var key in expiredKeys)
        {
            _entries.Remove(key);
        }

        var expiredPaths = _entriesByPath
            .Where(item => item.Value.ExpiresAt <= now || item.Value.ProcessId <= 4)
            .Select(item => item.Key)
            .ToArray();
        foreach (var key in expiredPaths)
        {
            _entriesByPath.Remove(key);
        }

        var expiredImages = _entriesByImage
            .Where(item => item.Value.ExpiresAt <= now || item.Value.ProcessId <= 4)
            .Select(item => item.Key)
            .ToArray();
        foreach (var key in expiredImages)
        {
            _entriesByImage.Remove(key);
        }

        if (_entries.Count <= _maxEntries)
        {
            return;
        }

        var removeCount = _entries.Count - _maxEntries;
        var oldestKeys = _entries
            .OrderBy(item => item.Value.LastSeen)
            .Take(removeCount)
            .Select(item => item.Key)
            .ToArray();

        foreach (var key in oldestKeys)
        {
            _entries.Remove(key);
        }

        var validPids = _entries.Keys.ToHashSet();
        var stalePathKeys = _entriesByPath
            .Where(item => !validPids.Contains(item.Value.ProcessId))
            .Select(item => item.Key)
            .ToArray();
        foreach (var key in stalePathKeys)
        {
            _entriesByPath.Remove(key);
        }

        var staleImageKeys = _entriesByImage
            .Where(item => !validPids.Contains(item.Value.ProcessId))
            .Select(item => item.Key)
            .ToArray();
        foreach (var key in staleImageKeys)
        {
            _entriesByImage.Remove(key);
        }
    }

    private static string Normalize(string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.TrimEnd('\0').Trim();
    }

    private static string TryReadLiveProcessPath(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);

            string? rawMainModulePath = null;
            try
            {
                rawMainModulePath = process.MainModule?.FileName;
            }
            catch
            {
                rawMainModulePath = null;
            }

            var mainModulePath = Normalize(rawMainModulePath);
            if (!string.IsNullOrWhiteSpace(mainModulePath))
            {
                return mainModulePath;
            }

            var queriedPath = TryQueryFullProcessImageName(processId);
            if (!string.IsNullOrWhiteSpace(queriedPath))
            {
                return Normalize(queriedPath);
            }

            string? rawProcessName = null;
            try
            {
                rawProcessName = process.ProcessName;
            }
            catch
            {
                rawProcessName = null;
            }

            var processName = Normalize(rawProcessName);
            if (!string.IsNullOrWhiteSpace(processName))
            {
                return processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    ? processName
                    : processName + ".exe";
            }

            return string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string GetImageName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        try
        {
            return Path.GetFileName(value);
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string TryQueryFullProcessImageName(int processId)
    {
        IntPtr handle = IntPtr.Zero;
        try
        {
            handle = OpenProcess(0x1000, false, (uint)processId);
            if (handle == IntPtr.Zero)
            {
                return string.Empty;
            }

            var buffer = new char[32768];
            var size = buffer.Length;
            if (!QueryFullProcessImageNameW(handle, 0, buffer, ref size) || size <= 0)
            {
                return string.Empty;
            }

            return new string(buffer, 0, size);
        }
        catch
        {
            return string.Empty;
        }
        finally
        {
            if (handle != IntPtr.Zero)
            {
                CloseHandle(handle);
            }
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(
        IntPtr processHandle,
        uint flags,
        [Out] char[] exeName,
        ref int size);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}
