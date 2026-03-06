using RollbackGuard.Common.Models;

namespace RollbackGuard.Service.Engine;

public sealed class ProcessContextManager
{
    private readonly Dictionary<int, ProcessContext> _contexts = [];
    private readonly Dictionary<int, DateTimeOffset> _terminatedAt = [];
    private static readonly TimeSpan TerminatedRetention = TimeSpan.FromMinutes(5);
    private const int MaxContexts = 4096;
    private DateTimeOffset _lastPrune = DateTimeOffset.Now;

    public ProcessContext GetOrCreate(int pid, string? imageName = null)
    {
        if (_contexts.TryGetValue(pid, out var existing))
        {
            if (!string.IsNullOrWhiteSpace(imageName))
            {
                if (string.IsNullOrWhiteSpace(existing.ImageName) ||
                    (!existing.ImageName.Contains('\\', StringComparison.Ordinal) &&
                     imageName.Contains('\\', StringComparison.Ordinal)))
                {
                    existing.ImageName = imageName;
                }
            }

            return existing;
        }

        var image = imageName ?? string.Empty;
        var ctx = new ProcessContext { PID = pid, ImageName = image };
        _contexts[pid] = ctx;

        PruneIfNeeded();
        return ctx;
    }

    public ProcessContext? Get(int pid)
    {
        return _contexts.GetValueOrDefault(pid);
    }

    public void InitFromProcessCreate(TelemetryEvent evt)
    {
        // Reset context for new process
        _contexts.Remove(evt.ProcessId);
        _terminatedAt.Remove(evt.ProcessId);

        var ctx = new ProcessContext
        {
            PID = evt.ProcessId,
            PPID = evt.ParentProcessId,
            ImageName = evt.ProcessPath,
            ParentImageName = evt.ParentProcessPath,
            CreateTime = evt.Timestamp,
            IsSuspended = evt.IsSuspendedCreate,
            IntegrityLevel = evt.IntegrityLevel
        };

        _contexts[evt.ProcessId] = ctx;
    }

    public void MarkTerminated(int pid)
    {
        _terminatedAt[pid] = DateTimeOffset.Now;
    }

    public void Remove(int pid)
    {
        _contexts.Remove(pid);
        _terminatedAt.Remove(pid);
    }

    public IReadOnlyDictionary<int, ProcessContext> AllContexts => _contexts;

    private void PruneIfNeeded()
    {
        var now = DateTimeOffset.Now;
        if (now - _lastPrune < TimeSpan.FromSeconds(30) && _contexts.Count < MaxContexts)
        {
            return;
        }

        _lastPrune = now;

        // Remove terminated processes that have been gone long enough
        var toRemove = new List<int>();
        foreach (var (pid, terminatedAt) in _terminatedAt)
        {
            if (now - terminatedAt > TerminatedRetention)
            {
                toRemove.Add(pid);
            }
        }

        foreach (var pid in toRemove)
        {
            _contexts.Remove(pid);
            _terminatedAt.Remove(pid);
        }

        // If still over limit, remove oldest non-terminated contexts
        if (_contexts.Count > MaxContexts)
        {
            var candidates = _contexts
                .Where(kv => !_terminatedAt.ContainsKey(kv.Key))
                .OrderBy(kv => kv.Value.CreateTime)
                .Take(_contexts.Count - MaxContexts + 256)
                .Select(kv => kv.Key)
                .ToList();

            foreach (var pid in candidates)
            {
                _contexts.Remove(pid);
            }
        }
    }
}
