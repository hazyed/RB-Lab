using System.Diagnostics;
using System.Threading;
using RollbackGuard.Common.Models;

namespace RollbackGuard.Service.Engine;

public sealed class PeriodicMemoryScanner : IDisposable
{
    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan BasePerProcessCooldown = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan HighRiskPerProcessCooldown = TimeSpan.FromSeconds(3);
    private const int MaxCandidatesPerTick = 16;

    private readonly ProcessContextManager _contextManager;
    private readonly MemoryScanner _memoryScanner;
    private readonly Action<int, MemoryScanResult, ProcessContext> _onScanCompleted;
    private readonly Dictionary<int, DateTimeOffset> _lastScanAt = [];
    private readonly System.Threading.Timer _timer;
    private int _scanGate;
    private volatile bool _started;

    public PeriodicMemoryScanner(
        ProcessContextManager contextManager,
        MemoryScanner memoryScanner,
        Action<int, MemoryScanResult, ProcessContext> onScanCompleted)
    {
        _contextManager = contextManager;
        _memoryScanner = memoryScanner;
        _onScanCompleted = onScanCompleted;
        _timer = new System.Threading.Timer(_ => Tick(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
    }

    public void Start()
    {
        if (_started)
        {
            return;
        }

        _started = true;
        _timer.Change(ScanInterval, ScanInterval);
    }

    private void Tick()
    {
        if (Interlocked.Exchange(ref _scanGate, 1) != 0)
        {
            return;
        }

        try
        {
            var now = DateTimeOffset.Now;
            var candidates = _contextManager.AllContexts.Values
                .Select(context =>
                {
                    EnsureResolvedProcessIdentity(context);
                    return context;
                })
                .Where(context =>
                    context.PID > 4 &&
                    !ShouldSkipUserModeMemoryInspection(context) &&
                    !context.RecentlyRemediatedMemory &&
                    (context.Score >= 20 ||
                     context.WasTargetedBySuspiciousHandle ||
                     context.WasRemotelyCreated ||
                     HasSuspiciousParent(context)))
                .Where(context =>
                    !_lastScanAt.TryGetValue(context.PID, out var lastScan) ||
                    now - lastScan >= GetCooldown(context))
                .OrderByDescending(context => context.Score)
                .ThenByDescending(context => context.WasTargetedBySuspiciousHandle)
                .ThenByDescending(context => context.WasRemotelyCreated)
                .ThenByDescending(HasSuspiciousParent)
                .Take(MaxCandidatesPerTick)
                .ToList();

            foreach (var context in candidates)
            {
                try
                {
                    var result = _memoryScanner.ScanProcess(context.PID);
                    if (result != null)
                    {
                        context.ApplyEnhancedMemoryScan(result);
                        _onScanCompleted(context.PID, result, context);
                    }
                }
                catch
                {
                    // process may have exited; record the attempt regardless
                }
                finally
                {
                    _lastScanAt[context.PID] = DateTimeOffset.Now;
                }
            }

            // Remove stale entries for PIDs no longer tracked (avoids false "recently scanned" for reused PIDs).
            var activePids = _contextManager.AllContexts.Keys.ToHashSet();
            foreach (var stalePid in _lastScanAt.Keys.Where(pid => !activePids.Contains(pid)).ToList())
            {
                _lastScanAt.Remove(stalePid);
            }
        }
        finally
        {
            Volatile.Write(ref _scanGate, 0);
        }
    }

    public void Dispose()
    {
        _timer.Dispose();
    }

    private bool HasSuspiciousParent(ProcessContext context)
    {
        if (context.PPID <= 4)
        {
            return false;
        }

        var parent = _contextManager.Get(context.PPID);
        if (parent == null)
        {
            return false;
        }

        if (parent.IsRestrictedProcess ||
            parent.LoadedUnsignedDll ||
            parent.LoadedSuspiciousDll ||
            parent.LoadedNonMicrosoftDll)
        {
            return true;
        }

        if (parent.SuspiciousHandleOpenCount > 0 || parent.SuspiciousThreadHijackCount > 0)
        {
            return true;
        }

        if (parent.MemoryShellcodePatternCount > 0 ||
            parent.MemoryReflectiveDllCount > 0 ||
            parent.MemorySyscallStubCount > 0 ||
            parent.MemoryWxTransitionCount > 0)
        {
            return true;
        }

        if (parent.IsLolBinProcess)
        {
            return true;
        }

        return parent.Score >= 20 || parent.State >= ProcessState.Alert;
    }

    private static TimeSpan GetCooldown(ProcessContext context)
    {
        if (context.WasTargetedBySuspiciousHandle ||
            context.WasRemotelyCreated ||
            context.MemoryShellcodePatternCount > 0 ||
            context.MemoryReflectiveDllCount > 0 ||
            context.MemorySyscallStubCount > 0 ||
            context.MemoryWxTransitionCount > 0)
        {
            return HighRiskPerProcessCooldown;
        }

        return BasePerProcessCooldown;
    }

    private static bool ShouldSkipUserModeMemoryInspection(ProcessContext context) =>
        (context.SignatureEvaluated &&
         context.IsMicrosoftSignedProcess &&
         context.IsMicrosoftCleanChain) ||
        TrustedProcessValidator.IsLikelyTrustedWindowsProcessPendingTrust(context);

    private static void EnsureResolvedProcessIdentity(ProcessContext context)
    {
        if (context.PID <= 4 || !string.IsNullOrWhiteSpace(context.ImageName))
        {
            return;
        }

        var resolvedPath = TryReadLiveProcessPath(context.PID);
        if (!string.IsNullOrWhiteSpace(resolvedPath))
        {
            context.ImageName = resolvedPath;
        }
    }

    private static string TryReadLiveProcessPath(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);

            string? mainModulePath = null;
            try
            {
                mainModulePath = process.MainModule?.FileName?.Trim();
            }
            catch
            {
                mainModulePath = null;
            }

            if (!string.IsNullOrWhiteSpace(mainModulePath))
            {
                return mainModulePath;
            }

            string? processName = null;
            try
            {
                processName = process.ProcessName?.Trim();
            }
            catch
            {
                processName = null;
            }

            if (string.IsNullOrWhiteSpace(processName))
            {
                return string.Empty;
            }

            return processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? processName
                : processName + ".exe";
        }
        catch
        {
            return string.Empty;
        }
    }
}
