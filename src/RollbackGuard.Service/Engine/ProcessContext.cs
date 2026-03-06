using RollbackGuard.Common.Models;

namespace RollbackGuard.Service.Engine;

public sealed class ProcessContext
{
    private static readonly TimeSpan SlidingWindow = TimeSpan.FromSeconds(60);
    private const int MaxEventHistory = 200;
    private const double EntropyHighThreshold = 7.2;
    private const double EntropySpikeDeltaThreshold = 1.1;
    private static readonly TimeSpan EntropyConsecutiveGap = TimeSpan.FromSeconds(20);
    private static readonly HashSet<string> CompressedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".zst", ".cab",
        ".iso", ".img", ".vhd", ".vhdx", ".jar", ".war", ".apk",
        ".mp3", ".aac", ".flac", ".mp4", ".mkv", ".avi", ".mov",
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic",
        ".pdf", ".db", ".sqlite", ".sqlite3"
    };

    private readonly object _lock = new();

    public int PID { get; init; }
    public int PPID { get; set; }
    public string ImageName { get; set; } = string.Empty;
    public string? ParentImageName { get; set; }
    public DateTimeOffset CreateTime { get; set; } = DateTimeOffset.Now;
    public bool HasValidSignature { get; set; }
    public bool IsSuspended { get; set; }
    public bool SignatureEvaluated { get; set; }
    public bool IsMicrosoftSignedProcess { get; set; }
    public ProcessIntegrityLevel IntegrityLevel { get; set; } = ProcessIntegrityLevel.Unknown;
    public ExecutionTrustTier BaseTrustTier { get; set; } = ExecutionTrustTier.Unknown;
    public ExecutionTrustTier CurrentTrustTier { get; set; } = ExecutionTrustTier.Unknown;
    public bool StartupTrustEstablished { get; set; }
    public bool IsRestrictedProcess => CurrentTrustTier == ExecutionTrustTier.Unsigned;

    public int TotalFilesWritten { get; set; }
    public int TotalDirsAccessed { get; set; }
    public int TotalFileOverwrites { get; set; }
    public int TotalFileRenames { get; set; }
    public int UniqueFileAccesses { get; set; }
    public int TotalFileAccesses { get; set; }

    public int FilesWrittenInWindow { get; set; }
    public int DirsAccessedInWindow { get; set; }
    public DateTimeOffset WindowStart { get; set; } = DateTimeOffset.Now;

    public bool WasRemotelyCreated { get; set; }
    public bool HasAnomalousCallStack { get; set; }
    public bool HasRemoteMemoryWrite { get; set; }
    public bool LoadedUnsignedDll { get; set; }
    public bool LoadedSuspiciousDll { get; set; }
    public bool LoadedNonMicrosoftDll { get; set; }
    public bool WasTargetedBySuspiciousHandle { get; set; }
    public int LastSuspiciousSourcePid { get; set; }
    public DateTimeOffset LastSuspiciousSourceAt { get; set; }
    public int SuspiciousHandleOpenCount { get; private set; }
    public int SuspiciousThreadHijackCount { get; private set; }
    public DateTimeOffset LastInjectHandleAt { get; private set; }
    public bool HasHandleInjectionBurst =>
        SuspiciousHandleOpenCount >= 2 || SuspiciousThreadHijackCount > 0;
    public bool HasCorrelatedInjection =>
        HasHandleInjectionBurst && WasRemotelyCreated;
    public int HighEntropySpikeCount { get; private set; }
    public int HighEntropyConsecutiveSpikeFiles { get; private set; }
    public int KernelHighEntropyRawCount { get; private set; }
    public int KernelLowToHighEntropyCount { get; private set; }
    public int KernelEntropyAutoBlockCount { get; private set; }
    public int KernelConsecutiveRuleHitCount { get; private set; }
    public int KernelCumulativeRuleHitCount { get; private set; }
    public int CompressionRatioConfirmedCount { get; private set; }
    public double LastCompressionSavingsRatio { get; private set; }
    public string LastCompressionSummary { get; private set; } = string.Empty;
    public int CallStackProbeCount { get; private set; }
    public int CallStackUnbackedFrameCount { get; private set; }
    public string LastCallStackSummary { get; private set; } = string.Empty;
    public DateTimeOffset LastKernelTrustRefreshAt { get; private set; }
    public DateTimeOffset LastCompressionProbeAt { get; private set; }
    public DateTimeOffset LastCallStackProbeAt { get; private set; }

    public bool IsLolBinProcess { get; set; }
    public string? LolBinType { get; set; }

    public int PersistenceAttempts { get; set; }
    public List<string> PersistenceTypes { get; } = [];

    public bool MemoryScanCompleted { get; private set; }
    public bool MemoryScanSuspicious { get; private set; }
    public int MemoryRwxRegionCount { get; private set; }
    public int MemoryShellcodePatternCount { get; private set; }
    public int MemoryAmsiDetectionCount { get; private set; }
    public int MemoryUnbackedExecRegionCount { get; private set; }
    public int MemoryHighEntropyRegionCount { get; private set; }
    public int MemoryWxTransitionCount { get; private set; }
    public int MemoryReflectiveDllCount { get; private set; }
    public int MemoryPebWalkPatternCount { get; private set; }
    public int MemoryApiHashPatternCount { get; private set; }
    public int MemorySyscallStubCount { get; private set; }
    public List<MemoryRegionSnapshot> LastScanRegions { get; private set; } = [];
    public DateTimeOffset LastMemoryScanTime { get; private set; }
    public int MemoryScanCount { get; private set; }
    public DateTimeOffset LastMemoryRemediationAt { get; private set; }
    public bool RecentlyRemediatedMemory =>
        LastMemoryRemediationAt != DateTimeOffset.MinValue &&
        DateTimeOffset.Now - LastMemoryRemediationAt <= TimeSpan.FromMinutes(2);

    public List<RemediationRecord> RemediationHistory { get; } = [];
    public bool HasBeenRemediated => RemediationHistory.Count > 0;

    public List<LoadedDllInfo> LoadedDlls { get; } = [];

    public int Score { get; set; }
    public ProcessState State { get; set; } = ProcessState.Monitoring;

    public List<TelemetryEvent> EventHistory { get; } = [];

    private readonly HashSet<string> _uniqueFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _uniqueDirs = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _windowFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _windowDirs = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, double> _preWriteEntropyByFile = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, double> _lastObservedEntropyByFile = new(StringComparer.OrdinalIgnoreCase);
    private string? _lastReadFile;
    private string? _lastEntropySpikeFile;
    private DateTimeOffset _lastEntropySpikeAt;
    private int _extensionChangeCount;

    public int ExtensionChangeCount => _extensionChangeCount;
    public bool IsMicrosoftCleanChain =>
        IsMicrosoftSignedProcess && !LoadedUnsignedDll && !LoadedNonMicrosoftDll;

    public double UniqueFileRatio =>
        TotalFileAccesses > 0 ? (double)UniqueFileAccesses / TotalFileAccesses : 0.0;

    public double DirGrowthRate
    {
        get
        {
            var elapsed = (DateTimeOffset.Now - CreateTime).TotalSeconds;
            if (elapsed < 10)
            {
                return 0;
            }

            return TotalDirsAccessed / (elapsed / 10.0);
        }
    }

    public void UpdateFromEvent(TelemetryEvent evt)
    {
        if (NoisePathFilter.IsIgnorableFileEvent(evt))
        {
            return;
        }

        lock (_lock)
        {
        EventHistory.Add(evt);
        if (EventHistory.Count > MaxEventHistory)
        {
            EventHistory.RemoveAt(0);
        }

        RefreshSlidingWindow();

        switch (evt.Kind)
        {
            case EventKind.FileWrite:
                ObserveKernelEntropyEvidence(evt);
                if (evt.IsPreOperation)
                {
                    CapturePreWriteEntropy(evt.TargetPath);
                }

                HandleFileWrite(evt);
                if (!evt.IsPreOperation)
                {
                    EvaluatePostWriteEntropy(evt.TargetPath);
                }
                break;
            case EventKind.FileDelete:
                HandleFileAccess(evt);
                break;
            case EventKind.FileRename:
                HandleFileRename(evt);
                break;
            case EventKind.FileCreate:
                HandleFileAccess(evt);
                break;
            case EventKind.ImageLoadUnsigned:
                TrackLoadedDll(evt.TargetPath, isSigned: false, isMicrosoftSigned: false, evt.Timestamp);
                break;
            case EventKind.ImageLoad:
                TrackLoadedDll(evt.TargetPath, isSigned: true, isMicrosoftSigned: false, evt.Timestamp);
                break;
            case EventKind.ProcessInject:
            case EventKind.InjectPrelude:
                HandleProcessInject(evt);
                break;
            case EventKind.ProcessCreate:
                if (evt.ParentProcessId > 0)
                {
                    PPID = evt.ParentProcessId;
                }

                if (evt.IsSuspendedCreate)
                {
                    IsSuspended = true;
                }

                if (evt.IntegrityLevel != ProcessIntegrityLevel.Unknown)
                {
                    IntegrityLevel = evt.IntegrityLevel;
                }
                break;
            case EventKind.LolBinExecution:
                IsLolBinProcess = true;
                break;
            case EventKind.PersistenceWmi:
            case EventKind.PersistenceScheduledTask:
            case EventKind.PersistenceService:
            case EventKind.PersistenceStartupFolder:
            case EventKind.PersistenceComHijack:
                PersistenceAttempts++;
                var persistType = evt.Kind.ToString();
                if (!PersistenceTypes.Contains(persistType))
                {
                    PersistenceTypes.Add(persistType);
                }
                break;
        }
        } // lock
    }

    public void ApplyMemoryScan(MemoryScanResult result) => ApplyEnhancedMemoryScan(result);

    public void ApplyEnhancedMemoryScan(MemoryScanResult result)
    {
        var regions = result.SuspiciousRegions
            .Select(region => new MemoryRegionSnapshot(
                region.BaseAddress,
                region.Size,
                region.Protection,
                BuildRegionSummary(region)))
            .ToList();

        lock (_lock)
        {
            MemoryScanCompleted = true;
            MemoryScanSuspicious = result.IsSuspicious || result.CalculateScore() > 0;
            MemoryRwxRegionCount = result.RwxRegionCount;
            MemoryShellcodePatternCount = result.ShellcodePatternCount;
            MemoryAmsiDetectionCount = result.AmsiDetectionCount;
            MemoryUnbackedExecRegionCount = result.UnbackedExecRegionCount;
            MemoryHighEntropyRegionCount = result.HighEntropyRegionCount;
            MemoryWxTransitionCount = result.WxTransitionCount;
            MemoryReflectiveDllCount = result.ReflectiveDllCount;
            MemoryPebWalkPatternCount = result.PebWalkPatternCount;
            MemoryApiHashPatternCount = result.ApiHashPatternCount;
            MemorySyscallStubCount = result.SyscallStubCount;
            LastScanRegions = regions;
            LastMemoryScanTime = DateTimeOffset.Now;
            MemoryScanCount++;
        }
    }

    public void UpdateLoadedDllTrust(string? modulePath, BinaryTrustVerdict verdict, DateTimeOffset loadTime)
    {
        if (string.IsNullOrWhiteSpace(modulePath))
        {
            return;
        }

        if (verdict.Tier == ExecutionTrustTier.Unknown)
        {
            return;
        }

        var effectiveSigned = IsEffectivelySigned(verdict);
        var effectiveMicrosoftSigned = IsEffectivelyMicrosoftSigned(verdict);
        var normalized = NormalizePathKey(modulePath);
        for (var i = LoadedDlls.Count - 1; i >= 0; i--)
        {
            var existing = LoadedDlls[i];
            if (!NormalizePathKey(existing.Path).Equals(normalized, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            LoadedDlls[i] = existing with
            {
                Path = modulePath.Trim().TrimEnd('\0'),
                IsSigned = effectiveSigned,
                IsMicrosoftSigned = effectiveMicrosoftSigned,
                LoadTime = loadTime
            };
            return;
        }

        TrackLoadedDll(modulePath, effectiveSigned, effectiveMicrosoftSigned, loadTime);
    }

    public void AddRemediationRecord(string action, string detail, bool success)
    {
        RemediationHistory.Add(new RemediationRecord(
            DateTimeOffset.Now,
            string.IsNullOrWhiteSpace(action) ? "memory-remediation" : action,
            string.IsNullOrWhiteSpace(detail) ? "(no-detail)" : detail,
            success));
    }

    public void MarkMemoryRemediationSuccess()
    {
        lock (_lock)
        {
            MemoryScanSuspicious = false;
            MemoryRwxRegionCount = 0;
            MemoryShellcodePatternCount = 0;
            MemoryAmsiDetectionCount = 0;
            MemoryUnbackedExecRegionCount = 0;
            MemoryHighEntropyRegionCount = 0;
            MemoryWxTransitionCount = 0;
            MemoryReflectiveDllCount = 0;
            MemoryPebWalkPatternCount = 0;
            MemoryApiHashPatternCount = 0;
            MemorySyscallStubCount = 0;
            LastScanRegions = [];
            LastMemoryScanTime = DateTimeOffset.Now;
            LastMemoryRemediationAt = DateTimeOffset.Now;
            WasTargetedBySuspiciousHandle = false;
            // WasRemotelyCreated is process provenance, not current memory state — preserve it
            LastSuspiciousSourcePid = 0;
            LastSuspiciousSourceAt = DateTimeOffset.MinValue;
        }
    }

    private void TrackLoadedDll(string? path, bool isSigned, bool isMicrosoftSigned, DateTimeOffset loadTime)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        var normalized = NormalizePathKey(path);
        for (var i = LoadedDlls.Count - 1; i >= 0; i--)
        {
            if (!NormalizePathKey(LoadedDlls[i].Path).Equals(normalized, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            LoadedDlls[i] = LoadedDlls[i] with
            {
                Path = path.Trim().TrimEnd('\0'),
                IsSigned = isSigned,
                IsMicrosoftSigned = isMicrosoftSigned,
                LoadTime = loadTime
            };
            return;
        }

        LoadedDlls.Add(new LoadedDllInfo(
            path.Trim().TrimEnd('\0'),
            isSigned,
            isMicrosoftSigned,
            loadTime));
    }

    private void HandleFileWrite(TelemetryEvent evt)
    {
        var target = evt.TargetPath;
        if (string.IsNullOrWhiteSpace(target))
        {
            return;
        }

        TotalFileAccesses++;
        if (_uniqueFiles.Add(target))
        {
            UniqueFileAccesses++;
            TotalFilesWritten++;
        }

        if (_windowFiles.Add(target))
        {
            FilesWrittenInWindow++;
        }

        var dir = Path.GetDirectoryName(target);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            if (_uniqueDirs.Add(dir))
            {
                TotalDirsAccessed++;
            }

            if (_windowDirs.Add(dir))
            {
                DirsAccessedInWindow++;
            }
        }

        if (_lastReadFile != null && _lastReadFile.Equals(target, StringComparison.OrdinalIgnoreCase))
        {
            TotalFileOverwrites++;
        }

        _lastReadFile = target;
    }

    private void HandleFileRename(TelemetryEvent evt)
    {
        TotalFileRenames++;

        var source = evt.SourcePath;
        var target = evt.TargetPath;
        if (string.IsNullOrWhiteSpace(source) || string.IsNullOrWhiteSpace(target))
        {
            return;
        }

        var srcExt = Path.GetExtension(source);
        var dstExt = Path.GetExtension(target);
        if (!string.IsNullOrWhiteSpace(srcExt) &&
            !string.IsNullOrWhiteSpace(dstExt) &&
            !srcExt.Equals(dstExt, StringComparison.OrdinalIgnoreCase))
        {
            _extensionChangeCount++;
        }
    }

    private void HandleFileAccess(TelemetryEvent evt)
    {
        var target = evt.TargetPath;
        if (string.IsNullOrWhiteSpace(target))
        {
            return;
        }

        TotalFileAccesses++;
        if (_uniqueFiles.Add(target))
        {
            UniqueFileAccesses++;
        }

        var dir = Path.GetDirectoryName(target);
        if (!string.IsNullOrWhiteSpace(dir) && _uniqueDirs.Add(dir))
        {
            TotalDirsAccessed++;
        }
    }

    private void HandleProcessInject(TelemetryEvent evt)
    {
        LastInjectHandleAt = evt.Timestamp;
        var accessMask = ParseAccessMask(evt.SourcePath);
        if (IsThreadHandleAccess(evt.SourcePath) &&
            ((accessMask & 0x0010U) != 0 || (accessMask & 0x0008U) != 0 || (accessMask & 0x0002U) != 0))
        {
            SuspiciousThreadHijackCount++;
            return;
        }

        SuspiciousHandleOpenCount++;
    }

    private void RefreshSlidingWindow()
    {
        var now = DateTimeOffset.Now;
        if (now - WindowStart > SlidingWindow)
        {
            WindowStart = now;
            FilesWrittenInWindow = 0;
            DirsAccessedInWindow = 0;
            _windowFiles.Clear();
            _windowDirs.Clear();
        }
    }

    public void UpdateState(int score)
    {
        Score = score;
        State = score switch
        {
            < 30 => ProcessState.Monitoring,
            < 60 => ProcessState.Alert,
            < 85 => ProcessState.Suspicious,
            _ => ProcessState.Malicious
        };
    }

    public void ApplyBaseTrust(BinaryTrustVerdict verdict)
    {
        var effectiveSigned = IsEffectivelySigned(verdict);
        var effectiveMicrosoftSigned = IsEffectivelyMicrosoftSigned(verdict);
        SignatureEvaluated = true;
        HasValidSignature = effectiveSigned;
        IsMicrosoftSignedProcess = effectiveMicrosoftSigned;
        BaseTrustTier = verdict.Tier;
        if (CurrentTrustTier == ExecutionTrustTier.Unknown || CurrentTrustTier == BaseTrustTier)
        {
            CurrentTrustTier = verdict.Tier;
        }
        else if (CurrentTrustTier != ExecutionTrustTier.Unsigned && verdict.Tier == ExecutionTrustTier.Unsigned)
        {
            CurrentTrustTier = ExecutionTrustTier.Unsigned;
        }

        StartupTrustEstablished = true;
    }

    public void ApplyModuleTrust(BinaryTrustVerdict verdict)
    {
        if (verdict.Tier == ExecutionTrustTier.Unknown)
        {
            return;
        }

        var effectiveSigned = IsEffectivelySigned(verdict);
        var effectiveMicrosoftSigned = IsEffectivelyMicrosoftSigned(verdict);
        var modulePath = verdict.ResolvedPath;
        var isNonSystemPath = !string.IsNullOrWhiteSpace(modulePath) && !IsSystemDir(modulePath);
        var isDllLikeModule = IsDllLikeImagePath(modulePath);

        // Image-load callbacks also report the main EXE image. Module trust should only
        // degrade the process for actual DLL/OCX side-loading evidence.
        if (!isDllLikeModule)
        {
            return;
        }

        if (!effectiveSigned)
        {
            LoadedUnsignedDll = true;
            CurrentTrustTier = ExecutionTrustTier.Unsigned;
        }
        else if (!effectiveMicrosoftSigned)
        {
            LoadedNonMicrosoftDll = true;
            if (BaseTrustTier == ExecutionTrustTier.MicrosoftSigned &&
                CurrentTrustTier == ExecutionTrustTier.MicrosoftSigned)
            {
                CurrentTrustTier = ExecutionTrustTier.Signed;
            }
            else if (BaseTrustTier == ExecutionTrustTier.Signed &&
                     CurrentTrustTier == ExecutionTrustTier.Unknown)
            {
                CurrentTrustTier = ExecutionTrustTier.Signed;
            }
        }
        else if (CurrentTrustTier == ExecutionTrustTier.Unknown &&
                 BaseTrustTier is ExecutionTrustTier.MicrosoftSigned or ExecutionTrustTier.Signed)
        {
            CurrentTrustTier = BaseTrustTier;
        }

        if (isDllLikeModule && isNonSystemPath && !effectiveSigned)
        {
            LoadedSuspiciousDll = true;
        }
    }

    public void ObserveKernelEntropyEvidence(TelemetryEvent evt)
    {
        if (!evt.IsPreOperation || evt.Kind != EventKind.FileWrite)
        {
            return;
        }

        if (KernelEntropyEvidence.HasHighEntropyRaw(evt))
        {
            KernelHighEntropyRawCount++;
        }

        if (KernelEntropyEvidence.IsLowToHigh(evt))
        {
            KernelLowToHighEntropyCount++;
        }

        if (KernelEntropyEvidence.WasAutoBlocked(evt))
        {
            KernelEntropyAutoBlockCount++;
        }

        if (KernelEntropyEvidence.TriggeredConsecutiveRule(evt))
        {
            KernelConsecutiveRuleHitCount++;
        }

        if (KernelEntropyEvidence.TriggeredCumulativeRule(evt))
        {
            KernelCumulativeRuleHitCount++;
        }
    }

    public void MarkKernelTrustRefresh(DateTimeOffset when)
    {
        LastKernelTrustRefreshAt = when;
    }

    public void ApplyCompressionRatioVerdict(CompressionRatioVerdict verdict, DateTimeOffset when)
    {
        LastCompressionProbeAt = when;
        LastCompressionSavingsRatio = verdict.SavingsRatio;
        LastCompressionSummary = verdict.Summary;
        if (verdict.Confirmed)
        {
            CompressionRatioConfirmedCount++;
        }
    }

    public void ApplyCallStackInspection(CallStackInspectionVerdict verdict, DateTimeOffset when)
    {
        LastCallStackProbeAt = when;
        LastCallStackSummary = verdict.Summary;
        CallStackProbeCount++;
        if (verdict.UnbackedFrameCount > CallStackUnbackedFrameCount)
        {
            CallStackUnbackedFrameCount = verdict.UnbackedFrameCount;
        }

        if (verdict.HasAnomalousFrame)
        {
            HasAnomalousCallStack = true;
        }
    }

    private static bool IsEffectivelySigned(BinaryTrustVerdict verdict) =>
        verdict.IsSigned && verdict.Tier is ExecutionTrustTier.Signed or ExecutionTrustTier.MicrosoftSigned;

    private static bool IsEffectivelyMicrosoftSigned(BinaryTrustVerdict verdict) =>
        verdict.IsMicrosoftSigned && verdict.Tier == ExecutionTrustTier.MicrosoftSigned;

    private void CapturePreWriteEntropy(string? targetPath)
    {
        if (!ShouldTrackEntropyPath(targetPath))
        {
            return;
        }

        if (!FileEntropyAnalyzer.TryMeasure(targetPath, out var sample))
        {
            return;
        }

        _preWriteEntropyByFile[NormalizePathKey(targetPath!)] = sample.Entropy;
    }

    private void EvaluatePostWriteEntropy(string? targetPath)
    {
        if (!ShouldTrackEntropyPath(targetPath))
        {
            return;
        }

        if (!FileEntropyAnalyzer.TryMeasure(targetPath, out var sample))
        {
            return;
        }

        var key = NormalizePathKey(targetPath!);
        var hasBefore = _preWriteEntropyByFile.Remove(key, out var beforeEntropy);
        if (!hasBefore)
        {
            hasBefore = _lastObservedEntropyByFile.TryGetValue(key, out beforeEntropy);
        }

        _lastObservedEntropyByFile[key] = sample.Entropy;
        if (!hasBefore)
        {
            return;
        }

        var entropyDelta = sample.Entropy - beforeEntropy;
        var highEntropySpike = sample.Entropy >= EntropyHighThreshold &&
                               entropyDelta >= EntropySpikeDeltaThreshold;
        if (!highEntropySpike)
        {
            return;
        }

        HighEntropySpikeCount++;
        var now = DateTimeOffset.Now;
        if (_lastEntropySpikeFile is null ||
            !key.Equals(_lastEntropySpikeFile, StringComparison.OrdinalIgnoreCase))
        {
            if (_lastEntropySpikeAt == default || now - _lastEntropySpikeAt > EntropyConsecutiveGap)
            {
                HighEntropyConsecutiveSpikeFiles = 1;
            }
            else
            {
                HighEntropyConsecutiveSpikeFiles++;
            }

            _lastEntropySpikeFile = key;
            _lastEntropySpikeAt = now;
        }
    }

    private static string BuildRegionSummary(SuspiciousMemoryRegion region)
    {
        var details = new List<string> { region.Reason };
        if (region.Entropy > 0)
        {
            details.Add($"entropy={region.Entropy:F2}");
        }

        if (region.NullByteRatio > 0)
        {
            details.Add($"null={region.NullByteRatio:P1}");
        }

        return string.Join(", ", details);
    }

    private static bool ShouldTrackEntropyPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || NoisePathFilter.IsIgnorablePath(path))
        {
            return false;
        }

        var ext = Path.GetExtension(path);
        if (string.IsNullOrWhiteSpace(ext))
        {
            return true;
        }

        return !CompressedExtensions.Contains(ext);
    }

    private static string NormalizePathKey(string value) =>
        value.Trim().TrimEnd('\0').Replace('/', '\\');

    private static uint ParseAccessMask(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return 0;
        }

        var normalized = value.Trim();
        var prefixes = new[]
        {
            "access=0x",
            "process-access=0x",
            "thread-access=0x"
        };

        foreach (var prefix in prefixes)
        {
            if (!normalized.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return uint.TryParse(
                normalized[prefix.Length..],
                System.Globalization.NumberStyles.HexNumber,
                System.Globalization.CultureInfo.InvariantCulture,
                out var parsed)
                ? parsed
                : 0;
        }

        return 0;
    }

    private static bool IsThreadHandleAccess(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return value.Trim().StartsWith("thread-access=0x", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSystemDir(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        return path.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(@"\Windows\", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@"\System32\", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@"\SysWOW64\", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@"\WinSxS\", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDllLikeImagePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var ext = Path.GetExtension(path.Trim().TrimEnd('\0'));
        return ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".ocx", StringComparison.OrdinalIgnoreCase);
    }
}

public sealed record MemoryRegionSnapshot(ulong BaseAddress, long Size, uint Protection, string Reason);
public sealed record RemediationRecord(DateTimeOffset Time, string Action, string Detail, bool Success);
public sealed record LoadedDllInfo(string Path, bool IsSigned, bool IsMicrosoftSigned, DateTimeOffset LoadTime);
