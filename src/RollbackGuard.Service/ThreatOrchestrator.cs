using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using RollbackGuard.Common.Diagnostics;
using RollbackGuard.Common.Models;
using RollbackGuard.Common.Protocol;
using RollbackGuard.Common.Security;
using RollbackGuard.Service.Engine;
using RollbackGuard.Service.Infra;
using RollbackGuard.Service.Interaction;
using RollbackGuard.Service.Rollback;

namespace RollbackGuard.Service;

public sealed class ThreatOrchestrator
{
    private static readonly TimeSpan PreRollbackDrainMinWindow = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan PreRollbackDrainMaxWindow = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan PreRollbackDrainQuietWindow = TimeSpan.FromMilliseconds(700);
    private static readonly TimeSpan PreRollbackDrainPoll = TimeSpan.FromMilliseconds(120);
    private static readonly TimeSpan MemoryScanCooldown = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan StartupMemoryGuardWindow = TimeSpan.FromMilliseconds(900);
    private static readonly TimeSpan StartupMemoryGuardPoll = TimeSpan.FromMilliseconds(120);
    private static readonly TimeSpan EntropyTrustRefreshCooldown = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan EntropyCompressionProbeCooldown = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan EntropyCallStackProbeCooldown = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan UacRegistryHitWindow = TimeSpan.FromSeconds(45);
    private static readonly TimeSpan UacTriggerWindow = TimeSpan.FromSeconds(25);
    private static readonly HashSet<string> AutoElevatedTriggerNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "fodhelper.exe",
        "computerdefaults.exe",
        "slui.exe",
        "eventvwr.exe",
        "sdclt.exe",
        "compmgmtlauncher.exe",
        "wsreset.exe",
        "cmstp.exe",
        "mmc.exe"
    };
    private static readonly string[] UacBypassRegistryPrefixes =
    [
        "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\Command",
        "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command",
        "HKCU\\Software\\Classes\\CLSID\\",
        "HKCU\\Environment\\windir"
    ];
    private const int DrainReadBurstBatches = 32;
    private const int ManualEnforcementScoreThreshold = 85;
    private const int FastUnsignedBlockScoreThreshold = 50;
    private const int UnsignedStartupWriteDelayMs = 2000;

    private readonly PolicyConfig _policy;
    private readonly RiskEngine _riskEngine;
    private readonly DriverCommandBridge _bridge;
    private readonly DriverCommandBridge _miniBridge;
    private readonly RollbackJournal _journal;
    private readonly IUserApprovalGate _approvalGate;
    private readonly ProcessContextManager _contextManager;
    private readonly BinaryTrustCache _binaryTrustCache;
    private readonly BehaviorChainEngine _behaviorChain;
    private readonly HoneypotManager _honeypot;
    private readonly ProcessTree _processTree;
    private readonly BackupSpaceManager _backupSpaceManager;
    private readonly MemoryScanner? _memoryScanner;
    private readonly ShellcodeRemediator? _remediator;
    private readonly Dictionary<int, List<TelemetryEvent>> _eventBuckets = [];
    private readonly HashSet<int> _terminatedProcesses = [];
    private readonly HashSet<int> _rollbackApprovedProcesses = [];
    private readonly HashSet<int> _rollbackFinalizedProcesses = [];
    private readonly Dictionary<int, UacRegistryHitState> _uacRegistryHits = [];
    private readonly Dictionary<int, UacTriggerState> _uacTriggers = [];
    private readonly HashSet<int> _uacHandledResultPids = [];
    private readonly ConcurrentQueue<TelemetryEvent> _syntheticTelemetry = [];

    public ThreatOrchestrator(
        PolicyConfig policy,
        RiskEngine riskEngine,
        DriverCommandBridge bridge,
        DriverCommandBridge miniBridge,
        RollbackJournal journal,
        IUserApprovalGate approvalGate,
        ProcessContextManager contextManager,
        BinaryTrustCache binaryTrustCache,
        BehaviorChainEngine behaviorChain,
        HoneypotManager honeypot,
        ProcessTree? processTree = null,
        BackupSpaceManager? backupSpaceManager = null,
        MemoryScanner? memoryScanner = null,
        ShellcodeRemediator? remediator = null)
    {
        _policy = policy;
        _riskEngine = riskEngine;
        _bridge = bridge;
        _miniBridge = miniBridge;
        _journal = journal;
        _approvalGate = approvalGate;
        _contextManager = contextManager;
        _binaryTrustCache = binaryTrustCache;
        _behaviorChain = behaviorChain;
        _honeypot = honeypot;
        _processTree = processTree ?? new ProcessTree();
        _backupSpaceManager = backupSpaceManager ?? new BackupSpaceManager(journal.FileRoot);
        _memoryScanner = memoryScanner;
        _remediator = remediator;
    }

    public int PendingRollbackEntries => _journal.PendingEntriesCount;

    public List<TelemetryEvent> DrainSyntheticTelemetry()
    {
        var drained = new List<TelemetryEvent>();
        while (_syntheticTelemetry.TryDequeue(out var item))
        {
            drained.Add(item);
        }

        return drained;
    }

    public void IngestSyntheticMemoryEvent(int pid, MemoryScanResult result)
    {
        var context = _contextManager.Get(pid);
        if (context == null)
        {
            return;
        }

        EnsureResolvedProcessIdentity(pid, context);

        if (ShouldSkipUserModeMemoryInspection(context))
        {
            return;
        }

        foreach (var evt in BuildSyntheticMemoryEvents(context, result))
        {
            _syntheticTelemetry.Enqueue(evt);
        }
#if false



        
        {
            StartupLog.Write("MemScan", $"内存扫描失败 pid={telemetryEvent.TargetProcessId}, reason=inline-target-{telemetryEvent.Kind}: {ex.Message}");
        }
#endif
    }

    public OrchestratorResult Ingest(TelemetryEvent telemetryEvent)
    {
        telemetryEvent = EnrichProcessIdentity(telemetryEvent);
        if (telemetryEvent.Kind == EventKind.ProcessCreate && telemetryEvent.ProcessId > 0)
        {
            var parentProcessPath = ResolveParentProcessPath(telemetryEvent.ParentProcessId);
            if (!string.IsNullOrWhiteSpace(parentProcessPath))
            {
                telemetryEvent = telemetryEvent with { ParentProcessPath = parentProcessPath };
            }

            ResetProcessStateForNewProcess(telemetryEvent.ProcessId);
            _contextManager.InitFromProcessCreate(telemetryEvent);
            _processTree.RegisterProcess(
                telemetryEvent.ProcessId,
                telemetryEvent.ParentProcessId,
                telemetryEvent.ProcessPath,
                telemetryEvent.Timestamp);

            var lolMatch = LolBinDetector.Evaluate(telemetryEvent.ProcessPath);
            if (lolMatch != null)
            {
                var ctx = _contextManager.GetOrCreate(telemetryEvent.ProcessId, telemetryEvent.ProcessPath);
                ctx.IsLolBinProcess = true;
                ctx.LolBinType = lolMatch.Category;
            }

            var persistCreate = PersistenceDetector.EvaluateProcessCreate(telemetryEvent.ProcessPath);
            if (persistCreate != null)
            {
                var ctx = _contextManager.GetOrCreate(telemetryEvent.ProcessId, telemetryEvent.ProcessPath);
                ctx.PersistenceAttempts++;
                if (!ctx.PersistenceTypes.Contains(persistCreate.Type))
                {
                    ctx.PersistenceTypes.Add(persistCreate.Type);
                }
            }
        }

        if (telemetryEvent.Kind == EventKind.ProcessTerminate && telemetryEvent.ProcessId > 0)
        {
            _contextManager.MarkTerminated(telemetryEvent.ProcessId);
            _processTree.MarkTerminated(telemetryEvent.ProcessId);
            _ = _miniBridge.TryClearRestrictedProcess(telemetryEvent.ProcessId, out _);
            _ = _miniBridge.TryClearProcessTrust(telemetryEvent.ProcessId, out _);
        }

        var effectiveEvent = DetectHoneypotAccess(telemetryEvent);
        if (NoisePathFilter.IsIgnorableFileEvent(effectiveEvent))
        {
            var ignored = new ThreatDecision(SecurityAction.Allow, 0, "noise-file-ignored", effectiveEvent.Timestamp);
            return new OrchestratorResult(ignored, 0, true, "noise-file-ignored");
        }

        var context = _contextManager.GetOrCreate(effectiveEvent.ProcessId, effectiveEvent.ProcessPath);
        EnsureProcessTrustTier(effectiveEvent, context);
        context.UpdateFromEvent(effectiveEvent);
        CorrelateCrossProcessEvent(effectiveEvent);
        EnsureModuleTrustTier(effectiveEvent, context);
        ApplyKernelEntropySecondaryAnalysis(effectiveEvent, context);

        if (IsSyntheticMemoryEvent(effectiveEvent.Kind) &&
            ShouldSkipUserModeMemoryInspection(context))
        {
            var suppressed = new ThreatDecision(
                SecurityAction.Allow,
                0,
                "trusted-windows-memory-skip",
                effectiveEvent.Timestamp);
            return new OrchestratorResult(suppressed, 0, true, "trusted-windows-memory-skip");
        }

        if (IsSyntheticMemoryEvent(effectiveEvent.Kind) &&
            context.RecentlyRemediatedMemory &&
            IsStabilityCriticalProcess(context, effectiveEvent.ProcessPath))
        {
            var suppressed = new ThreatDecision(
                SecurityAction.Allow,
                0,
                "recent-critical-memory-remediation-skip",
                effectiveEvent.Timestamp);
            return new OrchestratorResult(suppressed, 0, true, "recent-critical-memory-remediation-skip");
        }

        if (TrustedProcessValidator.IsRollbackGuardBinary(context.ImageName) ||
            TrustedProcessValidator.IsRollbackGuardBinary(effectiveEvent.ProcessPath))
        {
            var allowSelf = new ThreatDecision(SecurityAction.Allow, 0, "rollbackguard-self-process", effectiveEvent.Timestamp);
            return new OrchestratorResult(allowSelf, 0, true, "rollbackguard-self-process");
        }

        if (effectiveEvent.Kind is EventKind.RegistrySet or EventKind.RegistryDelete)
        {
            var persistReg = PersistenceDetector.EvaluateRegistryEvent(effectiveEvent.TargetPath);
            if (persistReg != null)
            {
                context.PersistenceAttempts++;
                if (!context.PersistenceTypes.Contains(persistReg.Type))
                {
                    context.PersistenceTypes.Add(persistReg.Type);
                }
            }
        }

        if (effectiveEvent.Kind is EventKind.FileWrite or EventKind.FileCreate or EventKind.FileRename)
        {
            var persistFile = PersistenceDetector.EvaluateFileEvent(effectiveEvent.TargetPath);
            if (persistFile != null)
            {
                context.PersistenceAttempts++;
                if (!context.PersistenceTypes.Contains(persistFile.Type))
                {
                    context.PersistenceTypes.Add(persistFile.Type);
                }
            }
        }

        var ancestorAnalysis = _processTree.AnalyzeAncestors(effectiveEvent.ProcessId);
        if (ancestorAnalysis.IsSuspicious && ancestorAnalysis.SuspicionScore > 0)
        {
            context.Score += ancestorAnalysis.SuspicionScore;
        }

        TryRunInlineMemoryScan(context, effectiveEvent);

        if (!_eventBuckets.TryGetValue(effectiveEvent.ProcessId, out var bucket))
        {
            bucket = [];
            _eventBuckets[effectiveEvent.ProcessId] = bucket;
        }

        bucket.Add(effectiveEvent);
        var windowStart = DateTimeOffset.Now.AddSeconds(-_policy.TimeWindowSeconds);
        bucket.RemoveAll(item => item.Timestamp < windowStart);

        if (!ShouldSkipSnapshotCapture(effectiveEvent.ProcessId) &&
            ShouldCaptureRollbackSnapshot(effectiveEvent, context))
        {
            CaptureRollbackSnapshots(effectiveEvent);
        }

        if (TryHandleImmediateUacBypass(effectiveEvent, out var uacBypassResult))
        {
            return uacBypassResult;
        }

        if (!IsSyntheticMemoryEvent(effectiveEvent.Kind) &&
            effectiveEvent.Kind != EventKind.HoneyFileTouched &&
            effectiveEvent.Kind != EventKind.ShadowDeleteAttempt)
        {
            if (IsMicrosoftSignedProcessClean(context))
            {
                var allow = new ThreatDecision(SecurityAction.Allow, 0, "microsoft-signed-clean-chain", effectiveEvent.Timestamp);
                return new OrchestratorResult(allow, 0, true, "microsoft-signed-clean-chain");
            }

            if (IsAllowListedProcess(effectiveEvent.ProcessPath) &&
                context.IsMicrosoftSignedProcess &&
                !HasUnsignedOrUntrustedImage(context))
            {
                var allow = new ThreatDecision(SecurityAction.Allow, 0, "allowlist-clean", effectiveEvent.Timestamp);
                return new OrchestratorResult(allow, 0, true, "allowlist-clean");
            }
        }

        var chainResults = _behaviorChain.Evaluate(context, effectiveEvent);
        var chainExtraScore = 0;
        var chainReasons = new List<string>();
        foreach (var cr in chainResults)
        {
            chainExtraScore += cr.ExtraScore;
            chainReasons.Add($"{cr.RuleName}+{cr.ExtraScore}");
        }

        var decision = _riskEngine.Evaluate(_policy, context, bucket);
        var totalScore = (int)decision.Score + chainExtraScore + ancestorAnalysis.SuspicionScore;
        totalScore = Math.Max(0, totalScore);
        context.UpdateState(totalScore);

        var combinedReason = decision.Reason;
        if (chainReasons.Count > 0)
        {
            combinedReason += ";" + string.Join(";", chainReasons);
        }

        if (ancestorAnalysis.IsSuspicious)
        {
            combinedReason += $";ancestor({ancestorAnalysis.Reason})+{ancestorAnalysis.SuspicionScore}";
        }

        var hasUnsignedExecutionEvidence = HasUnsignedExecutionEvidence(context, effectiveEvent);
        var hasHighConfidenceExecutionCompromise = HasHighConfidenceExecutionCompromise(context);
        if (!hasUnsignedExecutionEvidence)
        {
            if (hasHighConfidenceExecutionCompromise && IsStabilityCriticalProcess(context, effectiveEvent.ProcessPath))
            {
                var correlatedContainment = TryExecuteCorrelatedSourceContainment(
                    effectiveEvent,
                    context,
                    decision with
                    {
                        Score = totalScore,
                        Reason = combinedReason
                    });
                if (correlatedContainment != null)
                {
                    return correlatedContainment;
                }

                return ExecuteCriticalProcessRemediation(effectiveEvent, context, decision with
                {
                    Score = totalScore,
                    Reason = combinedReason
                });
            }
        }

        var enforcementThreshold = Math.Max(_policy.ScoreMalicious, ManualEnforcementScoreThreshold);
        if (totalScore >= enforcementThreshold &&
            ShouldPromptForFastContainment(effectiveEvent, context, totalScore, chainResults))
        {
            var fastDecision = decision with
            {
                Action = SecurityAction.Terminate,
                Score = totalScore,
                Reason = string.IsNullOrWhiteSpace(combinedReason)
                    ? "fast-manual-contain"
                    : $"{combinedReason};fast-manual-contain"
            };
            return ExecuteManualEnforcement(effectiveEvent, fastDecision);
        }

        var finalAction = totalScore >= enforcementThreshold
            ? SecurityAction.Terminate
            : SecurityAction.Allow;

        decision = decision with { Action = finalAction, Score = totalScore, Reason = combinedReason };
        if (decision.Action != SecurityAction.Terminate)
        {
            return new OrchestratorResult(decision, 0, true, "allow");
        }

        if (effectiveEvent.ProcessId <= 4)
        {
            var skipUnknownPid = decision with
            {
                Action = SecurityAction.Allow,
                Reason = $"{decision.Reason}; reserved-pid-no-enforce"
            };
            return new OrchestratorResult(skipUnknownPid, 0, true, "reserved-pid-no-enforce");
        }

        if (IsStabilityCriticalProcess(context, effectiveEvent.ProcessPath))
        {
            return ExecuteCriticalProcessRemediation(effectiveEvent, context, decision);
        }

        if (_terminatedProcesses.Contains(effectiveEvent.ProcessId))
        {
            return HandleTerminatedProcessEvent(effectiveEvent, decision);
        }

        if (ShouldPromptExitedProcessRollback(effectiveEvent, decision))
        {
            return ExecuteExitedProcessRollback(effectiveEvent, decision);
        }

        return ExecuteManualEnforcement(effectiveEvent, decision);
    }

    private void TryRunInlineMemoryScan(ProcessContext context, TelemetryEvent telemetryEvent)
    {
        if (_memoryScanner == null)
        {
            return;
        }

        if (ShouldSkipUserModeMemoryInspection(context))
        {
            return;
        }

        var shouldScan =
            telemetryEvent.ProcessId > 4 &&
            (context.Score >= 15 ||
             telemetryEvent.Kind is EventKind.ProcessInject or EventKind.ThreadCreateRemote);
        if (!shouldScan || DateTimeOffset.Now - context.LastMemoryScanTime < MemoryScanCooldown)
        {
            goto ScanTargetProcess;
        }

        try
        {
            var result = _memoryScanner.ScanProcess(telemetryEvent.ProcessId);
            context.ApplyEnhancedMemoryScan(result);
            if (!result.IsSuspicious)
            {
                goto ScanTargetProcess;
            }

            foreach (var synthetic in BuildSyntheticMemoryEvents(context, result))
            {
                _syntheticTelemetry.Enqueue(synthetic);
            }

            StartupLog.WriteDetection(
                "Detection",
                $"内存扫描命中 pid={telemetryEvent.ProcessId}, rwx={result.RwxRegionCount}, unbacked={result.UnbackedExecRegionCount}, wx={result.WxTransitionCount}, reflective={result.ReflectiveDllCount}");
        }
        catch (Exception ex)
        {
            StartupLog.Write("MemScan", $"内存扫描失败 pid={telemetryEvent.ProcessId}: {ex.Message}");
        }
    ScanTargetProcess:
        if (telemetryEvent.TargetProcessId <= 4 ||
            telemetryEvent.TargetProcessId == telemetryEvent.ProcessId ||
            telemetryEvent.Kind is not (EventKind.ProcessInject or EventKind.ThreadCreateRemote))
        {
            return;
        }

        var targetContext = _contextManager.GetOrCreate(telemetryEvent.TargetProcessId);
        if (ShouldSkipUserModeMemoryInspection(targetContext))
        {
            return;
        }

        if (DateTimeOffset.Now - targetContext.LastMemoryScanTime < MemoryScanCooldown)
        {
            return;
        }

        TryRunSuspendedStartupScanAttempt(telemetryEvent.TargetProcessId, targetContext, $"inline-target-{telemetryEvent.Kind}");
    }

    private IEnumerable<TelemetryEvent> BuildSyntheticMemoryEvents(ProcessContext context, MemoryScanResult result)
    {
        var summary = BuildMemoryScanSummary(result);
        var target = BuildMemoryRegionSummary(result);
        var unsigned = context.CurrentTrustTier == ExecutionTrustTier.Unsigned;

        if (result.ShellcodePatternCount > 0 || result.AmsiDetectionCount > 0)
            yield return BuildSyntheticMemoryEvent(EventKind.MemoryScanShellcode, context, target, summary, unsigned);
        if (result.RwxRegionCount > 0)
            yield return BuildSyntheticMemoryEvent(EventKind.MemoryScanRwx, context, target, summary, unsigned);
        if (result.UnbackedExecRegionCount > 0)
            yield return BuildSyntheticMemoryEvent(EventKind.MemoryScanUnbackedExec, context, target, summary, unsigned);
        if (result.WxTransitionCount > 0)
            yield return BuildSyntheticMemoryEvent(EventKind.MemoryScanWxTransition, context, target, summary, unsigned);
        if (result.ReflectiveDllCount > 0)
            yield return BuildSyntheticMemoryEvent(EventKind.MemoryScanReflectiveDll, context, target, summary, unsigned);
    }

    private static TelemetryEvent BuildSyntheticMemoryEvent(
        EventKind kind,
        ProcessContext context,
        string target,
        string summary,
        bool unsigned)
    {
        return new TelemetryEvent(
            DateTimeOffset.Now,
            kind,
            context.ImageName,
            context.PID,
            target,
            summary,
            null,
            0,
            false,
            false,
            false,
            unsigned);
    }

    private static string BuildMemoryScanSummary(MemoryScanResult result)
    {
        var parts = new List<string>();
        if (result.RwxRegionCount > 0) parts.Add($"memory-rwx({result.RwxRegionCount})");
        if (result.UnbackedExecRegionCount > 0) parts.Add($"unbacked-exec({result.UnbackedExecRegionCount})");
        if (result.WxTransitionCount > 0) parts.Add($"wx-transition({result.WxTransitionCount})");
        if (result.ReflectiveDllCount > 0) parts.Add($"reflective-dll({result.ReflectiveDllCount})");
        if (result.PebWalkPatternCount > 0) parts.Add($"peb-walk({result.PebWalkPatternCount})");
        if (result.ApiHashPatternCount > 0) parts.Add($"api-hash({result.ApiHashPatternCount})");
        if (result.SyscallStubCount > 0) parts.Add($"direct-syscall({result.SyscallStubCount})");
        if (result.HighEntropyRegionCount > 0) parts.Add($"entropy({result.HighEntropyRegionCount})");
        if (result.ShellcodePatternCount > 0) parts.Add($"shellcode({result.ShellcodePatternCount})");
        return string.Join(";", parts);
    }

    private static string BuildMemoryRegionSummary(MemoryScanResult result)
    {
        if (result.SuspiciousRegions.Count == 0)
        {
            return "(无可疑区域)";
        }

        return string.Join(" | ", result.SuspiciousRegions
            .Take(4)
            .Select(region => $"0x{region.BaseAddress:X} size={region.Size} {region.Reason}"));
    }

    private OrchestratorResult ExecuteCriticalProcessRemediation(
        TelemetryEvent telemetryEvent,
        ProcessContext context,
        ThreatDecision decision)
    {
        if (_remediator == null || !context.MemoryScanSuspicious || context.LastScanRegions.Count == 0)
        {
            var skip = decision with
            {
                Action = SecurityAction.Allow,
                Reason = $"{decision.Reason}; stability-critical-no-enforce"
            };
            return new OrchestratorResult(skip, 0, true, "stability-critical-no-enforce");
        }

        var remediation = _remediator.Remediate(telemetryEvent.ProcessId, BuildMemoryScanResultFromContext(context), context);
        var resumed = true;
        var resumeMessage = string.Empty;
        if (remediation.Success && context.IsSuspended)
        {
            resumed = _bridge.TryResumeProcess(telemetryEvent.ProcessId, out resumeMessage);
            if (resumed)
            {
                context.IsSuspended = false;
            }
        }

        var summary = remediation.Success
            ? $"memory-remediation regions={remediation.RegionsRemediated.Count}"
            : $"memory-remediation-failed error={remediation.Error}";
        if (!string.IsNullOrWhiteSpace(remediation.VerificationMessage))
        {
            summary += $"; verify={remediation.VerificationMessage}";
        }
        if (!string.IsNullOrWhiteSpace(resumeMessage) || !resumed)
        {
            summary += $"; resumed={resumed}; resume-msg={resumeMessage}";
        }

        context.AddRemediationRecord("memory-remediation-summary", summary, remediation.Success && resumed);
        if (remediation.Success)
        {
            context.MarkMemoryRemediationSuccess();
        }

        _syntheticTelemetry.Enqueue(new TelemetryEvent(
            DateTimeOffset.Now,
            EventKind.RemediationMemoryZeroed,
            telemetryEvent.ProcessPath,
            telemetryEvent.ProcessId,
            BuildRemediationTarget(remediation),
            summary,
            null,
            0,
            false,
            false,
            false,
            context.CurrentTrustTier == ExecutionTrustTier.Unsigned));

        var allowDecision = decision with
        {
            Action = SecurityAction.Allow,
            Reason = $"{decision.Reason}; stability-critical-remediated"
        };
        return new OrchestratorResult(allowDecision, 0, remediation.Success && resumed, summary);
    }

    private static string BuildRemediationTarget(RemediationResult result)
    {
        if (result.RegionsRemediated.Count == 0)
        {
            return "(无)";
        }

        return string.Join(" | ", result.RegionsRemediated
            .Take(4)
            .Select(region => $"0x{region.BaseAddress:X} size={region.Size} {region.Reason}"));
    }

    private static MemoryScanResult BuildMemoryScanResultFromContext(ProcessContext context)
    {
        return new MemoryScanResult
        {
            ProcessId = context.PID,
            IsSuspicious = context.MemoryScanSuspicious,
            RwxRegionCount = context.MemoryRwxRegionCount,
            ShellcodePatternCount = context.MemoryShellcodePatternCount,
            AmsiDetectionCount = context.MemoryAmsiDetectionCount,
            UnbackedExecRegionCount = context.MemoryUnbackedExecRegionCount,
            HighEntropyRegionCount = context.MemoryHighEntropyRegionCount,
            WxTransitionCount = context.MemoryWxTransitionCount,
            ReflectiveDllCount = context.MemoryReflectiveDllCount,
            PebWalkPatternCount = context.MemoryPebWalkPatternCount,
            ApiHashPatternCount = context.MemoryApiHashPatternCount,
            SyscallStubCount = context.MemorySyscallStubCount,
            SuspiciousRegions = context.LastScanRegions
                .Select(region => new SuspiciousMemoryRegion
                {
                    BaseAddress = region.BaseAddress,
                    Size = region.Size,
                    Protection = region.Protection,
                    Reason = region.Reason
                })
                .ToList()
        };
    }

    private static bool IsSyntheticMemoryEvent(EventKind kind) =>
        kind is EventKind.MemoryScanShellcode or EventKind.MemoryScanRwx or EventKind.MemoryScanUnbackedExec
            or EventKind.MemoryScanWxTransition or EventKind.MemoryScanReflectiveDll or EventKind.RemediationMemoryZeroed;

    private TelemetryEvent DetectHoneypotAccess(TelemetryEvent evt)
    {
        if (evt.Kind is not (EventKind.FileWrite or EventKind.FileRename or EventKind.FileDelete or EventKind.FileCreate))
        {
            return evt;
        }

        if (_honeypot.IsHoneypotPath(evt.TargetPath) || _honeypot.IsHoneypotPath(evt.SourcePath))
        {
            return evt with { Kind = EventKind.HoneyFileTouched };
        }

        return evt;
    }

    private void CorrelateCrossProcessEvent(TelemetryEvent telemetryEvent)
    {
        if (telemetryEvent.TargetProcessId <= 4 || telemetryEvent.TargetProcessId == telemetryEvent.ProcessId)
        {
            return;
        }

        var targetContext = _contextManager.GetOrCreate(telemetryEvent.TargetProcessId);
        EnsureResolvedProcessIdentity(targetContext.PID, targetContext);
        targetContext.LastSuspiciousSourcePid = telemetryEvent.ProcessId;
        targetContext.LastSuspiciousSourceAt = telemetryEvent.Timestamp;
        if (telemetryEvent.Kind == EventKind.ThreadCreateRemote)
        {
            targetContext.WasRemotelyCreated = true;
            return;
        }

        if (telemetryEvent.Kind is EventKind.ProcessInject or EventKind.InjectPrelude)
        {
            targetContext.WasTargetedBySuspiciousHandle = true;
        }
    }

    private bool TryHandleImmediateUacBypass(
        TelemetryEvent telemetryEvent,
        out OrchestratorResult result)
    {
        result = default!;
        var now = telemetryEvent.Timestamp;
        PruneUacTracking(now);

        if (telemetryEvent.Kind == EventKind.ProcessTerminate)
        {
            var terminatedPid = telemetryEvent.ProcessId;
            _uacRegistryHits.Remove(terminatedPid);
            _uacTriggers.Remove(terminatedPid);
            _uacHandledResultPids.Remove(terminatedPid);
            return false;
        }

        if (telemetryEvent.Kind is EventKind.RegistrySet or EventKind.RegistryDelete)
        {
            if (TryMatchUacBypassRegistryPath(telemetryEvent.TargetPath, out var matchedRegistryPath))
            {
                _uacRegistryHits[telemetryEvent.ProcessId] = new UacRegistryHitState
                {
                    SourcePid = telemetryEvent.ProcessId,
                    LastHitAt = now,
                    LastPath = matchedRegistryPath
                };

                StartupLog.WriteDetection(
                    "Detection",
                    $"uac-registry-hit pid={telemetryEvent.ProcessId}, path={matchedRegistryPath}, op={telemetryEvent.Kind}");
            }

            return false;
        }

        if (telemetryEvent.Kind != EventKind.ProcessCreate)
        {
            return false;
        }

        var processName = Path.GetFileName(telemetryEvent.ProcessPath);
        var isAutoElevatedTrigger = !string.IsNullOrWhiteSpace(processName) && AutoElevatedTriggerNames.Contains(processName);
        if (isAutoElevatedTrigger &&
            TryGetRecentRegistryHitByLineage(
                telemetryEvent.ParentProcessId,
                now,
                out var parentHit,
                out var registryHitMatchMode,
                out var registryAnchorPid))
        {
            _uacTriggers[telemetryEvent.ProcessId] = new UacTriggerState
            {
                TriggerPid = telemetryEvent.ProcessId,
                SourcePid = parentHit.SourcePid,
                TriggeredAt = now,
                TriggerPath = telemetryEvent.ProcessPath,
                MatchedRegistryPath = parentHit.LastPath,
                RegistryHitMatchMode = registryHitMatchMode,
                RegistryAnchorPid = registryAnchorPid
            };

            StartupLog.WriteDetection(
                "Detection",
                $"uac-trigger pid={telemetryEvent.ProcessId}, parent={telemetryEvent.ParentProcessId}, trigger={processName}, path={telemetryEvent.ProcessPath}, registry={parentHit.LastPath}, match={registryHitMatchMode}, anchorPid={registryAnchorPid}");
        }

        if (telemetryEvent.IntegrityLevel != ProcessIntegrityLevel.High)
        {
            return false;
        }

        if (_uacHandledResultPids.Contains(telemetryEvent.ProcessId))
        {
            return false;
        }

        UacTriggerState? matchedTrigger = null;
        if (_uacTriggers.TryGetValue(telemetryEvent.ParentProcessId, out var triggerState) &&
            now - triggerState.TriggeredAt <= UacTriggerWindow)
        {
            var sourcePid = triggerState.SourcePid;
            var matchedRegistryPath = triggerState.MatchedRegistryPath;
            if (TryGetRecentRegistryHit(triggerState.SourcePid, now, out var sourceHit))
            {
                sourcePid = sourceHit.SourcePid;
                matchedRegistryPath = sourceHit.LastPath;
            }

            matchedTrigger = new UacTriggerState
            {
                TriggerPid = triggerState.TriggerPid,
                SourcePid = sourcePid,
                TriggeredAt = triggerState.TriggeredAt,
                TriggerPath = triggerState.TriggerPath,
                MatchedRegistryPath = matchedRegistryPath,
                RegistryHitMatchMode = triggerState.RegistryHitMatchMode,
                RegistryAnchorPid = triggerState.RegistryAnchorPid
            };
        }
        else if (isAutoElevatedTrigger &&
                 TryGetRecentRegistryHitByLineage(
                     telemetryEvent.ParentProcessId,
                     now,
                     out var directParentHit,
                     out var directParentMatchMode,
                     out var directParentAnchorPid))
        {
            // Trigger process itself already came up as high integrity.
            matchedTrigger = new UacTriggerState
            {
                TriggerPid = telemetryEvent.ProcessId,
                SourcePid = directParentHit.SourcePid,
                TriggeredAt = now,
                TriggerPath = telemetryEvent.ProcessPath,
                MatchedRegistryPath = directParentHit.LastPath,
                RegistryHitMatchMode = directParentMatchMode,
                RegistryAnchorPid = directParentAnchorPid
            };
        }

        if (matchedTrigger == null)
        {
            return false;
        }

        _uacHandledResultPids.Add(telemetryEvent.ProcessId);
        result = ExecuteImmediateUacBypassContainment(telemetryEvent, matchedTrigger);
        return true;
    }

    private OrchestratorResult ExecuteImmediateUacBypassContainment(
        TelemetryEvent telemetryEvent,
        UacTriggerState trigger)
    {
        var triggerName = Path.GetFileName(trigger.TriggerPath);
        var matchMode = string.IsNullOrWhiteSpace(trigger.RegistryHitMatchMode)
            ? "direct-pid"
            : trigger.RegistryHitMatchMode;
        var reason =
            $"uac-bypass-direct;registry={trigger.MatchedRegistryPath};trigger={triggerName};sourcePid={trigger.SourcePid};resultIntegrity={telemetryEvent.IntegrityLevel};registryMatch={matchMode};anchorPid={trigger.RegistryAnchorPid}";

        var cleanupMessage = TryRollbackUacRegistryArtifacts(trigger.SourcePid);
        var decision = new ThreatDecision(SecurityAction.Terminate, 100, reason, telemetryEvent.Timestamp);

        StartupLog.WriteDetection(
            "Detection",
            $"uac-bypass-direct-hit sourcePid={trigger.SourcePid}, triggerPid={trigger.TriggerPid}, resultPid={telemetryEvent.ProcessId}, trigger={trigger.TriggerPath}, registry={trigger.MatchedRegistryPath}, integrity={telemetryEvent.IntegrityLevel}, match={matchMode}, anchorPid={trigger.RegistryAnchorPid}, cleanup={cleanupMessage}");

        var enforcementResult = ExecuteManualEnforcement(telemetryEvent, decision);
        var mergedMessage = AppendMessage(cleanupMessage, enforcementResult.DriverMessage);
        return enforcementResult with { DriverMessage = mergedMessage };
    }

    private string TryRollbackUacRegistryArtifacts(int sourcePid)
    {
        if (sourcePid <= 4)
        {
            return "uac-registry-cleanup-skip-source";
        }

        var pendingEntries = _journal.PendingEntriesCountForProcess(sourcePid);
        if (pendingEntries <= 0)
        {
            return "uac-registry-cleanup-no-pending";
        }

        try
        {
            var rollback = _journal.RollbackProcess(sourcePid);
            if (rollback.Errors.Count > 0)
            {
                return $"uac-registry-cleanup errors={rollback.Errors.Count}, processed={rollback.Processed}";
            }

            return $"uac-registry-cleanup ok={rollback.Processed}";
        }
        catch (Exception ex)
        {
            return $"uac-registry-cleanup-exception={ex.Message}";
        }
    }

    private void PruneUacTracking(DateTimeOffset now)
    {
        var staleRegistryPids = _uacRegistryHits
            .Where(pair => now - pair.Value.LastHitAt > UacRegistryHitWindow)
            .Select(pair => pair.Key)
            .ToList();
        foreach (var pid in staleRegistryPids)
        {
            _uacRegistryHits.Remove(pid);
        }

        var staleTriggerPids = _uacTriggers
            .Where(pair => now - pair.Value.TriggeredAt > UacTriggerWindow)
            .Select(pair => pair.Key)
            .ToList();
        foreach (var pid in staleTriggerPids)
        {
            _uacTriggers.Remove(pid);
        }
    }

    private bool TryGetRecentRegistryHit(int sourcePid, DateTimeOffset now, out UacRegistryHitState state)
    {
        state = default!;
        if (sourcePid <= 4)
        {
            return false;
        }

        if (!_uacRegistryHits.TryGetValue(sourcePid, out var hit))
        {
            return false;
        }

        if (now - hit.LastHitAt > UacRegistryHitWindow)
        {
            _uacRegistryHits.Remove(sourcePid);
            return false;
        }

        state = hit;
        return true;
    }

    private bool TryGetRecentRegistryHitByLineage(
        int sourcePid,
        DateTimeOffset now,
        out UacRegistryHitState state,
        out string matchMode,
        out int anchorPid)
    {
        state = default!;
        matchMode = string.Empty;
        anchorPid = 0;

        if (TryGetRecentRegistryHit(sourcePid, now, out state))
        {
            matchMode = "direct-pid";
            anchorPid = sourcePid;
            return true;
        }

        if (sourcePid <= 4)
        {
            return false;
        }

        var recentHits = GetRecentRegistryHits(now);
        if (recentHits.Count == 0)
        {
            return false;
        }

        if (TryGetParentProcessId(sourcePid, out var sourceParentPid) && sourceParentPid > 4)
        {
            foreach (var candidate in recentHits)
            {
                if (candidate.SourcePid == sourcePid)
                {
                    continue;
                }

                if (!TryGetParentProcessId(candidate.SourcePid, out var candidateParentPid))
                {
                    continue;
                }

                if (candidateParentPid != sourceParentPid || candidateParentPid <= 4)
                {
                    continue;
                }

                state = candidate;
                matchMode = "same-parent-lineage";
                anchorPid = sourceParentPid;
                return true;
            }
        }

        foreach (var candidate in recentHits)
        {
            if (candidate.SourcePid == sourcePid)
            {
                continue;
            }

            if (!TryFindStrongSharedAncestor(
                    sourcePid,
                    candidate.SourcePid,
                    maxDepth: 4,
                    maxHopFromLeaf: 2,
                    out var sharedAncestorPid,
                    out var sharedAncestorName))
            {
                continue;
            }

            state = candidate;
            matchMode = $"shared-ancestor({sharedAncestorName})";
            anchorPid = sharedAncestorPid;
            return true;
        }

        return false;
    }

    private List<UacRegistryHitState> GetRecentRegistryHits(DateTimeOffset now)
    {
        var recentHits = new List<UacRegistryHitState>();
        var stalePids = new List<int>();
        foreach (var pair in _uacRegistryHits)
        {
            if (now - pair.Value.LastHitAt > UacRegistryHitWindow)
            {
                stalePids.Add(pair.Key);
                continue;
            }

            recentHits.Add(pair.Value);
        }

        foreach (var pid in stalePids)
        {
            _uacRegistryHits.Remove(pid);
        }

        recentHits.Sort((left, right) => right.LastHitAt.CompareTo(left.LastHitAt));
        return recentHits;
    }

    private bool TryGetParentProcessId(int pid, out int parentPid)
    {
        parentPid = 0;
        if (pid <= 4)
        {
            return false;
        }

        var chain = _processTree.GetAncestorChain(pid, maxDepth: 2);
        if (chain.Count >= 2)
        {
            parentPid = chain[1].PID;
            if (parentPid > 0)
            {
                return true;
            }
        }

        var context = _contextManager.Get(pid);
        if (context != null && context.PPID > 0)
        {
            parentPid = context.PPID;
            return true;
        }

        return false;
    }

    private bool TryFindStrongSharedAncestor(
        int leftPid,
        int rightPid,
        int maxDepth,
        int maxHopFromLeaf,
        out int sharedAncestorPid,
        out string sharedAncestorName)
    {
        sharedAncestorPid = 0;
        sharedAncestorName = string.Empty;

        if (leftPid <= 4 || rightPid <= 4)
        {
            return false;
        }

        var leftChain = _processTree.GetAncestorChain(leftPid, maxDepth);
        var rightChain = _processTree.GetAncestorChain(rightPid, maxDepth);
        if (leftChain.Count == 0 || rightChain.Count == 0)
        {
            return false;
        }

        var bestScore = int.MaxValue;
        for (var leftDepth = 0; leftDepth < leftChain.Count; leftDepth++)
        {
            if (leftDepth > maxHopFromLeaf)
            {
                break;
            }

            var leftNode = leftChain[leftDepth];
            if (leftNode.PID <= 4)
            {
                continue;
            }

            for (var rightDepth = 0; rightDepth < rightChain.Count; rightDepth++)
            {
                if (rightDepth > maxHopFromLeaf)
                {
                    break;
                }

                var rightNode = rightChain[rightDepth];
                if (leftNode.PID != rightNode.PID)
                {
                    continue;
                }

                var ancestorName = !string.IsNullOrWhiteSpace(leftNode.ProcessName)
                    ? leftNode.ProcessName
                    : rightNode.ProcessName;
                if (IsWeakLineageAnchor(ancestorName))
                {
                    continue;
                }

                var score = leftDepth + rightDepth;
                if (score >= bestScore)
                {
                    continue;
                }

                bestScore = score;
                sharedAncestorPid = leftNode.PID;
                sharedAncestorName = ancestorName;
            }
        }

        return sharedAncestorPid > 4;
    }

    private static bool IsWeakLineageAnchor(string processName)
    {
        if (string.IsNullOrWhiteSpace(processName))
        {
            return true;
        }

        var normalized = processName.Trim().ToLowerInvariant();
        return normalized is
            "explorer.exe" or
            "cmd.exe" or
            "powershell.exe" or
            "pwsh.exe" or
            "conhost.exe" or
            "svchost.exe" or
            "services.exe" or
            "wininit.exe" or
            "smss.exe";
    }

    private static bool TryMatchUacBypassRegistryPath(string? rawPath, out string normalizedPath)
    {
        normalizedPath = NormalizeRegistryPath(rawPath);
        if (string.IsNullOrWhiteSpace(normalizedPath))
        {
            return false;
        }

        foreach (var prefix in UacBypassRegistryPrefixes)
        {
            if (normalizedPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        if (normalizedPath.EndsWith("\\DelegateExecute", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (normalizedPath.Contains("\\Software\\Classes\\CLSID\\", StringComparison.OrdinalIgnoreCase) &&
            (normalizedPath.EndsWith("\\InprocServer32", StringComparison.OrdinalIgnoreCase) ||
             normalizedPath.EndsWith("\\LocalServer32", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return false;
    }

    private static string NormalizeRegistryPath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim();
        while (normalized.Contains(@"\\", StringComparison.Ordinal))
        {
            normalized = normalized.Replace(@"\\", @"\", StringComparison.Ordinal);
        }

        if (normalized.StartsWith(@"\REGISTRY\MACHINE\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = "HKLM\\" + normalized[@"\REGISTRY\MACHINE\".Length..];
        }
        else if (normalized.StartsWith(@"\REGISTRY\USER\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = "HKU\\" + normalized[@"\REGISTRY\USER\".Length..];
        }
        else if (normalized.StartsWith(@"HKEY_CURRENT_USER\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = "HKCU\\" + normalized[@"HKEY_CURRENT_USER\".Length..];
        }
        else if (normalized.StartsWith(@"HKEY_LOCAL_MACHINE\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = "HKLM\\" + normalized[@"HKEY_LOCAL_MACHINE\".Length..];
        }
        else if (normalized.StartsWith(@"HKEY_USERS\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = "HKU\\" + normalized[@"HKEY_USERS\".Length..];
        }

        if (normalized.StartsWith(@"HKU\", StringComparison.OrdinalIgnoreCase))
        {
            var rest = normalized[4..];
            var slash = rest.IndexOf('\\');
            if (slash > 0)
            {
                var sid = rest[..slash];
                if (sid.StartsWith("S-1-5-", StringComparison.OrdinalIgnoreCase))
                {
                    normalized = "HKCU\\" + rest[(slash + 1)..];
                }
            }
        }

        return normalized;
    }

    private OrchestratorResult ExecuteManualEnforcement(TelemetryEvent telemetryEvent, ThreatDecision originalDecision)
    {
        var pid = telemetryEvent.ProcessId;
        var enforceDecision = originalDecision with { Action = SecurityAction.Terminate };
        _rollbackFinalizedProcesses.Remove(pid);
        var pendingForProcess = _journal.PendingEntriesCountForProcess(pid);
        var writeBlocked = _miniBridge.TryBlockProcessWrites(pid, out var writeBlockMessage);

        var suspended = false;
        var suspendMessage = string.Empty;
        var suspendUnsupported = false;
        for (var i = 0; i < 3; i++)
        {
            suspended = _bridge.TrySuspendProcess(pid, out suspendMessage);
            if (suspended)
            {
                break;
            }

            if (IsNotSupportedError(suspendMessage))
            {
                suspendUnsupported = true;
                break;
            }
        }

        var containmentSummary = BuildContainmentSummary(writeBlocked, writeBlockMessage, suspended, suspendUnsupported, suspendMessage);
        var enforcementChoice = _approvalGate.RequestEnforcement(
            telemetryEvent,
            enforceDecision,
            containmentSummary,
            pendingForProcess,
            out var approvalAudit);

        if (enforcementChoice == EnforcementChoice.Ignore)
        {
            _rollbackApprovedProcesses.Remove(pid);
            _rollbackFinalizedProcesses.Remove(pid);
            var resumed = true;
            var resumeMessage = string.Empty;
            if (suspended)
            {
                resumed = _bridge.TryResumeProcess(pid, out resumeMessage);
            }

            var allowDecision = enforceDecision with
            {
                Action = SecurityAction.Allow,
                Reason = $"{originalDecision.Reason}; user-ignore"
            };

            var allMessage = approvalAudit;
            allMessage = AppendMessage(allMessage, containmentSummary);
            allMessage = AppendMessage(allMessage, writeBlockMessage);
            if (suspended)
            {
                allMessage = AppendMessage(allMessage, resumeMessage);
                var unblockedAfterIgnore = _miniBridge.TryUnblockProcessWrites(pid, out var unblockAfterIgnoreMessage);
                allMessage = AppendMessage(allMessage, unblockAfterIgnoreMessage);
                return new OrchestratorResult(allowDecision, 0, resumed && unblockedAfterIgnore, allMessage);
            }

            allMessage = AppendMessage(allMessage, suspendUnsupported ? "suspend-not-supported-skip" : suspendMessage);
            var unblockedNoSuspend = _miniBridge.TryUnblockProcessWrites(pid, out var unblockNoSuspendMessage);
            allMessage = AppendMessage(allMessage, unblockNoSuspendMessage);
            return new OrchestratorResult(allowDecision, 0, unblockedNoSuspend, allMessage);
        }

        var terminateOk = _bridge.TryTerminateProcess(pid, out var terminateMessage);
        var executeMessage = AppendMessage(suspendMessage, approvalAudit);
        executeMessage = AppendMessage(executeMessage, containmentSummary);
        executeMessage = AppendMessage(executeMessage, writeBlockMessage);
        executeMessage = AppendMessage(executeMessage, terminateMessage);

        if (!terminateOk && IsProcessGoneOrInvalid(terminateMessage))
        {
            executeMessage = AppendMessage(executeMessage, "terminate-race-process-gone-proceed-rollback");
            terminateOk = true;
        }

        if (!terminateOk)
        {
            _rollbackApprovedProcesses.Remove(pid);
            _rollbackFinalizedProcesses.Remove(pid);
            if (suspended)
            {
                var resumeAfterFailOk = _bridge.TryResumeProcess(pid, out var resumeAfterFailMessage);
                executeMessage = AppendMessage(executeMessage, resumeAfterFailMessage);
                var unblockAfterFailOk = _miniBridge.TryUnblockProcessWrites(pid, out var unblockAfterFailMessage);
                executeMessage = AppendMessage(executeMessage, unblockAfterFailMessage);
                return new OrchestratorResult(
                    enforceDecision,
                    0,
                    resumeAfterFailOk && unblockAfterFailOk,
                    AppendMessage(executeMessage, $"resume-after-fail={resumeAfterFailOk}; unblock-after-fail={unblockAfterFailOk}"));
            }

            var unblockTermFailOk = _miniBridge.TryUnblockProcessWrites(pid, out var unblockTermFailMessage);
            executeMessage = AppendMessage(executeMessage, unblockTermFailMessage);
            return new OrchestratorResult(enforceDecision, 0, unblockTermFailOk, executeMessage);
        }

        var rollbackCount = 0;
        var rollbackModeOk = _bridge.TryEnableRollbackMode(pid, out var rollbackModeMessage);
        executeMessage = AppendMessage(executeMessage, rollbackModeMessage);
        _eventBuckets.Remove(pid);

        if (_terminatedProcesses.Add(pid))
        {
            executeMessage = AppendMessage(executeMessage, RemediateCorrelatedCriticalTargets(pid));
            var drainCaptured = DrainPendingEventsBeforeRollback(pid, telemetryEvent.ProcessPath);
            pendingForProcess = _journal.PendingEntriesCountForProcess(pid);
            var preview = _journal.GetPendingEntriesPreviewForProcess(pid, 200);
            StartupLog.Write("Rollback",
                $"回滚确认: pid={pid}, pending={pendingForProcess}, previewCount={preview.Count}, drainCaptured={drainCaptured}, sample={BuildPreviewSample(preview)}");

            if (pendingForProcess <= 0 || preview.Count == 0)
            {
                _rollbackApprovedProcesses.Remove(pid);
                _journal.ClearProcessEntries(pid);
                _rollbackFinalizedProcesses.Add(pid);
                executeMessage = AppendMessage(executeMessage, "rollback-skipped-no-pending");
                StartupLog.Write("Rollback", $"rollback skipped: pid={pid}, reason=no-pending");
            }
            else
            {
            var rollbackChoice = _approvalGate.RequestRollback(
                telemetryEvent,
                enforceDecision,
                preview,
                pendingForProcess,
                out var rollbackAudit);

            executeMessage = AppendMessage(executeMessage, rollbackAudit);
            StartupLog.Write("Rollback",
                $"回滚选择: pid={pid}, choice={rollbackChoice}, pending={pendingForProcess}, audit={rollbackAudit}");

            if (rollbackChoice == RollbackChoice.Rollback)
            {
                _rollbackApprovedProcesses.Add(pid);
                try
                {
                    pendingForProcess = _journal.PendingEntriesCountForProcess(pid);
                    StartupLog.Write("Rollback", $"回滚开始: pid={pid}, pending={pendingForProcess}");
                    var rollback = _journal.RollbackProcess(pid);
                    rollbackCount = rollback.Processed;
                    StartupLog.Write("Rollback", $"回滚完成: pid={pid}, processed={rollback.Processed}, errors={rollback.Errors.Count}");

                    if (rollback.Errors.Count > 0)
                    {
                        executeMessage = AppendMessage(executeMessage, $"rollback-errors={rollback.Errors.Count}");
                        var maxDetail = Math.Min(20, rollback.Errors.Count);
                        for (var i = 0; i < maxDetail; i++)
                        {
                            StartupLog.Write("Rollback", $"回滚失败[{i + 1}/{rollback.Errors.Count}]: {rollback.Errors[i]}");
                        }
                    }

                    try
                    {
                        _approvalGate.ShowRollbackResult(telemetryEvent, enforceDecision, preview.Count, rollback);
                    }
                    catch (Exception popupEx)
                    {
                        StartupLog.Write("Rollback", $"回滚结果弹窗失败: pid={pid}", popupEx);
                    }
                }
                catch (Exception rollbackEx)
                {
                    StartupLog.Write("Rollback", $"回滚异常: pid={pid}", rollbackEx);
                    executeMessage = AppendMessage(executeMessage, $"rollback-exception={rollbackEx.Message}");
                }

                _rollbackFinalizedProcesses.Add(pid);
            }
            else
            {
                _rollbackApprovedProcesses.Remove(pid);
                _journal.ClearProcessEntries(pid);
                _rollbackFinalizedProcesses.Add(pid);
                executeMessage = AppendMessage(executeMessage, "rollback-skipped-by-user");
                StartupLog.Write("Rollback", $"回滚跳过: pid={pid}, pending={pendingForProcess}");
            }
        }
        }
        else
        {
            executeMessage = AppendMessage(executeMessage, "terminate already processed");
            StartupLog.Write("Rollback", $"回滚忽略: pid={pid}, reason=terminate-already-processed");
        }

        var unblockAfterTerminateOk = _miniBridge.TryUnblockProcessWrites(pid, out var unblockAfterTerminateMessage);
        executeMessage = AppendMessage(executeMessage, unblockAfterTerminateMessage);

        return new OrchestratorResult(
            enforceDecision,
            rollbackCount,
            terminateOk && rollbackModeOk && unblockAfterTerminateOk,
            executeMessage);
    }

    private OrchestratorResult ExecuteExitedProcessRollback(TelemetryEvent telemetryEvent, ThreatDecision originalDecision)
    {
        var pid = telemetryEvent.ProcessId;
        _rollbackFinalizedProcesses.Remove(pid);
        var enforceDecision = originalDecision with
        {
            Action = SecurityAction.Terminate,
            Reason = $"{originalDecision.Reason}; process-already-exited"
        };

        if (!_terminatedProcesses.Add(pid))
        {
            return HandleTerminatedProcessEvent(telemetryEvent, enforceDecision);
        }

        _eventBuckets.Remove(pid);
        var drainCaptured = DrainPendingEventsBeforeRollback(pid, telemetryEvent.ProcessPath);
        var pending = _journal.PendingEntriesCountForProcess(pid);
        var preview = _journal.GetPendingEntriesPreviewForProcess(pid, 200);
        StartupLog.WriteRollback(
            "Rollback",
            $"进程已退出回滚确认: pid={pid}, pending={pending}, previewCount={preview.Count}, drainCaptured={drainCaptured}, sample={BuildPreviewSample(preview)}");

        if (pending <= 0 || preview.Count == 0)
        {
            _rollbackApprovedProcesses.Remove(pid);
            _journal.ClearProcessEntries(pid);
            _rollbackFinalizedProcesses.Add(pid);
            StartupLog.WriteRollback("Rollback", $"rollback skipped: pid={pid}, reason=no-pending");
            return new OrchestratorResult(
                enforceDecision with { Action = SecurityAction.Allow, Reason = $"{enforceDecision.Reason}; rollback-skipped-no-pending" },
                0,
                true,
                "rollback-skipped-no-pending");
        }

        var rollbackChoice = _approvalGate.RequestRollback(
            telemetryEvent,
            enforceDecision,
            preview,
            pending,
            out var rollbackAudit);
        StartupLog.WriteRollback(
            "Rollback",
            $"进程已退出回滚选择: pid={pid}, choice={rollbackChoice}, pending={pending}, audit={rollbackAudit}");

        if (rollbackChoice != RollbackChoice.Rollback)
        {
            _rollbackApprovedProcesses.Remove(pid);
            _journal.ClearProcessEntries(pid);
            _rollbackFinalizedProcesses.Add(pid);
            return new OrchestratorResult(
                enforceDecision with { Action = SecurityAction.Allow, Reason = $"{enforceDecision.Reason}; rollback-skipped-by-user" },
                0,
                true,
                rollbackAudit);
        }

        _rollbackApprovedProcesses.Add(pid);
        var rollbackCount = 0;
        var success = true;
        var message = rollbackAudit;
        try
        {
            StartupLog.WriteRollback("Rollback", $"进程已退出回滚开始: pid={pid}, pending={pending}");
            var rollback = _journal.RollbackProcess(pid);
            rollbackCount = rollback.Processed;
            StartupLog.WriteRollback("Rollback", $"进程已退出回滚完成: pid={pid}, processed={rollback.Processed}, errors={rollback.Errors.Count}");

            if (rollback.Errors.Count > 0)
            {
                success = false;
                message = AppendMessage(message, $"rollback-errors={rollback.Errors.Count}");
                var maxDetail = Math.Min(20, rollback.Errors.Count);
                for (var i = 0; i < maxDetail; i++)
                {
                    StartupLog.WriteRollback("Rollback", $"进程已退出回滚失败[{i + 1}/{rollback.Errors.Count}]: {rollback.Errors[i]}");
                }
            }

            try
            {
                _approvalGate.ShowRollbackResult(telemetryEvent, enforceDecision, preview.Count, rollback);
            }
            catch (Exception popupEx)
            {
                StartupLog.WriteRollback("Rollback", $"进程已退出回滚结果弹窗失败: pid={pid}", popupEx);
            }
        }
        catch (Exception ex)
        {
            success = false;
            message = AppendMessage(message, $"rollback-exception={ex.Message}");
            StartupLog.WriteRollback("Rollback", $"进程已退出回滚异常: pid={pid}", ex);
        }
        finally
        {
            _rollbackFinalizedProcesses.Add(pid);
        }

        return new OrchestratorResult(enforceDecision, rollbackCount, success, message);
    }

    private OrchestratorResult HandleTerminatedProcessEvent(TelemetryEvent telemetryEvent, ThreatDecision decision)
    {
        var pid = telemetryEvent.ProcessId;
        if (!_rollbackApprovedProcesses.Contains(pid))
        {
            _journal.ClearProcessEntries(pid);
            _rollbackFinalizedProcesses.Add(pid);
            return new OrchestratorResult(
                decision with { Action = SecurityAction.Allow, Reason = $"{decision.Reason}; terminated-no-rollback-clear" },
                0,
                true,
                "terminated-no-rollback-clear");
        }

        var pending = _journal.PendingEntriesCountForProcess(pid);
        if (pending <= 0)
        {
            _rollbackFinalizedProcesses.Add(pid);
            return new OrchestratorResult(
                decision with { Action = SecurityAction.Allow, Reason = $"{decision.Reason}; terminated-rollback-drained" },
                0,
                true,
                "terminated-rollback-drained");
        }

        try
        {
            StartupLog.WriteRollback("Rollback",
                $"延迟事件回滚开始: pid={pid}, pending={pending}, kind={telemetryEvent.Kind}, target={telemetryEvent.TargetPath}");
            var rollback = _journal.RollbackProcess(pid);
            StartupLog.WriteRollback("Rollback", $"延迟事件回滚完成: pid={pid}, processed={rollback.Processed}, errors={rollback.Errors.Count}");
            _rollbackFinalizedProcesses.Add(pid);

            if (rollback.Errors.Count > 0)
            {
                var maxDetail = Math.Min(20, rollback.Errors.Count);
                for (var i = 0; i < maxDetail; i++)
                {
                    StartupLog.WriteRollback("Rollback", $"延迟回滚失败[{i + 1}/{rollback.Errors.Count}]: {rollback.Errors[i]}");
                }
            }

            var resultMessage = $"terminated-late-rollback processed={rollback.Processed} errors={rollback.Errors.Count}";
            return new OrchestratorResult(
                decision with { Action = SecurityAction.Allow, Reason = $"{decision.Reason}; {resultMessage}" },
                rollback.Processed,
                rollback.Errors.Count == 0,
                resultMessage);
        }
        catch (Exception ex)
        {
            StartupLog.WriteRollback("Rollback", $"延迟事件回滚异常: pid={pid}", ex);
            _journal.ClearProcessEntries(pid);
            _rollbackFinalizedProcesses.Add(pid);
            return new OrchestratorResult(
                decision with { Action = SecurityAction.Allow, Reason = $"{decision.Reason}; terminated-late-rollback-exception" },
                0,
                false,
                $"terminated-late-rollback-exception: {ex.Message}");
        }
    }

    private int DrainPendingEventsBeforeRollback(int processId, string processPath)
    {
        if (processId <= 4)
        {
            return 0;
        }

        var captured = 0;
        var loops = 0;
        var startAt = DateTimeOffset.UtcNow;
        var minUntil = startAt.Add(PreRollbackDrainMinWindow);
        var maxUntil = startAt.Add(PreRollbackDrainMaxWindow);
        var lastCaptureAt = startAt;

        while (true)
        {
            var now = DateTimeOffset.UtcNow;
            if (now >= maxUntil)
            {
                break;
            }

            if (now >= minUntil && now - lastCaptureAt >= PreRollbackDrainQuietWindow)
            {
                break;
            }

            loops++;
            var capturedNow = 0;
            capturedNow += DrainBridgeEventsForProcess(_miniBridge, processId, processPath, "minifilter-pre-rollback-drain");
            capturedNow += DrainBridgeEventsForProcess(_bridge, processId, processPath, "driver-pre-rollback-drain");
            captured += capturedNow;

            if (capturedNow > 0)
            {
                lastCaptureAt = DateTimeOffset.UtcNow;
            }
            else if (loops == 1 && captured == 0)
            {
                break;
            }
            else
            {
                Thread.Sleep((int)PreRollbackDrainPoll.TotalMilliseconds);
            }
        }

        StartupLog.WriteRollback("Rollback", $"回滚前吸收事件: pid={processId}, captured={captured}, loops={loops}");
        return captured;
    }

    private int DrainBridgeEventsForProcess(DriverCommandBridge bridge, int processId, string processPath, string reasonPrefix)
    {
        var captured = 0;
        for (var batch = 0; batch < DrainReadBurstBatches; batch++)
        {
            if (!bridge.TryReadEventsDirect(out var rawEvents, out var error))
            {
                if (!string.IsNullOrWhiteSpace(error))
                {
                    StartupLog.WriteRollback("Rollback", $"回滚前吸收读取失败: pid={processId}, source={reasonPrefix}, error={error}");
                }

                return captured;
            }

            if (rawEvents.Count == 0)
            {
                return captured;
            }

            List<DriverProtocol.DriverEventRecordRaw>? requeue = null;
            foreach (var raw in rawEvents)
            {
                if (!IsRawEventFromProcess(raw, processId, processPath))
                {
                    requeue ??= [];
                    requeue.Add(raw);
                    continue;
                }

                var pendingBefore = _journal.PendingEntriesCountForProcess(processId);
                if (!CaptureSnapshotFromRawEvent(raw, processId, reasonPrefix))
                {
                    continue;
                }

                var pendingAfter = _journal.PendingEntriesCountForProcess(processId);
                if (pendingAfter > pendingBefore)
                {
                    captured += pendingAfter - pendingBefore;
                }
            }

            if (requeue is { Count: > 0 })
            {
                bridge.RequeueEvents(requeue);
            }

            if (rawEvents.Count < DriverProtocol.MaxBatchEvents)
            {
                return captured;
            }
        }

        return captured;
    }

    private bool CaptureSnapshotFromRawEvent(DriverProtocol.DriverEventRecordRaw raw, int processId, string reasonPrefix)
    {
        var target = SanitizeRawPath(raw.TargetPath);
        var source = SanitizeRawPath(raw.SourcePath);

        switch (raw.Kind)
        {
            case DriverProtocol.DriverEventKind.FileWrite:
                var isPreOperation = (raw.Flags & DriverProtocol.DriverEventFlags.PreOperation) != 0;
                if (isPreOperation)
                {
                    _journal.CaptureKernelPreWriteSnapshot(target, source, $"{reasonPrefix}-file-pre-write-kernel", processId, raw.VolumeSerialNumber, raw.FileId);
                }
                else
                {
                    _journal.CaptureFileForRuntimeEvent(target, $"{reasonPrefix}-file-write", processId, raw.VolumeSerialNumber, raw.FileId);
                }

                return true;
            case DriverProtocol.DriverEventKind.FileDelete:
                _journal.CaptureFileForRuntimeEvent(target, $"{reasonPrefix}-file-delete", processId, raw.VolumeSerialNumber, raw.FileId);
                return true;
            case DriverProtocol.DriverEventKind.FileRename:
                _journal.CaptureRenameForRuntimeEvent(source, target, $"{reasonPrefix}-file-rename", processId, raw.VolumeSerialNumber, raw.FileId);
                return true;
            case DriverProtocol.DriverEventKind.RegistrySet:
            case DriverProtocol.DriverEventKind.RegistryDelete:
                _journal.CaptureRegistryBeforeChange(target, $"{reasonPrefix}-registry", processId);
                return true;
            default:
                return false;
        }
    }

    private static string? SanitizeRawPath(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim().TrimEnd('\0');

    private bool ShouldSkipSnapshotCapture(int processId) =>
        processId > 4 && _terminatedProcesses.Contains(processId) && _rollbackFinalizedProcesses.Contains(processId);

    private static bool ShouldCaptureRollbackSnapshot(TelemetryEvent telemetryEvent, ProcessContext context)
    {
        if (telemetryEvent.Kind is not (EventKind.FileWrite or EventKind.FileDelete or EventKind.FileRename))
        {
            return true;
        }

        if (context.CurrentTrustTier is ExecutionTrustTier.MicrosoftSigned or ExecutionTrustTier.Signed)
        {
            return false;
        }

        if (telemetryEvent.Kind == EventKind.FileWrite &&
            telemetryEvent.IsPreOperation &&
            string.IsNullOrWhiteSpace(telemetryEvent.SourcePath))
        {
            return false;
        }

        return true;
    }

    private bool ShouldPromptExitedProcessRollback(TelemetryEvent telemetryEvent, ThreatDecision decision)
    {
        var pid = telemetryEvent.ProcessId;
        if (pid <= 4) return false;
        if (_terminatedProcesses.Contains(pid)) return false;
        if (IsProcessAlive(pid)) return false;
        if (_journal.PendingEntriesCountForProcess(pid) <= 0) return false;
        if (decision.Action == SecurityAction.Terminate) return true;
        return decision.Score >= Math.Max(_policy.ScoreMalicious, ManualEnforcementScoreThreshold);
    }

    private static bool IsProcessAlive(int pid)
    {
        if (pid <= 0)
        {
            return false;
        }

        try
        {
            using var process = Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsRawEventFromProcess(DriverProtocol.DriverEventRecordRaw raw, int processId, string processPath)
    {
        if ((int)raw.ProcessId == processId)
        {
            return true;
        }

        var rawProcessPath = SanitizeRawPath(raw.ProcessPath);
        if (string.IsNullOrWhiteSpace(rawProcessPath) || string.IsNullOrWhiteSpace(processPath))
        {
            return false;
        }

        if (PathEquals(rawProcessPath, processPath))
        {
            return true;
        }

        var left = Path.GetFileName(rawProcessPath);
        var right = Path.GetFileName(processPath);
        return !string.IsNullOrWhiteSpace(left) &&
               !string.IsNullOrWhiteSpace(right) &&
               left.Equals(right, StringComparison.OrdinalIgnoreCase);
    }

    private static bool PathEquals(string left, string right)
    {
        try
        {
            return Path.GetFullPath(left).Equals(Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return left.Equals(right, StringComparison.OrdinalIgnoreCase);
        }
    }

    private bool IsAllowListedProcess(string processPath) =>
        TrustedProcessValidator.IsAllowListed(processPath, _policy.AllowListProcesses);

    private bool ShouldPromptForFastContainment(
        TelemetryEvent telemetryEvent,
        ProcessContext context,
        int totalScore,
        IReadOnlyCollection<BehaviorChainResult> chainResults)
    {
        var maliciousThreshold = Math.Max(_policy.ScoreMalicious, ManualEnforcementScoreThreshold);
        if (telemetryEvent.ProcessId <= 4) return false;
        if (_terminatedProcesses.Contains(telemetryEvent.ProcessId)) return false;
        if (totalScore < maliciousThreshold) return false;
        if (ShouldSkipUserModeMemoryInspection(context)) return false;
        if (IsStabilityCriticalProcess(context, telemetryEvent.ProcessPath)) return false;
        if (KernelEntropyEvidence.WasAutoBlocked(telemetryEvent)) return true;
        if (KernelEntropyEvidence.IsLowToHigh(telemetryEvent)) return true;
        if (context.CompressionRatioConfirmedCount > 0 && context.KernelLowToHighEntropyCount > 0) return true;
        if (context.HasAnomalousCallStack && context.KernelHighEntropyRawCount > 0) return true;
        if (chainResults.Any(result => result.ShouldSuspend && IsImmediateContainmentRule(result.RuleName))) return true;
        if (IsSyntheticMemoryEvent(telemetryEvent.Kind) && HasHighConfidenceExecutionCompromise(context)) return true;
        if (totalScore < FastUnsignedBlockScoreThreshold) return false;
        if (telemetryEvent.Kind is EventKind.HoneyFileTouched or EventKind.ShadowDeleteAttempt) return true;
        if (!telemetryEvent.IsPreOperation) return IsSyntheticMemoryEvent(telemetryEvent.Kind);
        if (telemetryEvent.Kind is not (EventKind.FileWrite or EventKind.FileRename or EventKind.FileDelete)) return false;
        if (telemetryEvent.IsProtectedTarget || telemetryEvent.IsSuspiciousExtension) return true;
        if (context.TotalFileOverwrites >= 4 || context.TotalFileRenames >= 3) return true;
        if (context.FilesWrittenInWindow >= 8 && context.UniqueFileRatio >= 0.75) return true;
        return context.FilesWrittenInWindow >= 3;
    }

    private void EnsureProcessTrustTier(TelemetryEvent telemetryEvent, ProcessContext context)
    {
        if (context.StartupTrustEstablished && !ShouldRefreshStartupTrust(telemetryEvent, context))
        {
            return;
        }

        var isRefresh = context.StartupTrustEstablished;

        var verdict = ResolveBinaryVerdictForProcess(
            telemetryEvent.ProcessId,
            telemetryEvent.ProcessPath,
            allowExistingSuspendedState: telemetryEvent.IsSuspendedCreate || context.IsSuspended,
            "process-create",
            telemetryEvent.TrustHint,
            allowLiveProcessPathFallback: true);

        context.ApplyBaseTrust(verdict);
        SyncMiniFilterProcessState(
            telemetryEvent.ProcessId,
            context,
            startupDelayMs: context.IsRestrictedProcess ? UnsignedStartupWriteDelayMs : 0,
            isRefresh ? "process-trust-refresh" : "process-create");
        FinalizeStartupSuspendedProcess(telemetryEvent, context, isRefresh ? "process-trust-refresh" : "process-create");

        if (telemetryEvent.TrustHint != KernelTrustHint.Unknown)
        {
            StartupLog.WriteDetection(
                "Detection",
                $"{(isRefresh ? "startup-kernel-trust-observed-refresh" : "startup-kernel-trust-observed")} pid={telemetryEvent.ProcessId}, hint={telemetryEvent.TrustHint}, tier={context.CurrentTrustTier}, path={telemetryEvent.ProcessPath}");
        }
    }

    private void EnsureModuleTrustTier(TelemetryEvent telemetryEvent, ProcessContext context)
    {
        if (telemetryEvent.Kind is not (EventKind.ImageLoad or EventKind.ImageLoadUnsigned))
        {
            return;
        }

        var modulePath = telemetryEvent.TargetPath;
        if (string.IsNullOrWhiteSpace(modulePath))
        {
            return;
        }

        var verdict = ResolveBinaryVerdictForProcess(
            telemetryEvent.ProcessId,
            modulePath,
            allowExistingSuspendedState: false,
            "image-load",
            telemetryEvent.TrustHint);

        var wasRestricted = context.IsRestrictedProcess;
        context.ApplyModuleTrust(verdict);
        context.UpdateLoadedDllTrust(modulePath, verdict, telemetryEvent.Timestamp);

        if (telemetryEvent.TrustHint != KernelTrustHint.Unknown)
        {
            StartupLog.WriteDetection(
                "Detection",
                $"module-kernel-trust pid={telemetryEvent.ProcessId}, hint={telemetryEvent.TrustHint}, module={modulePath}");
        }

        if (!wasRestricted && context.IsRestrictedProcess)
        {
            SyncMiniFilterProcessState(
                telemetryEvent.ProcessId,
                context,
                startupDelayMs: UnsignedStartupWriteDelayMs,
                "module-unsigned");
        }
        else
        {
            SyncMiniFilterProcessState(
                telemetryEvent.ProcessId,
                context,
                startupDelayMs: context.IsRestrictedProcess ? UnsignedStartupWriteDelayMs : 0,
                "module-trust-sync");
        }
    }

    private void ApplyKernelEntropySecondaryAnalysis(TelemetryEvent telemetryEvent, ProcessContext context)
    {
        if (!KernelEntropyEvidence.IsRelevant(telemetryEvent))
        {
            return;
        }

        var now = DateTimeOffset.Now;
        if (now - context.LastKernelTrustRefreshAt >= EntropyTrustRefreshCooldown)
        {
            context.MarkKernelTrustRefresh(now);
            StartupLog.WriteDetection(
                "Detection",
                $"entropy-trust-tier pid={telemetryEvent.ProcessId}, tier={context.CurrentTrustTier}, path={telemetryEvent.ProcessPath}, evidence={KernelEntropyEvidence.Describe(telemetryEvent)}");
        }

        if (!telemetryEvent.IsPreOperation &&
            KernelEntropyEvidence.HasHighEntropyRaw(telemetryEvent) &&
            now - context.LastCompressionProbeAt >= EntropyCompressionProbeCooldown &&
            CompressionRatioAnalyzer.TryEvaluate(telemetryEvent.TargetPath, out var compressionVerdict))
        {
            context.ApplyCompressionRatioVerdict(compressionVerdict, now);
            StartupLog.WriteDetection(
                "Detection",
                $"entropy-compression pid={telemetryEvent.ProcessId}, target={telemetryEvent.TargetPath}, confirmed={compressionVerdict.Confirmed}, sample={compressionVerdict.SampleSize}, summary={compressionVerdict.Summary}");
        }

        if (telemetryEvent.IsPreOperation &&
            (KernelEntropyEvidence.WasAutoBlocked(telemetryEvent) || KernelEntropyEvidence.IsLowToHigh(telemetryEvent)) &&
            now - context.LastCallStackProbeAt >= EntropyCallStackProbeCooldown &&
            ProcessCallStackInspector.TryInspect(telemetryEvent.ProcessId, out var callStackVerdict))
        {
            context.ApplyCallStackInspection(callStackVerdict, now);
            StartupLog.WriteDetection(
                "Detection",
                $"entropy-callstack pid={telemetryEvent.ProcessId}, anomalous={callStackVerdict.HasAnomalousFrame}, frames={callStackVerdict.FrameCount}, summary={callStackVerdict.Summary}");
        }
    }

    private BinaryTrustVerdict ResolveBinaryVerdictForProcess(
        int processId,
        string? filePath,
        bool allowExistingSuspendedState,
        string reason,
        KernelTrustHint trustHint = KernelTrustHint.Unknown,
        bool allowLiveProcessPathFallback = false)
    {
        LogTrustProbeStart(processId, reason, filePath, trustHint, allowLiveProcessPathFallback);

        // The kernel's Code Integrity (CI) module validates the image at map time,
        // before userspace code runs. Any concrete kernel trust hint is therefore
        // authoritative for the realtime path and should not be delayed by an
        // additional userspace signature verification round-trip.
        if (trustHint != KernelTrustHint.Unknown &&
            TryCreateKernelHintVerdict(filePath, trustHint, out var kernelVerdict))
        {
            StartupLog.WriteDetection(
                "Detection",
                $"startup-verify-kernel-hint pid={processId}, reason={reason}, hint={trustHint}, path={filePath}");
            LogTrustVerdict(processId, reason, "kernel-hint", filePath, kernelVerdict, trustHint);
            return kernelVerdict;
        }

        var liveProcessPath = allowLiveProcessPathFallback
            ? ResolveLiveProcessPathForTrust(processId, filePath)
            : string.Empty;

        if (_binaryTrustCache.TryGetFastVerdict(filePath, out var fastVerdict))
        {
            fastVerdict = NormalizeWindowsUnsignedUnknownKernel(fastVerdict, filePath, trustHint);
            LogTrustVerdict(processId, reason, "cache-fast", filePath, fastVerdict, trustHint);
            return fastVerdict;
        }

        if (!string.IsNullOrWhiteSpace(liveProcessPath) &&
            _binaryTrustCache.TryGetFastVerdict(liveProcessPath, out var liveFastVerdict))
        {
            liveFastVerdict = NormalizeWindowsUnsignedUnknownKernel(liveFastVerdict, liveProcessPath, trustHint);
            StartupLog.WriteDetection(
                "Detection",
                $"startup-verify-live-fast pid={processId}, reason={reason}, tier={liveFastVerdict.Tier}, path={liveFastVerdict.ResolvedPath}");
            LogTrustVerdict(processId, reason, "cache-fast-live-path", liveProcessPath, liveFastVerdict, trustHint);
            return liveFastVerdict;
        }

        var suspendedByUs = false;
        if (!allowExistingSuspendedState &&
            processId > 4 &&
            !TrustedProcessValidator.IsStabilityCritical(filePath, trustHint == KernelTrustHint.MicrosoftSigned))
        {
            suspendedByUs = _bridge.TrySuspendProcess(processId, out var suspendMessage);
            StartupLog.WriteDetection(
                "Detection",
                $"startup-verify-suspend pid={processId}, reason={reason}, ok={suspendedByUs}, msg={suspendMessage}");
        }

        try
        {
            if (_binaryTrustCache.TryGetOrAddVerdict(filePath, out var verdict))
            {
                verdict = NormalizeWindowsUnsignedUnknownKernel(verdict, filePath, trustHint);
                StartupLog.WriteDetection(
                    "Detection",
                    $"startup-verify pid={processId}, reason={reason}, tier={verdict.Tier}, cacheHit={verdict.CacheHit}, path={verdict.ResolvedPath}");
                LogTrustVerdict(processId, reason, verdict.CacheHit ? "cache-hit" : "cache-miss-evaluated", filePath, verdict, trustHint);
                return verdict;
            }

            if (!string.IsNullOrWhiteSpace(liveProcessPath) &&
                _binaryTrustCache.TryGetOrAddVerdict(liveProcessPath, out var liveVerdict))
            {
                liveVerdict = NormalizeWindowsUnsignedUnknownKernel(liveVerdict, liveProcessPath, trustHint);
                StartupLog.WriteDetection(
                    "Detection",
                    $"startup-verify-live pid={processId}, reason={reason}, tier={liveVerdict.Tier}, cacheHit={liveVerdict.CacheHit}, path={liveVerdict.ResolvedPath}");
                LogTrustVerdict(processId, reason, liveVerdict.CacheHit ? "cache-hit-live-path" : "cache-miss-evaluated-live-path", liveProcessPath, liveVerdict, trustHint);
                return liveVerdict;
            }

            var fallback = BinaryTrustCache.CreateFallbackUnknown(filePath);
            StartupLog.WriteDetection(
                "Detection",
                $"startup-verify-fallback pid={processId}, reason={reason}, tier={fallback.Tier}, path={fallback.ResolvedPath}");
            LogTrustVerdict(processId, reason, "fallback-unknown", filePath, fallback, trustHint);
            return fallback;
        }
        finally
        {
            if (suspendedByUs)
            {
                _ = _bridge.TryResumeProcess(processId, out var resumeMessage);
                StartupLog.WriteDetection(
                    "Detection",
                    $"startup-verify-resume pid={processId}, reason={reason}, msg={resumeMessage}");
            }
        }
    }

    private static BinaryTrustVerdict NormalizeWindowsUnsignedUnknownKernel(
        BinaryTrustVerdict verdict,
        string? requestedPath,
        KernelTrustHint trustHint)
    {
        // Guardrail: if kernel hint is still unknown and userspace resolved a Windows
        // system binary as Unsigned, avoid hard-downgrading to Unsigned immediately.
        // This prevents false shellcode/ransomware escalation caused by user-mode
        // WinVerifyTrust/catalog visibility mismatch (e.g. system binaries relying on
        // catalog trust rather than embedded signature).
        if (trustHint == KernelTrustHint.Unknown &&
            verdict.Tier == ExecutionTrustTier.Unsigned &&
            verdict.KernelSigningLevel == SeSigningLevel.Unchecked &&
            TrustedProcessValidator.LooksLikeWindowsRuntimeProcess(requestedPath ?? verdict.ResolvedPath))
        {
            return verdict with
            {
                Tier = ExecutionTrustTier.Unknown,
                StatusSummary = string.IsNullOrWhiteSpace(verdict.StatusSummary)
                    ? "windows-unknown-kernel-hint-guardrail"
                    : $"{verdict.StatusSummary}; normalized=windows-unknown-kernel-hint-guardrail"
            };
        }

        return verdict;
    }

    private static string ResolveLiveProcessPathForTrust(int processId, string? filePath)
    {
        if (processId <= 4 || string.IsNullOrWhiteSpace(filePath) || !LooksLikeWindowsRuntimeProcess(filePath))
        {
            return string.Empty;
        }

        var liveProcessPath = TryReadLiveProcessPath(processId);
        if (string.IsNullOrWhiteSpace(liveProcessPath))
        {
            return string.Empty;
        }

        if (SignatureTrustEvaluator.TryNormalizeDisplayPath(filePath, out var normalizedOriginal) &&
            SignatureTrustEvaluator.TryNormalizeDisplayPath(liveProcessPath, out var normalizedLive) &&
            normalizedOriginal.Equals(normalizedLive, StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }

        return liveProcessPath;
    }

    private void SyncMiniFilterProcessState(int processId, ProcessContext context, int startupDelayMs, string reason)
    {
        if (processId <= 4)
        {
            return;
        }

        var trustTierValue = (int)context.CurrentTrustTier;
        var setTrustOk = _miniBridge.TrySetProcessTrust(processId, trustTierValue, out var trustMessage);
        StartupLog.WriteDetection(
            "Detection",
            $"process-trust-sync pid={processId}, tier={context.CurrentTrustTier}, reason={reason}, setTrustOk={setTrustOk}, msg={trustMessage}");

        if (context.IsRestrictedProcess)
        {
            _ = _miniBridge.TrySetRestrictedProcess(processId, startupDelayMs, out var restrictMessage);
            StartupLog.WriteDetection(
                "Detection",
                $"restricted-set pid={processId}, tier={context.CurrentTrustTier}, delayMs={startupDelayMs}, reason={reason}, msg={restrictMessage}");
            return;
        }

        _ = _miniBridge.TryClearRestrictedProcess(processId, out var clearMessage);
        StartupLog.WriteDetection(
            "Detection",
            $"restricted-clear pid={processId}, tier={context.CurrentTrustTier}, reason={reason}, msg={clearMessage}");
    }

    private static bool IsStabilityCriticalProcess(ProcessContext? context, string? processPath = null)
    {
        if (context != null && TrustedProcessValidator.IsStabilityCritical(context))
        {
            return true;
        }

        return context != null &&
               TrustedProcessValidator.IsStabilityCritical(
                   string.IsNullOrWhiteSpace(processPath) ? context.ImageName : processPath,
                   context.BaseTrustTier == ExecutionTrustTier.MicrosoftSigned && context.IsMicrosoftSignedProcess);
    }

    private static bool ShouldSkipUserModeMemoryInspection(ProcessContext context) =>
        IsMicrosoftSignedProcessClean(context) ||
        TrustedProcessValidator.IsLikelyTrustedWindowsProcessPendingTrust(context);

    private static bool HasUnsignedOrUntrustedImage(ProcessContext context) =>
        context.BaseTrustTier == ExecutionTrustTier.Unsigned ||
        context.CurrentTrustTier == ExecutionTrustTier.Unsigned ||
        context.LoadedUnsignedDll || context.LoadedSuspiciousDll || context.LoadedNonMicrosoftDll;

    private static bool IsMicrosoftSignedProcessClean(ProcessContext context) =>
        context.SignatureEvaluated && context.IsMicrosoftSignedProcess && context.IsMicrosoftCleanChain;

    private static bool HasUnsignedExecutionEvidence(ProcessContext context, TelemetryEvent telemetryEvent)
    {
        if (context.BaseTrustTier == ExecutionTrustTier.Unsigned) return true;
        if (context.CurrentTrustTier == ExecutionTrustTier.Unsigned) return true;
        if (telemetryEvent.IsUnsignedProcess) return true;
        if (context.LoadedUnsignedDll) return true;
        return false;
    }

    private static bool TryCreateKernelHintVerdict(
        string? path,
        KernelTrustHint trustHint,
        out BinaryTrustVerdict verdict)
    {
        verdict = trustHint switch
        {
            KernelTrustHint.WindowsSigned => new BinaryTrustVerdict(
                path ?? string.Empty,
                string.Empty,
                IsSigned:          true,
                IsMicrosoftSigned: true,
                ExecutionTrustTier.MicrosoftSigned,
                CacheHit:          false,
                PublisherTrustLevel.High,
                PublisherName:     "Microsoft Windows",
                HasTimestampSignature: false,
                RevocationChecked: true,
                ChainValid:        true,
                IsRevoked:         false,
                PathPolicySatisfied: true,
                PathPolicyName:    "kernel-hint",
                StatusSummary:     "kernel-hint-windows",
                KernelSigningLevel: SeSigningLevel.Windows),
            KernelTrustHint.MicrosoftSigned => new BinaryTrustVerdict(
                path ?? string.Empty,
                string.Empty,
                IsSigned:          true,
                IsMicrosoftSigned: true,
                ExecutionTrustTier.MicrosoftSigned,
                CacheHit:          false,
                PublisherTrustLevel.High,
                PublisherName:     "kernel-hint-microsoft",
                HasTimestampSignature: false,
                RevocationChecked: true,
                ChainValid:        true,
                IsRevoked:         false,
                PathPolicySatisfied: true,
                PathPolicyName:    "kernel-hint",
                StatusSummary:     "kernel-hint-microsoft",
                KernelSigningLevel: SeSigningLevel.Microsoft),
            KernelTrustHint.Signed => new BinaryTrustVerdict(
                path ?? string.Empty,
                string.Empty,
                IsSigned:          true,
                IsMicrosoftSigned: false,
                ExecutionTrustTier.Signed,
                CacheHit:          false,
                PublisherTrustLevel.Low,
                PublisherName:     "kernel-hint-signed",
                HasTimestampSignature: false,
                RevocationChecked: true,
                ChainValid:        true,
                IsRevoked:         false,
                PathPolicySatisfied: true,
                PathPolicyName:    "kernel-hint",
                StatusSummary:     "kernel-hint-signed",
                KernelSigningLevel: SeSigningLevel.Authenticode),
            KernelTrustHint.Unsigned => new BinaryTrustVerdict(
                path ?? string.Empty,
                string.Empty,
                IsSigned:          false,
                IsMicrosoftSigned: false,
                ExecutionTrustTier.Unsigned,
                CacheHit:          false,
                PublisherTrustLevel.Unknown,
                PublisherName:     string.Empty,
                HasTimestampSignature: false,
                RevocationChecked: false,
                ChainValid:        false,
                IsRevoked:         false,
                PathPolicySatisfied: false,
                PathPolicyName:    "kernel-hint",
                StatusSummary:     "kernel-hint-unsigned",
                KernelSigningLevel: SeSigningLevel.Unsigned),
            _ => default
        };

        return trustHint != KernelTrustHint.Unknown;
    }

    private static bool ShouldRefreshStartupTrust(TelemetryEvent telemetryEvent, ProcessContext context)
    {
        if (!context.StartupTrustEstablished)
        {
            return true;
        }

        if (context.BaseTrustTier != ExecutionTrustTier.Unknown)
        {
            return false;
        }

        var candidatePath = string.IsNullOrWhiteSpace(telemetryEvent.ProcessPath)
            ? context.ImageName
            : telemetryEvent.ProcessPath;
        if (string.IsNullOrWhiteSpace(candidatePath))
        {
            return false;
        }

        var normalized = candidatePath.Trim().TrimEnd('\0');
        if (!LooksLikeBinaryPath(normalized))
        {
            return false;
        }

        return true;
    }

    private static void LogTrustProbeStart(
        int processId,
        string reason,
        string? requestedPath,
        KernelTrustHint trustHint,
        bool allowLiveProcessPathFallback)
    {
        StartupLog.WriteSign(
            "TrustFlow",
            $"trust-probe-start pid={processId}, reason={reason}, requestedPath={SafeTrustText(requestedPath)}, kernelHint={trustHint}, allowLivePathFallback={allowLiveProcessPathFallback}");
    }

    private static void LogTrustVerdict(
        int processId,
        string reason,
        string source,
        string? requestedPath,
        BinaryTrustVerdict verdict,
        KernelTrustHint trustHint)
    {
        StartupLog.WriteSign(
            "TrustFlow",
            $"trust-verdict pid={processId}, reason={reason}, source={source}, requestedPath={SafeTrustText(requestedPath)}, resolvedPath={SafeTrustText(verdict.ResolvedPath)}, tier={verdict.Tier}, isSigned={verdict.IsSigned}, isMicrosoftSigned={verdict.IsMicrosoftSigned}, kernelHint={trustHint}, kernelSigningLevel={verdict.KernelSigningLevel}, cacheHit={verdict.CacheHit}, publisher={SafeTrustText(verdict.PublisherName)}, publisherTrust={verdict.PublisherTrustLevel}, chainValid={verdict.ChainValid}, revoked={verdict.IsRevoked}, revocationChecked={verdict.RevocationChecked}, hasTimestamp={verdict.HasTimestampSignature}, pathPolicySatisfied={verdict.PathPolicySatisfied}, pathPolicy={SafeTrustText(verdict.PathPolicyName)}, status={SafeTrustText(verdict.StatusSummary)}, hash={SafeTrustText(verdict.FileHash)}");
    }

    private static string SafeTrustText(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "(empty)";
        }

        return value.Trim().TrimEnd('\0').Replace('\r', ' ').Replace('\n', ' ');
    }

    private static bool LooksLikeBinaryPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var normalized = path.Replace('/', '\\');
        if (!normalized.Contains('\\', StringComparison.Ordinal))
        {
            return false;
        }

        return normalized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsImmediateContainmentRule(string ruleName) =>
        ruleName is
            "RULE-003-RemoteInjection" or
            "RULE-004-HandleToRemoteThread" or
            "RULE-005-RansomwareTriple" or
            "RULE-006-ShadowDelete" or
            "RULE-010-HoneypotTouch" or
            "RULE-012-WxTransitionRemoteThread" or
            "RULE-013-ProcessHollowing" or
            "RULE-016-DriverRemoteThreadStartExec" or
            "RULE-015-SuspiciousParentMemoryExec";

    private void FinalizeStartupSuspendedProcess(TelemetryEvent telemetryEvent, ProcessContext context, string reason)
    {
        if (!telemetryEvent.IsSuspendedCreate || telemetryEvent.ProcessId <= 4)
        {
            return;
        }

        if (TryHoldStartupSuspendedProcessForMemoryGuard(telemetryEvent, context, reason, out var guardMessage))
        {
            StartupLog.WriteDetection(
                "Detection",
                $"startup-verify-hold pid={telemetryEvent.ProcessId}, reason={reason}, tier={context.CurrentTrustTier}, msg={guardMessage}");
            return;
        }

        var resumed = _bridge.TryResumeProcess(telemetryEvent.ProcessId, out var resumeMessage);
        if (resumed)
        {
            context.IsSuspended = false;
        }

        StartupLog.WriteDetection(
            "Detection",
            $"startup-verify-release pid={telemetryEvent.ProcessId}, reason={reason}, tier={context.CurrentTrustTier}, resumed={resumed}, msg={resumeMessage}");
    }

    private bool TryHoldStartupSuspendedProcessForMemoryGuard(
        TelemetryEvent telemetryEvent,
        ProcessContext context,
        string reason,
        out string guardMessage)
    {
        guardMessage = "startup-memory-guard-skip";
        if (!ShouldInspectStartupSuspendedProcess(telemetryEvent, context, out var parentContext))
        {
            return false;
        }

        var attempts = 0;
        var until = DateTimeOffset.UtcNow.Add(StartupMemoryGuardWindow);
        while (true)
        {
            attempts++;
            TryRunSuspendedStartupScanAttempt(telemetryEvent.ProcessId, context, $"{reason}-startup-attempt{attempts}");
            if (HasHighConfidenceExecutionCompromise(context))
            {
                guardMessage =
                    $"startup-memory-guard-hit attempts={attempts}, parentPid={context.PPID}, parent={parentContext?.ImageName}, summary={BuildProcessMemoryRiskSummary(context)}";
                return true;
            }

            if (DateTimeOffset.UtcNow >= until)
            {
                break;
            }

            Thread.Sleep((int)StartupMemoryGuardPoll.TotalMilliseconds);
        }

        guardMessage = $"startup-memory-guard-clear attempts={attempts}, parentPid={context.PPID}";
        return false;
    }

    private bool ShouldInspectStartupSuspendedProcess(
        TelemetryEvent telemetryEvent,
        ProcessContext context,
        out ProcessContext? parentContext)
    {
        parentContext = null;
        if (_memoryScanner == null ||
            telemetryEvent.Kind != EventKind.ProcessCreate ||
            !telemetryEvent.IsSuspendedCreate ||
            telemetryEvent.ProcessId <= 4)
        {
            return false;
        }

        var shouldGuardTarget =
            LooksLikeWindowsRuntimeProcess(telemetryEvent.ProcessPath) ||
            TrustedProcessValidator.IsTrustedSystemProcess(context) ||
            context.BaseTrustTier is ExecutionTrustTier.MicrosoftSigned or ExecutionTrustTier.Signed;
        if (context.IsRestrictedProcess || !shouldGuardTarget)
        {
            return false;
        }

        if (TrustedProcessValidator.IsRollbackGuardBinary(telemetryEvent.ProcessPath) || context.PPID <= 4)
        {
            return false;
        }

        parentContext = _contextManager.Get(context.PPID);
        if (parentContext == null ||
            TrustedProcessValidator.IsRollbackGuardBinary(parentContext.ImageName))
        {
            return false;
        }

        return IsPotentialInjectionParent(parentContext);
    }

    private string RemediateCorrelatedCriticalTargets(int sourcePid)
    {
        if (_memoryScanner == null || _remediator == null || sourcePid <= 4)
        {
            return "correlated-target-remediation-skip";
        }

        var now = DateTimeOffset.Now;
        var remediated = 0;
        var scanned = 0;
        var details = new List<string>();

        foreach (var targetContext in _contextManager.AllContexts.Values
                     .Where(context =>
                         context.PID > 4 &&
                         context.LastSuspiciousSourcePid == sourcePid &&
                         now - context.LastSuspiciousSourceAt <= TimeSpan.FromMinutes(2)))
        {
            EnsureResolvedProcessIdentity(targetContext.PID, targetContext);
            if (!IsStabilityCriticalProcess(targetContext))
            {
                continue;
            }

            scanned++;
            TryRunSuspendedStartupScanAttempt(
                targetContext.PID,
                targetContext,
                $"post-terminate-correlated-source-{sourcePid}");

            if (!targetContext.MemoryScanSuspicious || targetContext.LastScanRegions.Count == 0)
            {
                continue;
            }

            var targetEvent = BuildSyntheticMemoryEvent(
                SelectPrimaryMemoryEventKind(targetContext),
                targetContext,
                string.IsNullOrWhiteSpace(targetContext.ImageName) ? "(resolved-target)" : targetContext.ImageName,
                BuildProcessMemoryRiskSummary(targetContext),
                targetContext.CurrentTrustTier == ExecutionTrustTier.Unsigned);

            var remediation = ExecuteCriticalProcessRemediation(
                targetEvent,
                targetContext,
                new ThreatDecision(
                    SecurityAction.Allow,
                    Math.Max(targetContext.Score, 90),
                    $"correlated-target-memory-remediation source={sourcePid}",
                    DateTimeOffset.Now));

            if (remediation.DriverCommandSucceeded)
            {
                remediated++;
                details.Add($"pid={targetContext.PID}");
            }
        }

        return $"correlated-target-remediation scanned={scanned} remediated={remediated}{(details.Count > 0 ? $" [{string.Join(", ", details)}]" : string.Empty)}";
    }

    private OrchestratorResult? TryExecuteCorrelatedSourceContainment(
        TelemetryEvent targetEvent,
        ProcessContext targetContext,
        ThreatDecision targetDecision)
    {
        var sourceContext = ResolveCorrelatedSourceContext(targetContext, targetEvent.Timestamp);
        if (sourceContext == null || sourceContext.PID <= 4)
        {
            return null;
        }

        EnsureResolvedProcessIdentity(sourceContext.PID, sourceContext);
        if (string.IsNullOrWhiteSpace(sourceContext.ImageName) ||
            IsStabilityCriticalProcess(sourceContext) ||
            TrustedProcessValidator.IsRollbackGuardBinary(sourceContext.ImageName))
        {
            return null;
        }

        var sourceEvent = new TelemetryEvent(
            targetEvent.Timestamp,
            targetEvent.Kind,
            sourceContext.ImageName,
            sourceContext.PID,
            string.IsNullOrWhiteSpace(targetContext.ImageName) ? targetEvent.ProcessPath : targetContext.ImageName,
            $"critical-target={targetEvent.ProcessId}",
            null,
            0,
            false,
            false,
            false,
            sourceContext.CurrentTrustTier == ExecutionTrustTier.Unsigned,
            false,
            0,
            0,
            sourceContext.PPID,
            targetContext.PID,
            false,
            KernelTrustHint.Unknown);

        var sourceDecision = targetDecision with
        {
            Action = SecurityAction.Terminate,
            Score = Math.Max(targetDecision.Score, 90),
            Reason = string.IsNullOrWhiteSpace(targetDecision.Reason)
                ? $"critical-target-compromise target={targetContext.PID}"
                : $"{targetDecision.Reason};critical-target-compromise target={targetContext.PID}"
        };

        var sourceResult = ExecuteManualEnforcement(sourceEvent, sourceDecision);
        if (sourceResult.Decision.Action == SecurityAction.Allow &&
            sourceResult.Decision.Reason.Contains("user-ignore", StringComparison.OrdinalIgnoreCase))
        {
            var remediationResult = ExecuteCriticalProcessRemediation(
                targetEvent,
                targetContext,
                targetDecision with
                {
                    Action = SecurityAction.Allow,
                    Score = Math.Max(targetDecision.Score, 90),
                    Reason = string.IsNullOrWhiteSpace(targetDecision.Reason)
                        ? $"critical-target-user-ignore-remediated source={sourceContext.PID}"
                        : $"{targetDecision.Reason};critical-target-user-ignore-remediated source={sourceContext.PID}"
                });

            return new OrchestratorResult(
                sourceResult.Decision,
                sourceResult.RollbackCount,
                sourceResult.DriverCommandSucceeded && remediationResult.DriverCommandSucceeded,
                AppendMessage(sourceResult.DriverMessage, remediationResult.DriverMessage),
                sourceEvent);
        }

        return sourceResult with { IncidentTelemetry = sourceEvent };
    }

    private ProcessContext? ResolveCorrelatedSourceContext(ProcessContext targetContext, DateTimeOffset now)
    {
        if (targetContext.LastSuspiciousSourcePid > 4 &&
            now - targetContext.LastSuspiciousSourceAt <= TimeSpan.FromMinutes(2))
        {
            var recent = _contextManager.Get(targetContext.LastSuspiciousSourcePid);
            if (recent != null)
            {
                return recent;
            }
        }

        if (targetContext.PPID <= 4)
        {
            return null;
        }

        var parent = _contextManager.Get(targetContext.PPID);
        return parent != null && IsPotentialInjectionParent(parent) ? parent : null;
    }

    private void TryRunSuspendedStartupScanAttempt(int processId, ProcessContext context, string scanReason)
    {
        if (_memoryScanner == null || processId <= 4)
        {
            return;
        }

        try
        {
            var result = _memoryScanner.ScanProcess(processId);
            context.ApplyEnhancedMemoryScan(result);
            if (!result.IsSuspicious)
            {
                return;
            }

            foreach (var synthetic in BuildSyntheticMemoryEvents(context, result))
            {
                _syntheticTelemetry.Enqueue(synthetic);
            }

            StartupLog.WriteDetection(
                "Detection",
                $"memory-scan-hit pid={processId}, reason={scanReason}, rwx={result.RwxRegionCount}, unbacked={result.UnbackedExecRegionCount}, wx={result.WxTransitionCount}, reflective={result.ReflectiveDllCount}, syscall={result.SyscallStubCount}");
        }
        catch (Exception ex)
        {
            StartupLog.Write("MemScan", $"内存扫描失败 pid={processId}, reason={scanReason}: {ex.Message}");
        }
    }

    private TelemetryEvent EnrichProcessIdentity(TelemetryEvent telemetryEvent)
    {
        if (telemetryEvent.ProcessId <= 4 || !string.IsNullOrWhiteSpace(telemetryEvent.ProcessPath))
        {
            return telemetryEvent;
        }

        var resolvedPath = string.Empty;
        var existing = _contextManager.Get(telemetryEvent.ProcessId);
        if (existing != null && !string.IsNullOrWhiteSpace(existing.ImageName))
        {
            resolvedPath = existing.ImageName;
        }

        if (string.IsNullOrWhiteSpace(resolvedPath))
        {
            resolvedPath = TryReadLiveProcessPath(telemetryEvent.ProcessId);
        }

        if (string.IsNullOrWhiteSpace(resolvedPath))
        {
            return telemetryEvent;
        }

        if (existing != null)
        {
            existing.ImageName = resolvedPath;
        }

        return telemetryEvent with { ProcessPath = resolvedPath };
    }

    private void EnsureResolvedProcessIdentity(int processId, ProcessContext context)
    {
        if (processId <= 4 || !string.IsNullOrWhiteSpace(context.ImageName))
        {
            return;
        }

        var resolvedPath = TryReadLiveProcessPath(processId);
        if (!string.IsNullOrWhiteSpace(resolvedPath))
        {
            context.ImageName = resolvedPath;
        }
    }

    private string ResolveParentProcessPath(int parentProcessId)
    {
        if (parentProcessId <= 4)
        {
            return string.Empty;
        }

        var parentContext = _contextManager.Get(parentProcessId);
        if (parentContext != null && !string.IsNullOrWhiteSpace(parentContext.ImageName))
        {
            return parentContext.ImageName;
        }

        return TryReadLiveProcessPath(parentProcessId);
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

            var queriedPath = TryQueryFullProcessImageName(pid);
            if (!string.IsNullOrWhiteSpace(queriedPath))
            {
                return queriedPath;
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

    private static string TryQueryFullProcessImageName(int pid)
    {
        IntPtr handle = IntPtr.Zero;
        try
        {
            handle = OpenProcess(0x1000, false, (uint)pid);
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
                _ = CloseHandle(handle);
            }
        }
    }

    private static bool LooksLikeWindowsRuntimeProcess(string? processPath) =>
        TrustedProcessValidator.LooksLikeWindowsRuntimeProcess(processPath);

    private static bool IsPotentialInjectionParent(ProcessContext context)
    {
        if (context.IsRestrictedProcess || context.CurrentTrustTier == ExecutionTrustTier.Unsigned)
        {
            return true;
        }

        if (context.LoadedUnsignedDll || context.LoadedSuspiciousDll || context.LoadedNonMicrosoftDll)
        {
            return true;
        }

        if (context.SuspiciousHandleOpenCount > 0 || context.SuspiciousThreadHijackCount > 0)
        {
            return true;
        }

        if (context.MemoryShellcodePatternCount > 0 ||
            context.MemoryReflectiveDllCount > 0 ||
            context.MemoryWxTransitionCount > 0 ||
            context.MemorySyscallStubCount > 0)
        {
            return true;
        }

        if (context.IsLolBinProcess)
        {
            return true;
        }

        if (context.Score >= 20 || context.State >= ProcessState.Alert)
        {
            return true;
        }

        return context.SignatureEvaluated && !context.HasValidSignature;
    }

    private static bool HasHighConfidenceExecutionCompromise(ProcessContext context)
    {
        if (!context.MemoryScanCompleted)
        {
            return false;
        }

        if (context.MemoryShellcodePatternCount > 0 ||
            context.MemoryReflectiveDllCount > 0 ||
            context.MemorySyscallStubCount > 0)
        {
            return true;
        }

        if (context.MemoryWxTransitionCount > 0 &&
            (context.MemoryUnbackedExecRegionCount > 0 || context.MemoryRwxRegionCount > 0))
        {
            return true;
        }

        var hasExecutionHeuristics =
            context.MemoryPebWalkPatternCount > 0 ||
            context.MemoryApiHashPatternCount > 0;

        if (context.MemoryUnbackedExecRegionCount > 0 &&
            (hasExecutionHeuristics || context.WasTargetedBySuspiciousHandle || context.WasRemotelyCreated))
        {
            return true;
        }

        return context.MemoryRwxRegionCount > 0 && hasExecutionHeuristics;
    }

    private static string BuildProcessMemoryRiskSummary(ProcessContext context)
    {
        var parts = new List<string>();
        if (context.MemoryShellcodePatternCount > 0) parts.Add($"shellcode={context.MemoryShellcodePatternCount}");
        if (context.MemoryReflectiveDllCount > 0) parts.Add($"reflective={context.MemoryReflectiveDllCount}");
        if (context.MemorySyscallStubCount > 0) parts.Add($"syscall={context.MemorySyscallStubCount}");
        if (context.MemoryWxTransitionCount > 0) parts.Add($"wx={context.MemoryWxTransitionCount}");
        if (context.MemoryUnbackedExecRegionCount > 0) parts.Add($"unbacked={context.MemoryUnbackedExecRegionCount}");
        if (context.MemoryRwxRegionCount > 0) parts.Add($"rwx={context.MemoryRwxRegionCount}");
        if (context.MemoryPebWalkPatternCount > 0) parts.Add($"peb={context.MemoryPebWalkPatternCount}");
        if (context.MemoryApiHashPatternCount > 0) parts.Add($"apihash={context.MemoryApiHashPatternCount}");
        return parts.Count == 0 ? "no-memory-evidence" : string.Join(",", parts);
    }

    private static EventKind SelectPrimaryMemoryEventKind(ProcessContext context)
    {
        if (context.MemoryShellcodePatternCount > 0 || context.MemorySyscallStubCount > 0)
        {
            return EventKind.MemoryScanShellcode;
        }

        if (context.MemoryReflectiveDllCount > 0)
        {
            return EventKind.MemoryScanReflectiveDll;
        }

        if (context.MemoryWxTransitionCount > 0)
        {
            return EventKind.MemoryScanWxTransition;
        }

        if (context.MemoryUnbackedExecRegionCount > 0)
        {
            return EventKind.MemoryScanUnbackedExec;
        }

        return EventKind.MemoryScanRwx;
    }

    private sealed class UacRegistryHitState
    {
        public int SourcePid { get; init; }
        public DateTimeOffset LastHitAt { get; init; }
        public string LastPath { get; init; } = string.Empty;
    }

    private sealed class UacTriggerState
    {
        public int TriggerPid { get; init; }
        public int SourcePid { get; init; }
        public DateTimeOffset TriggeredAt { get; init; }
        public string TriggerPath { get; init; } = string.Empty;
        public string MatchedRegistryPath { get; init; } = string.Empty;
        public string RegistryHitMatchMode { get; init; } = string.Empty;
        public int RegistryAnchorPid { get; init; }
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

    private void CaptureRollbackSnapshots(TelemetryEvent telemetryEvent)
    {
        if (telemetryEvent.Kind is EventKind.FileWrite or EventKind.FileDelete or EventKind.FileRename)
        {
            var estimatedSize = EstimateBackupSize(telemetryEvent.TargetPath);
            if (!_backupSpaceManager.CanAcceptBackup(estimatedSize))
            {
                return;
            }

            try
            {
                if (telemetryEvent.Kind == EventKind.FileRename)
                {
                    _journal.CaptureRenameForRuntimeEvent(
                        telemetryEvent.SourcePath,
                        telemetryEvent.TargetPath,
                        "file-rename",
                        telemetryEvent.ProcessId,
                        telemetryEvent.VolumeSerialNumber,
                        telemetryEvent.FileId);
                }
                else if (telemetryEvent.Kind == EventKind.FileWrite && telemetryEvent.IsPreOperation)
                {
                    _journal.CaptureKernelPreWriteSnapshot(
                        telemetryEvent.TargetPath,
                        telemetryEvent.SourcePath,
                        "file-pre-write-kernel",
                        telemetryEvent.ProcessId,
                        telemetryEvent.VolumeSerialNumber,
                        telemetryEvent.FileId);
                }
                else
                {
                    var reason = telemetryEvent.Kind == EventKind.FileDelete ? "file-delete" : "file-write";
                    _journal.CaptureFileForRuntimeEvent(
                        telemetryEvent.TargetPath,
                        reason,
                        telemetryEvent.ProcessId,
                        telemetryEvent.VolumeSerialNumber,
                        telemetryEvent.FileId);
                }
            }
            catch (Exception ex)
            {
                StartupLog.Write("Rollback",
                    $"文件快照失败: kind={telemetryEvent.Kind}, target={telemetryEvent.TargetPath}, source={telemetryEvent.SourcePath}",
                    ex);
            }
        }

        if (telemetryEvent.Kind is EventKind.RegistrySet or EventKind.RegistryDelete)
        {
            try
            {
                _journal.CaptureRegistryBeforeChange(telemetryEvent.TargetPath, "registry-change", telemetryEvent.ProcessId);
            }
            catch (Exception ex)
            {
                StartupLog.Write("Rollback", $"注册表快照失败: kind={telemetryEvent.Kind}, target={telemetryEvent.TargetPath}", ex);
            }
        }
    }

    private static string AppendMessage(string current, string append)
    {
        if (string.IsNullOrWhiteSpace(append)) return current;
        if (string.IsNullOrWhiteSpace(current) || current.Equals("allow", StringComparison.OrdinalIgnoreCase)) return append;
        return $"{current}; {append}";
    }

    private static string BuildContainmentSummary(
        bool writeBlocked,
        string writeBlockMessage,
        bool suspended,
        bool suspendUnsupported,
        string suspendMessage)
    {
        var writeState = writeBlocked
            ? "write-block=ok"
            : $"write-block=failed({NormalizeControlMessage(writeBlockMessage)})";

        var suspendState = suspended
            ? "suspend=ok"
            : suspendUnsupported
                ? "suspend=unsupported"
                : $"suspend=failed({NormalizeControlMessage(suspendMessage)})";

        return $"{writeState}; {suspendState}";
    }

    private static string NormalizeControlMessage(string message) =>
        string.IsNullOrWhiteSpace(message) ? "none" : message;

    private static bool IsNotSupportedError(string message) =>
        !string.IsNullOrWhiteSpace(message) &&
        (message.Contains("(50)", StringComparison.Ordinal) ||
         message.Contains("not supported", StringComparison.OrdinalIgnoreCase) ||
         message.Contains("不支持该请求", StringComparison.Ordinal));

    private static bool IsProcessGoneOrInvalid(string message) =>
        !string.IsNullOrWhiteSpace(message) &&
        (message.Contains("(87)", StringComparison.Ordinal) ||
         message.Contains("(1168)", StringComparison.Ordinal) ||
         message.Contains("not found", StringComparison.OrdinalIgnoreCase) ||
         message.Contains("不存在", StringComparison.Ordinal) ||
         message.Contains("找不到", StringComparison.Ordinal));

    private static string BuildPreviewSample(IReadOnlyList<string> preview) =>
        preview.Count == 0 ? "<empty>" : string.Join(" | ", preview.Take(Math.Min(6, preview.Count)));

    private void ResetProcessStateForNewProcess(int processId)
    {
        _eventBuckets.Remove(processId);
        _terminatedProcesses.Remove(processId);
        _rollbackApprovedProcesses.Remove(processId);
        _rollbackFinalizedProcesses.Remove(processId);
        _uacRegistryHits.Remove(processId);
        _uacTriggers.Remove(processId);
        _uacHandledResultPids.Remove(processId);
        _journal.ClearProcessEntries(processId);
        _ = _miniBridge.TryUnblockProcessWrites(processId, out _);
        _ = _miniBridge.TryClearRestrictedProcess(processId, out _);
    }

    private static long EstimateBackupSize(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return 0;
        }

        try
        {
            var fileInfo = new FileInfo(filePath);
            return fileInfo.Exists ? fileInfo.Length : 0;
        }
        catch
        {
            return 0;
        }
    }
}

public sealed record OrchestratorResult(
    ThreatDecision Decision,
    int RollbackCount,
    bool DriverCommandSucceeded,
    string DriverMessage,
    TelemetryEvent? IncidentTelemetry = null
);
