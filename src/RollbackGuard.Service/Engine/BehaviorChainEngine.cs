using RollbackGuard.Common.Models;

namespace RollbackGuard.Service.Engine;

public sealed record BehaviorChainResult(
    string RuleName,
    int ExtraScore,
    string Action,
    bool ShouldSuspend,
    bool ShouldAutoRollback
);

public sealed class BehaviorChainEngine
{
    private static readonly TimeSpan InjectionCorrelationWindow = TimeSpan.FromSeconds(8);

    private static readonly HashSet<string> OfficeProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE"
    };

    private static readonly HashSet<string> SuspiciousChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe"
    };

    private readonly ProcessContextManager _contextManager;

    public BehaviorChainEngine(ProcessContextManager contextManager)
    {
        _contextManager = contextManager;
    }

    public List<BehaviorChainResult> Evaluate(ProcessContext context, TelemetryEvent currentEvent)
    {
        var results = new List<BehaviorChainResult>();

        // RULE-010: Honeypot file touch (highest priority, immediate).
        var r10 = EvaluateRule010_HoneypotTouch(context, currentEvent);
        if (r10 != null)
        {
            results.Add(r10);
        }

        // RULE-006: Shadow copy deletion.
        var r6 = EvaluateRule006_ShadowDelete(context, currentEvent);
        if (r6 != null)
        {
            results.Add(r6);
        }

        // RULE-001: Office macro spawning child process.
        var r1 = EvaluateRule001_OfficeMacro(context, currentEvent);
        if (r1 != null)
        {
            results.Add(r1);
        }

        // RULE-002: Suspicious cross-process handle access before execution transfer.
        var r2 = EvaluateRule002_HandleInjectionPrelude(context, currentEvent);
        if (r2 != null)
        {
            results.Add(r2);
        }

        var r16 = EvaluateRule016_DriverRemoteThreadStartExec(context, currentEvent);
        if (r16 != null)
        {
            results.Add(r16);
        }

        // RULE-003: Classic remote injection sequence.
        var r3 = EvaluateRule003_RemoteInjection(context, currentEvent);
        if (r3 != null)
        {
            results.Add(r3);
        }

        // RULE-004: Suspicious handle access followed by remote thread execution.
        var r4 = EvaluateRule004_HandleToRemoteThread(context, currentEvent);
        if (r4 != null)
        {
            results.Add(r4);
        }

        // RULE-005: Ransomware triple (traverse + overwrite + rename).
        var r5 = EvaluateRule005_RansomwareTriple(context);
        if (r5 != null)
        {
            results.Add(r5);
        }

        // RULE-008: DLL sideload then mass file ops.
        var r8 = EvaluateRule008_DllSideload(context);
        if (r8 != null)
        {
            results.Add(r8);
        }

        // RULE-011: LOLBin suspicious execution chain.
        var r11 = EvaluateRule011_LolBinChain(context, currentEvent);
        if (r11 != null)
        {
            results.Add(r11);
        }

        var r12 = EvaluateRule012_WxTransitionRemoteThread(context, currentEvent);
        if (r12 != null)
        {
            results.Add(r12);
        }

        var r13 = EvaluateRule013_ProcessHollowing(context, currentEvent);
        if (r13 != null)
        {
            results.Add(r13);
        }

        var r15 = EvaluateRule015_SuspiciousParentMemoryExec(context, currentEvent);
        if (r15 != null)
        {
            results.Add(r15);
        }

        var r14 = EvaluateRule014_UnbackedExecWithFileWrites(context, currentEvent);
        if (r14 != null)
        {
            results.Add(r14);
        }

        return results;
    }

    /// RULE-001: Office macro spawning suspicious child process.
    /// MATCH: Office process creates cmd/powershell/wscript/etc within 10s.
    private BehaviorChainResult? EvaluateRule001_OfficeMacro(ProcessContext context, TelemetryEvent currentEvent)
    {
        if (currentEvent.Kind != EventKind.ProcessCreate)
        {
            return null;
        }

        if (context.PPID <= 0)
        {
            return null;
        }

        var childName = Path.GetFileName(context.ImageName);
        if (string.IsNullOrWhiteSpace(childName) || !SuspiciousChildren.Contains(childName))
        {
            return null;
        }

        var parent = _contextManager.Get(context.PPID);
        if (parent == null)
        {
            return null;
        }

        var parentName = Path.GetFileName(parent.ImageName);
        if (string.IsNullOrWhiteSpace(parentName) || !OfficeProcesses.Contains(parentName))
        {
            return null;
        }

        return new BehaviorChainResult(
            "RULE-001-OfficeMacro",
            30,
            "Alert(HIGH)",
            ShouldSuspend: false,
            ShouldAutoRollback: false);
    }

    /// RULE-002: Suspicious handle access that looks like injection setup.
    private BehaviorChainResult? EvaluateRule002_HandleInjectionPrelude(ProcessContext context, TelemetryEvent currentEvent)
    {
        if (currentEvent.Kind != EventKind.InjectPrelude)
        {
            return null;
        }

        if (IsTrustedSystemContext(context))
        {
            return null;
        }

        var hasThreadHijack = context.SuspiciousThreadHijackCount > 0;
        var score = hasThreadHijack ? 38 : 18;
        return new BehaviorChainResult(
            "RULE-002-HandleInjectionPrelude",
            score,
            hasThreadHijack ? "Alert(HIGH)" : "Alert(MEDIUM)",
            ShouldSuspend: false,
            ShouldAutoRollback: false);
    }

    /// RULE-003: Classic remote injection (alloc -> write -> remote thread).
    private BehaviorChainResult? EvaluateRule003_RemoteInjection(ProcessContext context, TelemetryEvent currentEvent)
    {
        if (currentEvent.Kind != EventKind.ThreadCreateRemote)
        {
            return null;
        }

        var targetPid = currentEvent.TargetProcessId;
        if (targetPid <= 4 || targetPid == context.PID)
        {
            return null;
        }

        var targetCtx = _contextManager.Get(targetPid);
        if (targetCtx == null)
        {
            return null;
        }

        var hasCorrelatedPrelude = HasRecentInjectPreludeToTarget(context, targetPid, currentEvent.Timestamp);
        var hasTargetExecutionEvidence = HasTargetExecutionEvidence(targetCtx);
        var hasDriverHighConfidenceExecutionTransfer = DriverThreadEvidence.IsHighConfidenceExecutionTransfer(currentEvent);
        var looksLikeImageBackedBootstrapThread =
            DriverThreadEvidence.HasStartMetadata(currentEvent) &&
            DriverThreadEvidence.IsImageBacked(currentEvent) &&
            !hasDriverHighConfidenceExecutionTransfer &&
            !hasCorrelatedPrelude;

        // Suppress the common CreateProcess bootstrap-thread shape:
        // image-backed start address + no inject prelude.
        if (looksLikeImageBackedBootstrapThread)
        {
            return null;
        }

        if (!hasCorrelatedPrelude && !hasTargetExecutionEvidence)
        {
            return null;
        }

        if (IsTrustedSystemContext(context) && !hasTargetExecutionEvidence)
        {
            return null;
        }

        return new BehaviorChainResult(
            "RULE-003-RemoteInjection",
            hasCorrelatedPrelude && hasTargetExecutionEvidence ? 95 : 75,
            "Suspend+Alert(CRITICAL)",
            ShouldSuspend: true,
            ShouldAutoRollback: false);
    }

    /// RULE-016: Driver already proved that the remote thread starts inside executable private/unbacked or WX memory.
    private BehaviorChainResult? EvaluateRule016_DriverRemoteThreadStartExec(ProcessContext context, TelemetryEvent currentEvent)
    {
        if (currentEvent.Kind != EventKind.ThreadCreateRemote)
        {
            return null;
        }

        if (!DriverThreadEvidence.IsHighConfidenceExecutionTransfer(currentEvent))
        {
            return null;
        }

        if (currentEvent.TargetProcessId <= 4 || currentEvent.TargetProcessId == context.PID)
        {
            return null;
        }

        var hasCorrelatedPrelude = HasRecentInjectPreludeToTarget(context, currentEvent.TargetProcessId, currentEvent.Timestamp);
        var targetContext = _contextManager.Get(currentEvent.TargetProcessId);
        var hasTargetExecutionEvidence = targetContext != null && HasTargetExecutionEvidence(targetContext);
        var sourceAlreadySuspicious =
            context.IsRestrictedProcess ||
            context.CurrentTrustTier == ExecutionTrustTier.Unsigned ||
            context.SuspiciousHandleOpenCount > 0 ||
            context.SuspiciousThreadHijackCount > 0;

        if (!hasCorrelatedPrelude && !hasTargetExecutionEvidence && !sourceAlreadySuspicious)
        {
            return null;
        }

        if (IsTrustedSystemContext(context) && !hasCorrelatedPrelude && !hasTargetExecutionEvidence)
        {
            return null;
        }

        var extraScore = DriverThreadEvidence.IsWriteExecute(currentEvent) ? 95 : 85;
        return new BehaviorChainResult(
            "RULE-016-DriverRemoteThreadStartExec",
            extraScore,
            "Suspend+Alert(CRITICAL)",
            ShouldSuspend: true,
            ShouldAutoRollback: false);
    }

    /// RULE-004: Cross-process handle access followed by remote thread execution.
    private BehaviorChainResult? EvaluateRule004_HandleToRemoteThread(ProcessContext context, TelemetryEvent currentEvent)
    {
        if (currentEvent.Kind != EventKind.ThreadCreateRemote)
        {
            return null;
        }

        if (!HasRecentInjectPreludeToTarget(context, currentEvent.TargetProcessId, currentEvent.Timestamp))
        {
            return null;
        }

        if (IsTrustedSystemContext(context))
        {
            return null;
        }

        return new BehaviorChainResult(
            "RULE-004-HandleToRemoteThread",
            45,
            "Suspend+Alert(CRITICAL)",
            ShouldSuspend: true,
            ShouldAutoRollback: false);
    }

    /// RULE-005: Ransomware triple (traverse + overwrite + rename).
    /// MATCH: 60s window: FilesWritten > 20 AND (Dirs > 5 OR (Dirs >= 1 AND Files > 30)) AND (Renames > 5 OR Overwrites > 10).
    private BehaviorChainResult? EvaluateRule005_RansomwareTriple(ProcessContext context)
    {
        if (context.FilesWrittenInWindow <= 20)
        {
            return null;
        }

        var hasDirTraversal = context.TotalDirsAccessed > 5;
        var hasMassFileOps = context.TotalDirsAccessed >= 1 && context.FilesWrittenInWindow > 30;
        if (!hasDirTraversal && !hasMassFileOps)
        {
            return null;
        }

        if (context.TotalFileRenames <= 5 && context.TotalFileOverwrites <= 10)
        {
            return null;
        }

        return new BehaviorChainResult(
            "RULE-005-RansomwareTriple",
            85,
            "Suspend+Alert(HIGH)",
            ShouldSuspend: true,
            ShouldAutoRollback: false);
    }

    /// RULE-006: Shadow copy deletion.
    private BehaviorChainResult? EvaluateRule006_ShadowDelete(ProcessContext context, TelemetryEvent currentEvent)
    {
        if (currentEvent.Kind != EventKind.ShadowDeleteAttempt)
        {
            return null;
        }

        return new BehaviorChainResult(
            "RULE-006-ShadowDelete",
            95,
            "Suspend+Alert(CRITICAL)",
            ShouldSuspend: true,
            ShouldAutoRollback: false);
    }

    /// RULE-008: DLL sideload then mass file operations.
    /// MATCH: Suspicious DLL + burst writes in 60s + overwrite/extension-change evidence.
    private BehaviorChainResult? EvaluateRule008_DllSideload(ProcessContext context)
    {
        if (!context.LoadedSuspiciousDll)
        {
            return null;
        }

        // Suppress this rule for trusted Windows system processes.
        if (IsTrustedSystemContext(context))
        {
            return null;
        }

        var now = DateTimeOffset.Now;
        var recentFileWrites = context.EventHistory
            .Count(e => e.Kind == EventKind.FileWrite && (now - e.Timestamp) <= TimeSpan.FromSeconds(60));

        if (recentFileWrites <= 15)
        {
            return null;
        }

        if (context.TotalFileOverwrites <= 5 && context.ExtensionChangeCount <= 2)
        {
            return null;
        }

        return new BehaviorChainResult(
            "RULE-008-DllSideloadFileOps",
            25,
            "Alert(HIGH)",
            ShouldSuspend: false,
            ShouldAutoRollback: false);
    }

    /// RULE-010: Honeypot file touch.
    /// Immediate manual containment candidate.
    private BehaviorChainResult? EvaluateRule010_HoneypotTouch(ProcessContext context, TelemetryEvent currentEvent)
    {
        if (currentEvent.Kind != EventKind.HoneyFileTouched)
        {
            return null;
        }

        return new BehaviorChainResult(
            "RULE-010-HoneypotTouch",
            100,
            "Suspend+ManualReview",
            ShouldSuspend: true,
            ShouldAutoRollback: true);
    }

    /// RULE-011: LOLBin spawned by suspicious parent with file writes or network.
    private BehaviorChainResult? EvaluateRule011_LolBinChain(ProcessContext context, TelemetryEvent currentEvent)
    {
        if (!context.IsLolBinProcess)
            return null;

        if (currentEvent.Kind != EventKind.ProcessCreate && context.TotalFilesWritten < 1)
            return null;

        // Check if parent is also suspicious
        if (context.PPID <= 0)
            return null;

        var parent = _contextManager.Get(context.PPID);
        if (parent == null)
            return null;

        var parentName = Path.GetFileName(parent.ImageName);
        if (string.IsNullOrWhiteSpace(parentName))
            return null;

        // LOLBin spawned by another LOLBin or Office = high suspicion
        if (SuspiciousChildren.Contains(parentName) || OfficeProcesses.Contains(parentName) || parent.IsLolBinProcess)
        {
            return new BehaviorChainResult(
                "RULE-011-LolBinChain",
                40,
                "Alert(HIGH)",
                ShouldSuspend: false,
                ShouldAutoRollback: false);
        }

        return null;
    }

    private BehaviorChainResult? EvaluateRule012_WxTransitionRemoteThread(ProcessContext context, TelemetryEvent currentEvent)
    {
        if (currentEvent.Kind != EventKind.ThreadCreateRemote)
        {
            return null;
        }

        var target = _contextManager.Get(currentEvent.TargetProcessId);
        if (target == null)
        {
            return null;
        }

        if (target.MemoryWxTransitionCount <= 0 && target.MemoryUnbackedExecRegionCount <= 0)
        {
            return null;
        }

        return new BehaviorChainResult(
            "RULE-012-WxTransitionRemoteThread",
            90,
            "Suspend+Alert(CRITICAL)",
            ShouldSuspend: true,
            ShouldAutoRollback: false);
    }

    private BehaviorChainResult? EvaluateRule013_ProcessHollowing(ProcessContext context, TelemetryEvent currentEvent)
    {
        if (currentEvent.Kind != EventKind.ThreadCreateRemote)
        {
            return null;
        }

        var target = _contextManager.Get(currentEvent.TargetProcessId);
        if (target == null || !target.IsSuspended || !HasRecentInjectPreludeToTarget(context, currentEvent.TargetProcessId, currentEvent.Timestamp))
        {
            return null;
        }

        return new BehaviorChainResult(
            "RULE-013-ProcessHollowing",
            95,
            "Suspend+Alert(CRITICAL)",
            ShouldSuspend: true,
            ShouldAutoRollback: false);
    }

    private BehaviorChainResult? EvaluateRule015_SuspiciousParentMemoryExec(ProcessContext context, TelemetryEvent currentEvent)
    {
        if (currentEvent.Kind is not (
            EventKind.MemoryScanShellcode or
            EventKind.MemoryScanRwx or
            EventKind.MemoryScanUnbackedExec or
            EventKind.MemoryScanWxTransition or
            EventKind.MemoryScanReflectiveDll))
        {
            return null;
        }

        if (!HasTargetExecutionEvidence(context) || context.PPID <= 4)
        {
            return null;
        }

        var parent = _contextManager.Get(context.PPID);
        if (parent == null || !IsPotentialInjectionParent(parent))
        {
            return null;
        }

        var extraScore =
            parent.SuspiciousThreadHijackCount > 0 ||
            parent.MemorySyscallStubCount > 0 ||
            parent.MemoryReflectiveDllCount > 0
                ? 95
                : 80;

        // If the hollowing TARGET is itself a trusted system process (e.g. svchost being hollowed),
        // that indicates a higher-severity scenario — elevate the minimum score to 90.
        // Note: this intentionally scores HIGHER than the default 80 for non-trusted targets;
        // a trusted process exhibiting these indicators strongly suggests process hollowing.
        if (IsTrustedSystemContext(context))
        {
            extraScore = Math.Max(extraScore, 90);
        }

        return new BehaviorChainResult(
            "RULE-015-SuspiciousParentMemoryExec",
            extraScore,
            "Suspend+Alert(CRITICAL)",
            ShouldSuspend: true,
            ShouldAutoRollback: false);
    }

    private static BehaviorChainResult? EvaluateRule014_UnbackedExecWithFileWrites(ProcessContext context, TelemetryEvent currentEvent)
    {
        if (currentEvent.Kind is not (EventKind.FileWrite or EventKind.FileCreate))
        {
            return null;
        }

        if (context.MemoryUnbackedExecRegionCount <= 0 || context.TotalFilesWritten < 3)
        {
            return null;
        }

        return new BehaviorChainResult(
            "RULE-014-UnbackedExecWithFileWrites",
            60,
            "Alert(HIGH)",
            ShouldSuspend: false,
            ShouldAutoRollback: false);
    }

    private static bool IsTrustedSystemContext(ProcessContext context)
    {
        return TrustedProcessValidator.IsTrustedSystemProcess(context);
    }

    private static bool HasRecentInjectPreludeToTarget(ProcessContext context, int targetPid, DateTimeOffset now)
    {
        if (targetPid <= 4)
        {
            return false;
        }

        return context.EventHistory.Any(evt =>
            evt.Kind == EventKind.InjectPrelude &&
            evt.TargetProcessId == targetPid &&
            now - evt.Timestamp <= InjectionCorrelationWindow);
    }

    private static bool HasTargetExecutionEvidence(ProcessContext target)
    {
        if (target.MemoryShellcodePatternCount > 0 ||
            target.MemoryReflectiveDllCount > 0 ||
            target.MemorySyscallStubCount > 0)
        {
            return true;
        }

        if (target.MemoryWxTransitionCount > 0 &&
            (target.MemoryUnbackedExecRegionCount > 0 || target.MemoryRwxRegionCount > 0))
        {
            return true;
        }

        return target.MemoryUnbackedExecRegionCount > 0 &&
               (target.MemoryPebWalkPatternCount > 0 || target.MemoryApiHashPatternCount > 0);
    }

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
}
