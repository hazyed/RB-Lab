using RollbackGuard.Common.Models;

namespace RollbackGuard.Service.Engine;

public sealed class RiskEngine
{
    private static readonly HashSet<string> OfficeProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE"
    };

    private static readonly HashSet<string> SuspiciousOfficeChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
        "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe"
    };

    public ThreatDecision Evaluate(
        PolicyConfig policy,
        ProcessContext context,
        IReadOnlyCollection<TelemetryEvent> recentEvents)
    {
        if (recentEvents.Count == 0)
        {
            return new ThreatDecision(SecurityAction.Allow, 0, "no-event", DateTimeOffset.Now);
        }

        var ordered = recentEvents.OrderBy(e => e.Timestamp).ToList();
        var last = ordered[^1];
        var score = 0;
        var reasons = new List<string>();
        var isTrustedSystemProcess = IsTrustedSystemProcessContext(context);

        // Extreme confidence (single trigger -> action).
        if (ordered.Any(e => e.Kind == EventKind.HoneyFileTouched))
        {
            score += 100;
            reasons.Add("honeypot+100");
        }

        if (context.KernelEntropyAutoBlockCount > 0)
        {
            var kernelBlockScore = isTrustedSystemProcess ? 45 : 140;
            score += kernelBlockScore;
            reasons.Add($"kernel-entropy-autoblock({context.KernelEntropyAutoBlockCount})+{kernelBlockScore}");
        }
        else if (context.KernelLowToHighEntropyCount >= 3)
        {
            var kernelLowToHighScore = isTrustedSystemProcess ? 25 : 90;
            score += kernelLowToHighScore;
            reasons.Add($"kernel-low-to-high({context.KernelLowToHighEntropyCount})+{kernelLowToHighScore}");
        }
        else if (context.KernelHighEntropyRawCount > 0)
        {
            var kernelRawScore = isTrustedSystemProcess ? 6 : 20;
            score += kernelRawScore;
            reasons.Add($"kernel-raw-high({context.KernelHighEntropyRawCount})+{kernelRawScore}");
        }

        if (context.HighEntropyConsecutiveSpikeFiles >= 2)
        {
            const int entropyRansomScore = 130;
            score += entropyRansomScore;
            reasons.Add($"entropy-ransom({context.HighEntropyConsecutiveSpikeFiles})+{entropyRansomScore}");
        }
        else if (context.HighEntropySpikeCount >= 1)
        {
            const int entropySpikeScore = 40;
            score += entropySpikeScore;
            reasons.Add($"entropy-spike({context.HighEntropySpikeCount})+{entropySpikeScore}");
        }

        if (ordered.Any(e => e.Kind == EventKind.ShadowDeleteAttempt))
        {
            score += 95;
            reasons.Add("shadow-delete+95");
        }

        if (context.CompressionRatioConfirmedCount > 0)
        {
            var compressionScore = isTrustedSystemProcess ? 20 : 70;
            score += compressionScore;
            reasons.Add($"compression-confirm({context.CompressionRatioConfirmedCount})+{compressionScore}");
        }

        if (context.HasAnomalousCallStack)
        {
            var callStackScore = isTrustedSystemProcess ? 25 : 80;
            score += callStackScore;
            reasons.Add($"callstack-unbacked({context.CallStackUnbackedFrameCount})+{callStackScore}");
        }

        // High confidence.
        if (context.ExtensionChangeCount > 5)
        {
            var extScore = isTrustedSystemProcess ? 35 : 80;
            score += extScore;
            reasons.Add($"ext-change({context.ExtensionChangeCount})+{extScore}");
        }
        else if (context.ExtensionChangeCount > 2)
        {
            var extScore = isTrustedSystemProcess ? 15 : 45;
            score += extScore;
            reasons.Add($"ext-change-early({context.ExtensionChangeCount})+{extScore}");
        }

        if (context.TotalFileAccesses > 10 && context.UniqueFileRatio > 0.85)
        {
            var ratioScore = isTrustedSystemProcess ? 15 : 50;
            score += ratioScore;
            reasons.Add($"unique-ratio({context.UniqueFileRatio:F2})+{ratioScore}");
        }

        var hasRemoteThread = ordered.Any(e => e.Kind == EventKind.ThreadCreateRemote);
        var hasCorrelatedPrelude = HasRemoteThreadPreludeCorrelation(ordered);
        var hasDriverHighConfidenceRemoteThread = ordered.Any(DriverThreadEvidence.IsHighConfidenceExecutionTransfer);
        if (hasRemoteThread)
        {
            var remoteThreadScore = hasDriverHighConfidenceRemoteThread && hasCorrelatedPrelude
                ? (isTrustedSystemProcess ? 35 : 85)
                : hasDriverHighConfidenceRemoteThread
                    ? (isTrustedSystemProcess ? 8 : 24)
                    : hasCorrelatedPrelude
                    ? (isTrustedSystemProcess ? 15 : 40)
                    : (isTrustedSystemProcess ? 4 : 12);
            score += remoteThreadScore;
            reasons.Add(hasDriverHighConfidenceRemoteThread && hasCorrelatedPrelude
                ? $"driver-thread-start-exec({DescribeDriverThreadEvidence(ordered)})+{remoteThreadScore}"
                : hasDriverHighConfidenceRemoteThread
                    ? $"driver-thread-start-observed({DescribeDriverThreadEvidence(ordered)})+{remoteThreadScore}"
                : hasCorrelatedPrelude
                    ? $"remote-thread-chain+{remoteThreadScore}"
                    : $"remote-thread-observed+{remoteThreadScore}");
        }

        var injectHandleEvents = ordered.Count(e => e.Kind == EventKind.InjectPrelude);
        if (injectHandleEvents > 0)
        {
            var injectHandleScore = isTrustedSystemProcess
                ? 2
                : Math.Min(12, 4 + ((injectHandleEvents - 1) * 2));
            score += injectHandleScore;
            reasons.Add($"inject-prelude({injectHandleEvents})+{injectHandleScore}");
        }

        var confirmedInjectEvents = ordered.Count(e => e.Kind == EventKind.ProcessInject);
        if (confirmedInjectEvents > 0)
        {
            var confirmedInjectScore = isTrustedSystemProcess ? 12 : 30;
            score += confirmedInjectScore;
            reasons.Add($"confirmed-inject({confirmedInjectEvents})+{confirmedInjectScore}");
        }

        if (context.LoadedSuspiciousDll)
        {
            // System process loading suspicious DLL is highly unusual.
            var dllScore = isTrustedSystemProcess ? 65 : 40;
            score += dllScore;
            reasons.Add($"suspicious-dll+{dllScore}");
        }
        else if (context.LoadedUnsignedDll)
        {
            // Unsigned DLL inside trusted system process should stay suspicious.
            var unsignedDllScore = isTrustedSystemProcess ? 55 : 25;
            score += unsignedDllScore;
            reasons.Add($"unsigned-dll+{unsignedDllScore}");
        }

        if (context.TotalFileOverwrites > 10)
        {
            var overwriteScore = isTrustedSystemProcess ? 18 : 65;
            score += overwriteScore;
            reasons.Add($"overwrite-pattern({context.TotalFileOverwrites})+{overwriteScore}");
        }

        var suspiciousExtCount = ordered.Count(e => e.IsSuspiciousExtension);
        if (suspiciousExtCount >= 2)
        {
            var suspiciousExtScore = isTrustedSystemProcess ? 20 : 50;
            score += suspiciousExtScore;
            reasons.Add($"suspicious-ext({suspiciousExtCount})+{suspiciousExtScore}");
        }

        if (context.DirGrowthRate > 1.0 && context.TotalDirsAccessed > 5)
        {
            var dirGrowthScore = isTrustedSystemProcess ? 15 : 45;
            score += dirGrowthScore;
            reasons.Add($"dir-growth({context.DirGrowthRate:F1})+{dirGrowthScore}");
        }

        // Medium confidence.
        if (ordered.Any(e => e.IsUnsignedProcess))
        {
            reasons.Add("unsigned-process-observed-no-score");
        }

        if (context.KernelLowToHighEntropyCount > 0 && !context.HasValidSignature)
        {
            var unsignedEntropyScore = isTrustedSystemProcess ? 8 : 35;
            score += unsignedEntropyScore;
            reasons.Add($"unsigned-kernel-entropy+{unsignedEntropyScore}");
        }

        if (context.WasRemotelyCreated && context.TotalFilesWritten > 0)
        {
            score += 30;
            reasons.Add("remote-created-then-write+30");
        }

        if (context.HasCorrelatedInjection)
        {
            var correlatedScore = isTrustedSystemProcess ? 20 : 70;
            score += correlatedScore;
            reasons.Add($"handle-remote-thread-chain+{correlatedScore}");
        }
        else if (context.HasHandleInjectionBurst)
        {
            var handleBurstScore = isTrustedSystemProcess ? 8 : 35;
            score += handleBurstScore;
            reasons.Add($"handle-injection-burst+{handleBurstScore}");
        }

        var regPersistence = ordered.Count(e => e.HitsPersistenceRegistry);
        if (regPersistence > 0)
        {
            score += 20;
            reasons.Add($"persistence-reg({regPersistence})+20");
        }

        if (context.FilesWrittenInWindow > 50)
        {
            var highFreqScore = isTrustedSystemProcess ? 5 : 15;
            score += highFreqScore;
            reasons.Add($"high-freq-write({context.FilesWrittenInWindow})+{highFreqScore}");
        }
        else if (context.FilesWrittenInWindow > 30)
        {
            var writeRateScore = isTrustedSystemProcess ? 8 : 20;
            score += writeRateScore;
            reasons.Add($"write-rate({context.FilesWrittenInWindow})+{writeRateScore}");
        }

        if (context.DirsAccessedInWindow > 10)
        {
            var dirRateScore = isTrustedSystemProcess ? 5 : 15;
            score += dirRateScore;
            reasons.Add($"dir-rate({context.DirsAccessedInWindow})+{dirRateScore}");
        }

        if (context.TotalFilesWritten > 50)
        {
            var lifeScore = isTrustedSystemProcess ? 5 : 15;
            score += lifeScore;
            reasons.Add($"lifetime-files({context.TotalFilesWritten})+{lifeScore}");
        }

        var protectedTouch = ordered.Count(e => e.IsProtectedTarget);
        if (protectedTouch > 0)
        {
            var protectedBase = Math.Min(30, protectedTouch * 5);
            var protectedScore = isTrustedSystemProcess ? Math.Max(1, protectedBase / 3) : protectedBase;
            score += protectedScore;
            reasons.Add($"protected({protectedTouch})+{protectedScore}");
        }

        if (IsOfficeMacroChild(context))
        {
            score += 20;
            reasons.Add("office-macro-child+20");
        }

        // LOLBin execution with file writes
        if (context.IsLolBinProcess && context.TotalFilesWritten > 0)
        {
            var lolScore = isTrustedSystemProcess ? 10 : 35;
            score += lolScore;
            reasons.Add($"lolbin-write({context.LolBinType})+{lolScore}");
        }

        if (context.MemoryScanSuspicious)
        {
            var hasHighConfidenceMemoryExecutionTransfer =
                context.MemoryUnbackedExecRegionCount > 0 ||
                context.MemoryWxTransitionCount > 0 ||
                context.MemoryReflectiveDllCount > 0 ||
                context.MemoryAmsiDetectionCount > 0 ||
                context.HasCorrelatedInjection ||
                hasDriverHighConfidenceRemoteThread;
            var hasCorrelatedShellcodePattern =
                context.MemoryShellcodePatternCount > 0 &&
                (hasHighConfidenceMemoryExecutionTransfer ||
                 (context.MemoryRwxRegionCount > 0 &&
                  (context.MemoryPebWalkPatternCount > 0 ||
                   context.MemoryApiHashPatternCount > 0 ||
                   context.MemorySyscallStubCount > 0)));

            if (hasCorrelatedShellcodePattern)
            {
                var shellcodeScore = isTrustedSystemProcess ? 35 : 85;
                score += shellcodeScore;
                reasons.Add($"memory-shellcode({context.MemoryShellcodePatternCount})+{shellcodeScore}");
            }
            else if (context.MemoryShellcodePatternCount > 0)
            {
                reasons.Add($"memory-shellcode-observed({context.MemoryShellcodePatternCount})-no-score");
            }
            else if (context.MemoryAmsiDetectionCount > 0)
            {
                var amsiMemoryScore = isTrustedSystemProcess ? 40 : 90;
                score += amsiMemoryScore;
                reasons.Add($"memory-amsi({context.MemoryAmsiDetectionCount})+{amsiMemoryScore}");
            }
            else if (context.MemoryRwxRegionCount > 0)
            {
                var rwxScore = isTrustedSystemProcess ? 10 : Math.Min(45, context.MemoryRwxRegionCount * 15);
                score += rwxScore;
                reasons.Add($"memory-rwx({context.MemoryRwxRegionCount})+{rwxScore}");
            }
        }

        if (context.MemoryUnbackedExecRegionCount > 0)
        {
            var scoreDelta = isTrustedSystemProcess ? 20 : 50;
            score += scoreDelta;
            reasons.Add($"unbacked-exec({context.MemoryUnbackedExecRegionCount})+{scoreDelta}");
        }

        if (context.MemoryWxTransitionCount > 0)
        {
            var scoreDelta = isTrustedSystemProcess ? 30 : 70;
            score += scoreDelta;
            reasons.Add($"wx-transition({context.MemoryWxTransitionCount})+{scoreDelta}");
        }

        if (context.MemoryReflectiveDllCount > 0)
        {
            var scoreDelta = isTrustedSystemProcess ? 40 : 90;
            score += scoreDelta;
            reasons.Add($"reflective-dll({context.MemoryReflectiveDllCount})+{scoreDelta}");
        }

        var hasMemoryExecutionTransferEvidence =
            context.MemoryUnbackedExecRegionCount > 0 ||
            context.MemoryWxTransitionCount > 0 ||
            context.MemoryReflectiveDllCount > 0 ||
            context.MemoryAmsiDetectionCount > 0 ||
            context.HasCorrelatedInjection ||
            hasDriverHighConfidenceRemoteThread;

        if (context.MemoryPebWalkPatternCount > 0 || context.MemoryApiHashPatternCount > 0)
        {
            if (hasMemoryExecutionTransferEvidence)
            {
                var scoreDelta = isTrustedSystemProcess ? 12 : 35;
                score += scoreDelta;
                reasons.Add($"api-resolve-pattern-correlated({context.MemoryPebWalkPatternCount + context.MemoryApiHashPatternCount})+{scoreDelta}");
            }
            else
            {
                reasons.Add($"api-resolve-pattern-observed({context.MemoryPebWalkPatternCount + context.MemoryApiHashPatternCount})-no-score");
            }
        }

        if (context.MemorySyscallStubCount > 0)
        {
            if (hasMemoryExecutionTransferEvidence)
            {
                var scoreDelta = isTrustedSystemProcess ? 10 : 30;
                score += scoreDelta;
                reasons.Add($"direct-syscall-correlated({context.MemorySyscallStubCount})+{scoreDelta}");
            }
            else
            {
                reasons.Add($"direct-syscall-observed({context.MemorySyscallStubCount})-no-score");
            }
        }

        if (context.MemoryHighEntropyRegionCount > 3)
        {
            var scoreDelta = isTrustedSystemProcess ? 15 : 35;
            score += scoreDelta;
            reasons.Add($"memory-entropy({context.MemoryHighEntropyRegionCount})+{scoreDelta}");
        }

        if (context.HasBeenRemediated)
        {
            score -= 20;
            reasons.Add("remediated-20");
        }

        // Persistence: multiple mechanisms
        if (context.PersistenceAttempts >= 2)
        {
            score += 40;
            reasons.Add($"multi-persistence({context.PersistenceAttempts})+40");
        }
        else if (context.PersistenceAttempts == 1)
        {
            score += 20;
            reasons.Add($"persistence({string.Join(",", context.PersistenceTypes)})+20");
        }

        // Score reduction (false positive mitigation).
        if (context.HasValidSignature)
        {
            score -= 30;
            reasons.Add("signed-30");
        }

        if (context.IsMicrosoftCleanChain)
        {
            score -= 35;
            reasons.Add("microsoft-clean-chain-35");
        }

        if (isTrustedSystemProcess)
        {
            score -= 15;
            reasons.Add("trusted-microsoft-process-15");
        }

        score = Math.Max(0, score);

        context.UpdateState(score);

        var reason = string.Join(";", reasons);
        var action = ResolveAction(policy, score);

        return new ThreatDecision(action, score, reason, last.Timestamp);
    }

    private static SecurityAction ResolveAction(PolicyConfig policy, int score)
    {
        if (score >= policy.ScoreMalicious)
        {
            return SecurityAction.Terminate;
        }

        if (score >= policy.ScoreSuspicious)
        {
            return SecurityAction.Block;
        }

        if (score >= policy.ScoreAlert)
        {
            return SecurityAction.Block;
        }

        return SecurityAction.Allow;
    }

    private static bool IsOfficeMacroChild(ProcessContext context)
    {
        if (context.PPID <= 0 || string.IsNullOrWhiteSpace(context.ParentImageName))
        {
            return false;
        }

        var processName = Path.GetFileName(context.ImageName);
        if (string.IsNullOrWhiteSpace(processName) || !SuspiciousOfficeChildren.Contains(processName))
        {
            return false;
        }

        var parentName = Path.GetFileName(context.ParentImageName);
        return !string.IsNullOrWhiteSpace(parentName) && OfficeProcesses.Contains(parentName);
    }

    private static bool IsTrustedSystemProcessContext(ProcessContext context)
    {
        // Use full path + signature validation instead of name-only check
        return TrustedProcessValidator.IsTrustedSystemProcess(context);
    }

    private static bool HasRemoteThreadPreludeCorrelation(IReadOnlyList<TelemetryEvent> ordered)
    {
        for (var i = 0; i < ordered.Count; i++)
        {
            var evt = ordered[i];
            if (evt.Kind != EventKind.ThreadCreateRemote || evt.TargetProcessId <= 4)
            {
                continue;
            }

            for (var j = i - 1; j >= 0; j--)
            {
                var previous = ordered[j];
                if (previous.ProcessId != evt.ProcessId)
                {
                    continue;
                }

                if (evt.Timestamp - previous.Timestamp > TimeSpan.FromSeconds(8))
                {
                    break;
                }

                if (previous.Kind == EventKind.InjectPrelude && previous.TargetProcessId == evt.TargetProcessId)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static string DescribeDriverThreadEvidence(IReadOnlyList<TelemetryEvent> ordered)
    {
        foreach (var evt in ordered)
        {
            if (DriverThreadEvidence.IsHighConfidenceExecutionTransfer(evt))
            {
                return DriverThreadEvidence.Describe(evt);
            }
        }

        return "none";
    }

}
