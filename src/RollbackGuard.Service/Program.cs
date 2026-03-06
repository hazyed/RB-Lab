using RollbackGuard.Service;
using System.Diagnostics;
using RollbackGuard.Common.Diagnostics;
using RollbackGuard.Common.Models;
using RollbackGuard.Common.Protocol;
using RollbackGuard.Common.Runtime;
using RollbackGuard.Common.Storage;
using RollbackGuard.Service.Engine;
using RollbackGuard.Service.Infra;
using RollbackGuard.Service.Interaction;
using RollbackGuard.Service.Rollback;
using System.Text.Json;

try
{
    RuntimePaths.EnsureAll();
    StartupLog.Write("Service", "startup begin");

    var policy = PolicyConfigStore.LoadOrCreate(RuntimePaths.PolicyPath);
    StartupLog.Write("Service", $"dataRoot={RuntimePaths.DataRoot}; device={policy.DriverDevicePath}; minifilter={policy.MiniFilterDevicePath}; policy={policy.PolicyVersion}");

    using var bridge = new DriverCommandBridge(policy.DriverDevicePath);
    if (!bridge.TryConnect(out var connectError))
    {
        var connectMessage = $"driver connect failed: {connectError}";
        Console.Error.WriteLine($"RollbackGuard.Service ERROR: {connectError}");
        StartupLog.Write("Service", connectMessage);

        StatusStore.Save(RuntimePaths.StatusPath, new RuntimeStatus(
            DateTimeOffset.Now,
            false,
            "driver-disconnected",
            policy.PolicyVersion,
            0,
            connectError));

        Environment.ExitCode = 2;
        return;
    }
    StartupLog.Write("Service", $"driver connected: {policy.DriverDevicePath}; transport={bridge.TransportMode}");

    if (string.IsNullOrWhiteSpace(policy.MiniFilterDevicePath))
    {
        const string pathError = "minifilter device path is empty";
        Console.Error.WriteLine($"RollbackGuard.Service ERROR: {pathError}");
        StartupLog.Write("Service", pathError);

        StatusStore.Save(RuntimePaths.StatusPath, new RuntimeStatus(
            DateTimeOffset.Now,
            false,
            "minifilter-disconnected",
            policy.PolicyVersion,
            0,
            pathError));

        Environment.ExitCode = 2;
        return;
    }

    using var miniBridge = new DriverCommandBridge(policy.MiniFilterDevicePath);
    if (!miniBridge.TryConnect(out var miniConnectError))
    {
        var connectMessage = $"minifilter connect failed: {miniConnectError}";
        Console.Error.WriteLine($"RollbackGuard.Service ERROR: {miniConnectError}");
        StartupLog.Write("Service", connectMessage);

        StatusStore.Save(RuntimePaths.StatusPath, new RuntimeStatus(
            DateTimeOffset.Now,
            false,
            "minifilter-disconnected",
            policy.PolicyVersion,
            0,
            miniConnectError));

        Environment.ExitCode = 2;
        return;
    }
    StartupLog.Write("Service", $"minifilter connected: {policy.MiniFilterDevicePath}; transport={miniBridge.TransportMode}");

    var journal = new RollbackJournal(RuntimePaths.RollbackRoot, policy.ProtectedFolders);
    StartupLog.Write("Service", "baseline disabled; backup-mode=kernel-prewrite-only");

    var contextManager = new ProcessContextManager();
    var binaryTrustCache = new BinaryTrustCache(RuntimePaths.SignatureCachePath);
    var behaviorChain = new BehaviorChainEngine(contextManager);
    var honeypot = new HoneypotManager();
    var processTree = new ProcessTree();
    var backupSpaceManager = new BackupSpaceManager(journal.FileRoot);

    // Initialize AMSI scanner for memory scanning.
    AmsiScanner? amsiScanner = null;
    try
    {
        amsiScanner = new AmsiScanner();
        if (!amsiScanner.Initialize())
        {
            StartupLog.Write("Service", "AMSI init failed (non-fatal); continuing without AMSI");
            amsiScanner.Dispose();
            amsiScanner = null;
        }
    }
    catch (Exception amsiEx)
    {
        StartupLog.Write("Service", $"AMSI init exception (non-fatal): {amsiEx.Message}");
        amsiScanner = null;
    }

    // Initialize Memory Scanner
    var memoryScanner = new MemoryScanner(amsiScanner);
    var shellcodeRemediator = new ShellcodeRemediator(memoryScanner);

    try
    {
        honeypot.Deploy();
        honeypot.RegisterWithMinifilter(miniBridge);
    }
    catch (Exception honeypotEx)
    {
        StartupLog.Write("Service", $"honeypot init failed (non-fatal): {honeypotEx.Message}");
    }

    var approvalGate = new UserPopupApprovalGate();

    var orchestrator = new ThreatOrchestrator(
        policy,
        new RiskEngine(),
        bridge,
        miniBridge,
        journal,
        approvalGate,
        contextManager,
        binaryTrustCache,
        behaviorChain,
        honeypot,
        processTree,
        backupSpaceManager,
        memoryScanner,
        shellcodeRemediator);
    using var periodicMemoryScanner = new PeriodicMemoryScanner(
        contextManager,
        memoryScanner,
        (pid, result, _) => orchestrator.IngestSyntheticMemoryEvent(pid, result));
    periodicMemoryScanner.Start();
    var processAttributionCache = new ProcessAttributionCache();
    var selfPid = Environment.ProcessId;
    var selfProcessPath = NormalizePath(Environment.ProcessPath);
    var selfProcessName = string.IsNullOrWhiteSpace(selfProcessPath)
        ? string.Empty
        : Path.GetFileName(selfProcessPath);
    var selfBaseDir = NormalizePath(AppContext.BaseDirectory);
    StartupLog.Write("Service", "startup complete; source=kernel-driver-only; approval-mode=manual-confirm");
    approvalGate.ShowServiceReady(
        $"策略版本: {policy.PolicyVersion}\r\n" +
        $"驱动设备: {policy.DriverDevicePath}\r\n" +
        $"微过滤器: {policy.MiniFilterDevicePath}\r\n" +
        $"蜜罐/周期扫描: 已启动\r\n" +
        $"提示: 现在可以开始测试");
    StartupLog.Write("Service", "ready-popup queued; event loop entering");

    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, args) =>
    {
        args.Cancel = true;
        cts.Cancel();
    };
    var kernelWaitHandles = BuildKernelWaitHandles();

    var burstCounter = new Dictionary<int, int>();
    const int MaxReadBatchesPerCycle = 64;

    while (!cts.IsCancellationRequested)
    {
        WaitHandle.WaitAny(kernelWaitHandles, TimeSpan.FromMilliseconds(80));
        if (cts.IsCancellationRequested)
        {
            break;
        }

        var telemetryBatch = new List<TelemetryEvent>();
        telemetryBatch.AddRange(orchestrator.DrainSyntheticTelemetry());
        var driverRawCount = 0;
        var miniRawCount = 0;
        var filteredSelfCount = 0;
        var filteredReservedPidCount = 0;
        var recoveredPidCount = 0;

        var bridgeReadOk = ReadBridgeBurst(bridge, MaxReadBatchesPerCycle, out var rawEvents, out var readError);
        if (!bridgeReadOk)
        {
            var message = $"driver read-events failed: {readError}";
            StartupLog.Write("Service", message);
            throw new IOException(message);
        }
        driverRawCount = rawEvents.Count;

        foreach (var raw in rawEvents)
        {
            var mappedTimestamp = raw.TimestampUnixMs > 0
                ? DateTimeOffset.FromUnixTimeMilliseconds(raw.TimestampUnixMs)
                : DateTimeOffset.Now;
            var mappedPath = processAttributionCache.ResolvePath((int)raw.ProcessId, raw.ProcessPath, mappedTimestamp);
            var mappedPid = (int)raw.ProcessId;
            if (mappedPid <= 4 && !string.IsNullOrWhiteSpace(mappedPath))
            {
                var recoveredPid = processAttributionCache.ResolvePidByPath(mappedPath, mappedTimestamp);
                if (recoveredPid > 4)
                {
                    mappedPid = recoveredPid;
                    recoveredPidCount++;
                }
            }

            var mapped = TelemetryMapper.Map(raw, policy, 0, mappedPath, mappedPid);

            if (IsSelfTelemetry(mapped))
            {
                filteredSelfCount++;
                continue;
            }

            processAttributionCache.Observe(mapped.ProcessId, mapped.ProcessPath, mapped.Timestamp);

            if (mapped.ProcessId <= 4)
            {
                filteredReservedPidCount++;
                continue;
            }

            telemetryBatch.Add(mapped);
        }

        var miniReadOk = ReadBridgeBurst(miniBridge, MaxReadBatchesPerCycle, out var miniRawEvents, out var miniReadError);
        if (!miniReadOk)
        {
            var message = $"minifilter read-events failed: {miniReadError}";
            StartupLog.Write("Service", message);
            throw new IOException(message);
        }
        miniRawCount = miniRawEvents.Count;

        foreach (var raw in miniRawEvents)
        {
            var mappedTimestamp = raw.TimestampUnixMs > 0
                ? DateTimeOffset.FromUnixTimeMilliseconds(raw.TimestampUnixMs)
                : DateTimeOffset.Now;
            var mappedPath = processAttributionCache.ResolvePath((int)raw.ProcessId, raw.ProcessPath, mappedTimestamp);
            var mappedPid = (int)raw.ProcessId;
            if (mappedPid <= 4 && !string.IsNullOrWhiteSpace(mappedPath))
            {
                var recoveredPid = processAttributionCache.ResolvePidByPath(mappedPath, mappedTimestamp);
                if (recoveredPid > 4)
                {
                    mappedPid = recoveredPid;
                    recoveredPidCount++;
                }
            }

            var mapped = TelemetryMapper.Map(raw, policy, 0, mappedPath, mappedPid);

            if (IsSelfTelemetry(mapped))
            {
                filteredSelfCount++;
                continue;
            }

            processAttributionCache.Observe(mapped.ProcessId, mapped.ProcessPath, mapped.Timestamp);

            if (mapped.ProcessId <= 4)
            {
                filteredReservedPidCount++;
                continue;
            }

            telemetryBatch.Add(mapped);
        }

        if (driverRawCount > 0 || miniRawCount > 0)
        {
            StartupLog.WriteDetection(
                "Detection",
                $"batch-summary driverRaw={driverRawCount}, miniRaw={miniRawCount}, queued={telemetryBatch.Count}, filteredSelf={filteredSelfCount}, filteredReservedPid={filteredReservedPidCount}, recoveredPid={recoveredPidCount}");
        }

        if (telemetryBatch.Count == 0)
        {
            var driversConnected = bridge.IsConnected && miniBridge.IsConnected;
            SaveStatus(
                driversConnected,
                driversConnected ? "connected" : "disconnected",
                orchestrator.PendingRollbackEntries,
                string.Empty);

            continue;
        }

        foreach (var telemetryRaw in telemetryBatch
                     .OrderByDescending(e => e.Kind == EventKind.ProcessCreate)
                     .ThenByDescending(e => e.IsPreOperation && e.Kind == EventKind.FileWrite)
                     .ThenByDescending(e => e.IsPreOperation && e.Kind == EventKind.FileRename)
                     .ThenByDescending(e => e.IsPreOperation && e.Kind == EventKind.FileDelete)
                     .ThenBy(e => e.Timestamp))
        {
            if (telemetryRaw.ProcessId <= 4 || IsSelfTelemetry(telemetryRaw))
            {
                continue;
            }

            var bucketKey = telemetryRaw.ProcessId;
            if (!burstCounter.TryGetValue(bucketKey, out var counter))
            {
                counter = 0;
            }

            counter++;
            burstCounter[bucketKey] = counter;

            var telemetry = telemetryRaw with { BurstCount = counter };
            var result = orchestrator.Ingest(telemetry);

            var incidentTelemetry = result.IncidentTelemetry ?? telemetry;
            var context = contextManager.Get(incidentTelemetry.ProcessId);
            var moduleInfo = FindLoadedModule(context, incidentTelemetry);
            try
            {
                AppendIncidentCompat(RuntimePaths.IncidentLogPath, incidentTelemetry, result, context, moduleInfo);
            }
            catch (Exception appendEx)
            {
                StartupLog.Write("Service", $"incident-append failed: {appendEx.Message}");
            }

            if (!result.DriverCommandSucceeded)
            {
                StartupLog.Write("Service", $"driver-command failed: pid={telemetry.ProcessId}; message={result.DriverMessage}");
            }

            StartupLog.WriteDetection(
                "Detection",
                $"decision pid={incidentTelemetry.ProcessId}, kind={incidentTelemetry.Kind}, action={result.Decision.Action}, score={result.Decision.Score:F3}, target={incidentTelemetry.TargetPath}, source={incidentTelemetry.SourcePath}, process={incidentTelemetry.ProcessPath}, reason={result.Decision.Reason}, rollback={result.RollbackCount}, cmdOk={result.DriverCommandSucceeded}");

            var driversConnected = bridge.IsConnected && miniBridge.IsConnected;
            SaveStatus(
                driversConnected,
                driversConnected ? "connected" : "disconnected",
                orchestrator.PendingRollbackEntries,
                result.DriverCommandSucceeded ? string.Empty : result.DriverMessage);
        }
    }
    StartupLog.Write("Service", "shutdown");

    // Cleanup
    amsiScanner?.Dispose();

    void SaveStatus(bool connected, string state, int pendingRollbackEntries, string lastError)
    {
        try
        {
            StatusStore.Save(RuntimePaths.StatusPath, new RuntimeStatus(
                DateTimeOffset.Now,
                connected,
                state,
                policy.PolicyVersion,
                pendingRollbackEntries,
                lastError));
        }
        catch (Exception statusEx)
        {
            StartupLog.Write("Service", $"status-save failed: {statusEx.Message}");
        }
    }

    WaitHandle[] BuildKernelWaitHandles()
    {
        var handles = new List<WaitHandle>
        {
            cts.Token.WaitHandle,
            bridge.ControlWaitHandle,
            miniBridge.ControlWaitHandle
        };

        if (bridge.TelemetryWaitHandle is not null)
        {
            handles.Add(bridge.TelemetryWaitHandle);
        }

        if (miniBridge.TelemetryWaitHandle is not null)
        {
            handles.Add(miniBridge.TelemetryWaitHandle);
        }

        return handles.ToArray();
    }

    static bool ReadBridgeBurst(
        DriverCommandBridge source,
        int maxBatches,
        out List<DriverProtocol.DriverEventRecordRaw> events,
        out string error)
    {
        events = [];
        error = string.Empty;

        var burst = Math.Max(1, maxBatches);
        for (var i = 0; i < burst; i++)
        {
            if (!source.TryReadEvents(out var batch, out error))
            {
                return false;
            }

            if (batch.Count == 0)
            {
                break;
            }

            events.AddRange(batch);
            if (batch.Count < DriverProtocol.MaxBatchEvents)
            {
                break;
            }
        }

        error = string.Empty;
        return true;
    }

    bool IsSelfTelemetry(TelemetryEvent telemetry)
    {
        if (telemetry.ProcessId == selfPid)
        {
            return true;
        }

        var normalized = NormalizePath(telemetry.ProcessPath);
        if (string.IsNullOrWhiteSpace(normalized) && telemetry.ProcessId > 4)
        {
            normalized = NormalizePath(TryReadLiveProcessPath(telemetry.ProcessId));
        }

        if (TrustedProcessValidator.IsRollbackGuardBinary(normalized))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(normalized))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(selfProcessPath) &&
            normalized.Equals(selfProcessPath, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(selfProcessName) &&
            Path.GetFileName(normalized).Equals(selfProcessName, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(selfBaseDir) &&
            normalized.StartsWith(selfBaseDir, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    static string TryReadLiveProcessPath(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);

            string? mainModulePath = null;
            try
            {
                mainModulePath = process.MainModule?.FileName;
            }
            catch
            {
                mainModulePath = null;
            }

            if (!string.IsNullOrWhiteSpace(mainModulePath))
            {
                return mainModulePath;
            }

            string? name = null;
            try
            {
                name = process.ProcessName;
            }
            catch
            {
                name = null;
            }

            return string.IsNullOrWhiteSpace(name) ? string.Empty : $"{name}.exe";
        }
        catch
        {
            return string.Empty;
        }
    }

    static string NormalizePath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var trimmed = value.Trim().TrimEnd('\0');
        try
        {
            return Path.GetFullPath(trimmed);
        }
        catch
        {
            return trimmed;
        }
    }

    static string? BuildRemediationSummary(ProcessContext? context)
    {
        if (context == null || context.RemediationHistory.Count == 0)
        {
            return null;
        }

        var last = context.RemediationHistory[^1];
        return $"{last.Time.LocalDateTime:yyyy-MM-dd HH:mm:ss} | {last.Action} | {(last.Success ? "成功" : "失败")} | {last.Detail}";
    }

    static string? BuildIncidentTrustTier(ProcessContext? context)
    {
        if (context == null)
        {
            return null;
        }

        return context.CurrentTrustTier.ToString();
    }

    static string? BuildBaseTrustTier(ProcessContext? context) => context?.BaseTrustTier.ToString();

    static string? BuildCurrentTrustTier(ProcessContext? context) => context?.CurrentTrustTier.ToString();

    static int? BuildIncidentParentProcessId(ProcessContext? context) =>
        context is null || context.PPID <= 0 ? null : context.PPID;

    static string? BuildIncidentParentProcessPath(ProcessContext? context) =>
        NormalizeIncidentPath(context?.ParentImageName);

    static string? BuildMemoryScanDetail(ProcessContext? context)
    {
        if (context == null || context.LastScanRegions.Count == 0)
        {
            return null;
        }

        var summary = new List<string>
        {
            $"扫描时间={context.LastMemoryScanTime.LocalDateTime:yyyy-MM-dd HH:mm:ss}",
            $"扫描次数={context.MemoryScanCount}",
            $"RWX={context.MemoryRwxRegionCount}",
            $"Unbacked={context.MemoryUnbackedExecRegionCount}",
            $"W->X={context.MemoryWxTransitionCount}",
            $"ReflectiveDll={context.MemoryReflectiveDllCount}",
            $"PebWalk={context.MemoryPebWalkPatternCount}",
            $"ApiHash={context.MemoryApiHashPatternCount}",
            $"Syscall={context.MemorySyscallStubCount}"
        };

        foreach (var region in context.LastScanRegions.Take(6))
        {
            summary.Add($"0x{region.BaseAddress:X} size={region.Size} prot=0x{region.Protection:X} {region.Reason}");
        }

        return string.Join(" | ", summary);
    }

    static LoadedDllInfo? FindLoadedModule(ProcessContext? context, TelemetryEvent telemetryEvent)
    {
        if (context == null ||
            telemetryEvent.Kind is not (EventKind.ImageLoad or EventKind.ImageLoadUnsigned))
        {
            return null;
        }

        var modulePath = NormalizeIncidentPath(telemetryEvent.TargetPath);
        if (string.IsNullOrWhiteSpace(modulePath))
        {
            return null;
        }

        for (var i = context.LoadedDlls.Count - 1; i >= 0; i--)
        {
            var candidate = context.LoadedDlls[i];
            var candidatePath = NormalizeIncidentPath(candidate.Path);
            if (!string.IsNullOrWhiteSpace(candidatePath) &&
                candidatePath.Equals(modulePath, StringComparison.OrdinalIgnoreCase))
            {
                return candidate;
            }
        }

        return null;
    }

    static string? BuildModuleTrustTier(TelemetryEvent telemetryEvent, LoadedDllInfo? moduleInfo)
    {
        if (telemetryEvent.Kind is not (EventKind.ImageLoad or EventKind.ImageLoadUnsigned))
        {
            return null;
        }

        if (moduleInfo != null)
        {
            if (!moduleInfo.IsSigned)
            {
                return ExecutionTrustTier.Unsigned.ToString();
            }

            return moduleInfo.IsMicrosoftSigned
                ? ExecutionTrustTier.MicrosoftSigned.ToString()
                : ExecutionTrustTier.Signed.ToString();
        }

        return telemetryEvent.Kind == EventKind.ImageLoadUnsigned
            ? ExecutionTrustTier.Unsigned.ToString()
            : ExecutionTrustTier.Signed.ToString();
    }

    static bool? BuildModuleSigned(TelemetryEvent telemetryEvent, LoadedDllInfo? moduleInfo)
    {
        if (telemetryEvent.Kind is not (EventKind.ImageLoad or EventKind.ImageLoadUnsigned))
        {
            return null;
        }

        return moduleInfo?.IsSigned ?? telemetryEvent.Kind == EventKind.ImageLoad;
    }

    static bool? BuildModuleMicrosoftSigned(TelemetryEvent telemetryEvent, LoadedDllInfo? moduleInfo)
    {
        if (telemetryEvent.Kind is not (EventKind.ImageLoad or EventKind.ImageLoadUnsigned))
        {
            return null;
        }

        return moduleInfo?.IsMicrosoftSigned ?? false;
    }

    static string? BuildKernelTrustHint(TelemetryEvent telemetryEvent) =>
        telemetryEvent.TrustHint == KernelTrustHint.Unknown
            ? null
            : telemetryEvent.TrustHint.ToString();

    static void AppendIncidentCompat(
        string path,
        TelemetryEvent incidentTelemetry,
        OrchestratorResult result,
        ProcessContext? context,
        LoadedDllInfo? moduleInfo)
    {
        var payload = new
        {
            incidentTelemetry.Timestamp,
            ProcessPath = incidentTelemetry.ProcessPath,
            ProcessId = incidentTelemetry.ProcessId,
            TargetPath = incidentTelemetry.TargetPath,
            EventKind = incidentTelemetry.Kind,
            Action = result.Decision.Action,
            Score = result.Decision.Score,
            Reason = result.Decision.Reason,
            RollbackCount = result.RollbackCount,
            DriverCommandSucceeded = result.DriverCommandSucceeded,
            DriverMessage = result.DriverMessage,
            TrustTier = BuildIncidentTrustTier(context),
            RemediationSummary = BuildRemediationSummary(context),
            MemoryScanDetail = BuildMemoryScanDetail(context),
            BaseTrustTier = BuildBaseTrustTier(context),
            CurrentTrustTier = BuildCurrentTrustTier(context),
            SignatureEvaluated = context?.SignatureEvaluated,
            HasValidSignature = context?.HasValidSignature,
            IsMicrosoftSigned = context?.IsMicrosoftSignedProcess,
            LoadedUnsignedDll = context?.LoadedUnsignedDll,
            LoadedSuspiciousDll = context?.LoadedSuspiciousDll,
            LoadedNonMicrosoftDll = context?.LoadedNonMicrosoftDll,
            ParentProcessId = BuildIncidentParentProcessId(context),
            ParentProcessPath = BuildIncidentParentProcessPath(context),
            ModuleTrustTier = BuildModuleTrustTier(incidentTelemetry, moduleInfo),
            ModuleSigned = BuildModuleSigned(incidentTelemetry, moduleInfo),
            ModuleMicrosoftSigned = BuildModuleMicrosoftSigned(incidentTelemetry, moduleInfo),
            KernelTrustHint = BuildKernelTrustHint(incidentTelemetry)
        };

        AppendJsonLine(path, payload);
    }

    static void AppendJsonLine(string path, object payload)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
        });

        var line = json + Environment.NewLine;
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                using var writer = new StreamWriter(stream);
                writer.Write(line);
                writer.Flush();
                return;
            }
            catch (IOException) when (attempt < 3)
            {
                Thread.Sleep(20 * attempt);
            }
        }

        throw new IOException($"append incident failed after retries: {path}");
    }

    static string? NormalizeIncidentPath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return value.Trim().TrimEnd('\0');
    }
}
catch (Exception ex)
{
    StartupLog.Write("Service", "fatal", ex);
    Console.Error.WriteLine($"RollbackGuard.Service FATAL: {ex}");
    Environment.ExitCode = 3;
}
