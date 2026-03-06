using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using RollbackGuard.Common.Diagnostics;
using RollbackGuard.Common.Models;

namespace RollbackGuard.Service.Rollback;

public sealed class RollbackJournal
{
    private readonly string _fileRoot;
    private readonly string _registryRoot;
    private readonly List<string> _protectedRoots;

    public string FileRoot => _fileRoot;
    private readonly Dictionary<int, HashSet<string>> _capturedFileTargetsByProcess = [];
    private readonly Dictionary<int, HashSet<string>> _failedFileTargetsByProcess = [];
    private readonly Dictionary<string, string> _baselineFileSnapshots = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _baselineFileSnapshotsByFileKey = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, HashSet<string>> _capturedRegistryTargetsByProcess = [];
    private readonly Dictionary<int, HashSet<string>> _failedRegistryTargetsByProcess = [];
    private readonly Dictionary<int, HashSet<string>> _pendingDeleteTargetsByProcess = [];
    private readonly Dictionary<int, Dictionary<string, string>> _pendingRenameRestoreTargetsByProcess = [];
    private readonly Dictionary<int, HashSet<string>> _pendingRenameRestoreNameOnlyTargetsByProcess = [];
    private readonly Dictionary<int, List<RollbackEntry>> _entriesByProcess = [];
    private readonly object _sync = new();

    public RollbackJournal(string rootPath, IEnumerable<string>? protectedRoots = null)
    {
        _fileRoot = Path.Combine(rootPath, "files");
        _registryRoot = Path.Combine(rootPath, "registry");
        _protectedRoots = (protectedRoots ?? [])
            .Select(NormalizePath)
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        Directory.CreateDirectory(_fileRoot);
        Directory.CreateDirectory(_registryRoot);
    }

    public int PendingEntriesCount
    {
        get
        {
            lock (_sync)
            {
                return _entriesByProcess.Values.Sum(list => list.Count) +
                       _pendingDeleteTargetsByProcess.Values.Sum(set => set.Count) +
                       _pendingRenameRestoreTargetsByProcess.Values.Sum(map => map.Count);
            }
        }
    }

    public int PendingEntriesCountForProcess(int processId)
    {
        processId = NormalizeProcessId(processId);
        lock (_sync)
        {
            var entryCount = _entriesByProcess.TryGetValue(processId, out var entries)
                ? entries.Count
                : 0;
            var pendingDeleteCount = _pendingDeleteTargetsByProcess.TryGetValue(processId, out var pendingDeletes)
                ? pendingDeletes.Count
                : 0;
            var pendingRenameRestoreCount = _pendingRenameRestoreTargetsByProcess.TryGetValue(processId, out var pendingRenameRestore)
                ? pendingRenameRestore.Count
                : 0;
            return entryCount + pendingDeleteCount + pendingRenameRestoreCount;
        }
    }

    public IReadOnlyList<string> GetPendingEntriesPreview(int maxItems)
    {
        if (maxItems <= 0)
        {
            maxItems = 100;
        }

        lock (_sync)
        {
            var entryPreview = _entriesByProcess
                .SelectMany(pair => pair.Value)
                .OrderByDescending(entry => entry.CapturedAt)
                .Select(entry => $"{entry.EntryType}:{entry.TargetPath}")
                .ToList();

            var pendingDeletePreview = _pendingDeleteTargetsByProcess
                .SelectMany(pair => pair.Value)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .Select(path => $"FileDelete:{path}")
                .ToList();

            var pendingRenameRestorePreview = _pendingRenameRestoreTargetsByProcess
                .SelectMany(pair =>
                {
                    var nameOnlyTargets = _pendingRenameRestoreNameOnlyTargetsByProcess.TryGetValue(pair.Key, out var set)
                        ? set
                        : null;
                    return pair.Value.Select(item =>
                        nameOnlyTargets is not null && nameOnlyTargets.Contains(item.Key)
                            ? $"FileRenameRestore:{item.Key}=>{item.Value} (仅文件名)"
                            : $"FileRenameRestore:{item.Key}=>{item.Value}");
                })
                .OrderBy(item => item, StringComparer.OrdinalIgnoreCase)
                .ToList();

            return entryPreview
                .Concat(pendingDeletePreview)
                .Concat(pendingRenameRestorePreview)
                .Take(maxItems)
                .ToList();
        }
    }

    public IReadOnlyList<string> GetPendingEntriesPreviewForProcess(int processId, int maxItems)
    {
        if (maxItems <= 0)
        {
            maxItems = 100;
        }

        processId = NormalizeProcessId(processId);
        lock (_sync)
        {
            var entries = _entriesByProcess.TryGetValue(processId, out var processEntries)
                ? processEntries
                : [];
            var pendingDeletes = _pendingDeleteTargetsByProcess.TryGetValue(processId, out var processPendingDeletes)
                ? processPendingDeletes
                : [];
            var pendingRenameRestore = _pendingRenameRestoreTargetsByProcess.TryGetValue(processId, out var processPendingRenameRestore)
                ? processPendingRenameRestore
                : [];

            if (entries.Count == 0 && pendingDeletes.Count == 0 && pendingRenameRestore.Count == 0)
            {
                return [];
            }

            var entryPreview = entries
                .AsEnumerable()
                .Reverse()
                .Select(entry => $"{entry.EntryType}:{entry.TargetPath}")
                .ToList();

            var pendingDeletePreview = pendingDeletes
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .Select(path => $"FileDelete:{path}")
                .ToList();

            var pendingRenameRestorePreview = pendingRenameRestore
                .OrderBy(item => item.Key, StringComparer.OrdinalIgnoreCase)
                .Select(item =>
                    _pendingRenameRestoreNameOnlyTargetsByProcess.TryGetValue(processId, out var nameOnlyTargets) &&
                    nameOnlyTargets.Contains(item.Key)
                        ? $"FileRenameRestore:{item.Key}=>{item.Value} (仅文件名)"
                        : $"FileRenameRestore:{item.Key}=>{item.Value}")
                .ToList();

            return entryPreview
                .Concat(pendingDeletePreview)
                .Concat(pendingRenameRestorePreview)
                .Take(maxItems)
                .ToList();
        }
    }

    public BaselineCaptureResult CaptureBaseline(IEnumerable<string> roots, int maxFiles, long maxFileSizeBytes)
    {
        var copied = 0;
        var skipped = 0;
        var errors = new List<string>();

        if (maxFiles <= 0)
        {
            return new BaselineCaptureResult(0, 0, false, ["maxFiles must be > 0"]);
        }

        if (maxFileSizeBytes <= 0)
        {
            maxFileSizeBytes = 16 * 1024 * 1024;
        }

        foreach (var root in roots.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (copied >= maxFiles)
            {
                break;
            }

            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
            {
                continue;
            }

            foreach (var filePath in EnumerateFilesSafe(root, errors))
            {
                if (copied >= maxFiles)
                {
                    break;
                }

                try
                {
                    var info = new FileInfo(filePath);
                    if (!info.Exists)
                    {
                        continue;
                    }

                    if (info.Length > maxFileSizeBytes)
                    {
                        skipped++;
                        continue;
                    }

                    CaptureBaselineFileSnapshot(filePath);
                    copied++;
                }
                catch (Exception ex)
                {
                    errors.Add($"baseline capture failed: {filePath}: {ex.Message}");
                    StartupLog.WriteBackup("Backup", $"baseline-capture failed: target={filePath}; message={ex.Message}");
                }
            }
        }

        return new BaselineCaptureResult(copied, skipped, copied >= maxFiles, errors);
    }

    private void CaptureBaselineFileSnapshot(string targetPath)
    {
        var normalized = NormalizePath(targetPath);
        lock (_sync)
        {
            if (_baselineFileSnapshots.ContainsKey(normalized))
            {
                return;
            }

            var key = ComputeKey(normalized);
            var backupPath = Path.Combine(_fileRoot, key + ".bin");
            var missingMarker = Path.Combine(_fileRoot, key + ".missing");
            Directory.CreateDirectory(_fileRoot);

            if (File.Exists(backupPath))
            {
                _baselineFileSnapshots[normalized] = backupPath;
                if (TryBuildFileCaptureKeyFromExistingPath(normalized, out var existingCaptureKey))
                {
                    _baselineFileSnapshotsByFileKey[existingCaptureKey] = backupPath;
                }
                StartupLog.WriteBackup("Backup", $"baseline-reuse target={normalized}; snapshot={backupPath}");
                return;
            }

            if (File.Exists(normalized))
            {
                File.Copy(normalized, backupPath, false);
                _baselineFileSnapshots[normalized] = backupPath;
                if (TryBuildFileCaptureKeyFromExistingPath(normalized, out var fileCaptureKey))
                {
                    _baselineFileSnapshotsByFileKey[fileCaptureKey] = backupPath;
                }
                StartupLog.WriteBackup("Backup", $"baseline-captured target={normalized}; snapshot={backupPath}");
            }
            else
            {
                if (!File.Exists(missingMarker))
                {
                    File.WriteAllText(missingMarker, "missing-before-baseline");
                }
                _baselineFileSnapshots[normalized] = missingMarker;
                StartupLog.WriteBackup("Backup", $"baseline-missing target={normalized}; marker={missingMarker}");
            }
        }
    }

    public void CaptureFileBeforeChange(string? targetPath, string reason, int processId = 0)
    {
        if (string.IsNullOrWhiteSpace(targetPath))
        {
            return;
        }

        processId = NormalizeProcessId(processId);
        var normalized = NormalizePath(targetPath);
        lock (_sync)
        {
            CaptureFileCoreLocked(
                processId,
                normalized,
                reason,
                copyIfExists: true,
                BuildFileCaptureKey(normalized, 0, 0));
        }
    }

    public void CaptureFileBeforeRuntimeWrite(
        string? targetPath,
        string reason,
        int processId = 0,
        ulong volumeSerialNumber = 0,
        ulong fileId = 0)
    {
        if (string.IsNullOrWhiteSpace(targetPath))
        {
            return;
        }

        processId = NormalizeProcessId(processId);
        var normalized = NormalizePath(targetPath);
        if (IsSkipCapturePath(normalized))
        {
            StartupLog.WriteBackup("Backup", $"prewrite-capture skipped: pid={processId}; reason=skip-capture-path; target={normalized}");
            return;
        }

        if (!IsPathUnderProtectedRoots(normalized))
        {
            StartupLog.WriteBackup("Backup", $"prewrite-capture skipped: pid={processId}; reason=outside-protected; target={normalized}");
            return;
        }

        var captureKey = BuildFileCaptureKey(normalized, volumeSerialNumber, fileId);
        lock (_sync)
        {
            var failedFileTargets = GetOrCreateStringSetLocked(_failedFileTargetsByProcess, processId);
            if (failedFileTargets.Contains(captureKey))
            {
                return;
            }

            var capturedFileTargets = GetOrCreateStringSetLocked(_capturedFileTargetsByProcess, processId);
            if (capturedFileTargets.Contains(captureKey))
            {
                return;
            }

            // 对 pre-write 事件必须优先抓“当下写前内容”，不能直接复用 baseline。
            // 否则 baseline 一旦被污染，会持续回滚到旧的错误状态（例如密文）。
            if (File.Exists(normalized))
            {
                CaptureFileCoreLocked(processId, normalized, reason, copyIfExists: true, captureKey);
                return;
            }

            // 处理迟到/吸收窗口场景：事件发生时文件存在，但处理时已被改名导致路径缺失。
            // 此时回退到 baseline，可避免首个 missing-marker 抢占去重键后无法恢复明文。
            if (TryGetBaselineSnapshotLocked(normalized, volumeSerialNumber, fileId, out var baselineSnapshot, out var baselineMatch))
            {
                var entries = GetOrCreateEntriesLocked(processId);
                entries.Add(new RollbackEntry(
                    RollbackEntryType.File,
                    normalized,
                    baselineSnapshot,
                    DateTimeOffset.Now,
                    $"{reason}-missing-fallback-baseline",
                    processId));
                capturedFileTargets.Add(captureKey);
                StartupLog.WriteBackup(
                    "Backup",
                    $"prewrite-capture missing-fallback-baseline-hit: pid={processId}; target={normalized}; fileKey={captureKey}; reason={reason}; match={baselineMatch}");
                return;
            }

            CaptureFileCoreLocked(processId, normalized, reason, copyIfExists: true, captureKey);
        }
    }

    public bool CaptureKernelPreWriteSnapshot(
        string? targetPath,
        string? kernelSnapshotPath,
        string reason,
        int processId = 0,
        ulong volumeSerialNumber = 0,
        ulong fileId = 0)
    {
        if (string.IsNullOrWhiteSpace(targetPath))
        {
            return true;
        }

        processId = NormalizeProcessId(processId);
        var normalizedTarget = NormalizePath(targetPath);
        if (IsSkipCapturePath(normalizedTarget))
        {
            StartupLog.WriteBackup("Backup", $"kernel-prewrite skipped: pid={processId}; reason=skip-capture-path; target={normalizedTarget}");
            return true;
        }

        if (!IsPathUnderProtectedRoots(normalizedTarget))
        {
            StartupLog.WriteBackup("Backup", $"kernel-prewrite skipped: pid={processId}; reason=outside-protected; target={normalizedTarget}");
            return true;
        }

        var captureKey = BuildFileCaptureKey(normalizedTarget, volumeSerialNumber, fileId);
        var normalizedSnapshot = NormalizePath(kernelSnapshotPath ?? string.Empty);
        lock (_sync)
        {
            var failedFileTargets = GetOrCreateStringSetLocked(_failedFileTargetsByProcess, processId);
            if (failedFileTargets.Contains(captureKey))
            {
                return false;
            }

            var capturedFileTargets = GetOrCreateStringSetLocked(_capturedFileTargetsByProcess, processId);
            if (capturedFileTargets.Contains(captureKey))
            {
                return true;
            }

            if (string.IsNullOrWhiteSpace(normalizedSnapshot))
            {
                failedFileTargets.Add(captureKey);
                StartupLog.WriteBackup(
                    "Backup",
                    $"kernel-prewrite invalid-snapshot-path: pid={processId}; target={normalizedTarget}; fileKey={captureKey}; reason={reason}");
                return false;
            }

            if (!File.Exists(normalizedSnapshot))
            {
                failedFileTargets.Add(captureKey);
                StartupLog.WriteBackup(
                    "Backup",
                    $"kernel-prewrite snapshot-not-found: pid={processId}; target={normalizedTarget}; fileKey={captureKey}; reason={reason}; snapshot={normalizedSnapshot}");
                return false;
            }

            var entries = GetOrCreateEntriesLocked(processId);
            entries.Add(new RollbackEntry(
                RollbackEntryType.File,
                normalizedTarget,
                normalizedSnapshot,
                DateTimeOffset.Now,
                reason,
                processId));

            capturedFileTargets.Add(captureKey);
            StartupLog.WriteBackup(
                "Backup",
                $"kernel-prewrite captured: pid={processId}; target={normalizedTarget}; fileKey={captureKey}; reason={reason}; snapshot={normalizedSnapshot}");
            return true;
        }
    }

    public void CaptureFileForRuntimeEvent(
        string? targetPath,
        string reason,
        int processId = 0,
        ulong volumeSerialNumber = 0,
        ulong fileId = 0)
    {
        if (string.IsNullOrWhiteSpace(targetPath))
        {
            return;
        }

        processId = NormalizeProcessId(processId);
        var normalized = NormalizePath(targetPath);
        if (IsSkipCapturePath(normalized))
        {
            StartupLog.WriteBackup("Backup", $"runtime-capture skipped: pid={processId}; reason=skip-capture-path; target={normalized}");
            return;
        }

        if (!IsPathUnderProtectedRoots(normalized))
        {
            StartupLog.WriteBackup("Backup", $"runtime-capture skipped: pid={processId}; reason=outside-protected; target={normalized}");
            return;
        }

        var captureKey = BuildFileCaptureKey(normalized, volumeSerialNumber, fileId);
        lock (_sync)
        {
            var failedFileTargets = GetOrCreateStringSetLocked(_failedFileTargetsByProcess, processId);
            if (failedFileTargets.Contains(captureKey))
            {
                return;
            }

            var capturedFileTargets = GetOrCreateStringSetLocked(_capturedFileTargetsByProcess, processId);
            if (capturedFileTargets.Contains(captureKey))
            {
                return;
            }

            var entries = GetOrCreateEntriesLocked(processId);
            if (TryGetBaselineSnapshotLocked(normalized, volumeSerialNumber, fileId, out var baselineSnapshot, out var baselineMatch))
            {
                entries.Add(new RollbackEntry(RollbackEntryType.File, normalized, baselineSnapshot, DateTimeOffset.Now, reason, processId));
                capturedFileTargets.Add(captureKey);
                StartupLog.WriteBackup("Backup", $"runtime-capture baseline-hit: pid={processId}; target={normalized}; fileKey={captureKey}; reason={reason}; match={baselineMatch}");
                return;
            }

            // 运行期事件来自 post-op，此时文件可能已被篡改；未知文件一律按“原本不存在”处理。
            CaptureFileCoreLocked(processId, normalized, reason, copyIfExists: false, captureKey);
        }
    }

    public void CaptureRenameForRuntimeEvent(
        string? sourcePath,
        string? targetPath,
        string reason,
        int processId = 0,
        ulong volumeSerialNumber = 0,
        ulong fileId = 0)
    {
        processId = NormalizeProcessId(processId);
        if (!string.IsNullOrWhiteSpace(sourcePath))
        {
            CaptureFileForRuntimeEvent(sourcePath, $"{reason}-source", processId, volumeSerialNumber, fileId);
        }

        if (string.IsNullOrWhiteSpace(targetPath))
        {
            return;
        }

        var normalizedTarget = NormalizePath(targetPath);
        if (string.IsNullOrWhiteSpace(normalizedTarget) || IsSkipCapturePath(normalizedTarget))
        {
            return;
        }

        if (!IsPathUnderProtectedRoots(normalizedTarget))
        {
            return;
        }

        var normalizedSource = string.IsNullOrWhiteSpace(sourcePath) ? string.Empty : NormalizePath(sourcePath);
        if (!string.IsNullOrWhiteSpace(normalizedSource) &&
            normalizedTarget.Equals(normalizedSource, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var targetCaptureKey = BuildFileCaptureKey(normalizedTarget, volumeSerialNumber, fileId);
        lock (_sync)
        {
            var failedFileTargets = GetOrCreateStringSetLocked(_failedFileTargetsByProcess, processId);
            var capturedFileTargets = GetOrCreateStringSetLocked(_capturedFileTargetsByProcess, processId);
            var alreadyCaptured = failedFileTargets.Contains(targetCaptureKey) || capturedFileTargets.Contains(targetCaptureKey);

            var forceDeleteTarget =
                !string.IsNullOrWhiteSpace(normalizedSource) &&
                !string.IsNullOrWhiteSpace(Path.GetExtension(normalizedSource)) &&
                !string.IsNullOrWhiteSpace(Path.GetExtension(normalizedTarget)) &&
                !Path.GetExtension(normalizedSource).Equals(Path.GetExtension(normalizedTarget), StringComparison.OrdinalIgnoreCase);
            var sourceHasBaselineSnapshot =
                !string.IsNullOrWhiteSpace(normalizedSource) &&
                TryGetBaselineSnapshotLocked(normalizedSource, volumeSerialNumber, fileId, out _, out _);
            var sourceHasRuntimeSnapshot =
                !string.IsNullOrWhiteSpace(normalizedSource) &&
                HasRuntimeFileSnapshotLocked(processId, normalizedSource);
            var sourceHasContentSnapshot = sourceHasBaselineSnapshot || sourceHasRuntimeSnapshot;

            var pendingDeleteTargets = GetOrCreateStringSetLocked(_pendingDeleteTargetsByProcess, processId);
            if (forceDeleteTarget)
            {
                if (!string.IsNullOrWhiteSpace(normalizedSource))
                {
                    var pendingRenameRestoreTargets = GetOrCreateStringMapLocked(_pendingRenameRestoreTargetsByProcess, processId);
                    pendingRenameRestoreTargets[normalizedTarget] = normalizedSource;
                    var nameOnlyTargets = GetOrCreateStringSetLocked(_pendingRenameRestoreNameOnlyTargetsByProcess, processId);
                    if (!sourceHasContentSnapshot)
                    {
                        nameOnlyTargets.Add(normalizedTarget);
                    }
                    else
                    {
                        nameOnlyTargets.Remove(normalizedTarget);
                    }
                    capturedFileTargets.Add(targetCaptureKey);
                    StartupLog.WriteBackup(
                        "Backup",
                        $"rename-capture pending-rename-restore: pid={processId}; source={normalizedSource}; target={normalizedTarget}; fileKey={targetCaptureKey}; reason={reason}; contentSnapshot={(sourceHasContentSnapshot ? "yes" : "no")}");
                    return;
                }

                pendingDeleteTargets.Add(normalizedTarget);
                capturedFileTargets.Add(targetCaptureKey);
                StartupLog.WriteBackup("Backup", $"rename-capture force-delete-target: pid={processId}; source={normalizedSource}; target={normalizedTarget}; fileKey={targetCaptureKey}; reason={reason}");
                return;
            }

            if (alreadyCaptured)
            {
                return;
            }

            var entries = GetOrCreateEntriesLocked(processId);
            if (TryGetBaselineSnapshotLocked(normalizedTarget, volumeSerialNumber, fileId, out var baselineSnapshot, out var baselineMatch))
            {
                entries.Add(new RollbackEntry(RollbackEntryType.File, normalizedTarget, baselineSnapshot, DateTimeOffset.Now, $"{reason}-target", processId));
                capturedFileTargets.Add(targetCaptureKey);
                StartupLog.WriteBackup("Backup", $"rename-capture baseline-hit: pid={processId}; source={normalizedSource}; target={normalizedTarget}; fileKey={targetCaptureKey}; reason={reason}; match={baselineMatch}");
                return;
            }

            pendingDeleteTargets.Add(normalizedTarget);
            capturedFileTargets.Add(targetCaptureKey);
            StartupLog.WriteBackup("Backup", $"rename-capture pending-delete: pid={processId}; source={normalizedSource}; target={normalizedTarget}; fileKey={targetCaptureKey}; reason={reason}");
        }
    }
    public void CaptureRegistryBeforeChange(string? targetPath, string reason, int processId = 0)
    {
        if (string.IsNullOrWhiteSpace(targetPath))
        {
            return;
        }

        processId = NormalizeProcessId(processId);
        var normalized = targetPath.Trim();
        lock (_sync)
        {
            var failedRegistryTargets = GetOrCreateStringSetLocked(_failedRegistryTargetsByProcess, processId);
            if (failedRegistryTargets.Contains(normalized))
            {
                return;
            }

            var capturedRegistryTargets = GetOrCreateStringSetLocked(_capturedRegistryTargetsByProcess, processId);
            if (capturedRegistryTargets.Contains(normalized))
            {
                return;
            }

            if (!TryParseRegistryPath(normalized, out var hive, out var subKey, out var valueName))
            {
                return;
            }

            Directory.CreateDirectory(_registryRoot);
            var key = ComputeProcessScopedKey(processId, normalized);
            var snapshotPath = Path.Combine(_registryRoot, key + ".json");

            try
            {
                var snapshot = CaptureRegistryValue(hive, subKey, valueName);
                var json = JsonSerializer.Serialize(snapshot);
                File.WriteAllText(snapshotPath, json, Encoding.UTF8);

                var entries = GetOrCreateEntriesLocked(processId);
                entries.Add(new RollbackEntry(RollbackEntryType.Registry, normalized, snapshotPath, DateTimeOffset.Now, reason, processId));
                capturedRegistryTargets.Add(normalized);
                StartupLog.WriteBackup("Backup", $"registry-capture ok: pid={processId}; target={normalized}; reason={reason}; snapshot={snapshotPath}");
            }
            catch (Exception ex)
            {
                failedRegistryTargets.Add(normalized);
                StartupLog.WriteBackup("Backup", $"registry-capture failed: pid={processId}; target={normalized}; reason={reason}; message={ex.Message}");
            }
        }
    }

    public RollbackExecutionResult RollbackAll()
    {
        var errors = new List<string>();
        var successItems = new List<string>();
        var failedItems = new List<string>();
        var processed = 0;

        int[] processIds;
        lock (_sync)
        {
            processIds = _entriesByProcess.Keys
                .Union(_pendingDeleteTargetsByProcess.Keys)
                .Union(_pendingRenameRestoreTargetsByProcess.Keys)
                .Distinct()
                .ToArray();
        }

        foreach (var processId in processIds)
        {
            var result = RollbackProcess(processId);
            processed += result.Processed;
            errors.AddRange(result.Errors);
            successItems.AddRange(result.SuccessItems);
            failedItems.AddRange(result.FailedItems);
        }

        return new RollbackExecutionResult(processed, errors, successItems, failedItems);
    }

    public RollbackExecutionResult RollbackProcess(int processId)
    {
        processId = NormalizeProcessId(processId);
        var errors = new List<string>();
        var successItems = new List<string>();
        var failedItems = new List<string>();
        var processed = 0;

        List<RollbackEntry> snapshot;
        HashSet<string> pendingDeletes;
        Dictionary<string, string> pendingRenameRestore;
        HashSet<string> pendingRenameNameOnly;
        lock (_sync)
        {
            snapshot = _entriesByProcess.TryGetValue(processId, out var entries)
                ? entries.ToList()
                : [];
            pendingDeletes = _pendingDeleteTargetsByProcess.TryGetValue(processId, out var deletes)
                ? [.. deletes]
                : [];
            pendingRenameRestore = _pendingRenameRestoreTargetsByProcess.TryGetValue(processId, out var renameRestore)
                ? new Dictionary<string, string>(renameRestore, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            pendingRenameNameOnly = _pendingRenameRestoreNameOnlyTargetsByProcess.TryGetValue(processId, out var renameNameOnly)
                ? [.. renameNameOnly]
                : [];
        }

        foreach (var pair in pendingRenameRestore)
        {
            var target = pair.Key;
            var source = pair.Value;
            try
            {
                if (File.Exists(target))
                {
                    var sourceDir = Path.GetDirectoryName(source);
                    if (!string.IsNullOrWhiteSpace(sourceDir))
                    {
                        Directory.CreateDirectory(sourceDir);
                    }

                    File.Move(target, source, true);
                }

                processed++;
                successItems.Add($"FileRenameRestore:{target} -> {source}");
                if (pendingRenameNameOnly.Contains(target))
                {
                    failedItems.Add($"FileRenameRestore:{target} -> {source} (仅恢复文件名，缺少明文快照)");
                }
            }
            catch (Exception ex)
            {
                errors.Add($"rollback rename-restore failed: {target} -> {source}: {ex.Message}");
                failedItems.Add($"FileRenameRestore:{target} -> {source} failed: {ex.Message}");
            }
        }

        var renameRestoreSources = new HashSet<string>(
            pendingRenameRestore.Values.Where(value => !string.IsNullOrWhiteSpace(value)),
            StringComparer.OrdinalIgnoreCase);

        foreach (var entry in snapshot.AsEnumerable().Reverse())
        {
            try
            {
                if (entry.EntryType == RollbackEntryType.File &&
                    entry.BackupPath.EndsWith(".missing", StringComparison.OrdinalIgnoreCase) &&
                    renameRestoreSources.Contains(entry.TargetPath))
                {
                    // 对同一文件已执行“扩展名还原”时，跳过可疑 missing-marker 删除，避免把刚还原回来的文件再次删掉。
                    processed++;
                    successItems.Add($"{entry.EntryType}:{entry.TargetPath} -> skip-missing-marker-after-rename-restore");
                    continue;
                }

                switch (entry.EntryType)
                {
                    case RollbackEntryType.File:
                        RestoreFile(entry);
                        break;
                    case RollbackEntryType.Registry:
                        RestoreRegistry(entry);
                        break;
                    default:
                        break;
                }

                processed++;
                successItems.Add($"{entry.EntryType}:{entry.TargetPath}");
            }
            catch (Exception ex)
            {
                errors.Add($"rollback failed: {entry.TargetPath}: {ex.Message}");
                failedItems.Add($"{entry.EntryType}:{entry.TargetPath} -> {ex.Message}");
            }
        }

        foreach (var target in pendingDeletes)
        {
            try
            {
                if (File.Exists(target))
                {
                    File.Delete(target);
                }

                processed++;
                successItems.Add($"File:{target} -> deleted");
            }
            catch (Exception ex)
            {
                errors.Add($"rollback delete target failed: {target}: {ex.Message}");
                failedItems.Add($"File:{target} -> delete failed: {ex.Message}");
            }
        }
        lock (_sync)
        {
            ClearProcessEntriesLocked(processId);
        }

        return new RollbackExecutionResult(processed, errors, successItems, failedItems);
    }

    public void ClearProcessEntries(int processId)
    {
        processId = NormalizeProcessId(processId);
        lock (_sync)
        {
            ClearProcessEntriesLocked(processId);
        }
    }

    private void CaptureFileCoreLocked(
        int processId,
        string normalized,
        string reason,
        bool copyIfExists,
        string? captureKey = null)
    {
        var normalizedCaptureKey = string.IsNullOrWhiteSpace(captureKey)
            ? BuildFileCaptureKey(normalized, 0, 0)
            : captureKey;

        var failedFileTargets = GetOrCreateStringSetLocked(_failedFileTargetsByProcess, processId);
        if (failedFileTargets.Contains(normalizedCaptureKey))
        {
            return;
        }

        var capturedFileTargets = GetOrCreateStringSetLocked(_capturedFileTargetsByProcess, processId);
        if (capturedFileTargets.Contains(normalizedCaptureKey))
        {
            return;
        }

        var entries = GetOrCreateEntriesLocked(processId);

        var key = ComputeProcessScopedKey(processId, normalized);
        var backupPath = Path.Combine(_fileRoot, key + ".bin");
        var missingMarker = Path.Combine(_fileRoot, key + ".missing");
        Directory.CreateDirectory(_fileRoot);

        try
        {
            var exists = File.Exists(normalized);
            if (copyIfExists)
            {
                if (exists)
                {
                    File.Copy(normalized, backupPath, true);
                    entries.Add(new RollbackEntry(RollbackEntryType.File, normalized, backupPath, DateTimeOffset.Now, reason, processId));
                    StartupLog.WriteBackup("Backup", $"file-capture copy: pid={processId}; target={normalized}; fileKey={normalizedCaptureKey}; reason={reason}; snapshot={backupPath}");
                }
                else
                {
                    File.WriteAllText(missingMarker, "missing-before-change");
                    entries.Add(new RollbackEntry(RollbackEntryType.File, normalized, missingMarker, DateTimeOffset.Now, reason, processId));
                    StartupLog.WriteBackup("Backup", $"file-capture missing-marker: pid={processId}; target={normalized}; fileKey={normalizedCaptureKey}; reason={reason}; marker={missingMarker}");
                }
            }
            else
            {
                if (!exists)
                {
                    // 注意：不能在这里标记 captured。
                    // 场景：先收到 write(旧路径) 再收到 rename(新路径)；
                    // 若 write 阶段因旧路径不存在而 skip 且已标记 captured，会导致后续 rename 无法入账。
                    StartupLog.WriteBackup("Backup", $"file-capture skip-missing-no-baseline: pid={processId}; target={normalized}; fileKey={normalizedCaptureKey}; reason={reason}");
                    return;
                }

                // 运行期且无基线时，当前内容通常已被篡改（例如加密后内容）；
                // 不应把“现状”当作可回滚备份，避免回滚到错误内容。
                StartupLog.WriteBackup("Backup", $"file-capture skip-existing-no-baseline: pid={processId}; target={normalized}; fileKey={normalizedCaptureKey}; reason={reason}");
                return;
            }

            capturedFileTargets.Add(normalizedCaptureKey);
        }
        catch (Exception ex)
        {
            failedFileTargets.Add(normalizedCaptureKey);
            StartupLog.WriteBackup("Backup", $"file-capture failed: pid={processId}; target={normalized}; fileKey={normalizedCaptureKey}; reason={reason}; message={ex.Message}");
        }
    }

    private static IEnumerable<string> EnumerateFilesSafe(string root, List<string> errors)
    {
        var stack = new Stack<string>();
        stack.Push(root);

        while (stack.Count > 0)
        {
            var current = stack.Pop();

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(current);
            }
            catch (Exception ex)
            {
                errors.Add($"enumerate files failed: {current}: {ex.Message}");
                continue;
            }

            foreach (var file in files)
            {
                yield return file;
            }

            IEnumerable<string> dirs;
            try
            {
                dirs = Directory.EnumerateDirectories(current);
            }
            catch (Exception ex)
            {
                errors.Add($"enumerate dirs failed: {current}: {ex.Message}");
                continue;
            }

            foreach (var dir in dirs)
            {
                try
                {
                    var attr = File.GetAttributes(dir);
                    if ((attr & FileAttributes.ReparsePoint) != 0)
                    {
                        continue;
                    }

                    stack.Push(dir);
                }
                catch (Exception ex)
                {
                    errors.Add($"inspect dir failed: {dir}: {ex.Message}");
                }
            }
        }
    }

    private static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        var candidate = path.Trim().TrimEnd('\0');
        candidate = ConvertNtPathToDosPath(candidate);

        try
        {
            return Path.GetFullPath(candidate);
        }
        catch
        {
            return candidate;
        }
    }

    private static string ConvertNtPathToDosPath(string value)
    {
        var path = value;

        if (path.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
        {
            path = path[4..];
        }

        if (path.Length > 3 &&
            path[1] == ':' &&
            (path[2] == '\\' || path[2] == '/') &&
            path.AsSpan(3).StartsWith("Device\\", StringComparison.OrdinalIgnoreCase))
        {
            path = "\\" + path[3..];
        }

        if (!path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            return path;
        }

        foreach (var map in GetDevicePrefixMap())
        {
            if (path.StartsWith(map.DevicePrefix, StringComparison.OrdinalIgnoreCase))
            {
                return map.DrivePrefix + path[map.DevicePrefix.Length..];
            }
        }

        return path;
    }

    private bool TryGetBaselineSnapshotLocked(
        string normalizedPath,
        ulong volumeSerialNumber,
        ulong fileId,
        out string baselineSnapshot,
        out string baselineMatch)
    {
        if (_baselineFileSnapshots.TryGetValue(normalizedPath, out baselineSnapshot!))
        {
            baselineMatch = "path";
            return true;
        }

        if (volumeSerialNumber != 0 && fileId != 0)
        {
            var fileCaptureKey = BuildFileCaptureKey(normalizedPath, volumeSerialNumber, fileId);
            if (_baselineFileSnapshotsByFileKey.TryGetValue(fileCaptureKey, out baselineSnapshot!))
            {
                baselineMatch = "file-id";
                return true;
            }
        }

        baselineSnapshot = string.Empty;
        baselineMatch = "none";
        return false;
    }

    private static bool TryBuildFileCaptureKeyFromExistingPath(string normalizedPath, out string captureKey)
    {
        captureKey = string.Empty;
        if (string.IsNullOrWhiteSpace(normalizedPath))
        {
            return false;
        }

        try
        {
            using var handle = File.OpenHandle(
                normalizedPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            if (handle.IsInvalid)
            {
                return false;
            }

            if (!GetFileInformationByHandle(handle, out var info))
            {
                return false;
            }

            var volumeSerialNumber = (ulong)info.DwVolumeSerialNumber;
            var fileId = ((ulong)info.NFileIndexHigh << 32) | info.NFileIndexLow;
            if (volumeSerialNumber == 0 || fileId == 0)
            {
                return false;
            }

            captureKey = BuildFileCaptureKey(normalizedPath, volumeSerialNumber, fileId);
            return captureKey.StartsWith("fid:", StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    private bool HasRuntimeFileSnapshotLocked(int processId, string normalizedPath)
    {
        if (!_entriesByProcess.TryGetValue(processId, out var entries) || entries.Count == 0)
        {
            return false;
        }

        foreach (var entry in entries)
        {
            if (entry.EntryType != RollbackEntryType.File)
            {
                continue;
            }

            if (!entry.TargetPath.Equals(normalizedPath, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (entry.BackupPath.EndsWith(".missing", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return true;
        }

        return false;
    }

    private static string BuildFileCaptureKey(string normalizedPath, ulong volumeSerialNumber, ulong fileId)
    {
        if (volumeSerialNumber != 0 && fileId != 0)
        {
            return $"fid:{volumeSerialNumber:X16}:{fileId:X16}";
        }

        return $"path:{normalizedPath.ToLowerInvariant()}";
    }

    private static IReadOnlyList<DevicePrefixMapEntry> GetDevicePrefixMap()
    {
        var list = new List<DevicePrefixMapEntry>();
        foreach (var driveRoot in Environment.GetLogicalDrives())
        {
            var drivePrefix = driveRoot.TrimEnd('\\');
            if (drivePrefix.Length != 2 || drivePrefix[1] != ':')
            {
                continue;
            }

            var buffer = new StringBuilder(1024);
            var result = QueryDosDevice(drivePrefix, buffer, buffer.Capacity);
            if (result == 0)
            {
                continue;
            }

            var target = buffer.ToString();
            foreach (var item in target.Split('\0', StringSplitOptions.RemoveEmptyEntries))
            {
                if (!item.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                list.Add(new DevicePrefixMapEntry(item, drivePrefix + "\\"));
            }
        }

        return list
            .OrderByDescending(item => item.DevicePrefix.Length)
            .ToList();
    }

    private static bool IsSkipCapturePath(string normalizedPath)
    {
        var fileName = Path.GetFileName(normalizedPath);
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return false;
        }

        if (fileName.StartsWith("ntuser.dat", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return fileName.Equals("pagefile.sys", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("swapfile.sys", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("hiberfil.sys", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("memory.dmp", StringComparison.OrdinalIgnoreCase);
    }

    private bool IsPathUnderProtectedRoots(string normalizedPath)
    {
        if (_protectedRoots.Count == 0)
        {
            return true;
        }

        foreach (var root in _protectedRoots)
        {
            if (normalizedPath.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                if (normalizedPath.Length == root.Length)
                {
                    return true;
                }

                var next = normalizedPath[root.Length];
                if (next == Path.DirectorySeparatorChar || next == Path.AltDirectorySeparatorChar)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static int NormalizeProcessId(int processId)
    {
        return processId > 0 ? processId : 0;
    }

    private static HashSet<string> GetOrCreateStringSetLocked(Dictionary<int, HashSet<string>> buckets, int processId)
    {
        if (!buckets.TryGetValue(processId, out var set))
        {
            set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            buckets[processId] = set;
        }

        return set;
    }

    private static Dictionary<string, string> GetOrCreateStringMapLocked(
        Dictionary<int, Dictionary<string, string>> buckets,
        int processId)
    {
        if (!buckets.TryGetValue(processId, out var map))
        {
            map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            buckets[processId] = map;
        }

        return map;
    }

    private List<RollbackEntry> GetOrCreateEntriesLocked(int processId)
    {
        if (!_entriesByProcess.TryGetValue(processId, out var entries))
        {
            entries = [];
            _entriesByProcess[processId] = entries;
        }

        return entries;
    }

    private void ClearProcessEntriesLocked(int processId)
    {
        _entriesByProcess.Remove(processId);
        _capturedFileTargetsByProcess.Remove(processId);
        _capturedRegistryTargetsByProcess.Remove(processId);
        _failedFileTargetsByProcess.Remove(processId);
        _failedRegistryTargetsByProcess.Remove(processId);
        _pendingDeleteTargetsByProcess.Remove(processId);
        _pendingRenameRestoreTargetsByProcess.Remove(processId);
        _pendingRenameRestoreNameOnlyTargetsByProcess.Remove(processId);
    }

    private static string ComputeKey(string input)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input.ToLowerInvariant()));
        return Convert.ToHexString(hash);
    }

    private static string ComputeProcessScopedKey(int processId, string input)
    {
        return ComputeKey($"{processId}:{input}");
    }

    private static void RestoreFile(RollbackEntry entry)
    {
        if (entry.BackupPath.EndsWith(".missing", StringComparison.OrdinalIgnoreCase))
        {
            if (File.Exists(entry.TargetPath))
            {
                File.Delete(entry.TargetPath);
            }

            return;
        }

        if (!File.Exists(entry.BackupPath))
        {
            throw new FileNotFoundException("backup not found", entry.BackupPath);
        }

        var dir = Path.GetDirectoryName(entry.TargetPath);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            Directory.CreateDirectory(dir);
        }

        File.Copy(entry.BackupPath, entry.TargetPath, true);
    }

    private static RegistryValueSnapshot CaptureRegistryValue(RegistryKey hive, string subKey, string valueName)
    {
        using var key = hive.OpenSubKey(subKey, writable: false);
        if (key is null)
        {
            return new RegistryValueSnapshot { Exists = false };
        }

        var names = key.GetValueNames();
        if (!names.Contains(valueName, StringComparer.OrdinalIgnoreCase))
        {
            return new RegistryValueSnapshot { Exists = false };
        }

        var kind = key.GetValueKind(valueName);
        var value = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);

        return new RegistryValueSnapshot
        {
            Exists = true,
            Kind = kind.ToString(),
            Data = value switch
            {
                null => null,
                byte[] bytes => Convert.ToBase64String(bytes),
                string[] multi => string.Join("\u0001", multi),
                _ => value.ToString()
            }
        };
    }

    private static void RestoreRegistry(RollbackEntry entry)
    {
        if (!File.Exists(entry.BackupPath))
        {
            throw new FileNotFoundException("registry snapshot not found", entry.BackupPath);
        }

        var snapshot = JsonSerializer.Deserialize<RegistryValueSnapshot>(File.ReadAllText(entry.BackupPath, Encoding.UTF8));
        if (snapshot is null)
        {
            throw new InvalidDataException("invalid registry snapshot");
        }

        if (!TryParseRegistryPath(entry.TargetPath, out var hive, out var subKey, out var valueName))
        {
            throw new InvalidDataException($"invalid registry path: {entry.TargetPath}");
        }

        using var key = hive.CreateSubKey(subKey, writable: true) ?? throw new InvalidOperationException("cannot open/create registry key");
        if (!snapshot.Exists)
        {
            try
            {
                key.DeleteValue(valueName, throwOnMissingValue: false);
            }
            catch
            {
                // ignore missing value
            }

            return;
        }

        var valueKind = Enum.TryParse<RegistryValueKind>(snapshot.Kind, out var parsed)
            ? parsed
            : RegistryValueKind.String;

        object? value = snapshot.Data;
        if (valueKind == RegistryValueKind.Binary)
        {
            value = string.IsNullOrWhiteSpace(snapshot.Data)
                ? Array.Empty<byte>()
                : Convert.FromBase64String(snapshot.Data);
        }
        else if (valueKind == RegistryValueKind.MultiString)
        {
            value = string.IsNullOrWhiteSpace(snapshot.Data)
                ? Array.Empty<string>()
                : snapshot.Data.Split("\u0001");
        }
        else if (valueKind is RegistryValueKind.DWord or RegistryValueKind.QWord)
        {
            if (!long.TryParse(snapshot.Data, out var numeric))
            {
                numeric = 0;
            }

            value = valueKind == RegistryValueKind.DWord
                ? (int)numeric
                : numeric;
        }

        key.SetValue(valueName, value ?? string.Empty, valueKind);
    }

    private static bool TryParseRegistryPath(string fullPath, out RegistryKey hive, out string subKeyPath, out string valueName)
    {
        hive = Registry.CurrentUser;
        subKeyPath = string.Empty;
        valueName = string.Empty;

        var normalized = fullPath.Trim();
        var firstSlash = normalized.IndexOf('\\');
        if (firstSlash <= 0 || firstSlash >= normalized.Length - 1)
        {
            return false;
        }

        var hiveName = normalized[..firstSlash].ToUpperInvariant();
        var remaining = normalized[(firstSlash + 1)..];
        var lastSlash = remaining.LastIndexOf('\\');
        if (lastSlash <= 0 || lastSlash >= remaining.Length - 1)
        {
            return false;
        }

        subKeyPath = remaining[..lastSlash];
        valueName = remaining[(lastSlash + 1)..];

        hive = hiveName switch
        {
            "HKCU" or "HKEY_CURRENT_USER" => Registry.CurrentUser,
            "HKLM" or "HKEY_LOCAL_MACHINE" => Registry.LocalMachine,
            "HKCR" or "HKEY_CLASSES_ROOT" => Registry.ClassesRoot,
            "HKU" or "HKEY_USERS" => Registry.Users,
            "HKCC" or "HKEY_CURRENT_CONFIG" => Registry.CurrentConfig,
            _ => null!
        };

        return hive is not null;
    }

    private sealed class RegistryValueSnapshot
    {
        public bool Exists { get; init; }
        public string Kind { get; init; } = RegistryValueKind.String.ToString();
        public string? Data { get; init; }
    }

    private sealed record DevicePrefixMapEntry(string DevicePrefix, string DrivePrefix);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTimeNative
    {
        public uint DwLowDateTime;
        public uint DwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public FileTimeNative CreationTime;
        public FileTimeNative LastAccessTime;
        public FileTimeNative LastWriteTime;
        public uint DwVolumeSerialNumber;
        public uint NFileSizeHigh;
        public uint NFileSizeLow;
        public uint NumberOfLinks;
        public uint NFileIndexHigh;
        public uint NFileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle hFile,
        out ByHandleFileInformation lpFileInformation);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(
        string lpDeviceName,
        StringBuilder lpTargetPath,
        int ucchMax);
}

public sealed record RollbackExecutionResult(
    int Processed,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> SuccessItems,
    IReadOnlyList<string> FailedItems);

public sealed record BaselineCaptureResult(
    int CapturedFiles,
    int SkippedFiles,
    bool Truncated,
    IReadOnlyList<string> Errors);

