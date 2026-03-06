using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using RollbackGuard.Common.Diagnostics;
using RollbackGuard.Common.Models;
using RollbackGuard.Common.Runtime;
using RollbackGuard.Common.Storage;
using RollbackGuard.Common.Threats;

namespace RollbackGuard.UI.ViewModels;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private static readonly TimeSpan IncidentMergeGap = TimeSpan.FromSeconds(12);
    private const int MaxDisplayedArtifacts = 24;

    private IncidentRowItem? _selectedIncident;
    private string _selectedIncidentTitle = "未选择日志";
    private string _selectedIncidentPath = "请选择左侧日志查看详情";
    private string _selectedIncidentDetail = string.Empty;
    private string _selectedIncidentMemoryDetail = string.Empty;
    private string _selectedIncidentDllList = string.Empty;
    private string _selectedIncidentRemediation = string.Empty;
    private string _driverState = "加载中";
    private string _policyVersion = "未知";
    private string _lastAction = "无事件";
    private string _noDataHint = string.Empty;
    private string _verifiedProgramsHint = string.Empty;
    private bool _isRefreshing;
    private List<IncidentLogEntry> _incidentSnapshot = [];
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private readonly object _refreshSync = new();
    private CancellationTokenSource? _refreshCts;
    private readonly object _detailSync = new();
    private CancellationTokenSource? _detailCts;
    private readonly object _rollbackCacheLock = new();
    private DateTime _rollbackCacheWriteTimeUtc;
    private Dictionary<int, RollbackTraceInfo> _rollbackTraceCache = [];

    public event PropertyChangedEventHandler? PropertyChanged;

    public string ProductName => "RollbackGuard";
    public string ProductTagline => "Ransomware Kill + Rollback + Registry Recovery";

    public string DriverState
    {
        get => _driverState;
        private set => SetField(ref _driverState, value);
    }

    public string PolicyVersion
    {
        get => _policyVersion;
        private set => SetField(ref _policyVersion, value);
    }

    public string LastAction
    {
        get => _lastAction;
        private set => SetField(ref _lastAction, value);
    }

    public string NoDataHint
    {
        get => _noDataHint;
        private set => SetField(ref _noDataHint, value);
    }

    public string VerifiedProgramsHint
    {
        get => _verifiedProgramsHint;
        private set => SetField(ref _verifiedProgramsHint, value);
    }

    public bool IsRefreshing
    {
        get => _isRefreshing;
        private set => SetField(ref _isRefreshing, value);
    }

    public string SelectedIncidentTitle
    {
        get => _selectedIncidentTitle;
        private set => SetField(ref _selectedIncidentTitle, value);
    }

    public string SelectedIncidentPath
    {
        get => _selectedIncidentPath;
        private set => SetField(ref _selectedIncidentPath, value);
    }

    public string SelectedIncidentDetail
    {
        get => _selectedIncidentDetail;
        private set => SetField(ref _selectedIncidentDetail, value);
    }

    public string SelectedIncidentMemoryDetail
    {
        get => _selectedIncidentMemoryDetail;
        private set => SetField(ref _selectedIncidentMemoryDetail, value);
    }

    public string SelectedIncidentDllList
    {
        get => _selectedIncidentDllList;
        private set => SetField(ref _selectedIncidentDllList, value);
    }

    public string SelectedIncidentRemediation
    {
        get => _selectedIncidentRemediation;
        private set => SetField(ref _selectedIncidentRemediation, value);
    }

    public ObservableCollection<IncidentRowItem> IncidentRows { get; } = [];
    public ObservableCollection<VerifiedProgramRowItem> VerifiedPrograms { get; } = [];

    public IncidentRowItem? SelectedIncident
    {
        get => _selectedIncident;
        set
        {
            if (SetField(ref _selectedIncident, value))
            {
                _ = RefreshSelectedIncidentDetailsAsync(value);
            }
        }
    }

    public MainViewModel()
    {
        _ = RefreshAsync();
    }

    public void Refresh()
    {
        _ = RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        CancellationTokenSource? previousCts;
        CancellationTokenSource currentCts;
        lock (_refreshSync)
        {
            previousCts = _refreshCts;
            _refreshCts = new CancellationTokenSource();
            currentCts = _refreshCts;
        }

        previousCts?.Cancel();
        previousCts?.Dispose();

        var token = currentCts.Token;

        try
        {
            await _refreshGate.WaitAsync(token);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        IsRefreshing = true;

        try
        {
            var uiState = await Task.Run(() => BuildRefreshState(token), token);
            if (token.IsCancellationRequested)
            {
                return;
            }

            ApplyRefreshState(uiState);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            StartupLog.Write("UI", "界面刷新失败", ex);
            DriverState = "状态读取失败";
            PolicyVersion = "未知";
            LastAction = "无事件";
            NoDataHint = $"读取数据失败: {ex.Message}";
            SelectedIncident = null;
            IncidentRows.Clear();
            VerifiedPrograms.Clear();
            VerifiedProgramsHint = $"已验证程序读取失败: {ex.Message}";
        }
        finally
        {
            IsRefreshing = false;
            _refreshGate.Release();
        }
    }

    private RefreshUiState BuildRefreshState(CancellationToken token)
    {
        RuntimePaths.EnsureAll();

        var policy = PolicyConfigStore.LoadOrCreate(RuntimePaths.PolicyPath);
        var status = StatusStore.TryLoad(RuntimePaths.StatusPath);
        var previousSelectionKey = SelectedIncident?.Group.GroupKey;

        token.ThrowIfCancellationRequested();

        var snapshot = IncidentStore.ReadLatest(RuntimePaths.IncidentLogPath, 20000)
            .OrderByDescending(item => item.Timestamp)
            .ThenBy(item => item.ProcessId)
            .ToList();

        token.ThrowIfCancellationRequested();

        var incidents = snapshot
            .Where(item => IsRelevantIncident(item, policy))
            .ToList();

        var groups = incidents.Count == 0 ? [] : BuildIncidentGroups(incidents);
        var rows = groups.Select(BuildRow).ToList();
        var verifiedPrograms = BuildVerifiedProgramRows(snapshot);

        return new RefreshUiState(
            PolicyVersion: policy.PolicyVersion,
            DriverState: status is null
                ? "无状态数据"
                : status.DriverConnected
                    ? $"已连接 ({status.DriverState})"
                    : $"未连接 ({status.DriverState})",
            LastAction: groups.Count == 0
                ? "无高风险事件"
                : $"{groups[0].ThreatType} / {groups[0].Action} @ {groups[0].EndTime.LocalDateTime:yyyy-MM-dd HH:mm:ss}",
            NoDataHint: groups.Count == 0 ? "当前没有高风险处置相关日志" : string.Empty,
            VerifiedProgramsHint: verifiedPrograms.Count == 0
                ? "当前没有已验证程序记录。"
                : $"已验证程序 {verifiedPrograms.Count} 个。",
            Snapshot: snapshot,
            Rows: rows,
            VerifiedPrograms: verifiedPrograms,
            Groups: groups,
            PreviousSelectionKey: previousSelectionKey);
    }

    private void ApplyRefreshState(RefreshUiState state)
    {
        _incidentSnapshot = state.Snapshot.ToList();

        PolicyVersion = state.PolicyVersion;
        DriverState = state.DriverState;
        LastAction = state.LastAction;
        NoDataHint = state.NoDataHint;
        VerifiedProgramsHint = state.VerifiedProgramsHint;

        IncidentRows.Clear();
        foreach (var row in state.Rows)
        {
            IncidentRows.Add(row);
        }

        VerifiedPrograms.Clear();
        foreach (var item in state.VerifiedPrograms)
        {
            VerifiedPrograms.Add(item);
        }

        if (state.Rows.Count == 0)
        {
            SelectedIncident = null;
            return;
        }

        if (!string.IsNullOrWhiteSpace(state.PreviousSelectionKey))
        {
            SelectedIncident = IncidentRows.FirstOrDefault(item =>
                item.Group.GroupKey.Equals(state.PreviousSelectionKey, StringComparison.Ordinal));
        }

        SelectedIncident ??= IncidentRows.FirstOrDefault();
    }

    private List<VerifiedProgramRowItem> BuildVerifiedProgramRows(IReadOnlyList<IncidentLogEntry> snapshot)
    {
        var merged = new Dictionary<string, VerifiedProgramCandidate>(StringComparer.OrdinalIgnoreCase);

        foreach (var item in LoadVerifiedProgramsFromSignatureCache())
        {
            MergeVerifiedProgramCandidate(merged, item);
        }

        foreach (var item in LoadVerifiedProgramsFromIncidents(snapshot))
        {
            MergeVerifiedProgramCandidate(merged, item);
        }

        return merged.Values
            .Select(BuildVerifiedProgramRowEx)
            .OrderBy(item => GetTrustDisplayRank(item.TrustTier))
            .ThenByDescending(item => item.LastSeen)
            .ThenBy(item => item.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public bool DeleteSelectedIncident(out string message)
    {
        try
        {
            if (SelectedIncident is null)
            {
                message = "请先选择一条日志。";
                return false;
            }

            var all = IncidentStore.ReadAll(RuntimePaths.IncidentLogPath).ToList();
            var selectedGroup = SelectedIncident.Group;
            var targets = new HashSet<IncidentLogEntry>(selectedGroup.Incidents);
            var removed = all.RemoveAll(item => targets.Contains(item));
            if (removed <= 0)
            {
                message = "选中日志不存在（可能已被覆盖或清理），已刷新。";
                Refresh();
                return false;
            }

            IncidentStore.Overwrite(RuntimePaths.IncidentLogPath, all);
            message = $"已删除聚合日志：PID {selectedGroup.ProcessId} / {selectedGroup.ThreatType} / {removed} 条原始记录";
            Refresh();
            return true;
        }
        catch (Exception ex)
        {
            StartupLog.Write("UI", "删除选中日志失败", ex);
            message = $"删除失败: {ex.Message}";
            return false;
        }
    }

    private void RefreshVerifiedPrograms(IReadOnlyList<IncidentLogEntry> snapshot)
    {
        var merged = new Dictionary<string, VerifiedProgramCandidate>(StringComparer.OrdinalIgnoreCase);

        foreach (var item in LoadVerifiedProgramsFromSignatureCache())
        {
            MergeVerifiedProgramCandidate(merged, item);
        }

        foreach (var item in LoadVerifiedProgramsFromIncidents(snapshot))
        {
            MergeVerifiedProgramCandidate(merged, item);
        }

        var ordered = merged.Values
            .Select(BuildVerifiedProgramRowEx)
            .OrderBy(item => GetTrustDisplayRank(item.TrustTier))
            .ThenByDescending(item => item.LastSeen)
            .ThenBy(item => item.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        VerifiedPrograms.Clear();
        foreach (var item in ordered)
        {
            VerifiedPrograms.Add(item);
        }

        VerifiedProgramsHint = ordered.Count == 0
            ? "当前没有已验证程序记录。"
            : $"已验证程序 {ordered.Count} 个。";
    }

    public bool DeleteAllIncidents(out string message)
    {
        try
        {
            IncidentStore.Overwrite(RuntimePaths.IncidentLogPath, []);
            message = "日志已清空。";
            Refresh();
            return true;
        }
        catch (Exception ex)
        {
            StartupLog.Write("UI", "清空日志失败", ex);
            message = $"清空失败: {ex.Message}";
            return false;
        }
    }

    private async Task RefreshSelectedIncidentDetailsAsync(IncidentRowItem? row)
    {
        CancellationTokenSource? previous;
        CancellationTokenSource current;
        lock (_detailSync)
        {
            previous = _detailCts;
            _detailCts = new CancellationTokenSource();
            current = _detailCts;
        }

        previous?.Cancel();
        previous?.Dispose();

        if (row is null)
        {
            ApplySelectedIncidentDetails(IncidentDetailState.Empty);
            return;
        }

        try
        {
            var state = await Task.Run(() => BuildIncidentDetailState(row, current.Token), current.Token);
            if (current.IsCancellationRequested || !ReferenceEquals(row, SelectedIncident))
            {
                return;
            }

            ApplySelectedIncidentDetails(state);
        }
        catch (OperationCanceledException)
        {
            // selection changed rapidly; ignore
        }
        catch (Exception ex)
        {
            StartupLog.Write("UI", "详情构建失败", ex);
            if (!current.IsCancellationRequested)
            {
                SelectedIncidentDetail = $"详情构建失败: {ex.Message}";
                SelectedIncidentMemoryDetail = string.Empty;
                SelectedIncidentDllList = string.Empty;
                SelectedIncidentRemediation = string.Empty;
            }
        }
        finally
        {
            if (ReferenceEquals(_detailCts, current))
            {
                lock (_detailSync)
                {
                    if (ReferenceEquals(_detailCts, current))
                    {
                        _detailCts = null;
                    }
                }
            }

            current.Dispose();
        }
    }

    private IncidentDetailState BuildIncidentDetailState(IncidentRowItem row, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var group = row.Group;
        var incident = group.Representative;
        var processName = DisplayProcessName(group.ProcessPath);
        var rollbackTrace = LoadRollbackTraceCached(group.ProcessId);

        cancellationToken.ThrowIfCancellationRequested();

        var detail = new StringBuilder();
        detail.AppendLine($"时间窗口: {group.StartTime.LocalDateTime:yyyy-MM-dd HH:mm:ss} ~ {group.EndTime.LocalDateTime:yyyy-MM-dd HH:mm:ss}");
        detail.AppendLine($"PID: {group.ProcessId}");
        detail.AppendLine($"进程名: {processName}");
        detail.AppendLine($"进程路径: {SafeDisplay(group.ProcessPath)}");
        detail.AppendLine($"信任分级: {group.TrustTier}");
        detail.AppendLine($"主判定事件: {group.ThreatType}");
        detail.AppendLine($"触发入口: {incident.EventKind}");
        detail.AppendLine($"聚合日志数: {group.Incidents.Count}");
        detail.AppendLine($"最高分: {group.MaxScore:F3}");
        AppendIncidentSection(detail, "[信任剖面]", BuildTrustProfileLines(group));
        AppendIncidentSection(detail, "[进程链]", BuildProcessChainLines(group));
        detail.AppendLine();
        detail.AppendLine("[判定缘由]");
        detail.AppendLine(BuildReasonNarrative(group));
        foreach (var evidence in BuildPrimaryEvidenceLines(group))
        {
            detail.AppendLine($"- {evidence}");
        }

        var suspiciousDllEvidence = BuildSuspiciousDllEvidenceForDetail(group);
        if (!string.IsNullOrWhiteSpace(suspiciousDllEvidence))
        {
            detail.AppendLine($"- DLL 线索: {suspiciousDllEvidence}");
        }

        detail.AppendLine($"原始原因串: {BuildRawReasonSummary(group)}");
        detail.AppendLine();

        detail.AppendLine("[涉及文件]");
        if (group.TouchedArtifacts.Count == 0)
        {
            detail.AppendLine("本组事件没有形成可展示的文件路径。");
        }
        else
        {
            detail.AppendLine($"归并后的文件/路径数量: {group.TouchedArtifacts.Count}");
            foreach (var item in group.TouchedArtifacts.Take(MaxDisplayedArtifacts))
            {
                detail.AppendLine($"- {item}");
            }

            if (group.TouchedArtifacts.Count > MaxDisplayedArtifacts)
            {
                detail.AppendLine($"- ... 其余 {group.TouchedArtifacts.Count - MaxDisplayedArtifacts} 项省略");
            }
        }

        detail.AppendLine();
        detail.AppendLine("[处置结果]");
        detail.AppendLine($"执行动作: {group.Action}");
        detail.AppendLine($"是否执行终止: {row.KillStatus}");
        detail.AppendLine($"终止目标: PID={group.ProcessId}, 进程={processName}, 路径={SafeDisplay(group.ProcessPath)}");
        detail.AppendLine($"回滚状态: {BuildRollbackStatusForDetail(group, rollbackTrace)}");
        detail.AppendLine($"回滚条目计数(incident): {group.Incidents.Sum(item => item.RollbackCount)}");

        detail.AppendLine();
        detail.AppendLine("[回滚了什么]");
        if (!string.IsNullOrWhiteSpace(rollbackTrace.Sample))
        {
            detail.AppendLine($"回滚清单样本: {rollbackTrace.Sample}");
        }
        else
        {
            detail.AppendLine("回滚清单样本: (日志无样本)");
        }

        if (rollbackTrace.Failures.Count > 0)
        {
            detail.AppendLine("回滚失败样本:");
            foreach (var line in rollbackTrace.Failures)
            {
                detail.AppendLine($"- {line}");
            }
        }

        detail.AppendLine();
        detail.AppendLine("[执行反馈]");
        detail.AppendLine(BuildExecutionFeedback(group));

        cancellationToken.ThrowIfCancellationRequested();

        return new IncidentDetailState(
            $"{group.EndTime.LocalDateTime:yyyy-MM-dd HH:mm:ss} | PID {group.ProcessId} | {group.ThreatType} | {processName}",
            string.IsNullOrWhiteSpace(group.ProcessPath) ? "(未知路径)" : group.ProcessPath,
            detail.ToString(),
            BuildMemoryDetailForTab(group),
            BuildDllListForTab(group),
            BuildRemediationForTab(group, rollbackTrace));
    }

    private void ApplySelectedIncidentDetails(IncidentDetailState state)
    {
        SelectedIncidentTitle = state.Title;
        SelectedIncidentPath = state.Path;
        SelectedIncidentDetail = state.Detail;
        SelectedIncidentMemoryDetail = state.MemoryDetail;
        SelectedIncidentDllList = state.DllList;
        SelectedIncidentRemediation = state.Remediation;
    }

    private static List<IncidentGroupInfo> BuildIncidentGroups(IReadOnlyList<IncidentLogEntry> incidents)
    {
        var groups = new List<IncidentGroupInfo>();
        var ordered = incidents
            .OrderBy(item => item.ProcessId)
            .ThenBy(item => SafeDisplay(item.ProcessPath))
            .ThenBy(item => item.Timestamp)
            .ThenBy(item => item.EventKind)
            .ToList();

        List<IncidentLogEntry>? current = null;
        var currentFamily = ThreatFamily.SuspiciousBehavior;
        var currentPid = 0;
        var currentProcessPath = string.Empty;

        foreach (var incident in ordered)
        {
            var family = ClassifyThreatFamily(incident);
            var normalizedProcessPath = SafeDisplay(incident.ProcessPath);
            var shouldStartNewGroup = current is null ||
                incident.ProcessId != currentPid ||
                !normalizedProcessPath.Equals(currentProcessPath, StringComparison.OrdinalIgnoreCase) ||
                family != currentFamily ||
                incident.Timestamp - current[^1].Timestamp > IncidentMergeGap;

            if (shouldStartNewGroup)
            {
                FinalizeCurrentGroup();
                current = [];
                currentFamily = family;
                currentPid = incident.ProcessId;
                currentProcessPath = normalizedProcessPath;
            }

            current!.Add(incident);
        }

        FinalizeCurrentGroup();

        return groups
            .OrderByDescending(group => group.EndTime)
            .ThenByDescending(group => group.MaxScore)
            .ToList();

        void FinalizeCurrentGroup()
        {
            if (current is null || current.Count == 0)
            {
                return;
            }

            groups.Add(BuildIncidentGroup(current, currentFamily));
            current = null;
        }
    }

    private static IncidentGroupInfo BuildIncidentGroup(IReadOnlyList<IncidentLogEntry> incidents, ThreatFamily family)
    {
        var representative = incidents
            .OrderByDescending(item => GetActionRank(item.Action))
            .ThenByDescending(item => item.Score)
            .ThenByDescending(item => item.Timestamp)
            .First();

        var processPath = incidents
            .Select(item => SafeDisplay(item.ProcessPath))
            .LastOrDefault(value => !string.IsNullOrWhiteSpace(value))
            ?? string.Empty;

        var touchedArtifacts = CollectTouchedArtifacts(incidents);
        var reasons = incidents
            .Select(item => SafeDisplay(item.Reason))
            .Where(item => !string.IsNullOrWhiteSpace(item) && item != "(无)")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new IncidentGroupInfo(
            GroupKey: $"{representative.ProcessId}|{family}|{incidents[0].Timestamp.UtcTicks}|{incidents[^1].Timestamp.UtcTicks}",
            Family: family,
            ThreatType: BuildThreatLabel(family),
            TrustTier: incidents
                .Select(item => string.IsNullOrWhiteSpace(item.TrustTier) ? null : item.TrustTier)
                .LastOrDefault(value => !string.IsNullOrWhiteSpace(value))
                ?? "Unknown",
            ProcessId: representative.ProcessId,
            ProcessPath: processPath,
            StartTime: incidents[0].Timestamp,
            EndTime: incidents[^1].Timestamp,
            Incidents: incidents.ToList(),
            Representative: representative,
            Action: BuildGroupAction(incidents),
            MaxScore: incidents.Max(item => item.Score),
            TouchedArtifacts: touchedArtifacts,
            RawReasons: reasons);
    }

    private static IncidentRowItem BuildRow(IncidentGroupInfo group) =>
        new()
        {
            Group = group,
            Time = group.EndTime.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss"),
            ProcessId = group.ProcessId,
            ProcessName = DisplayProcessName(group.ProcessPath),
            ProcessPath = SafeDisplay(group.ProcessPath),
            Action = group.Action.ToString(),
            Score = group.MaxScore,
            ThreatType = group.ThreatType,
            TrustTier = group.TrustTier,
            KillStatus = BuildKillStatus(group),
            RollbackStatus = BuildRollbackStatusSummary(group)
        };

    private static ThreatFamily ClassifyThreatFamily(IncidentLogEntry incident)
    {
        var label = ThreatLabelResolver.ResolveLabel(incident.EventKind, incident.Reason, incident.TargetPath);
        return label switch
        {
            "ransomware" => ThreatFamily.Ransomware,
            "shellcode" => ThreatFamily.Shellcode,
            "inject-prelude" => ThreatFamily.InjectPrelude,
            "remediation" => ThreatFamily.Remediation,
            "dll-sideload" => ThreatFamily.DllSideload,
            "macro-dropper" => ThreatFamily.MacroDropper,
            "destructive" => ThreatFamily.Destructive,
            _ => ThreatFamily.SuspiciousBehavior
        };
    }

    private static string BuildThreatLabel(ThreatFamily family) =>
        family switch
        {
            ThreatFamily.Ransomware => "ransomware",
            ThreatFamily.Shellcode => "shellcode",
            ThreatFamily.InjectPrelude => "inject-prelude",
            ThreatFamily.Remediation => "remediation",
            ThreatFamily.DllSideload => "dll-sideload",
            ThreatFamily.MacroDropper => "macro-dropper",
            ThreatFamily.Destructive => "destructive",
            _ => "suspicious-behavior"
        };

    private static SecurityAction BuildGroupAction(IReadOnlyList<IncidentLogEntry> incidents) =>
        incidents
            .OrderByDescending(item => GetActionRank(item.Action))
            .Select(item => item.Action)
            .First();

    private static int GetActionRank(SecurityAction action) =>
        action switch
        {
            SecurityAction.Terminate => 3,
            SecurityAction.Block => 2,
            _ => 1
        };

    private static IReadOnlyList<string> CollectTouchedArtifacts(IReadOnlyList<IncidentLogEntry> incidents)
    {
        var list = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var incident in incidents)
        {
            switch (incident.EventKind)
            {
                case EventKind.FileRename:
                    if (!string.IsNullOrWhiteSpace(incident.TargetPath))
                    {
                        AddArtifact(list, seen, $"RENAME -> {SafeDisplay(incident.TargetPath)}");
                    }
                    break;
                case EventKind.FileWrite:
                case EventKind.FileDelete:
                case EventKind.FileCreate:
                case EventKind.HoneyFileTouched:
                    AddArtifact(list, seen, incident.TargetPath);
                    break;
            }
        }

        return list;
    }

    private static void AddArtifact(List<string> list, HashSet<string> seen, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var normalized = value.Trim().TrimEnd('\0');
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return;
        }

        if (seen.Add(normalized))
        {
            list.Add(normalized);
        }
    }

    private static string BuildKillStatus(IncidentGroupInfo group)
    {
        if (group.Action != SecurityAction.Terminate)
        {
            return "否";
        }

        if (group.Incidents.Any(item => item.Action == SecurityAction.Terminate && item.DriverCommandSucceeded))
        {
            return "是";
        }

        var messages = string.Join(";", group.Incidents.Select(item => item.DriverMessage));
        if (ContainsAny(messages,
                "process-gone",
                "already-exited",
                "(1168)",
                "not found",
                "不存在",
                "找不到"))
        {
            return "进程已退出";
        }

        return "失败";
    }

    private static string BuildRollbackStatusSummary(IncidentGroupInfo group)
    {
        var rollbackCount = group.Incidents.Sum(item => item.RollbackCount);
        if (rollbackCount > 0)
        {
            return $"是({rollbackCount})";
        }

        var messages = string.Join(";", group.Incidents.Select(item => item.DriverMessage));
        if (ContainsAny(messages, "rollback-skipped-by-user", "user-denied rollback"))
        {
            return "否(用户取消)";
        }

        if (ContainsAny(messages, "terminated-late-rollback", "rollback-errors=", "rollback"))
        {
            return "已触发";
        }

        return "否";
    }

    private static string BuildRollbackStatusForDetail(IncidentGroupInfo group, RollbackTraceInfo trace)
    {
        var rollbackCount = group.Incidents.Sum(item => item.RollbackCount);
        if (rollbackCount > 0)
        {
            return $"已执行，processed={rollbackCount}";
        }

        var messages = string.Join(";", group.Incidents.Select(item => item.DriverMessage));
        if (ContainsAny(messages, "rollback-skipped-by-user", "user-denied rollback"))
        {
            return "未执行（用户取消）";
        }

        if (trace.HasCompletion)
        {
            var processed = trace.Processed.HasValue ? trace.Processed.Value.ToString() : "?";
            var errors = trace.Errors.HasValue ? trace.Errors.Value.ToString() : "?";
            return $"已执行（log: processed={processed}, errors={errors}）";
        }

        return "未执行/无记录";
    }

    private RollbackTraceInfo LoadRollbackTraceCached(int pid)
    {
        if (pid <= 0)
        {
            return RollbackTraceInfo.Empty;
        }

        var path = RuntimePaths.RollbackLogPath;
        if (!File.Exists(path))
        {
            lock (_rollbackCacheLock)
            {
                _rollbackTraceCache = [];
                _rollbackCacheWriteTimeUtc = DateTime.MinValue;
            }

            return RollbackTraceInfo.Empty;
        }

        DateTime writeTime;
        try
        {
            writeTime = File.GetLastWriteTimeUtc(path);
        }
        catch
        {
            return RollbackTraceInfo.Empty;
        }

        lock (_rollbackCacheLock)
        {
            if (_rollbackCacheWriteTimeUtc != writeTime)
            {
                _rollbackTraceCache = ParseRollbackTraceByPid(path);
                _rollbackCacheWriteTimeUtc = writeTime;
            }

            return _rollbackTraceCache.TryGetValue(pid, out var trace)
                ? trace
                : RollbackTraceInfo.Empty;
        }
    }

    private static Dictionary<int, RollbackTraceInfo> ParseRollbackTraceByPid(string path)
    {
        var bucket = new Dictionary<int, List<string>>();

        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream, Encoding.UTF8, true);
            while (true)
            {
                var line = reader.ReadLine();
                if (line is null)
                {
                    break;
                }

                var pid = ExtractInt(line, "pid");
                if (!pid.HasValue || pid.Value <= 0)
                {
                    continue;
                }

                if (!bucket.TryGetValue(pid.Value, out var list))
                {
                    list = [];
                    bucket[pid.Value] = list;
                }

                list.Add(line.Trim());
            }
        }
        catch
        {
            return [];
        }

        var result = new Dictionary<int, RollbackTraceInfo>();
        foreach (var (pid, lines) in bucket)
        {
            result[pid] = BuildRollbackTraceInfo(lines);
        }

        return result;
    }

    private static RollbackTraceInfo BuildRollbackTraceInfo(IReadOnlyList<string> matched)
    {
        if (matched.Count == 0)
        {
            return RollbackTraceInfo.Empty;
        }

        string sample = string.Empty;
        int? processed = null;
        int? errors = null;
        var failures = new List<string>();

        for (var i = matched.Count - 1; i >= 0; i--)
        {
            var line = matched[i];
            if (string.IsNullOrWhiteSpace(sample) &&
                line.Contains("sample=", StringComparison.OrdinalIgnoreCase))
            {
                var idx = line.IndexOf("sample=", StringComparison.OrdinalIgnoreCase);
                if (idx >= 0)
                {
                    sample = line[(idx + "sample=".Length)..].Trim();
                }
            }

            if (!processed.HasValue && line.Contains("processed=", StringComparison.OrdinalIgnoreCase))
            {
                processed = ExtractInt(line, "processed");
            }

            if (!errors.HasValue && line.Contains("errors=", StringComparison.OrdinalIgnoreCase))
            {
                errors = ExtractInt(line, "errors");
            }

            if (line.Contains("回滚失败", StringComparison.OrdinalIgnoreCase) ||
                line.Contains("rollback failed", StringComparison.OrdinalIgnoreCase))
            {
                failures.Add(line);
                if (failures.Count >= 8)
                {
                    break;
                }
            }
        }

        return new RollbackTraceInfo(
            sample,
            failures,
            processed,
            errors,
            processed.HasValue || errors.HasValue);
    }

    private static int? ExtractInt(string line, string key)
    {
        var match = Regex.Match(line, $@"{Regex.Escape(key)}=(\d+)", RegexOptions.IgnoreCase);
        if (!match.Success)
        {
            return null;
        }

        return int.TryParse(match.Groups[1].Value, out var value) ? value : null;
    }

    private static string BuildMemoryDetailForTab(IncidentGroupInfo group)
    {
        var lines = new List<string>
        {
            $"信任分级: {group.TrustTier}",
            $"时间窗口: {group.StartTime.LocalDateTime:yyyy-MM-dd HH:mm:ss} ~ {group.EndTime.LocalDateTime:yyyy-MM-dd HH:mm:ss}"
        };

        var memoryDetails = group.Incidents
            .Select(item => SafeDisplay(item.MemoryScanDetail))
            .Where(item => item != "(无)")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (memoryDetails.Count == 0)
        {
            lines.Add("未记录到内存扫描详情。");
            return string.Join(Environment.NewLine, lines);
        }

        lines.Add($"内存扫描记录数: {memoryDetails.Count}");
        foreach (var detail in memoryDetails)
        {
            lines.Add($"- {detail}");
        }

        return string.Join(Environment.NewLine, lines);
    }

    private string BuildDllListForTab(IncidentGroupInfo group)
    {
        var trustIncident = GetTrustSnapshotIncident(group);
        var lines = new List<string>
        {
            $"UI 当前分级: {group.TrustTier}",
            $"本体分级: {DisplayTrustTierValue(trustIncident.BaseTrustTier, group.TrustTier)}",
            $"运行态分级: {DisplayTrustTierValue(trustIncident.CurrentTrustTier, group.TrustTier)}",
            $"DLL 降级标志: 未签名={FormatBooleanState(trustIncident.LoadedUnsignedDll)} | 非微软={FormatBooleanState(trustIncident.LoadedNonMicrosoftDll)} | 可疑路径={FormatBooleanState(trustIncident.LoadedSuspiciousDll)}"
        };

        var end = group.EndTime.AddMinutes(1);
        var dllEvents = _incidentSnapshot
            .Where(item =>
                item.ProcessId == group.ProcessId &&
                item.Timestamp <= end &&
                SafeDisplay(item.ProcessPath).Equals(SafeDisplay(group.ProcessPath), StringComparison.OrdinalIgnoreCase) &&
                item.EventKind is EventKind.ImageLoad or EventKind.ImageLoadUnsigned)
            .OrderBy(item => item.Timestamp)
            .ToList();

        if (dllEvents.Count == 0)
        {
            lines.Add("未收集到 DLL 加载记录。");
            return string.Join(Environment.NewLine, lines);
        }

        var startIndex = Math.Max(0, dllEvents.Count - 64);
        if (startIndex > 0)
        {
            lines.Add($"DLL 加载记录过多，仅显示最后 {dllEvents.Count - startIndex} 条。");
        }

        foreach (var item in dllEvents.Skip(startIndex))
        {
            var path = SafeDisplay(item.TargetPath);
            var moduleTier = DisplayTrustTierValue(
                item.ModuleTrustTier,
                item.EventKind == EventKind.ImageLoadUnsigned ? "Unsigned" : "Signed");
            var signed = FormatBooleanState(item.ModuleSigned ?? (item.EventKind == EventKind.ImageLoad));
            var microsoftSigned = FormatBooleanState(item.ModuleMicrosoftSigned);
            var suspicious = ThreatLabelResolver.IsInterestingDllEvidencePath(item.TargetPath) ? "可疑路径" : "常规路径";
            lines.Add($"- {item.Timestamp.LocalDateTime:HH:mm:ss} | 分级={moduleTier} | 已签名={signed} | 微软签名={microsoftSigned} | {suspicious} | {path}");
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static string BuildRemediationForTab(IncidentGroupInfo group, RollbackTraceInfo rollbackTrace)
    {
        var lines = new List<string>();
        var remediation = group.Incidents
            .Select(item => SafeDisplay(item.RemediationSummary))
            .Where(item => item != "(无)")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (remediation.Count == 0)
        {
            lines.Add("未记录到内存清除操作。");
        }
        else
        {
            lines.Add($"清除记录条数: {remediation.Count}");
            foreach (var item in remediation)
            {
                lines.Add($"- {item}");
            }
        }

        lines.Add(string.Empty);
        lines.Add($"回滚状态: {BuildRollbackStatusForDetail(group, rollbackTrace)}");
        if (!string.IsNullOrWhiteSpace(rollbackTrace.Sample))
        {
            lines.Add($"回滚样本: {rollbackTrace.Sample}");
        }

        return string.Join(Environment.NewLine, lines);
    }

#pragma warning disable CS0162
    private static string BuildReasonNarrative(IncidentGroupInfo group)
    {
        return group.Family switch
        {
            ThreatFamily.Ransomware =>
                "判定依据以批量文件写入、重命名、覆盖写和扩展名变化为主。",
            ThreatFamily.Shellcode =>
                "判定依据以高置信度注入链路为主，至少包含远程线程与目标内存异常或已闭合的注入前序证据。",
            ThreatFamily.InjectPrelude =>
                "判定依据以跨进程高权限句柄申请或可疑远程线程观察为主，当前证据仍属于注入前兆，不直接等同于 shellcode。",
            ThreatFamily.Remediation =>
                "当前记录为内存清除或保护性处置结果，不代表再次触发了新的攻击家族。",
            ThreatFamily.DllSideload =>
                "判定依据以异常模块加载证据为主。",
            ThreatFamily.MacroDropper =>
                "判定依据以 Office 宏链路拉起可疑子进程为主。",
            ThreatFamily.Destructive =>
                "判定依据以破坏恢复能力或系统环境的行为为主。",
            _ =>
                "当前日志存在异常信号，但不足以归入更具体的攻击家族。"
        };

        return group.Family switch
        {
            ThreatFamily.Ransomware =>
                "判定依据以批量文件写入、重命名、覆盖写和扩展名变化为主。",
            ThreatFamily.Shellcode =>
                "判定依据以远程线程与注入链路证据为主。",
            ThreatFamily.Remediation =>
                "当前记录为内存清除/保护性处置结果，不代表再次触发了新的攻击家族。",
            ThreatFamily.DllSideload =>
                "判定依据以异常模块加载证据为主。",
            ThreatFamily.MacroDropper =>
                "判定依据以 Office 宏链路拉起可疑子进程为主。",
            ThreatFamily.Destructive =>
                "判定依据以破坏恢复能力或系统环境的行为为主。",
            _ =>
                "当前日志存在异常信号，但不足以归入更具体的攻击家族。"
        };
    }

    private static List<string> BuildPrimaryEvidenceLines(IncidentGroupInfo group)
    {
        var modernLines = new List<string>();
        var modernReasonBlob = string.Join(";", group.RawReasons);

        switch (group.Family)
        {
            case ThreatFamily.Ransomware:
                var modernWriteCount = group.Incidents.Count(item => item.EventKind == EventKind.FileWrite);
                var modernRenameCount = group.Incidents.Count(item => item.EventKind == EventKind.FileRename);
                var modernDeleteCount = group.Incidents.Count(item => item.EventKind == EventKind.FileDelete);
                if (modernWriteCount > 0 || modernRenameCount > 0 || modernDeleteCount > 0)
                {
                    modernLines.Add($"文件事件汇总: 写入 {modernWriteCount} / 重命名 {modernRenameCount} / 删除 {modernDeleteCount}");
                }

                if (ContainsAny(modernReasonBlob, "rule-005"))
                {
                    modernLines.Add("命中 RULE-005 勒索行为链");
                }

                if (ContainsAny(modernReasonBlob, "entropy-ransom", "entropy-spike"))
                {
                    modernLines.Add("存在高熵写入证据");
                }

                if (ContainsAny(modernReasonBlob, "ext-change", "suspicious-ext"))
                {
                    modernLines.Add("存在批量改扩展名或可疑扩展名证据");
                }

                if (ContainsAny(modernReasonBlob, "overwrite-pattern"))
                {
                    modernLines.Add("存在覆盖写模式");
                }

                if (ContainsAny(modernReasonBlob, "write-rate", "high-freq-write", "unique-ratio", "dir-growth"))
                {
                    modernLines.Add("存在短时间多目录、多文件批量处理");
                }
                break;

            case ThreatFamily.Shellcode:
                if (group.Incidents.Any(item => item.EventKind == EventKind.ThreadCreateRemote))
                {
                    modernLines.Add("捕获到跨进程远程线程创建");
                }

                if (group.Incidents.Any(item => item.EventKind == EventKind.ProcessInject) ||
                    ContainsAny(modernReasonBlob, "rule-003", "rule-012", "rule-013", "rule-014", "confirmed-inject"))
                {
                    modernLines.Add("注入证据链已闭合并达到高置信度");
                }

                if (ContainsAny(modernReasonBlob, "memory-shellcode", "unbacked-exec", "wx-transition", "reflective-dll", "peb-walk", "api-hash", "direct-syscall"))
                {
                    modernLines.Add("目标进程存在可执行内存异常证据");
                }
                break;

            case ThreatFamily.InjectPrelude:
                if (group.Incidents.Any(item => item.EventKind == EventKind.InjectPrelude))
                {
                    modernLines.Add("捕获到跨进程高权限句柄请求");
                }

                if (group.Incidents.Any(item => item.EventKind == EventKind.ThreadCreateRemote))
                {
                    modernLines.Add("观察到远程线程创建，但证据尚未闭合为 shellcode");
                }

                if (ContainsAny(modernReasonBlob, "rule-002", "rule-004", "inject-prelude", "inject-handle", "remote-thread-observed", "remote-thread-chain"))
                {
                    modernLines.Add("当前仅命中注入前兆评分链");
                }
                break;

            case ThreatFamily.Remediation:
                var modernRemediation = group.Incidents
                    .Select(item => SafeDisplay(item.RemediationSummary))
                    .LastOrDefault(item => item != "(无)");
                if (!string.IsNullOrWhiteSpace(modernRemediation) && modernRemediation != "(无)")
                {
                    modernLines.Add($"最近清除记录: {modernRemediation}");
                }
                break;

            case ThreatFamily.DllSideload:
                if (ContainsAny(modernReasonBlob, "suspicious-dll", "unsigned-dll"))
                {
                    modernLines.Add("加载了未签名或可疑 DLL");
                }

                if (ContainsAny(modernReasonBlob, "rule-008"))
                {
                    modernLines.Add("命中 RULE-008 DLL 侧载文件操作链");
                }
                break;

            case ThreatFamily.MacroDropper:
                modernLines.Add("命中 Office 宏拉起可疑子进程链路");
                break;

            case ThreatFamily.Destructive:
                modernLines.Add("命中 shadow-delete 或恢复能力破坏行为");
                break;

            default:
                modernLines.Add("当前分组以综合异常分为主，未归并到更具体的攻击家族");
                break;
        }

        if (modernLines.Count > 0)
        {
            return modernLines;
        }

        var lines = new List<string>();
        var reasonBlob = string.Join(";", group.RawReasons);

        switch (group.Family)
        {
            case ThreatFamily.Ransomware:
                var writeCount = group.Incidents.Count(item => item.EventKind == EventKind.FileWrite);
                var renameCount = group.Incidents.Count(item => item.EventKind == EventKind.FileRename);
                var deleteCount = group.Incidents.Count(item => item.EventKind == EventKind.FileDelete);
                if (writeCount > 0 || renameCount > 0 || deleteCount > 0)
                {
                    lines.Add($"文件事件汇总: 写入 {writeCount} / 重命名 {renameCount} / 删除 {deleteCount}");
                }

                if (ContainsAny(reasonBlob, "rule-005"))
                {
                    lines.Add("命中 RULE-005 勒索行为链");
                }

                if (ContainsAny(reasonBlob, "entropy-ransom", "entropy-spike"))
                {
                    lines.Add("存在高熵写入证据");
                }

                if (ContainsAny(reasonBlob, "ext-change", "suspicious-ext"))
                {
                    lines.Add("存在批量改扩展名/可疑扩展名证据");
                }

                if (ContainsAny(reasonBlob, "overwrite-pattern"))
                {
                    lines.Add("存在覆盖写模式");
                }

                if (ContainsAny(reasonBlob, "write-rate", "high-freq-write", "unique-ratio", "dir-growth"))
                {
                    lines.Add("存在短时间多目录、多文件批量处理");
                }

                if (ContainsAny(reasonBlob, "protected("))
                {
                    lines.Add("命中了受保护目录");
                }

                if (group.TouchedArtifacts.Count > 0)
                {
                    lines.Add($"归并后的文件/路径数量: {group.TouchedArtifacts.Count}");
                }
                break;

            case ThreatFamily.Shellcode:
                if (group.Incidents.Any(item => item.EventKind == EventKind.ThreadCreateRemote))
                {
                    lines.Add("捕获到 ThreadCreateRemote 事件");
                }

                if (group.Incidents.Any(item => item.EventKind == EventKind.ProcessInject) ||
                    ContainsAny(reasonBlob, "rule-003", "remote-thread", "inject"))
                {
                    lines.Add("注入评分链命中了 remote-thread / RULE-003");
                }
                break;

            case ThreatFamily.Remediation:
                var remediation = group.Incidents
                    .Select(item => SafeDisplay(item.RemediationSummary))
                    .LastOrDefault(item => item != "(无)");
                if (!string.IsNullOrWhiteSpace(remediation) && remediation != "(无)")
                {
                    lines.Add($"最近清除记录: {remediation}");
                }
                break;

            case ThreatFamily.DllSideload:
                if (ContainsAny(reasonBlob, "suspicious-dll", "unsigned-dll"))
                {
                    lines.Add("加载了未签名或可疑 DLL");
                }

                if (ContainsAny(reasonBlob, "rule-008"))
                {
                    lines.Add("命中 RULE-008 DLL 侧载文件操作链");
                }
                break;

            case ThreatFamily.MacroDropper:
                lines.Add("命中了 Office 宏拉起可疑子进程链路");
                break;

            case ThreatFamily.Destructive:
                lines.Add("命中了 shadow-delete / 恢复破坏类行为");
                break;

            default:
                lines.Add("当前分组以综合异常分为主，未能归并到更具体的攻击家族");
                break;
        }

        return lines;
    }
#pragma warning restore CS0162

    private string BuildShellcodeEvidenceForDetail(IncidentGroupInfo group)
    {
        if (group.Family != ThreatFamily.Shellcode)
        {
            return string.Empty;
        }

        var evidences = new List<string>();
        if (group.Incidents.Any(item => item.EventKind == EventKind.ThreadCreateRemote))
        {
            evidences.Add("日志里出现了 ThreadCreateRemote");
        }

        if (group.Incidents.Any(item => item.EventKind == EventKind.ProcessInject))
        {
            evidences.Add("日志里出现了 ProcessInject");
        }

        var reasonBlob = string.Join(";", group.RawReasons);
        if (ContainsAny(reasonBlob, "rule-003", "remote-thread", "inject"))
        {
            evidences.Add("评分链命中了 RULE-003 / remote-thread");
        }

        return evidences.Count == 0 ? string.Empty : string.Join(" | ", evidences);
    }

    private string BuildSuspiciousDllEvidenceForDetail(IncidentGroupInfo group)
    {
        if (group.Family != ThreatFamily.DllSideload)
        {
            return string.Empty;
        }

        var evidences = new List<string>();
        foreach (var incident in group.Incidents)
        {
            TryAddDllEvidencePath(evidences, incident.TargetPath);
        }

        var from = group.StartTime.AddMinutes(-10);
        var to = group.EndTime.AddMinutes(1);
        foreach (var item in _incidentSnapshot)
        {
            if (item.ProcessId != group.ProcessId ||
                item.Timestamp < from ||
                item.Timestamp > to ||
                item.EventKind is not (EventKind.ImageLoadUnsigned or EventKind.ImageLoad))
            {
                continue;
            }

            TryAddDllEvidencePath(evidences, item.TargetPath);
            if (evidences.Count >= 4)
            {
                break;
            }
        }

        return evidences.Count == 0 ? string.Empty : string.Join(" | ", evidences);
    }

    private static void TryAddDllEvidencePath(List<string> bucket, string? path)
    {
        if (!ThreatLabelResolver.IsInterestingDllEvidencePath(path))
        {
            return;
        }

        var value = path!.Trim().TrimEnd('\0');

        if (bucket.Any(existing => existing.Equals(value, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        bucket.Add(value);
    }

    private static string BuildRawReasonSummary(IncidentGroupInfo group)
    {
        if (group.RawReasons.Count == 0)
        {
            return "(无)";
        }

        var sample = group.RawReasons.Take(6).ToList();
        if (group.RawReasons.Count > sample.Count)
        {
            sample.Add($"... 其余 {group.RawReasons.Count - sample.Count} 条省略");
        }

        return string.Join(" | ", sample);
    }

    private static string BuildExecutionFeedback(IncidentGroupInfo group)
    {
        var messages = group.Incidents
            .Select(item => SafeDisplay(item.DriverMessage))
            .Where(item => !string.IsNullOrWhiteSpace(item) && item != "(无)")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return messages.Count == 0
            ? "(无执行反馈)"
            : string.Join(Environment.NewLine, messages);
    }

    private void AppendIncidentSection(StringBuilder detail, string title, IReadOnlyList<string> lines)
    {
        detail.AppendLine();
        detail.AppendLine(title);
        if (lines.Count == 0)
        {
            detail.AppendLine("- (无)");
            return;
        }

        foreach (var line in lines)
        {
            detail.AppendLine($"- {line}");
        }
    }

    private IReadOnlyList<string> BuildTrustProfileLines(IncidentGroupInfo group)
    {
        var incident = GetTrustSnapshotIncident(group);
        var baseTier = DisplayTrustTierValue(incident.BaseTrustTier, group.TrustTier);
        var currentTier = DisplayTrustTierValue(incident.CurrentTrustTier, group.TrustTier);
        var downgradeReasons = BuildTrustDowngradeReasons(incident);
        var liveTrustSummary = BuildLiveTrustSummary(group.ProcessPath);

        var lines = new List<string>
        {
            $"UI 当前分级: {group.TrustTier}",
            $"本体分级: {baseTier}",
            $"运行态分级: {currentTier}",
            $"签名已评估: {FormatBooleanState(incident.SignatureEvaluated)}",
            $"主程序签名有效: {FormatBooleanState(incident.HasValidSignature)}",
            $"微软签名: {FormatBooleanState(incident.IsMicrosoftSigned)}"
        };

        lines.Add($"内核判定: {DisplayTrustTierValue(incident.KernelTrustHint)}");
        lines.Add($"用户态判定: 本体={baseTier} | 运行态={currentTier}");

        if (!string.IsNullOrWhiteSpace(liveTrustSummary.TrustLine))
        {
            lines.Add(liveTrustSummary.TrustLine);
        }

        if (!string.IsNullOrWhiteSpace(liveTrustSummary.PublisherLine))
        {
            lines.Add(liveTrustSummary.PublisherLine);
        }

        if (!string.IsNullOrWhiteSpace(liveTrustSummary.StatusLine))
        {
            lines.Add(liveTrustSummary.StatusLine);
        }

        if (!string.IsNullOrWhiteSpace(liveTrustSummary.LiveTier) &&
            !string.Equals(baseTier, liveTrustSummary.LiveTier, StringComparison.OrdinalIgnoreCase))
        {
            lines.Add($"蹇収宸紓: incident 鏈綋鍒嗙骇={baseTier}锛屽綋鍓嶆湰鍦伴獙绛?={liveTrustSummary.LiveTier}");
        }

        if (string.Equals(baseTier, currentTier, StringComparison.OrdinalIgnoreCase))
        {
            lines.Add(string.Equals(currentTier, "Unsigned", StringComparison.OrdinalIgnoreCase)
                ? "降级原因: 主程序本体就是 Unsigned"
                : "降级原因: 当前未观察到 DLL 造成的额外降级");
        }
        else if (downgradeReasons.Count > 0)
        {
            lines.Add($"降级原因: {string.Join("；", downgradeReasons)}");
        }
        else
        {
            lines.Add($"降级原因: 本体 {baseTier} -> 运行态 {currentTier}，但当前快照没有记录到具体 DLL 标志");
        }

        return lines;
    }

    private IReadOnlyList<string> BuildProcessChainLines(IncidentGroupInfo group)
    {
        var lines = new List<string>
        {
            $"当前: PID={group.ProcessId} | 进程={DisplayProcessName(group.ProcessPath)} | 路径={SafeDisplay(group.ProcessPath)}"
        };

        var incident = GetTrustSnapshotIncident(group);
        var parentPid = incident.ParentProcessId ?? 0;
        var parentPath = incident.ParentProcessPath;
        if (parentPid <= 0 && string.IsNullOrWhiteSpace(parentPath))
        {
            lines.Add("父进程: 未记录到父进程上下文");
            return lines;
        }

        var visited = new HashSet<int> { group.ProcessId };
        for (var depth = 0; depth < 4 && (parentPid > 0 || !string.IsNullOrWhiteSpace(parentPath)); depth++)
        {
            IncidentLogEntry? ancestor = null;
            if (parentPid > 0)
            {
                if (!visited.Add(parentPid))
                {
                    lines.Add($"链路回环: PID={parentPid}");
                    break;
                }

                ancestor = FindLatestIncidentByPid(parentPid);
            }

            var displayPath = !string.IsNullOrWhiteSpace(ancestor?.ProcessPath)
                ? ancestor.ProcessPath
                : parentPath;
            var label = depth == 0 ? "父进程" : $"上级{depth + 1}";
            lines.Add($"{label}: PID={(parentPid > 0 ? parentPid.ToString() : "未知")} | 进程={DisplayProcessName(displayPath)} | 路径={SafeDisplay(displayPath)}");

            if (ancestor is null)
            {
                break;
            }

            parentPid = ancestor.ParentProcessId ?? 0;
            parentPath = ancestor.ParentProcessPath;
        }

        return lines;
    }

    private static LiveTrustSummary BuildLiveTrustSummary(string? processPath)
    {
        if (!VerifiedProgramTrustEvaluator.TryGetTrust(processPath, out _, out var liveTrust))
        {
            return LiveTrustSummary.Empty;
        }

        var liveTier = liveTrust.IsSigned
            ? liveTrust.IsMicrosoftSigned ? "MicrosoftSigned" : "Signed"
            : "Unsigned";

        return new LiveTrustSummary(
            $"褰撳墠鏈湴楠岀: 鍒嗙骇={liveTier} | 宸茬鍚?={FormatBooleanState(liveTrust.IsSigned)} | 寰蒋绛惧悕={FormatBooleanState(liveTrust.IsMicrosoftSigned)}",
            $"褰撳墠鍙戝竷鑰? {SafeDisplay(liveTrust.PublisherName)}",
            $"褰撳墠楠岀鐘舵€? {SafeDisplay(liveTrust.StatusSummary)}",
            liveTier);
    }

    private IncidentLogEntry GetTrustSnapshotIncident(IncidentGroupInfo group) =>
        group.Incidents
            .Where(HasTrustSnapshot)
            .OrderByDescending(item => item.Timestamp)
            .FirstOrDefault()
        ?? group.Representative;

    private IncidentLogEntry? FindLatestIncidentByPid(int pid) =>
        _incidentSnapshot
            .Where(item => item.ProcessId == pid)
            .OrderByDescending(item => item.Timestamp)
            .FirstOrDefault();

    private static bool HasTrustSnapshot(IncidentLogEntry item) =>
        !string.IsNullOrWhiteSpace(item.BaseTrustTier) ||
        !string.IsNullOrWhiteSpace(item.CurrentTrustTier) ||
        !string.IsNullOrWhiteSpace(item.KernelTrustHint) ||
        item.SignatureEvaluated.HasValue ||
        item.HasValidSignature.HasValue ||
        item.IsMicrosoftSigned.HasValue ||
        item.LoadedUnsignedDll.HasValue ||
        item.LoadedSuspiciousDll.HasValue ||
        item.LoadedNonMicrosoftDll.HasValue ||
        item.ParentProcessId.HasValue ||
        !string.IsNullOrWhiteSpace(item.ParentProcessPath);

    private static List<string> BuildTrustDowngradeReasons(IncidentLogEntry item)
    {
        var reasons = new List<string>();
        if (item.LoadedUnsignedDll == true)
        {
            reasons.Add("已加载未签名 DLL");
        }

        if (item.LoadedNonMicrosoftDll == true)
        {
            reasons.Add("已加载非微软签名 DLL");
        }

        if (item.LoadedSuspiciousDll == true)
        {
            reasons.Add("已加载非系统目录未签名 DLL");
        }

        return reasons;
    }

    private static string DisplayProcessName(string? processPath)
    {
        if (string.IsNullOrWhiteSpace(processPath))
        {
            return "(未知进程)";
        }

        var name = Path.GetFileName(processPath);
        return string.IsNullOrWhiteSpace(name) ? processPath : name;
    }

    private static string SafeDisplay(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? "(无)"
            : value.Trim().TrimEnd('\0');

    private static string FormatBooleanState(bool? value) =>
        value.HasValue
            ? value.Value ? "是" : "否"
            : "未知";

    private static string DisplayTrustTierValue(string? value, string fallback = "Unknown") =>
        string.IsNullOrWhiteSpace(value) ? fallback : value;

    private readonly record struct LiveTrustSummary(
        string TrustLine,
        string PublisherLine,
        string StatusLine,
        string? LiveTier)
    {
        public static LiveTrustSummary Empty => new(string.Empty, string.Empty, string.Empty, null);
    }

    private static bool ContainsAny(string text, params string[] needles)
    {
        foreach (var needle in needles)
        {
            if (text.Contains(needle, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsRelevantIncident(IncidentLogEntry incident, PolicyConfig policy)
    {
        if (incident.EventKind is EventKind.RemediationMemoryZeroed or EventKind.MemoryScanShellcode or
            EventKind.MemoryScanRwx or EventKind.MemoryScanUnbackedExec or
            EventKind.MemoryScanWxTransition or EventKind.MemoryScanReflectiveDll)
        {
            return true;
        }

        if (incident.Action != SecurityAction.Allow)
        {
            return true;
        }

        if (incident.RollbackCount > 0)
        {
            return true;
        }

        var driverMessage = incident.DriverMessage ?? string.Empty;
        if (ContainsAny(driverMessage,
                "user-approved",
                "user-denied",
                "rollback",
                "terminate-race",
                "block",
                "suspend"))
        {
            return true;
        }

        var reason = (incident.Reason ?? string.Empty).ToLowerInvariant();
        return reason.Contains("fast-manual-contain", StringComparison.Ordinal) ||
               reason.Contains("user-ignore", StringComparison.Ordinal) ||
               reason.Contains("rollback", StringComparison.Ordinal);
    }

    private static List<VerifiedProgramCandidate> LoadVerifiedProgramsFromIncidents(IReadOnlyList<IncidentLogEntry> snapshot)
    {
        var results = new List<VerifiedProgramCandidate>();
        foreach (var incident in snapshot)
        {
            if (!TryBuildVerifiedProgramCandidate(
                    incident.ProcessPath,
                    incident.TrustTier,
                    incident.KernelTrustHint,
                    incident.Timestamp,
                    out var candidate))
            {
                continue;
            }

            results.Add(candidate);
        }

        return results;
    }

    private static List<VerifiedProgramCandidate> LoadVerifiedProgramsFromSignatureCache()
    {
        var results = new List<VerifiedProgramCandidate>();
        try
        {
            if (!File.Exists(RuntimePaths.SignatureCachePath))
            {
                return results;
            }

            using var document = JsonDocument.Parse(File.ReadAllText(RuntimePaths.SignatureCachePath));
            if (!document.RootElement.TryGetProperty("Entries", out var entries) ||
                entries.ValueKind != JsonValueKind.Array)
            {
                return results;
            }

            foreach (var entry in entries.EnumerateArray())
            {
                if (!entry.TryGetProperty("LastSeenPath", out var pathElement))
                {
                    continue;
                }

                var isSigned = entry.TryGetProperty("IsSigned", out var isSignedElement) && isSignedElement.GetBoolean();
                var isMicrosoftSigned = entry.TryGetProperty("IsMicrosoftSigned", out var isMsElement) && isMsElement.GetBoolean();
                var trustTier = isSigned
                    ? (isMicrosoftSigned ? "MicrosoftSigned" : "Signed")
                    : "Unsigned";

                var lastSeen = DateTimeOffset.MinValue;
                if (entry.TryGetProperty("LastSeenUtc", out var lastSeenElement) &&
                    lastSeenElement.ValueKind == JsonValueKind.String &&
                    DateTimeOffset.TryParse(lastSeenElement.GetString(), out var parsed))
                {
                    lastSeen = parsed;
                }

                if (!TryBuildVerifiedProgramCandidate(
                        pathElement.GetString(),
                        trustTier,
                        null,
                        lastSeen,
                        out var candidate))
                {
                    continue;
                }

                results.Add(candidate);
            }
        }
        catch
        {
            return results;
        }

        return results;
    }

    private static void MergeVerifiedProgramCandidate(
        IDictionary<string, VerifiedProgramCandidate> bucket,
        VerifiedProgramCandidate candidate)
    {
        if (!bucket.TryGetValue(candidate.Key, out var existing))
        {
            bucket[candidate.Key] = candidate;
            return;
        }

        if (candidate.LastSeen > existing.LastSeen)
        {
            bucket[candidate.Key] = MergeVerifiedProgramCandidateDetails(candidate, existing);
            return;
        }

        if (candidate.LastSeen < existing.LastSeen)
        {
            bucket[candidate.Key] = MergeVerifiedProgramCandidateDetails(existing, candidate);
            return;
        }

        var existingRiskRank = GetTrustConflictRank(existing.TrustTier);
        var candidateRiskRank = GetTrustConflictRank(candidate.TrustTier);
        if (candidateRiskRank >= existingRiskRank)
        {
            bucket[candidate.Key] = MergeVerifiedProgramCandidateDetails(candidate, existing);
            return;
        }

        bucket[candidate.Key] = MergeVerifiedProgramCandidateDetails(existing, candidate);
    }

    private static VerifiedProgramRowItem BuildVerifiedProgramRow(VerifiedProgramCandidate item) =>
        new()
        {
            ProcessName = item.ProcessName,
            ProcessPath = item.ProcessPath,
            TrustTier = item.TrustTier,
            TrustDisplay = item.TrustTier switch
            {
                "MicrosoftSigned" => "微软签名",
                "Signed" => "已签名",
                "Unsigned" => "无签名",
                _ => "Unknown"
            },
            LastSeen = item.LastSeen == DateTimeOffset.MinValue
                ? "缓存"
                : item.LastSeen.LocalDateTime.ToString("MM-dd HH:mm:ss")
        };

    private static VerifiedProgramRowItem BuildVerifiedProgramRowEx(VerifiedProgramCandidate item) =>
        new()
        {
            ProcessName = item.ProcessName,
            ProcessPath = item.ProcessPath,
            TrustTier = item.TrustTier,
            TrustDisplay = FormatVerifiedProgramTrustDisplay(item.TrustTier),
            KernelTrustDisplay = FormatVerifiedProgramTrustDisplay(item.KernelTrustTier),
            UserModeTrustDisplay = FormatVerifiedProgramTrustDisplay(item.UserModeTrustTier),
            LastSeen = item.LastSeen == DateTimeOffset.MinValue
                ? "缓存"
                : item.LastSeen.LocalDateTime.ToString("MM-dd HH:mm:ss")
        };

    private static VerifiedProgramCandidate MergeVerifiedProgramCandidateDetails(
        VerifiedProgramCandidate primary,
        VerifiedProgramCandidate secondary)
    {
        var kernelTrustTier = PickKnownTrustTier(primary.KernelTrustTier, secondary.KernelTrustTier);
        var userModeTrustTier = PickKnownTrustTier(primary.UserModeTrustTier, secondary.UserModeTrustTier);
        var overallTrustTier = PickKnownTrustTier(
            primary.TrustTier,
            PickKnownTrustTier(userModeTrustTier, PickKnownTrustTier(kernelTrustTier, secondary.TrustTier)));

        return primary with
        {
            TrustTier = overallTrustTier,
            KernelTrustTier = kernelTrustTier,
            UserModeTrustTier = userModeTrustTier
        };
    }

    private static string PickKnownTrustTier(string? preferred, string? fallback)
    {
        var normalizedPreferred = NormalizeTrustTier(preferred);
        if (normalizedPreferred != "Unknown")
        {
            return normalizedPreferred;
        }

        return NormalizeTrustTier(fallback);
    }

    private static string FormatVerifiedProgramTrustDisplay(string? trustTier) =>
        NormalizeTrustTier(trustTier) switch
        {
            "MicrosoftSigned" => "微软签名",
            "Signed" => "已签名",
            "Unsigned" => "无签名",
            _ => "Unknown"
        };

    private static int GetTrustDisplayRank(string? trustTier) =>
        NormalizeTrustTier(trustTier) switch
        {
            "MicrosoftSigned" => 0,
            "Signed" => 1,
            "Unsigned" => 2,
            _ => 3
        };

    private static int GetTrustConflictRank(string? trustTier) =>
        NormalizeTrustTier(trustTier) switch
        {
            "Unsigned" => 3,
            "Unknown" => 2,
            "Signed" => 1,
            "MicrosoftSigned" => 0,
            _ => 2
        };

    private static string NormalizeTrustTier(string? trustTier)
    {
        if (string.IsNullOrWhiteSpace(trustTier))
        {
            return "Unknown";
        }

        var normalized = trustTier.Trim();
        if (normalized.Equals("MicrosoftSigned", StringComparison.OrdinalIgnoreCase))
        {
            return "MicrosoftSigned";
        }

        if (normalized.Equals("Signed", StringComparison.OrdinalIgnoreCase))
        {
            return "Signed";
        }

        if (normalized.Equals("Unsigned", StringComparison.OrdinalIgnoreCase))
        {
            return "Unsigned";
        }

        return "Unknown";
    }

    private static string NormalizeProgramKey(string? processPath)
    {
        if (string.IsNullOrWhiteSpace(processPath))
        {
            return string.Empty;
        }

        if (VerifiedProgramTrustEvaluator.TryNormalizeDisplayPath(processPath, out var resolved))
        {
            return resolved;
        }

        var normalized = processPath.Trim().TrimEnd('\0').Replace('/', '\\');
        return normalized;
    }

    private static bool TryBuildVerifiedProgramCandidate(
        string? rawPath,
        string? fallbackTrustTier,
        string? fallbackKernelTrustTier,
        DateTimeOffset lastSeen,
        out VerifiedProgramCandidate candidate)
    {
        candidate = default!;

        var path = NormalizeProgramKey(rawPath);
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var trustTier = NormalizeTrustTier(fallbackTrustTier);
        var kernelTrustTier = NormalizeTrustTier(fallbackKernelTrustTier);
        var userModeTrustTier = trustTier;
        if (VerifiedProgramTrustEvaluator.TryGetTrust(rawPath, out var resolvedPath, out var liveTrust))
        {
            path = resolvedPath;
            userModeTrustTier = liveTrust.IsSigned
                ? (liveTrust.IsMicrosoftSigned ? "MicrosoftSigned" : "Signed")
                : "Unsigned";
            trustTier = userModeTrustTier;
        }
        else if (VerifiedProgramTrustEvaluator.TryNormalizeDisplayPath(rawPath, out var normalizedPath))
        {
            path = normalizedPath;
            if (File.Exists(path))
            {
                // Verified-programs view should prefer current local verification.
                // If the live verifier failed unexpectedly, avoid presenting a stale
                // historical "Unsigned" result as the current truth.
                userModeTrustTier = "Unknown";
                trustTier = kernelTrustTier != "Unknown"
                    ? kernelTrustTier
                    : "Unknown";
            }
        }

        candidate = new VerifiedProgramCandidate(
            Key: path,
            ProcessName: DisplayProcessName(path),
            ProcessPath: path,
            TrustTier: trustTier,
            KernelTrustTier: kernelTrustTier,
            UserModeTrustTier: userModeTrustTier,
            LastSeen: lastSeen);
        return true;
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string propertyName = "")
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        return true;
    }
}

internal sealed record IncidentGroupInfo(
    string GroupKey,
    ThreatFamily Family,
    string ThreatType,
    string TrustTier,
    int ProcessId,
    string ProcessPath,
    DateTimeOffset StartTime,
    DateTimeOffset EndTime,
    IReadOnlyList<IncidentLogEntry> Incidents,
    IncidentLogEntry Representative,
    SecurityAction Action,
    double MaxScore,
    IReadOnlyList<string> TouchedArtifacts,
    IReadOnlyList<string> RawReasons);

internal sealed record RollbackTraceInfo(
    string Sample,
    IReadOnlyList<string> Failures,
    int? Processed,
    int? Errors,
    bool HasCompletion)
{
    public static RollbackTraceInfo Empty => new(string.Empty, [], null, null, false);
}

internal sealed record RefreshUiState(
    string PolicyVersion,
    string DriverState,
    string LastAction,
    string NoDataHint,
    string VerifiedProgramsHint,
    IReadOnlyList<IncidentLogEntry> Snapshot,
    IReadOnlyList<IncidentRowItem> Rows,
    IReadOnlyList<VerifiedProgramRowItem> VerifiedPrograms,
    IReadOnlyList<IncidentGroupInfo> Groups,
    string? PreviousSelectionKey);

internal sealed record IncidentDetailState(
    string Title,
    string Path,
    string Detail,
    string MemoryDetail,
    string DllList,
    string Remediation)
{
    public static IncidentDetailState Empty => new(
        "未选择日志",
        "请选择左侧日志查看详情",
        string.Empty,
        string.Empty,
        string.Empty,
        string.Empty);
}

internal enum ThreatFamily
{
    Ransomware = 0,
    Shellcode = 1,
    InjectPrelude = 2,
    Remediation = 3,
    DllSideload = 4,
    MacroDropper = 5,
    Destructive = 6,
    SuspiciousBehavior = 7
}

public sealed class IncidentRowItem
{
    internal IncidentGroupInfo Group { get; init; } = null!;
    public required string Time { get; init; }
    public required int ProcessId { get; init; }
    public required string ProcessName { get; init; }
    public required string ProcessPath { get; init; }
    public required string Action { get; init; }
    public required double Score { get; init; }
    public required string ThreatType { get; init; }
    public required string TrustTier { get; init; }
    public required string KillStatus { get; init; }
    public required string RollbackStatus { get; init; }
}

internal sealed record VerifiedProgramCandidate(
    string Key,
    string ProcessName,
    string ProcessPath,
    string TrustTier,
    string KernelTrustTier,
    string UserModeTrustTier,
    DateTimeOffset LastSeen);

public sealed class VerifiedProgramRowItem
{
    public required string ProcessName { get; init; }
    public required string ProcessPath { get; init; }
    public required string TrustTier { get; init; }
    public required string TrustDisplay { get; init; }
    public string KernelTrustDisplay { get; init; } = string.Empty;
    public string UserModeTrustDisplay { get; init; } = string.Empty;
    public required string LastSeen { get; init; }
}
