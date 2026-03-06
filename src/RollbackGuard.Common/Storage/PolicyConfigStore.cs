using System.Text.Json;
using System.Text.Json.Serialization;
using RollbackGuard.Common.Models;

namespace RollbackGuard.Common.Storage;

public static class PolicyConfigStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    public static PolicyConfig LoadOrCreate(string path)
    {
        if (!File.Exists(path))
        {
            var policy = PolicyConfig.CreateDefault();
            Save(path, policy);
            return policy;
        }

        try
        {
            var json = File.ReadAllText(path);
            var data = JsonSerializer.Deserialize<PolicyConfig>(json, JsonOptions);
            if (data is null)
            {
                var fallback = PolicyConfig.CreateDefault();
                Save(path, fallback);
                return fallback;
            }

            var normalized = NormalizePolicy(data);
            return normalized;
        }
        catch
        {
            var fallback = PolicyConfig.CreateDefault();
            Save(path, fallback);
            return fallback;
        }
    }

    public static void Save(string path, PolicyConfig policy)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var json = JsonSerializer.Serialize(policy, JsonOptions);
        File.WriteAllText(path, json);
    }

    private static PolicyConfig NormalizePolicy(PolicyConfig source)
    {
        var normalizedRegistryKeys = source.ProtectedRegistryKeys
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .Select(item => item.Replace(@"\\", @"\", StringComparison.Ordinal))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new PolicyConfig
        {
            PolicyVersion = source.PolicyVersion,
            DriverDevicePath = source.DriverDevicePath,
            MiniFilterDevicePath = string.IsNullOrWhiteSpace(source.MiniFilterDevicePath)
                ? "\\\\.\\RollbackGuardMiniFilter"
                : source.MiniFilterDevicePath,
            AskThresholdLow = source.AskThresholdLow,
            AskThresholdMid = source.AskThresholdMid,
            AskThresholdHigh = source.AskThresholdHigh,
            AskThresholdCritical = source.AskThresholdCritical,
            ActionLow = source.ActionLow,
            ActionMid = source.ActionMid,
            ActionHigh = source.ActionHigh,
            ActionCritical = source.ActionCritical,
            BurstTrigger = source.BurstTrigger,
            TimeWindowSeconds = source.TimeWindowSeconds,
            ProtectedFolders = [.. source.ProtectedFolders],
            ProtectedRegistryKeys = normalizedRegistryKeys,
            AllowListProcesses = [.. source.AllowListProcesses],
            SuspiciousExtensions = [.. source.SuspiciousExtensions],
            BaselineMaxFiles = source.BaselineMaxFiles,
            BaselineMaxFileSizeMb = source.BaselineMaxFileSizeMb,
            FileMonitorBufferKb = source.FileMonitorBufferKb,
            TerminationLookbackMinutes = source.TerminationLookbackMinutes,
            TerminationCandidateProcesses = [.. source.TerminationCandidateProcesses]
        };
    }
}
