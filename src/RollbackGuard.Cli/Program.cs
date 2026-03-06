using RollbackGuard.Common.Models;
using RollbackGuard.Common.Runtime;
using RollbackGuard.Common.Storage;

RuntimePaths.EnsureAll();

if (args.Length == 0)
{
    PrintUsage();
    return;
}

switch (args[0].ToLowerInvariant())
{
    case "policy":
        HandlePolicy(args.Skip(1).ToArray());
        break;
    case "status":
        HandleStatus(args.Skip(1).ToArray());
        break;
    case "incidents":
        HandleIncidents(args.Skip(1).ToArray());
        break;
    default:
        PrintUsage();
        break;
}

void HandlePolicy(string[] sub)
{
    if (sub.Length == 0)
    {
        PrintUsage();
        return;
    }

    var policy = PolicyConfigStore.LoadOrCreate(RuntimePaths.PolicyPath);
    var cmd = sub[0].ToLowerInvariant();

    if (cmd == "init")
    {
        PolicyConfigStore.Save(RuntimePaths.PolicyPath, PolicyConfig.CreateDefault());
        Console.WriteLine($"policy initialized: {RuntimePaths.PolicyPath}");
        return;
    }

    if (cmd == "show")
    {
        Console.WriteLine($"version={policy.PolicyVersion}");
        Console.WriteLine($"device={policy.DriverDevicePath}");
        Console.WriteLine($"thresholds={policy.AskThresholdLow}/{policy.AskThresholdMid}/{policy.AskThresholdHigh}/{policy.AskThresholdCritical}");
        Console.WriteLine($"actions={policy.ActionLow}/{policy.ActionMid}/{policy.ActionHigh}/{policy.ActionCritical}");
        Console.WriteLine($"protectedFolders={policy.ProtectedFolders.Count}");
        Console.WriteLine($"protectedRegistry={policy.ProtectedRegistryKeys.Count}");
        return;
    }

    if (cmd == "set-threshold" && sub.Length == 5)
    {
        var next = new PolicyConfig
        {
            PolicyVersion = $"{policy.PolicyVersion}-edited",
            DriverDevicePath = policy.DriverDevicePath,
            AskThresholdLow = double.Parse(sub[1]),
            AskThresholdMid = double.Parse(sub[2]),
            AskThresholdHigh = double.Parse(sub[3]),
            AskThresholdCritical = double.Parse(sub[4]),
            ActionLow = policy.ActionLow,
            ActionMid = policy.ActionMid,
            ActionHigh = policy.ActionHigh,
            ActionCritical = policy.ActionCritical,
            BurstTrigger = policy.BurstTrigger,
            TimeWindowSeconds = policy.TimeWindowSeconds,
            ProtectedFolders = policy.ProtectedFolders,
            ProtectedRegistryKeys = policy.ProtectedRegistryKeys,
            AllowListProcesses = policy.AllowListProcesses,
            SuspiciousExtensions = policy.SuspiciousExtensions
        };

        PolicyConfigStore.Save(RuntimePaths.PolicyPath, next);
        Console.WriteLine("policy thresholds updated");
        return;
    }

    PrintUsage();
}

void HandleStatus(string[] sub)
{
    if (sub.Length == 0 || sub[0].Equals("show", StringComparison.OrdinalIgnoreCase))
    {
        var status = StatusStore.TryLoad(RuntimePaths.StatusPath);
        if (status is null)
        {
            Console.WriteLine("status: none");
            return;
        }

        Console.WriteLine($"time={status.Timestamp:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine($"driverConnected={status.DriverConnected}");
        Console.WriteLine($"driverState={status.DriverState}");
        Console.WriteLine($"policy={status.PolicyVersion}");
        Console.WriteLine($"pendingRollback={status.PendingRollbackEntries}");
        Console.WriteLine($"lastError={status.LastError}");
        return;
    }

    PrintUsage();
}

void HandleIncidents(string[] sub)
{
    if (sub.Length == 0)
    {
        PrintUsage();
        return;
    }

    if (sub[0].Equals("tail", StringComparison.OrdinalIgnoreCase))
    {
        var count = 20;
        if (sub.Length > 1)
        {
            _ = int.TryParse(sub[1], out count);
            if (count <= 0)
            {
                count = 20;
            }
        }

        var items = IncidentStore.ReadLatest(RuntimePaths.IncidentLogPath, count);
        if (items.Count == 0)
        {
            Console.WriteLine("incidents: none");
            return;
        }

        foreach (var item in items)
        {
            Console.WriteLine($"{item.Timestamp:yyyy-MM-dd HH:mm:ss} pid={item.ProcessId} action={item.Action} score={item.Score:F3} target={item.TargetPath} msg={item.DriverMessage}");
        }

        return;
    }

    PrintUsage();
}

void PrintUsage()
{
    Console.WriteLine("RollbackGuard.Cli usage:");
    Console.WriteLine("  policy init");
    Console.WriteLine("  policy show");
    Console.WriteLine("  policy set-threshold <low> <mid> <high> <critical>");
    Console.WriteLine("  status show");
    Console.WriteLine("  incidents tail [count]");
}
