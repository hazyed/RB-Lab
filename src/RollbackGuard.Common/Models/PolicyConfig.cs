namespace RollbackGuard.Common.Models;

public sealed class PolicyConfig
{
    public required string PolicyVersion { get; init; }
    public required string DriverDevicePath { get; init; }
    public string MiniFilterDevicePath { get; init; } = "\\\\.\\RollbackGuardMiniFilter";

    public required double AskThresholdLow { get; init; }
    public required double AskThresholdMid { get; init; }
    public required double AskThresholdHigh { get; init; }
    public required double AskThresholdCritical { get; init; }

    public required int ActionLow { get; init; }
    public required int ActionMid { get; init; }
    public required int ActionHigh { get; init; }
    public required int ActionCritical { get; init; }

    public required int BurstTrigger { get; init; }
    public required int TimeWindowSeconds { get; init; }

    public required List<string> ProtectedFolders { get; init; }
    public required List<string> ProtectedRegistryKeys { get; init; }
    public required List<string> AllowListProcesses { get; init; }
    public required List<string> SuspiciousExtensions { get; init; }

    // Integer scoring thresholds (hips.md)
    public int ScoreAlert { get; init; } = 59;
    public int ScoreSuspicious { get; init; } = 84;
    public int ScoreMalicious { get; init; } = 85;

    public int BaselineMaxFiles { get; init; } = 15000;
    public int BaselineMaxFileSizeMb { get; init; } = 16;
    public int FileMonitorBufferKb { get; init; } = 64;
    public int TerminationLookbackMinutes { get; init; } = 15;
    public List<string> TerminationCandidateProcesses { get; init; } = [];

    public static PolicyConfig CreateDefault()
    {
        var protectedFolders = BuildDefaultProtectedFolders();

        return new PolicyConfig
        {
            PolicyVersion = "v0.4-default",
            DriverDevicePath = "\\\\.\\RollbackGuard",
            MiniFilterDevicePath = "\\\\.\\RollbackGuardMiniFilter",
            AskThresholdLow = 0.05,
            AskThresholdMid = 0.20,
            AskThresholdHigh = 0.55,
            AskThresholdCritical = 0.72,
            ActionLow = (int)SecurityAction.Allow,
            ActionMid = (int)SecurityAction.Allow,
            ActionHigh = (int)SecurityAction.Block,
            ActionCritical = (int)SecurityAction.Terminate,
            BurstTrigger = 12,
            TimeWindowSeconds = 15,
            ProtectedFolders = protectedFolders,
            ProtectedRegistryKeys =
            [
                @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                @"HKLM\System\CurrentControlSet\Services",
                @"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
            ],
            AllowListProcesses = [],
            SuspiciousExtensions =
            [
                ".locked",
                ".encrypt",
                ".encrypted",
                ".wncry",
                ".ryk"
            ],
            TerminationCandidateProcesses =
            [
                "cmd.exe",
                "powershell.exe",
                "pwsh.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
                "python.exe",
                "node.exe",
                "rundll32.exe",
                "regsvr32.exe"
            ]
        };
    }

    public SecurityAction ResolveAction(double score)
    {
        int code;
        if (score < AskThresholdLow)
        {
            code = ActionLow;
        }
        else if (score < AskThresholdMid)
        {
            code = ActionMid;
        }
        else if (score < AskThresholdHigh)
        {
            code = ActionHigh;
        }
        else
        {
            code = ActionCritical;
        }

        return Enum.IsDefined(typeof(SecurityAction), code)
            ? (SecurityAction)code
            : SecurityAction.Block;
    }

    private static List<string> BuildDefaultProtectedFolders()
    {
        var roots = new List<string>();

        AddIfValid(roots, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
        AddIfValid(roots, Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        AddIfValid(roots, Path.Combine(userProfile, "Downloads"));

        if (roots.Count == 0)
        {
            AddIfValid(roots, userProfile);
        }

        return roots;
    }

    private static void AddIfValid(List<string> roots, string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        var full = Path.GetFullPath(path);
        if (!Directory.Exists(full))
        {
            return;
        }

        if (roots.Any(existing => existing.Equals(full, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        roots.Add(full);
    }
}
