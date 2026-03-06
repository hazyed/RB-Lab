using RollbackGuard.Common.Models;

namespace RollbackGuard.Service.Engine;

/// <summary>
/// Detects comprehensive persistence mechanisms beyond basic registry Run keys.
/// Covers: WMI subscriptions, scheduled tasks, services, startup folder,
/// COM hijacking, AppInit_DLLs, IFEO, Winlogon, Shell extensions, etc.
/// </summary>
public static class PersistenceDetector
{
    /// <summary>
    /// All monitored persistence registry paths.
    /// </summary>
    private static readonly PersistenceRule[] RegistryRules =
    [
        // Standard Run keys (already partially covered)
        new(@"Software\Microsoft\Windows\CurrentVersion\Run", "RunKey", 20),
        new(@"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnceKey", 25),
        new(@"Software\Microsoft\Windows\CurrentVersion\RunServices", "RunServicesKey", 25),
        new(@"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", "RunServicesOnceKey", 25),

        // Explorer autostart
        new(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "ExplorerPolicyRun", 25),
        new(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "ShellFolders", 15),
        new(@"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", "UserShellFolders", 15),

        // Service creation
        new(@"System\CurrentControlSet\Services", "ServiceCreation", 30),

        // Image File Execution Options (IFEO) - debugger hijacking
        new(@"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "IFEO", 40),

        // AppInit_DLLs - loaded into every process
        new(@"Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs", "AppInitDlls", 50),
        new(@"Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs", "AppInitDlls32", 50),

        // Winlogon hooks
        new(@"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", "WinlogonShell", 45),
        new(@"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit", "WinlogonUserinit", 45),
        new(@"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify", "WinlogonNotify", 45),

        // Security providers
        new(@"System\CurrentControlSet\Control\SecurityProviders\SecurityProviders", "SecurityProviders", 40),
        new(@"System\CurrentControlSet\Control\Lsa\Authentication Packages", "LsaAuthPackages", 45),
        new(@"System\CurrentControlSet\Control\Lsa\Notification Packages", "LsaNotifyPackages", 45),
        new(@"System\CurrentControlSet\Control\Lsa\Security Packages", "LsaSecurityPackages", 45),

        // Print monitor (DLL injection)
        new(@"System\CurrentControlSet\Control\Print\Monitors", "PrintMonitor", 35),

        // COM hijacking
        new(@"Software\Classes\CLSID", "ComHijack", 20),
        new(@"Software\Classes\Wow6432Node\CLSID", "ComHijack32", 20),

        // Shell extensions
        new(@"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved", "ShellExtension", 15),
        new(@"Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad", "ShellServiceObject", 30),

        // Boot execute
        new(@"System\CurrentControlSet\Control\Session Manager\BootExecute", "BootExecute", 50),

        // Known DLLs modification
        new(@"System\CurrentControlSet\Control\Session Manager\KnownDLLs", "KnownDlls", 50),

        // BCD / Recovery
        new(@"BCD00000000", "BootConfig", 40),

        // WMI filter/consumer bindings (registry-based detection)
        new(@"Software\Microsoft\WBEM", "WmiPersistence", 35),

        // Scheduled Tasks (registry path)
        new(@"Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks", "ScheduledTask", 25),
        new(@"Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree", "ScheduledTaskTree", 25),

        // Terminal Server (RDP) autorun
        new(@"Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run", "TerminalServerRun", 25),
    ];

    /// <summary>
    /// Startup folder paths to monitor.
    /// </summary>
    private static readonly Lazy<string[]> StartupFolders = new(() =>
    {
        var paths = new List<string>();

        try
        {
            var userStartup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (!string.IsNullOrWhiteSpace(userStartup)) paths.Add(userStartup);
        }
        catch { }

        try
        {
            var commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
            if (!string.IsNullOrWhiteSpace(commonStartup)) paths.Add(commonStartup);
        }
        catch { }

        return paths.ToArray();
    });

    /// <summary>
    /// Evaluates a registry event to determine if it's a persistence attempt.
    /// </summary>
    public static PersistenceMatch? EvaluateRegistryEvent(string? registryPath)
    {
        if (string.IsNullOrWhiteSpace(registryPath))
            return null;

        var normalizedPath = NormalizeRegistryPath(registryPath);

        foreach (var rule in RegistryRules)
        {
            if (normalizedPath.Contains(rule.PathFragment, StringComparison.OrdinalIgnoreCase))
            {
                var eventKind = rule.Type switch
                {
                    "ServiceCreation" => EventKind.PersistenceService,
                    "ComHijack" or "ComHijack32" => EventKind.PersistenceComHijack,
                    "ScheduledTask" or "ScheduledTaskTree" => EventKind.PersistenceScheduledTask,
                    "WmiPersistence" => EventKind.PersistenceWmi,
                    _ => EventKind.RegistrySet // Use existing for standard registry persistence
                };

                return new PersistenceMatch(rule.Type, rule.Score, eventKind, rule.PathFragment);
            }
        }

        return null;
    }

    /// <summary>
    /// Evaluates a file event to detect startup folder persistence.
    /// </summary>
    public static PersistenceMatch? EvaluateFileEvent(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return null;

        var normalized = filePath.Replace('/', '\\');

        // Check startup folder writes
        foreach (var startupFolder in StartupFolders.Value)
        {
            if (normalized.StartsWith(startupFolder, StringComparison.OrdinalIgnoreCase))
            {
                // Executable files in startup are more suspicious
                var ext = Path.GetExtension(normalized)?.ToLowerInvariant();
                var score = ext is ".exe" or ".bat" or ".cmd" or ".vbs" or ".js" or ".wsf" or ".ps1" or ".lnk" ? 35 : 15;

                return new PersistenceMatch("StartupFolder", score, EventKind.PersistenceStartupFolder, startupFolder);
            }
        }

        // Check for WMI MOF file compilation
        if (normalized.Contains(@"\System32\wbem\", StringComparison.OrdinalIgnoreCase) &&
            normalized.EndsWith(".mof", StringComparison.OrdinalIgnoreCase))
        {
            return new PersistenceMatch("WmiMofCompile", 40, EventKind.PersistenceWmi, "wbem-mof");
        }

        // Check for scheduled task XML creation
        if (normalized.Contains(@"\Windows\System32\Tasks\", StringComparison.OrdinalIgnoreCase))
        {
            return new PersistenceMatch("ScheduledTaskFile", 30, EventKind.PersistenceScheduledTask, "task-xml");
        }

        return null;
    }

    /// <summary>
    /// Evaluates a process create event for persistence-related tool execution.
    /// </summary>
    public static PersistenceMatch? EvaluateProcessCreate(string? processPath, string? commandLine = null)
    {
        if (string.IsNullOrWhiteSpace(processPath))
            return null;

        var processName = Path.GetFileName(processPath)?.ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(processName))
            return null;

        // schtasks.exe - creating scheduled tasks
        if (processName == "schtasks.exe" && !string.IsNullOrWhiteSpace(commandLine) &&
            commandLine.Contains("/create", StringComparison.OrdinalIgnoreCase))
        {
            return new PersistenceMatch("SchtasksCreate", 30, EventKind.PersistenceScheduledTask, "schtasks-create");
        }

        // sc.exe - creating services
        if (processName == "sc.exe" && !string.IsNullOrWhiteSpace(commandLine) &&
            commandLine.Contains("create", StringComparison.OrdinalIgnoreCase))
        {
            return new PersistenceMatch("ScServiceCreate", 35, EventKind.PersistenceService, "sc-create");
        }

        // reg.exe - adding registry persistence
        if (processName == "reg.exe" && !string.IsNullOrWhiteSpace(commandLine) &&
            commandLine.Contains("add", StringComparison.OrdinalIgnoreCase) &&
            (commandLine.Contains("CurrentVersion\\Run", StringComparison.OrdinalIgnoreCase) ||
             commandLine.Contains("Image File Execution", StringComparison.OrdinalIgnoreCase)))
        {
            return new PersistenceMatch("RegAddPersistence", 30, EventKind.RegistrySet, "reg-add-persist");
        }

        // wmic.exe - WMI subscription persistence
        if (processName is "wmic.exe" or "powershell.exe" or "pwsh.exe" && !string.IsNullOrWhiteSpace(commandLine) &&
            (commandLine.Contains("__EventFilter", StringComparison.OrdinalIgnoreCase) ||
             commandLine.Contains("CommandLineEventConsumer", StringComparison.OrdinalIgnoreCase) ||
             commandLine.Contains("ActiveScriptEventConsumer", StringComparison.OrdinalIgnoreCase) ||
             commandLine.Contains("FilterToConsumerBinding", StringComparison.OrdinalIgnoreCase)))
        {
            return new PersistenceMatch("WmiSubscription", 45, EventKind.PersistenceWmi, "wmi-subscription");
        }

        return null;
    }

    private static string NormalizeRegistryPath(string path)
    {
        var normalized = path.Trim();
        while (normalized.Contains(@"\\", StringComparison.Ordinal))
            normalized = normalized.Replace(@"\\", @"\", StringComparison.Ordinal);

        if (normalized.StartsWith(@"\REGISTRY\MACHINE\", StringComparison.OrdinalIgnoreCase))
            normalized = normalized[@"\REGISTRY\MACHINE\".Length..];
        else if (normalized.StartsWith(@"\REGISTRY\USER\", StringComparison.OrdinalIgnoreCase))
            normalized = normalized[@"\REGISTRY\USER\".Length..];
        else if (normalized.StartsWith(@"HKEY_LOCAL_MACHINE\", StringComparison.OrdinalIgnoreCase))
            normalized = normalized[@"HKEY_LOCAL_MACHINE\".Length..];
        else if (normalized.StartsWith(@"HKEY_CURRENT_USER\", StringComparison.OrdinalIgnoreCase))
            normalized = normalized[@"HKEY_CURRENT_USER\".Length..];
        else if (normalized.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase))
            normalized = normalized[@"HKLM\".Length..];
        else if (normalized.StartsWith(@"HKCU\", StringComparison.OrdinalIgnoreCase))
            normalized = normalized[@"HKCU\".Length..];
        else if (normalized.StartsWith(@"HKU\", StringComparison.OrdinalIgnoreCase))
        {
            // Strip SID prefix: HKU\S-1-5-...\Software -> Software
            var firstBackslash = normalized.IndexOf('\\');
            if (firstBackslash > 0)
            {
                var afterSid = normalized[(firstBackslash + 1)..];
                var secondBackslash = afterSid.IndexOf('\\');
                if (secondBackslash > 0 && afterSid.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
                    normalized = afterSid[(secondBackslash + 1)..];
                else
                    normalized = afterSid;
            }
        }

        return normalized;
    }

    private sealed record PersistenceRule(string PathFragment, string Type, int Score);
}

public sealed record PersistenceMatch(
    string Type,
    int Score,
    EventKind EventKind,
    string Detail);
