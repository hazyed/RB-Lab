namespace RollbackGuard.Service.Engine;

/// <summary>
/// Detects Living Off the Land Binaries (LOLBins) - legitimate Windows tools
/// commonly abused by attackers for download, execution, and evasion.
/// </summary>
public static class LolBinDetector
{
    /// <summary>
    /// LOLBin categories with associated executables and their suspicious command-line patterns.
    /// </summary>
    private static readonly Dictionary<string, LolBinProfile> Profiles = new(StringComparer.OrdinalIgnoreCase)
    {
        // Download / File Transfer LOLBins
        ["certutil.exe"] = new("Download", ["-urlcache", "-split", "-decode", "-encode", "-decodehex", "-verifyctl"]),
        ["bitsadmin.exe"] = new("Download", ["/transfer", "/create", "/addfile", "/resume", "/complete"]),
        ["curl.exe"] = new("Download", ["-o", "--output", "-O"]),

        // Execution LOLBins
        ["mshta.exe"] = new("Execution", ["vbscript", "javascript", "http://", "https://", ".hta"]),
        ["rundll32.exe"] = new("Execution", ["javascript:", "vbscript:", "shell32.dll", "advpack.dll", "ieadvpack.dll", "pcwutl.dll", "setupapi.dll", "shdocvw.dll", "syssetup.dll", "url.dll", "zipfldr.dll"]),
        ["regsvr32.exe"] = new("Execution", ["/s", "/i:", "scrobj.dll", "http://", "https://"]),
        ["msiexec.exe"] = new("Execution", ["/q", "http://", "https://", "/y"]),
        ["wmic.exe"] = new("Execution", ["process", "call", "create", "/node:", "xsl"]),
        ["cmstp.exe"] = new("Execution", ["/s", "/ni", ".inf"]),
        ["installutil.exe"] = new("Execution", ["/logfile=", "/LogToConsole=false"]),
        ["regasm.exe"] = new("Execution", ["/U"]),
        ["regsvcs.exe"] = new("Execution", []),
        ["msconfig.exe"] = new("Execution", ["-5"]),
        ["msbuild.exe"] = new("Execution", [".xml", ".csproj", ".proj"]),

        // Script Hosts
        ["wscript.exe"] = new("ScriptHost", [".vbs", ".js", ".wsf", ".wsh", "//e:", "//b"]),
        ["cscript.exe"] = new("ScriptHost", [".vbs", ".js", ".wsf", ".wsh", "//e:", "//b"]),
        ["powershell.exe"] = new("ScriptHost", ["-enc", "-encodedcommand", "-nop", "-noprofile", "-w hidden", "-windowstyle hidden", "iex", "invoke-expression", "downloadstring", "downloadfile", "invoke-webrequest", "start-bitstransfer", "bypass", "-ep bypass", "frombase64"]),
        ["pwsh.exe"] = new("ScriptHost", ["-enc", "-encodedcommand", "-nop", "-noprofile", "-w hidden", "-windowstyle hidden", "iex", "invoke-expression", "downloadstring", "downloadfile"]),

        // Evasion LOLBins
        ["forfiles.exe"] = new("Evasion", ["/p", "/m", "/c"]),
        ["pcalua.exe"] = new("Evasion", ["-a"]),
        ["explorer.exe"] = new("Evasion", []), // Only suspicious from non-explorer parent + weird args
        ["control.exe"] = new("Evasion", [".cpl"]),
        ["presentationhost.exe"] = new("Evasion", [".xbap"]),
        ["bash.exe"] = new("Evasion", ["-c"]),
        ["wsl.exe"] = new("Evasion", ["-e", "--exec"]),

        // Reconnaissance
        ["nltest.exe"] = new("Recon", ["/dclist", "/domain_trusts", "/parentdomain"]),
        ["dsquery.exe"] = new("Recon", ["computer", "user", "group"]),
        ["net.exe"] = new("Recon", ["user", "group", "localgroup", "share", "use", "view"]),
        ["net1.exe"] = new("Recon", ["user", "group", "localgroup", "share"]),
        ["whoami.exe"] = new("Recon", ["/priv", "/groups", "/all"]),
        ["systeminfo.exe"] = new("Recon", []),
        ["tasklist.exe"] = new("Recon", ["/svc", "/v"]),
        ["ipconfig.exe"] = new("Recon", ["/all"]),
        ["netstat.exe"] = new("Recon", ["-an", "-ano"]),

        // Credential Access
        ["procdump.exe"] = new("CredAccess", ["lsass", "-ma"]),
        ["comsvcs.dll"] = new("CredAccess", ["MiniDump"]), // via rundll32
        ["vaultcmd.exe"] = new("CredAccess", ["/listcreds", "/list"]),
    };

    /// <summary>
    /// Checks if a process is a known LOLBin and returns the classification.
    /// </summary>
    public static LolBinMatch? Evaluate(string? processPath, string? commandLine = null)
    {
        if (string.IsNullOrWhiteSpace(processPath))
            return null;

        var processName = Path.GetFileName(processPath);
        if (string.IsNullOrWhiteSpace(processName))
            return null;

        if (!Profiles.TryGetValue(processName, out var profile))
            return null;

        // Some LOLBins are suspicious just by existing (e.g., mshta, certutil from non-system parent)
        // Others need suspicious command-line arguments
        var hasSuspiciousArgs = false;
        if (!string.IsNullOrWhiteSpace(commandLine) && profile.SuspiciousPatterns.Length > 0)
        {
            hasSuspiciousArgs = profile.SuspiciousPatterns
                .Any(p => commandLine.Contains(p, StringComparison.OrdinalIgnoreCase));
        }

        // Always-suspicious LOLBins (rarely used legitimately by regular applications)
        var alwaysSuspicious = processName.Equals("mshta.exe", StringComparison.OrdinalIgnoreCase) ||
                               processName.Equals("cmstp.exe", StringComparison.OrdinalIgnoreCase) ||
                               processName.Equals("regsvr32.exe", StringComparison.OrdinalIgnoreCase) ||
                               processName.Equals("certutil.exe", StringComparison.OrdinalIgnoreCase);

        return new LolBinMatch(processName, profile.Category, hasSuspiciousArgs || alwaysSuspicious);
    }

    /// <summary>
    /// Evaluates whether a process create event represents suspicious LOLBin usage
    /// based on parent-child relationship.
    /// </summary>
    public static bool IsSuspiciousParentChild(string? parentPath, string? childPath)
    {
        if (string.IsNullOrWhiteSpace(parentPath) || string.IsNullOrWhiteSpace(childPath))
            return false;

        var parentName = Path.GetFileName(parentPath)?.ToLowerInvariant();
        var childName = Path.GetFileName(childPath)?.ToLowerInvariant();

        if (string.IsNullOrWhiteSpace(parentName) || string.IsNullOrWhiteSpace(childName))
            return false;

        // Office -> LOLBin is always suspicious
        if (IsOfficeProcess(parentName) && Profiles.ContainsKey(childName))
            return true;

        // LOLBin -> LOLBin chain
        if (Profiles.ContainsKey(parentName) && Profiles.ContainsKey(childName))
            return true;

        // Services spawning LOLBins with download/execution capabilities
        if (parentName == "svchost.exe" && Profiles.TryGetValue(childName, out var childProfile) &&
            childProfile.Category is "Download" or "Execution")
            return true;

        return false;
    }

    private static bool IsOfficeProcess(string processName) =>
        processName is "winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe" or "msaccess.exe";

    private sealed record LolBinProfile(string Category, string[] SuspiciousPatterns);
}

public sealed record LolBinMatch(string ProcessName, string Category, bool IsSuspicious);
