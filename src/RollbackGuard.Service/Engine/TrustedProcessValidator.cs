using RollbackGuard.Common.Security;

namespace RollbackGuard.Service.Engine;

/// <summary>
/// Validates trusted/allow-listed processes using full path + signature verification
/// instead of process name alone (which can be spoofed).
/// </summary>
public static class TrustedProcessValidator
{
    private static readonly HashSet<string> RollbackGuardBinaryNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "RollbackGuard.Service.exe",
        "RollbackGuard.UI.exe",
        "RollbackGuard.Cli.exe"
    };

    // Stability-critical protection is a safety rail for remediation decisions,
    // not a trust source. Trust must come from signature evaluation instead.
    private static readonly HashSet<string> StabilityCriticalProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "lsass.exe",
        "services.exe",
        "svchost.exe",
        "dwm.exe",
        "taskhostw.exe",
        "sihost.exe",
        "startmenuexperiencehost.exe",
        "shellexperiencehost.exe",
        "searchhost.exe",
        "searchindexer.exe",
        "runtimebroker.exe",
        "ctfmon.exe",
        "explorer.exe"
    };

    public static bool IsTrustedMicrosoftProcess(ProcessContext context)
    {
        if (!context.SignatureEvaluated ||
            !context.IsMicrosoftSignedProcess ||
            context.BaseTrustTier != ExecutionTrustTier.MicrosoftSigned)
        {
            return false;
        }

        return context.IsMicrosoftCleanChain;
    }

    public static bool IsTrustedMicrosoftProcessClean(ProcessContext context)
    {
        return IsTrustedMicrosoftProcess(context);
    }

    public static bool IsTrustedSystemProcess(ProcessContext context)
    {
        return IsTrustedMicrosoftProcess(context);
    }

    public static bool IsAllowListed(string? processPath, IReadOnlyList<string> allowList)
    {
        if (string.IsNullOrWhiteSpace(processPath) || allowList.Count == 0)
            return false;

        var normalizedProcessPath = NormalizePath(processPath);
        if (string.IsNullOrWhiteSpace(normalizedProcessPath))
        {
            return false;
        }

        var processName = Path.GetFileName(normalizedProcessPath);
        foreach (var entry in allowList)
        {
            if (string.IsNullOrWhiteSpace(entry))
            {
                continue;
            }

            if (LooksLikePathEntry(entry))
            {
                var normalizedEntry = NormalizePath(entry);
                if (!string.IsNullOrWhiteSpace(normalizedEntry) &&
                    normalizedEntry.Equals(normalizedProcessPath, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                continue;
            }

            if (!string.IsNullOrWhiteSpace(processName) &&
                processName.Equals(entry.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    public static bool IsStabilityCritical(string? processPath)
    {
        return IsStabilityCritical(processPath, isMicrosoftSigned: false);
    }

    public static bool IsStabilityCritical(ProcessContext context)
    {
        if (!IsTrustedMicrosoftProcess(context))
        {
            return false;
        }

        return IsStabilityCritical(context.ImageName, isMicrosoftSigned: true);
    }

    public static bool IsStabilityCritical(string? processPath, bool isMicrosoftSigned)
    {
        if (!isMicrosoftSigned || string.IsNullOrWhiteSpace(processPath))
            return false;

        var normalized = NormalizePath(processPath);
        var processName = Path.GetFileName(normalized);
        if (string.IsNullOrWhiteSpace(processName))
            return false;

        if (!StabilityCriticalProcessNames.Contains(processName))
            return false;

        return normalized.Contains("\\Windows\\", StringComparison.OrdinalIgnoreCase);
    }

    public static bool LooksLikeWindowsRuntimeProcess(string? processPath)
    {
        if (string.IsNullOrWhiteSpace(processPath))
            return false;

        var normalized = NormalizePath(processPath);
        return normalized.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith(@"\Windows\", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsLikelyTrustedWindowsProcessPendingTrust(ProcessContext context)
    {
        if (context.SignatureEvaluated)
            return false;

        if (!LooksLikeWindowsRuntimeProcess(context.ImageName))
            return false;

        if (context.BaseTrustTier == ExecutionTrustTier.Unsigned ||
            context.CurrentTrustTier == ExecutionTrustTier.Unsigned ||
            context.IsRestrictedProcess)
        {
            return false;
        }

        if (context.LoadedUnsignedDll || context.LoadedSuspiciousDll || context.LoadedNonMicrosoftDll)
        {
            return false;
        }

        if (context.WasTargetedBySuspiciousHandle || context.WasRemotelyCreated)
        {
            return false;
        }

        if (context.SuspiciousHandleOpenCount > 0 || context.SuspiciousThreadHijackCount > 0)
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Returns true when every process in the ancestor chain — from
    /// <paramref name="context"/> up to the System process (PID ≤ 4) — is
    /// MicrosoftSigned.  A single unsigned or unknown node taints the whole chain.
    ///
    /// An all-Microsoft chain can skip file-system backup and full detection:
    /// those processes cannot be ransomware carriers and the OS would be
    /// inoperable if they were blocked.
    /// </summary>
    public static bool IsFullyTrustedChain(
        ProcessContext context,
        Func<int, ProcessContext?> getParent,
        int maxDepth = 10)
    {
        var current = context;
        for (var depth = 0; depth < maxDepth; depth++)
        {
            // Reached the System/Idle pseudo-process — the chain is clean.
            if (current.PID <= 4)
            {
                return true;
            }

            if (!current.IsMicrosoftSignedProcess ||
                current.BaseTrustTier != ExecutionTrustTier.MicrosoftSigned)
            {
                return false;
            }

            if (current.PPID <= 4)
            {
                // Parent is System — chain is clean.
                return true;
            }

            var parent = getParent(current.PPID);
            if (parent is null)
            {
                // Parent context is gone (process exited before we saw it).
                // Fail open: don't penalise processes whose parent already exited,
                // but don't grant full trust either — return false conservatively.
                return false;
            }

            current = parent;
        }

        // Exceeded depth limit — treat as untrusted to avoid infinite walks.
        return false;
    }

    public static bool IsRollbackGuardBinary(string? processPath)
    {
        if (string.IsNullOrWhiteSpace(processPath))
            return false;

        var fileName = Path.GetFileName(processPath.Trim().TrimEnd('\0'));
        return !string.IsNullOrWhiteSpace(fileName) && RollbackGuardBinaryNames.Contains(fileName);
    }

    private static bool LooksLikePathEntry(string value)
    {
        return value.Contains('\\', StringComparison.Ordinal) ||
               value.Contains('/', StringComparison.Ordinal) ||
               value.Contains(':', StringComparison.Ordinal) ||
               value.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePath(string path)
    {
        if (AuthenticodeTrustVerifier.TryNormalizeDisplayPath(path, out var normalized))
        {
            return normalized;
        }

        return path.Trim().TrimEnd('\0').Replace('/', '\\');
    }
}
