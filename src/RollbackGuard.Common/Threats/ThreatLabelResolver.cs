using RollbackGuard.Common.Models;

namespace RollbackGuard.Common.Threats;

public static class ThreatLabelResolver
{
    private static readonly HashSet<string> IgnoredSystemDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "ntdll.dll",
        "wow64.dll",
        "wow64win.dll",
        "wow64cpu.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "user32.dll",
        "gdi32.dll",
        "gdi32full.dll",
        "advapi32.dll",
        "sechost.dll",
        "ole32.dll",
        "oleaut32.dll",
        "rpcrt4.dll",
        "shell32.dll",
        "shlwapi.dll",
        "combase.dll",
        "ucrtbase.dll",
        "msvcrt.dll",
        "bcrypt.dll",
        "imm32.dll"
    };

    public static string ResolveLabel(EventKind eventKind, string? reason, string? targetPath)
    {
        var normalizedReason = (reason ?? string.Empty).ToLowerInvariant();
        var isFileCentricEvent = eventKind is EventKind.FileWrite or EventKind.FileRename or
            EventKind.FileDelete or EventKind.FileCreate or EventKind.HoneyFileTouched;
        var hasHighConfidenceMemoryExecutionEvidence =
            eventKind is EventKind.MemoryScanShellcode or EventKind.MemoryScanWxTransition
                or EventKind.MemoryScanReflectiveDll or EventKind.MemoryScanUnbackedExec ||
            ContainsAny(normalizedReason,
                "memory-shellcode(",
                "memory-amsi(",
                "unbacked-exec(",
                "wx-transition(",
                "reflective-dll(",
                "rule-012",
                "rule-013",
                "rule-016",
                "driver-thread-start-exec");
        var hasRansomEvidence = eventKind == EventKind.HoneyFileTouched ||
            ContainsAny(normalizedReason,
                "rule-005",
                "ransom",
                "entropy-ransom",
                "entropy-spike",
                "ext-change",
                "suspicious-ext",
                "overwrite-pattern",
                "write-rate",
                "high-freq-write",
                "unique-ratio",
                "dir-growth",
                "protected(",
                "lifetime-files");

        var hasShellcodeEvidence = eventKind == EventKind.ProcessInject ||
            hasHighConfidenceMemoryExecutionEvidence ||
            ContainsAny(normalizedReason, "rule-003", "confirmed-inject");

        var hasInjectPreludeEvidence = eventKind is EventKind.InjectPrelude or EventKind.ThreadCreateRemote ||
            ContainsAny(normalizedReason,
                "rule-002",
                "rule-004",
                "inject-prelude",
                "inject-handle",
                "remote-thread-observed",
                "remote-thread-chain",
                "handle-injection-burst");

        var hasDllEvidence = ((eventKind is EventKind.ImageLoadUnsigned or EventKind.ImageLoad) &&
                              IsInterestingDllEvidencePath(targetPath)) ||
            ContainsAny(normalizedReason, "rule-008", "suspicious-dll", "unsigned-dll");

        var hasMacroEvidence = ContainsAny(normalizedReason, "rule-001", "office-macro");
        var hasDestructiveEvidence = eventKind == EventKind.ShadowDeleteAttempt ||
            ContainsAny(normalizedReason, "rule-006", "shadow-delete");

        if (hasRansomEvidence && isFileCentricEvent)
        {
            return "ransomware";
        }

        if (eventKind == EventKind.RemediationMemoryZeroed)
        {
            return "remediation";
        }

        if (hasShellcodeEvidence)
        {
            return "shellcode";
        }

        if (hasInjectPreludeEvidence)
        {
            return "inject-prelude";
        }

        if (hasMacroEvidence)
        {
            return "macro-dropper";
        }

        if (hasDestructiveEvidence)
        {
            return "destructive";
        }

        if (hasDllEvidence)
        {
            return "dll-sideload";
        }

        if (hasRansomEvidence)
        {
            return "ransomware";
        }

        return "suspicious-behavior";
    }

    public static bool IsInterestingDllEvidencePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var value = path.Trim().TrimEnd('\0');
        if (!value.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) &&
            !value.EndsWith(".ocx", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var normalized = value.Replace('/', '\\');
        if (normalized.Contains("\\Windows\\System32\\", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("\\Windows\\SysWOW64\\", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("\\Windows\\WinSxS\\", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var fileName = Path.GetFileName(normalized);
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return false;
        }

        return !IgnoredSystemDllNames.Contains(fileName);
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
}
