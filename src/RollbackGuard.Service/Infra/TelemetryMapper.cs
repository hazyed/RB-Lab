using RollbackGuard.Common.Models;
using RollbackGuard.Common.Protocol;
using RollbackGuard.Common.Security;
using RollbackGuard.Service.Engine;

namespace RollbackGuard.Service.Infra;

public static class TelemetryMapper
{
    public static TelemetryEvent Map(
        DriverProtocol.DriverEventRecordRaw raw,
        PolicyConfig policy,
        int burstCount,
        string? processPathOverride = null,
        int? processIdOverride = null)
    {
        var target = Normalize(raw.TargetPath);
        var source = Normalize(raw.SourcePath);
        var processPath = Normalize(
            string.IsNullOrWhiteSpace(processPathOverride)
                ? raw.ProcessPath
                : processPathOverride);
        var isHandleAccessEvent = raw.Kind is DriverProtocol.DriverEventKind.SuspiciousHandleProcess or
            DriverProtocol.DriverEventKind.SuspiciousHandleThread;

        var kind = raw.Kind switch
        {
            DriverProtocol.DriverEventKind.FileWrite => EventKind.FileWrite,
            DriverProtocol.DriverEventKind.FileRename => EventKind.FileRename,
            DriverProtocol.DriverEventKind.FileDelete => EventKind.FileDelete,
            DriverProtocol.DriverEventKind.RegistrySet => EventKind.RegistrySet,
            DriverProtocol.DriverEventKind.RegistryDelete => EventKind.RegistryDelete,
            DriverProtocol.DriverEventKind.ProcessCreate => EventKind.ProcessCreate,
            DriverProtocol.DriverEventKind.ProcessInject => EventKind.ProcessInject,
            DriverProtocol.DriverEventKind.ProcessTerminate => EventKind.ProcessTerminate,
            DriverProtocol.DriverEventKind.ThreadCreateLocal => EventKind.ThreadCreateLocal,
            DriverProtocol.DriverEventKind.ThreadCreateRemote => EventKind.ThreadCreateRemote,
            DriverProtocol.DriverEventKind.ImageLoad => EventKind.ImageLoad,
            DriverProtocol.DriverEventKind.ImageLoadUnsigned => EventKind.ImageLoadUnsigned,
            DriverProtocol.DriverEventKind.ShadowDeleteAttempt => EventKind.ShadowDeleteAttempt,
            DriverProtocol.DriverEventKind.HoneyFileTouched => EventKind.HoneyFileTouched,
            DriverProtocol.DriverEventKind.FileCreate => EventKind.FileCreate,
            DriverProtocol.DriverEventKind.SuspiciousHandleProcess => EventKind.InjectPrelude,
            DriverProtocol.DriverEventKind.SuspiciousHandleThread => EventKind.InjectPrelude,
            _ => EventKind.Unknown
        };

        var timestamp = raw.TimestampUnixMs > 0
            ? DateTimeOffset.FromUnixTimeMilliseconds(raw.TimestampUnixMs)
            : DateTimeOffset.Now;

        var isProtectedTarget = (!isHandleAccessEvent && (raw.Flags & DriverProtocol.DriverEventFlags.ProtectedTarget) != 0) ||
                                IsProtectedTarget(target, policy);
        var isSuspiciousExt = (!isHandleAccessEvent && (raw.Flags & DriverProtocol.DriverEventFlags.SuspiciousExtension) != 0) ||
                              IsSuspiciousExtension(target, policy);
        var hitsPersistenceReg = (!isHandleAccessEvent && (raw.Flags & DriverProtocol.DriverEventFlags.PersistenceRegistry) != 0) ||
                                 HitsPersistenceRegistry(target, policy);
        var trustHint = GetKernelTrustHint(raw.Flags, isHandleAccessEvent);
        var integrityLevel = GetProcessIntegrityHint(raw.Flags, kind, isHandleAccessEvent);
        var isUnsigned = trustHint == KernelTrustHint.Unsigned ||
                         (trustHint == KernelTrustHint.Unknown &&
                          ((!isHandleAccessEvent && (raw.Flags & DriverProtocol.DriverEventFlags.UnsignedProcess) != 0) ||
                           IsUnsignedProcess(processPath)));
        var isPreOperation = !isHandleAccessEvent && (raw.Flags & DriverProtocol.DriverEventFlags.PreOperation) != 0;
        var isSuspendedCreate = !isHandleAccessEvent && (raw.Flags & DriverProtocol.DriverEventFlags.Suspended) != 0;

        // Parse encoded PIDs from SourcePath/TargetPath for specific event types
        var parentProcessId = 0;
        var targetProcessId = 0;

        if (kind == EventKind.ProcessCreate)
        {
            // PPID encoded in SourcePath
            parentProcessId = TryParseInt(source);
        }
        else if (kind is EventKind.ThreadCreateRemote or EventKind.ThreadCreateLocal)
        {
            // Target PID encoded in TargetPath. SourcePath carries driver-side thread start metadata.
            targetProcessId = TryParseInt(target);
            target = string.Empty;
        }
        else if (isHandleAccessEvent)
        {
            // Object callbacks encode the target PID in TargetPath; retain the requested access mask as text.
            targetProcessId = TryParseInt(target);
            target = string.Empty;
            source = raw.Kind == DriverProtocol.DriverEventKind.SuspiciousHandleThread
                ? $"thread-access=0x{(uint)raw.Flags:X8}"
                : $"process-access=0x{(uint)raw.Flags:X8}";
        }

        return new TelemetryEvent(
            timestamp,
            kind,
            processPath,
            processIdOverride ?? (int)raw.ProcessId,
            target,
            source,
            null,
            burstCount,
            isProtectedTarget,
            isSuspiciousExt,
            hitsPersistenceReg,
            isUnsigned,
            isPreOperation,
            raw.VolumeSerialNumber,
            raw.FileId,
            parentProcessId,
            targetProcessId,
            isSuspendedCreate,
            trustHint,
            (uint)raw.Flags,
            integrityLevel);
    }

    private static KernelTrustHint GetKernelTrustHint(DriverProtocol.DriverEventFlags flags, bool isHandleAccessEvent)
    {
        if (isHandleAccessEvent)
            return KernelTrustHint.Unknown;

        var signingStatus = DriverProtocol.ExtractKernelSigningStatus(flags);
        var rawLevel = DriverProtocol.ExtractKernelSigningLevel(flags);

        // Tiered-kernel semantics:
        // - Unchecked (0) means unknown and should not be auto-downgraded to unsigned.
        // - Unsigned status is authoritative high-risk.
        if (signingStatus == DriverProtocol.KernelSigningStatus.Unsigned)
            return KernelTrustHint.Unsigned;

        if (rawLevel > 0)
        {
            var seLevel = (SeSigningLevel)rawLevel;
            if (KernelSigningLevelChecker.IsWindowsCoreLevel(seLevel))
                return KernelTrustHint.WindowsSigned;
            if (KernelSigningLevelChecker.IsMicrosoftLevel(seLevel))
                return KernelTrustHint.MicrosoftSigned;
            if (KernelSigningLevelChecker.IsSignedLevel(seLevel))
                return KernelTrustHint.Signed;
            if (seLevel == SeSigningLevel.Unsigned)
                return KernelTrustHint.Unsigned;
        }

        // Verified with unknown level is still not unsigned.
        if (signingStatus == DriverProtocol.KernelSigningStatus.Verified)
            return KernelTrustHint.Signed;

        // Fallback for legacy drivers without tier metadata.
        if ((flags & DriverProtocol.DriverEventFlags.MicrosoftSignedHint) != 0)
            return KernelTrustHint.MicrosoftSigned;

        if ((flags & DriverProtocol.DriverEventFlags.SignedHint) != 0)
            return KernelTrustHint.Signed;

        if ((flags & DriverProtocol.DriverEventFlags.UnsignedProcess) != 0)
            return KernelTrustHint.Unsigned;

        return KernelTrustHint.Unknown;
    }

    private static int TryParseInt(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return 0;
        }

        return int.TryParse(value.Trim().TrimEnd('\0'), out var result) ? result : 0;
    }

    private static ProcessIntegrityLevel GetProcessIntegrityHint(
        DriverProtocol.DriverEventFlags flags,
        EventKind kind,
        bool isHandleAccessEvent)
    {
        if (isHandleAccessEvent || kind != EventKind.ProcessCreate)
        {
            return ProcessIntegrityLevel.Unknown;
        }

        return DriverProtocol.ExtractProcessIntegrityHint(flags) switch
        {
            DriverProtocol.ProcessIntegrityHint.Low => ProcessIntegrityLevel.Low,
            DriverProtocol.ProcessIntegrityHint.Medium => ProcessIntegrityLevel.Medium,
            DriverProtocol.ProcessIntegrityHint.High => ProcessIntegrityLevel.High,
            _ => ProcessIntegrityLevel.Unknown
        };
    }

    private static string Normalize(string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.TrimEnd('\0').Trim();
    }

    private static bool IsProtectedTarget(string target, PolicyConfig policy)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            return false;
        }

        return policy.ProtectedFolders.Any(prefix => target.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

    private static bool HitsPersistenceRegistry(string target, PolicyConfig policy)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            return false;
        }

        var normalizedTarget = NormalizeRegistryPath(target);
        foreach (var prefix in policy.ProtectedRegistryKeys)
        {
            var normalizedPrefix = NormalizeRegistryPath(prefix);
            if (string.IsNullOrWhiteSpace(normalizedPrefix))
            {
                continue;
            }

            if (normalizedTarget.StartsWith(normalizedPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (normalizedPrefix.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase) &&
                normalizedTarget.StartsWith("HKU\\", StringComparison.OrdinalIgnoreCase))
            {
                var hkcuSuffix = normalizedPrefix[4..];
                if (normalizedTarget.Contains(hkcuSuffix, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool IsSuspiciousExtension(string target, PolicyConfig policy)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            return false;
        }

        var ext = Path.GetExtension(target);
        if (string.IsNullOrWhiteSpace(ext))
        {
            return false;
        }

        return policy.SuspiciousExtensions.Any(item => ext.Equals(item, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsUnsignedProcess(string processPath)
    {
        if (IsLikelyWindowsSystemBinary(processPath))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(processPath) || !File.Exists(processPath))
        {
            return false;
        }

        return SignatureTrustEvaluator.TryGetTrust(processPath, out var trust) && !trust.IsSigned;
    }

    private static string NormalizeRegistryPath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim();
        while (normalized.Contains(@"\\", StringComparison.Ordinal))
        {
            normalized = normalized.Replace(@"\\", @"\", StringComparison.Ordinal);
        }

        if (normalized.StartsWith(@"\REGISTRY\MACHINE\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = "HKLM\\" + normalized[@"\REGISTRY\MACHINE\".Length..];
        }
        else if (normalized.StartsWith(@"\REGISTRY\USER\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = "HKU\\" + normalized[@"\REGISTRY\USER\".Length..];
        }
        else if (normalized.StartsWith(@"HKEY_LOCAL_MACHINE\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = "HKLM\\" + normalized[@"HKEY_LOCAL_MACHINE\".Length..];
        }
        else if (normalized.StartsWith(@"HKEY_CURRENT_USER\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = "HKCU\\" + normalized[@"HKEY_CURRENT_USER\".Length..];
        }
        else if (normalized.StartsWith(@"HKEY_USERS\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = "HKU\\" + normalized[@"HKEY_USERS\".Length..];
        }

        return normalized;
    }

    private static bool IsLikelyWindowsSystemBinary(string processPath)
    {
        if (string.IsNullOrWhiteSpace(processPath))
        {
            return false;
        }

        var normalized = processPath.Trim().Replace('/', '\\');

        if (normalized.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"\Windows\", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return normalized.StartsWith(@"\Device\HarddiskVolume", StringComparison.OrdinalIgnoreCase) &&
               normalized.IndexOf(@"\Windows\", StringComparison.OrdinalIgnoreCase) >= 0;
    }
}
