namespace RollbackGuard.Common.Models;

public enum EventKind
{
    Unknown = 0,
    FileWrite = 1,
    FileRename = 2,
    FileDelete = 3,
    RegistrySet = 4,
    RegistryDelete = 5,
    ProcessCreate = 6,
    ProcessInject = 7,
    ProcessTerminate = 8,
    ThreadCreateLocal = 9,
    ThreadCreateRemote = 10,
    ImageLoad = 11,
    ImageLoadUnsigned = 12,
    ShadowDeleteAttempt = 13,
    HoneyFileTouched = 14,
    FileCreate = 15,
    InjectPrelude = 16,

    // LOLBin events
    LolBinExecution = 40,

    // Persistence events
    PersistenceWmi = 50,
    PersistenceScheduledTask = 51,
    PersistenceService = 52,
    PersistenceStartupFolder = 53,
    PersistenceComHijack = 54,

    // Memory scan events (service-generated)
    MemoryScanShellcode = 60,
    MemoryScanRwx = 61,
    MemoryScanUnbackedExec = 62,
    MemoryScanWxTransition = 63,
    MemoryScanReflectiveDll = 64,

    // Remediation events
    RemediationMemoryZeroed = 70
}

public enum RollbackEntryType
{
    File = 1,
    Registry = 2
}

public enum ProcessState
{
    Monitoring = 0,
    Alert = 1,
    Suspicious = 2,
    Malicious = 3
}

public enum KernelTrustHint
{
    Unknown = 0,
    Unsigned = 1,
    Signed = 2,
    MicrosoftSigned = 3,
    WindowsSigned = 4   // SE_SIGNING_LEVEL_WINDOWS (12) or SE_SIGNING_LEVEL_WINDOWS_TCB (14)
}

public enum ProcessIntegrityLevel
{
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3
}

public sealed record TelemetryEvent(
    DateTimeOffset Timestamp,
    EventKind Kind,
    string ProcessPath,
    int ProcessId,
    string? TargetPath,
    string? SourcePath,
    string? ParentProcessPath,
    int BurstCount,
    bool IsProtectedTarget,
    bool IsSuspiciousExtension,
    bool HitsPersistenceRegistry,
    bool IsUnsignedProcess,
    bool IsPreOperation = false,
    ulong VolumeSerialNumber = 0,
    ulong FileId = 0,
    int ParentProcessId = 0,
    int TargetProcessId = 0,
    bool IsSuspendedCreate = false,
    KernelTrustHint TrustHint = KernelTrustHint.Unknown,
    uint DriverFlags = 0,
    ProcessIntegrityLevel IntegrityLevel = ProcessIntegrityLevel.Unknown
);

public sealed record ThreatDecision(
    SecurityAction Action,
    double Score,
    string Reason,
    DateTimeOffset Timestamp
);

public sealed record RollbackEntry(
    RollbackEntryType EntryType,
    string TargetPath,
    string BackupPath,
    DateTimeOffset CapturedAt,
    string Reason,
    int ProcessId = 0
);

public sealed record IncidentLogEntry(
    DateTimeOffset Timestamp,
    string ProcessPath,
    int ProcessId,
    string? TargetPath,
    EventKind EventKind,
    SecurityAction Action,
    double Score,
    string Reason,
    int RollbackCount,
    bool DriverCommandSucceeded,
    string? DriverMessage,
    string? TrustTier = null,
    string? RemediationSummary = null,
    string? MemoryScanDetail = null,
    string? BaseTrustTier = null,
    string? CurrentTrustTier = null,
    bool? SignatureEvaluated = null,
    bool? HasValidSignature = null,
    bool? IsMicrosoftSigned = null,
    bool? LoadedUnsignedDll = null,
    bool? LoadedSuspiciousDll = null,
    bool? LoadedNonMicrosoftDll = null,
    int? ParentProcessId = null,
    string? ParentProcessPath = null,
    string? ModuleTrustTier = null,
    bool? ModuleSigned = null,
    bool? ModuleMicrosoftSigned = null,
    string? KernelTrustHint = null
)
{
    public IncidentLogEntry()
        : this(
            default,
            string.Empty,
            0,
            null,
            EventKind.Unknown,
            SecurityAction.Allow,
            0,
            string.Empty,
            0,
            false,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null)
    {
    }

    // Keep the pre-v2.114 constructor shape so older binaries can still bind if
    // only RollbackGuard.Common is updated on the target machine.
    public IncidentLogEntry(
        DateTimeOffset Timestamp,
        string ProcessPath,
        int ProcessId,
        string? TargetPath,
        EventKind EventKind,
        SecurityAction Action,
        double Score,
        string Reason,
        int RollbackCount,
        bool DriverCommandSucceeded,
        string? DriverMessage,
        string? TrustTier = null,
        string? RemediationSummary = null,
        string? MemoryScanDetail = null)
        : this(
            Timestamp,
            ProcessPath,
            ProcessId,
            TargetPath,
            EventKind,
            Action,
            Score,
            Reason,
            RollbackCount,
            DriverCommandSucceeded,
            DriverMessage,
            TrustTier,
            RemediationSummary,
            MemoryScanDetail,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null)
    {
    }
}

public sealed record RuntimeStatus(
    DateTimeOffset Timestamp,
    bool DriverConnected,
    string DriverState,
    string PolicyVersion,
    int PendingRollbackEntries,
    string LastError
);
