using System.Runtime.InteropServices;

namespace RollbackGuard.Common.Protocol;

public static class DriverProtocol
{
    public const int ProcessPathSize = 260;
    public const int PathSize = 520;
    public const int ObjectNameSize = 128;
    public const int MaxBatchEvents = 128;
    public const uint SharedTelemetryVersion = 2;
    public const int ExpectedEventRecordSize = 1348;
    public const int PriorExpectedEventRecordSize = 1340;
    public const int LegacyExpectedEventRecordSize = 1324;
    public const int EventBatchHeaderSize = sizeof(uint);
    public const int SharedTelemetryHeaderSize = 32;
    public const int DefaultTelemetryRingCapacity = 8192;

    // CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, Function, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
    public const uint IoctlGetEvents = 0x00222004;
    public const uint IoctlCommand = 0x00222008;
    public const uint IoctlRegisterTelemetry = 0x0022200C;
    public const uint IoctlWaitControlEvent = 0x00222010;
    public const uint IoctlSetHoneyPaths = 0x00222014;

    public const uint DriverCommandBlock = 1;
    public const uint DriverCommandTerminate = 2;
    public const uint DriverCommandEnableRollback = 3;
    public const uint DriverCommandSuspend = 4;
    public const uint DriverCommandResume = 5;
    public const uint DriverCommandSetRestricted = 6;
    public const uint DriverCommandClearRestricted = 7;
    public const uint DriverCommandSetProcessTrust = 8;
    public const uint DriverCommandClearProcessTrust = 9;

    [Flags]
    public enum DriverEventFlags : uint
    {
        None = 0,
        ProtectedTarget = 1 << 0,
        SuspiciousExtension = 1 << 1,
        PersistenceRegistry = 1 << 2,
        UnsignedProcess = 1 << 3,
        PreOperation = 1 << 4,
        Suspended = 1 << 5,
        SignedHint = 1 << 6,
        MicrosoftSignedHint = 1 << 7,
        ThreadStartValid = 1 << 8,
        ThreadPrivate = 1 << 9,
        ThreadExecutable = 1 << 10,
        ThreadWritable = 1 << 11,
        ThreadWriteExecute = 1 << 12,
        ThreadUnbacked = 1 << 13,
        ThreadMemImage = 1 << 14,
        ThreadMemMapped = 1 << 15,
        KernelHighEntropyRaw = 1 << 16,
        KernelLowToHigh = 1 << 17,
        KernelAutoBlocked = 1 << 18,
        KernelRuleConsecutive = 1 << 19,
        KernelRuleCumulative = 1 << 20,
        KernelRuleHoneypot = 1 << 21

        // Bits 22-23 carry process integrity hint for process-create events.
        // Bits 24-27 carry the raw SE_SIGNING_LEVEL (0-15) for image-load and
        // process-create events.  Use ExtractKernelSigningLevel() to decode.
        // Not declared as named members here to avoid treating them as individual flags.
    }

    public enum ProcessIntegrityHint : byte
    {
        Unknown = 0,
        Low = 1,
        Medium = 2,
        High = 3
    }

    public const int IntegrityShift = 22;
    public const uint IntegrityMask = 0x00C00000u;
    public const int SigningLevelShift = 24;
    public const uint SigningLevelMask = 0x0F000000u;
    public const int SigningSourceShift = 28;
    public const uint SigningSourceMask = 0x30000000u;
    public const int SigningStatusShift = 30;
    public const uint SigningStatusMask = 0xC0000000u;

    public enum KernelSigningSource : byte
    {
        None = 0,
        Ppl = 1,
        CachedCi = 2,
        ActiveCi = 3
    }

    public enum KernelSigningStatus : byte
    {
        Unknown = 0,
        Verified = 1,
        Unsigned = 2,
        Error = 3
    }

    /// <summary>
    /// Decodes the raw SE_SIGNING_LEVEL byte (0-15) stored in bits 24-27 of the
    /// driver event flags. Returns 0 when Unchecked or unavailable.
    /// </summary>
    public static byte ExtractKernelSigningLevel(DriverEventFlags flags)
        => (byte)(((uint)flags >> SigningLevelShift) & 0x0F);

    public static KernelSigningSource ExtractKernelSigningSource(DriverEventFlags flags)
        => (KernelSigningSource)(((uint)flags >> SigningSourceShift) & 0x03);

    public static KernelSigningStatus ExtractKernelSigningStatus(DriverEventFlags flags)
        => (KernelSigningStatus)(((uint)flags >> SigningStatusShift) & 0x03);

    public static ProcessIntegrityHint ExtractProcessIntegrityHint(DriverEventFlags flags)
        => (ProcessIntegrityHint)(((uint)flags >> IntegrityShift) & 0x03);

    public enum DriverEventKind : uint
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
        SuspiciousHandleProcess = 20,
        SuspiciousHandleThread = 21
    }

    // Wire protocol is explicitly packed as 1 byte on native side.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct DriverEventRecordRaw
    {
        public DriverEventKind Kind;
        public uint ProcessId;
        public uint ThreadId;
        public long TimestampUnixMs;
        public DriverEventFlags Flags;
        public ulong VolumeSerialNumber;
        public ulong FileId;
        public ulong SequenceId;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = ProcessPathSize)]
        public string ProcessPath;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = PathSize)]
        public string TargetPath;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = PathSize)]
        public string SourcePath;
    }

    // Intermediate wire protocol: has VolumeSerialNumber/FileId but lacks SequenceId.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct DriverEventRecordRawCompat
    {
        public DriverEventKind Kind;
        public uint ProcessId;
        public uint ThreadId;
        public long TimestampUnixMs;
        public DriverEventFlags Flags;
        public ulong VolumeSerialNumber;
        public ulong FileId;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = ProcessPathSize)]
        public string ProcessPath;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = PathSize)]
        public string TargetPath;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = PathSize)]
        public string SourcePath;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct DriverEventRecordRawLegacy
    {
        public DriverEventKind Kind;
        public uint ProcessId;
        public uint ThreadId;
        public long TimestampUnixMs;
        public DriverEventFlags Flags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = ProcessPathSize)]
        public string ProcessPath;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = PathSize)]
        public string TargetPath;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = PathSize)]
        public string SourcePath;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct DriverCommandRequestRaw
    {
        public uint Command;
        public uint ProcessId;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    public struct DriverTelemetryRegistrationRaw
    {
        public uint Version;
        public uint RingCapacity;
        public uint SectionBytes;
        public uint Reserved;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = ObjectNameSize)]
        public string SectionName;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = ObjectNameSize)]
        public string SignalEventName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SharedTelemetryHeaderRaw
    {
        public uint Version;
        public uint RecordSize;
        public uint Capacity;
        public uint Reserved;
        public ulong WriteSequence;
        public ulong OverwriteCount;
    }

    public static int EventRecordSize => Marshal.SizeOf<DriverEventRecordRaw>();
    public static int CompatEventRecordSize => Marshal.SizeOf<DriverEventRecordRawCompat>();
    public static int LegacyEventRecordSize => Marshal.SizeOf<DriverEventRecordRawLegacy>();
    public static int TelemetryRegistrationSize => Marshal.SizeOf<DriverTelemetryRegistrationRaw>();
    public static int EventBatchBufferSize => EventBatchHeaderSize + (EventRecordSize * MaxBatchEvents);
    public static int TelemetrySectionBytes(int ringCapacity) => SharedTelemetryHeaderSize + (EventRecordSize * ringCapacity);
}
