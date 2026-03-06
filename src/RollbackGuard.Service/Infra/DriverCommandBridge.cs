using System.ComponentModel;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using RollbackGuard.Common.Models;
using RollbackGuard.Common.Protocol;

namespace RollbackGuard.Service.Infra;

public sealed class DriverCommandBridge : IDisposable
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x80;
    private const int ErrorInvalidFunction = 1;
    private const int ErrorInvalidHandle = 6;
    private const int ErrorNoMoreItems = 259;
    private const int ErrorOperationAborted = 995;
    private const int ErrorNotFound = 1168;
    private const int MaxTrackedControlSequences = 4096;
    private const int MaxHoneyPaths = 64;

    private readonly string _devicePath;
    private readonly object _pendingSync = new();
    private readonly Queue<DriverProtocol.DriverEventRecordRaw> _pendingEvents = new();
    private readonly Queue<ulong> _trackedControlSequenceOrder = new();
    private readonly HashSet<ulong> _trackedControlSequences = [];
    private readonly AutoResetEvent _controlSignal = new(false);

    private SafeFileHandle? _deviceHandle;
    private SafeFileHandle? _controlHandle;
    private MemoryMappedFile? _telemetryMapping;
    private MemoryMappedViewAccessor? _telemetryView;
    private EventWaitHandle? _telemetrySignal;
    private Thread? _controlThread;
    private volatile bool _disposeRequested;
    private volatile bool _advancedTransportReady;
    private ulong _nextReadSequence;

    public DriverCommandBridge(string devicePath)
    {
        _devicePath = devicePath;
    }

    public bool IsConnected => _deviceHandle is { IsInvalid: false, IsClosed: false };

    public bool UsesAdvancedTransport => _advancedTransportReady;

    public string TransportMode => _advancedTransportReady ? "tri-plane" : "legacy-ioctl";

    public WaitHandle ControlWaitHandle => _controlSignal;

    public WaitHandle? TelemetryWaitHandle => _telemetrySignal;

    public bool TryConnect(out string error)
    {
        if (IsConnected)
        {
            error = string.Empty;
            return true;
        }

        _deviceHandle = CreateDeviceHandle();
        if (_deviceHandle.IsInvalid)
        {
            var code = Marshal.GetLastWin32Error();
            error = $"connect {_devicePath} failed: {new Win32Exception(code).Message} ({code})";
            _deviceHandle.Dispose();
            _deviceHandle = null;
            return false;
        }

        if (!TryInitializeAdvancedTransport(out _))
        {
            CleanupAdvancedTransport();
        }

        error = string.Empty;
        return true;
    }

    public bool TryReadEvents(out IReadOnlyList<DriverProtocol.DriverEventRecordRaw> events, out string error)
    {
        events = [];

        var batch = new List<DriverProtocol.DriverEventRecordRaw>(DriverProtocol.MaxBatchEvents);
        lock (_pendingSync)
        {
            while (batch.Count < DriverProtocol.MaxBatchEvents && _pendingEvents.Count > 0)
            {
                batch.Add(_pendingEvents.Dequeue());
            }
        }

        if (batch.Count >= DriverProtocol.MaxBatchEvents)
        {
            events = batch;
            error = string.Empty;
            return true;
        }

        if (!TryReadEventsDirect(out var directEvents, out error))
        {
            return false;
        }

        var remain = DriverProtocol.MaxBatchEvents - batch.Count;
        if (directEvents.Count <= remain)
        {
            batch.AddRange(directEvents);
            events = batch;
            error = string.Empty;
            return true;
        }

        batch.AddRange(directEvents.Take(remain));
        RequeueEvents(directEvents.Skip(remain));
        events = batch;
        error = string.Empty;
        return true;
    }

    public bool TryReadEventsDirect(out IReadOnlyList<DriverProtocol.DriverEventRecordRaw> events, out string error)
    {
        if (_advancedTransportReady)
        {
            return TryReadEventsFromTelemetryRing(out events, out error);
        }

        return TryReadEventsLegacy(out events, out error);
    }

    public void RequeueEvents(IEnumerable<DriverProtocol.DriverEventRecordRaw> events)
    {
        lock (_pendingSync)
        {
            foreach (var item in events)
            {
                _pendingEvents.Enqueue(item);
            }
        }
    }

    public bool TryDispatch(ThreatDecision decision, int processId, out string message)
    {
        return decision.Action switch
        {
            SecurityAction.Terminate => TryTerminateProcess(processId, out message),
            SecurityAction.Block => Pass("block-deferred-manual-confirm", out message),
            _ => Pass("allow", out message)
        };
    }

    public bool TryEnableRollbackMode(int processId, out string message)
    {
        return TrySendCommand(DriverProtocol.DriverCommandEnableRollback, processId, out message);
    }

    public bool TryTerminateProcess(int processId, out string message)
    {
        return TrySendCommand(DriverProtocol.DriverCommandTerminate, processId, out message);
    }

    public bool TrySuspendProcess(int processId, out string message)
    {
        return TrySendCommand(DriverProtocol.DriverCommandSuspend, processId, out message);
    }

    public bool TryResumeProcess(int processId, out string message)
    {
        return TrySendCommand(DriverProtocol.DriverCommandResume, processId, out message);
    }

    public bool TryBlockProcessWrites(int processId, out string message)
    {
        return TrySendCommand(DriverProtocol.DriverCommandBlock, processId, out message);
    }

    public bool TryUnblockProcessWrites(int processId, out string message)
    {
        return TrySendCommand(DriverProtocol.DriverCommandResume, processId, out message);
    }

    public bool TrySetRestrictedProcess(int processId, int startupDelayMs, out string message)
    {
        var boundedDelay = startupDelayMs < 0 ? 0u : (uint)startupDelayMs;
        return TrySendCommand(DriverProtocol.DriverCommandSetRestricted, processId, boundedDelay, out message);
    }

    public bool TryClearRestrictedProcess(int processId, out string message)
    {
        return TrySendCommand(DriverProtocol.DriverCommandClearRestricted, processId, out message);
    }

    public bool TrySetProcessTrust(int processId, int trustTier, out string message)
    {
        var boundedTier = trustTier < 0 ? 0u : (uint)trustTier;
        return TrySendCommand(DriverProtocol.DriverCommandSetProcessTrust, processId, boundedTier, out message);
    }

    public bool TryClearProcessTrust(int processId, out string message)
    {
        return TrySendCommand(DriverProtocol.DriverCommandClearProcessTrust, processId, out message);
    }

    public bool TrySetHoneyFiles(string[] paths, out string message)
    {
        if (!IsConnected || _deviceHandle is null)
        {
            message = "driver handle not connected";
            return false;
        }

        var normalized = paths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(path => path.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(MaxHoneyPaths)
            .ToArray();

        var buffer = new byte[sizeof(uint) + (normalized.Length * DriverProtocol.PathSize)];
        BitConverter.GetBytes((uint)normalized.Length).CopyTo(buffer, 0);

        for (var index = 0; index < normalized.Length; index++)
        {
            var encoded = Encoding.ASCII.GetBytes(normalized[index]);
            var destinationOffset = sizeof(uint) + (index * DriverProtocol.PathSize);
            var copyLength = Math.Min(encoded.Length, DriverProtocol.PathSize - 1);
            Array.Copy(encoded, 0, buffer, destinationOffset, copyLength);
            buffer[destinationOffset + copyLength] = 0;
        }

        if (!DeviceIoControl(
            _deviceHandle,
            DriverProtocol.IoctlSetHoneyPaths,
            buffer,
            (uint)buffer.Length,
            IntPtr.Zero,
            0,
            out _,
            IntPtr.Zero))
        {
            var code = Marshal.GetLastWin32Error();
            if (code == ErrorInvalidFunction)
            {
                message = $"honeypot paths retained in R3 only: {normalized.Length}";
                return true;
            }

            message = $"set honeypot paths failed: {new Win32Exception(code).Message} ({code})";
            return false;
        }

        message = $"honeypot paths registered in kernel: {normalized.Length}";
        return true;
    }

    public void Dispose()
    {
        _disposeRequested = true;

        try
        {
            if (_controlHandle is { IsInvalid: false, IsClosed: false })
            {
                CancelIoEx(_controlHandle, IntPtr.Zero);
            }
        }
        catch
        {
            // Ignore teardown races.
        }

        CleanupAdvancedTransport();

        _deviceHandle?.Dispose();
        _deviceHandle = null;

        _controlSignal.Dispose();
    }

    private bool TryInitializeAdvancedTransport(out string error)
    {
        error = string.Empty;
        if (_deviceHandle is null || _deviceHandle.IsInvalid)
        {
            error = "driver handle not connected";
            return false;
        }

        try
        {
            var ringCapacity = DriverProtocol.DefaultTelemetryRingCapacity;
            var sectionBytes = DriverProtocol.TelemetrySectionBytes(ringCapacity);
            var baseName = BuildTransportBaseName();
            var sectionName = $"Global\\{baseName}.telemetry";
            var signalName = $"Global\\{baseName}.signal";

            _telemetryMapping = MemoryMappedFile.CreateOrOpen(sectionName, sectionBytes, MemoryMappedFileAccess.ReadWrite);
            _telemetryView = _telemetryMapping.CreateViewAccessor(0, sectionBytes, MemoryMappedFileAccess.ReadWrite);
            _telemetrySignal = new EventWaitHandle(false, EventResetMode.AutoReset, signalName);

            InitializeTelemetryHeader(_telemetryView, ringCapacity);

            var request = new DriverProtocol.DriverTelemetryRegistrationRaw
            {
                Version = DriverProtocol.SharedTelemetryVersion,
                RingCapacity = (uint)ringCapacity,
                SectionBytes = (uint)sectionBytes,
                Reserved = 0,
                SectionName = sectionName,
                SignalEventName = signalName
            };

            if (!DeviceIoControl(
                _deviceHandle,
                DriverProtocol.IoctlRegisterTelemetry,
                ref request,
                (uint)DriverProtocol.TelemetryRegistrationSize,
                IntPtr.Zero,
                0,
                out _,
                IntPtr.Zero))
            {
                var code = Marshal.GetLastWin32Error();
                error = $"register telemetry failed: {new Win32Exception(code).Message} ({code})";
                return false;
            }

            _controlHandle = CreateDeviceHandle();
            if (_controlHandle.IsInvalid)
            {
                var code = Marshal.GetLastWin32Error();
                error = $"open control handle failed: {new Win32Exception(code).Message} ({code})";
                _controlHandle.Dispose();
                _controlHandle = null;
                return false;
            }

            _advancedTransportReady = true;
            _nextReadSequence = 0;
            StartControlPump();
            return true;
        }
        catch (Exception ex)
        {
            error = $"advanced transport init failed: {ex.Message}";
            return false;
        }
    }

    private void InitializeTelemetryHeader(MemoryMappedViewAccessor view, int ringCapacity)
    {
        view.Write(0, DriverProtocol.SharedTelemetryVersion);
        view.Write(sizeof(uint), DriverProtocol.EventRecordSize);
        view.Write(sizeof(uint) * 2, ringCapacity);
        view.Write(sizeof(uint) * 3, 0);
        view.Write(16, 0L);
        view.Write(24, 0L);
        view.Flush();
    }

    private void StartControlPump()
    {
        _controlThread = new Thread(ControlPumpLoop)
        {
            IsBackground = true,
            Name = $"RollbackGuard.ControlPump[{_devicePath}]"
        };
        _controlThread.Start();
    }

    private void ControlPumpLoop()
    {
        while (!_disposeRequested && _advancedTransportReady)
        {
            if (!TryReadControlEvent(out var record, out var error))
            {
                if (_disposeRequested || string.IsNullOrWhiteSpace(error))
                {
                    break;
                }

                Thread.Sleep(50);
                continue;
            }

            lock (_pendingSync)
            {
                _pendingEvents.Enqueue(record);
            }
            TrackControlSequence(record.SequenceId);

            _controlSignal.Set();
        }
    }

    private bool TryReadControlEvent(out DriverProtocol.DriverEventRecordRaw record, out string error)
    {
        record = default;
        error = string.Empty;

        if (!_advancedTransportReady || _controlHandle is null || _controlHandle.IsInvalid)
        {
            error = "control handle not connected";
            return false;
        }

        var outBuffer = new byte[DriverProtocol.EventRecordSize];
        if (!DeviceIoControl(
            _controlHandle,
            DriverProtocol.IoctlWaitControlEvent,
            IntPtr.Zero,
            0,
            outBuffer,
            (uint)outBuffer.Length,
            out var bytesReturned,
            IntPtr.Zero))
        {
            var code = Marshal.GetLastWin32Error();
            if (code is ErrorOperationAborted or ErrorInvalidHandle or ErrorNotFound)
            {
                error = string.Empty;
                return false;
            }

            error = $"wait control event failed: {new Win32Exception(code).Message} ({code})";
            return false;
        }

        if (bytesReturned < DriverProtocol.EventRecordSize)
        {
            error = "control event payload too small";
            return false;
        }

        record = ReadStruct<DriverProtocol.DriverEventRecordRaw>(outBuffer, 0);
        return true;
    }

    private unsafe bool TryReadEventsFromTelemetryRing(out IReadOnlyList<DriverProtocol.DriverEventRecordRaw> events, out string error)
    {
        events = [];
        error = string.Empty;

        if (_telemetryView is null)
        {
            error = "telemetry ring not initialized";
            return false;
        }

        byte* rawPtr = null;
        _telemetryView.SafeMemoryMappedViewHandle.AcquirePointer(ref rawPtr);
        try
        {
            if (rawPtr is null)
            {
                error = "telemetry ring pointer unavailable";
                return false;
            }

            var header = (DriverProtocol.SharedTelemetryHeaderRaw*)rawPtr;
            if (header->Version != DriverProtocol.SharedTelemetryVersion)
            {
                error = $"telemetry version mismatch: shared={header->Version}, expected={DriverProtocol.SharedTelemetryVersion}";
                return false;
            }

            if (header->RecordSize != DriverProtocol.EventRecordSize)
            {
                error = $"telemetry record size mismatch: shared={header->RecordSize}, expected={DriverProtocol.EventRecordSize}";
                return false;
            }

            var capacity = header->Capacity;
            if (capacity == 0)
            {
                events = [];
                return true;
            }

            Thread.MemoryBarrier();
            var publishedSequence = header->WriteSequence;
            if (publishedSequence < _nextReadSequence)
            {
                _nextReadSequence = publishedSequence;
            }

            if (publishedSequence > _nextReadSequence + capacity)
            {
                _nextReadSequence = publishedSequence - capacity;
            }

            var available = publishedSequence - _nextReadSequence;
            if (available == 0)
            {
                events = [];
                return true;
            }

            var toRead = (int)Math.Min((ulong)DriverProtocol.MaxBatchEvents, available);
            var list = new List<DriverProtocol.DriverEventRecordRaw>(toRead);
            for (var i = 0; i < toRead; i++)
            {
                var sequence = _nextReadSequence + 1;
                var index = (sequence - 1) % capacity;
                var offset = DriverProtocol.SharedTelemetryHeaderSize + ((long)index * DriverProtocol.EventRecordSize);
                var record = Marshal.PtrToStructure<DriverProtocol.DriverEventRecordRaw>((IntPtr)(rawPtr + offset));
                _nextReadSequence = sequence;

                if (record.SequenceId != 0 && TryConsumeTrackedControlSequence(record.SequenceId))
                {
                    continue;
                }

                list.Add(record);
            }

            events = list;
            return true;
        }
        finally
        {
            _telemetryView.SafeMemoryMappedViewHandle.ReleasePointer();
        }
    }

    private bool TryReadEventsLegacy(out IReadOnlyList<DriverProtocol.DriverEventRecordRaw> events, out string error)
    {
        events = [];
        error = string.Empty;
        if (!IsConnected || _deviceHandle is null)
        {
            error = "driver handle not connected";
            return false;
        }

        var outBuffer = new byte[DriverProtocol.EventBatchBufferSize];
        if (!DeviceIoControl(
            _deviceHandle,
            DriverProtocol.IoctlGetEvents,
            IntPtr.Zero,
            0,
            outBuffer,
            (uint)outBuffer.Length,
            out var bytesReturned,
            IntPtr.Zero))
        {
            var code = Marshal.GetLastWin32Error();
            if (code is ErrorNoMoreItems or ErrorNotFound)
            {
                error = string.Empty;
                return true;
            }

            error = $"read events failed: {new Win32Exception(code).Message} ({code})";
            return false;
        }

        if (bytesReturned < sizeof(uint))
        {
            error = "driver returned empty payload";
            return false;
        }

        var recordSize = DriverProtocol.EventRecordSize;
        if (recordSize != DriverProtocol.ExpectedEventRecordSize)
        {
            error = $"driver protocol size mismatch: managed={recordSize}, expected={DriverProtocol.ExpectedEventRecordSize}";
            return false;
        }

        var compatRecordSize = DriverProtocol.CompatEventRecordSize;
        if (compatRecordSize != DriverProtocol.PriorExpectedEventRecordSize)
        {
            error = $"driver compat protocol size mismatch: managed={compatRecordSize}, expected={DriverProtocol.PriorExpectedEventRecordSize}";
            return false;
        }

        var legacyRecordSize = DriverProtocol.LegacyEventRecordSize;
        if (legacyRecordSize != DriverProtocol.LegacyExpectedEventRecordSize)
        {
            error = $"driver legacy protocol size mismatch: managed={legacyRecordSize}, expected={DriverProtocol.LegacyExpectedEventRecordSize}";
            return false;
        }

        var count = BitConverter.ToUInt32(outBuffer, 0);
        if (count > DriverProtocol.MaxBatchEvents)
        {
            count = DriverProtocol.MaxBatchEvents;
        }

        var payloadLength = Math.Max(sizeof(uint), (int)bytesReturned);
        var headerSize = DriverProtocol.EventBatchHeaderSize;
        var requiredNewBytes = headerSize + ((long)count * recordSize);
        var requiredCompatBytes = headerSize + ((long)count * compatRecordSize);
        var requiredLegacyBytes = headerSize + ((long)count * legacyRecordSize);

        var activeRecordSize = recordSize;
        var mode = 0;
        if (count > 0 && payloadLength < requiredNewBytes && payloadLength >= requiredCompatBytes)
        {
            activeRecordSize = compatRecordSize;
            mode = 1;
        }
        else if (count > 0 && payloadLength < requiredCompatBytes && payloadLength >= requiredLegacyBytes)
        {
            activeRecordSize = legacyRecordSize;
            mode = 2;
        }

        var availableCount = Math.Max(0, (payloadLength - headerSize) / activeRecordSize);
        var toRead = (int)Math.Min(count, (uint)availableCount);
        var list = new List<DriverProtocol.DriverEventRecordRaw>(toRead);
        for (var i = 0; i < toRead; i++)
        {
            var offset = headerSize + (i * activeRecordSize);
            if (offset + activeRecordSize > payloadLength || offset + activeRecordSize > outBuffer.Length)
            {
                break;
            }

            if (mode == 1)
            {
                var compat = ReadStruct<DriverProtocol.DriverEventRecordRawCompat>(outBuffer, offset);
                list.Add(new DriverProtocol.DriverEventRecordRaw
                {
                    Kind = compat.Kind,
                    ProcessId = compat.ProcessId,
                    ThreadId = compat.ThreadId,
                    TimestampUnixMs = compat.TimestampUnixMs,
                    Flags = compat.Flags,
                    VolumeSerialNumber = compat.VolumeSerialNumber,
                    FileId = compat.FileId,
                    SequenceId = 0,
                    ProcessPath = compat.ProcessPath,
                    TargetPath = compat.TargetPath,
                    SourcePath = compat.SourcePath
                });
            }
            else if (mode == 2)
            {
                var legacy = ReadStruct<DriverProtocol.DriverEventRecordRawLegacy>(outBuffer, offset);
                list.Add(new DriverProtocol.DriverEventRecordRaw
                {
                    Kind = legacy.Kind,
                    ProcessId = legacy.ProcessId,
                    ThreadId = legacy.ThreadId,
                    TimestampUnixMs = legacy.TimestampUnixMs,
                    Flags = legacy.Flags,
                    VolumeSerialNumber = 0,
                    FileId = 0,
                    SequenceId = 0,
                    ProcessPath = legacy.ProcessPath,
                    TargetPath = legacy.TargetPath,
                    SourcePath = legacy.SourcePath
                });
            }
            else
            {
                list.Add(ReadStruct<DriverProtocol.DriverEventRecordRaw>(outBuffer, offset));
            }
        }

        events = list;
        return true;
    }

    private void TrackControlSequence(ulong sequenceId)
    {
        if (sequenceId == 0)
        {
            return;
        }

        lock (_pendingSync)
        {
            if (_trackedControlSequences.Add(sequenceId))
            {
                _trackedControlSequenceOrder.Enqueue(sequenceId);
            }

            while (_trackedControlSequenceOrder.Count > MaxTrackedControlSequences)
            {
                var stale = _trackedControlSequenceOrder.Dequeue();
                _trackedControlSequences.Remove(stale);
            }
        }
    }

    private bool TryConsumeTrackedControlSequence(ulong sequenceId)
    {
        if (sequenceId == 0)
        {
            return false;
        }

        lock (_pendingSync)
        {
            return _trackedControlSequences.Remove(sequenceId);
        }
    }

    private static bool Pass(string value, out string message)
    {
        message = value;
        return true;
    }

    private bool TrySendCommand(uint command, int processId, out string message)
    {
        return TrySendCommand(command, processId, 0, out message);
    }

    private bool TrySendCommand(uint command, int processId, uint reserved, out string message)
    {
        if (!IsConnected || _deviceHandle is null)
        {
            message = "driver handle not connected";
            return false;
        }

        if (processId <= 0)
        {
            message = $"command {command} invalid pid={processId}";
            return false;
        }

        var request = new DriverProtocol.DriverCommandRequestRaw
        {
            Command = command,
            ProcessId = (uint)processId,
            Reserved = reserved
        };

        if (!DeviceIoControl(
            _deviceHandle,
            DriverProtocol.IoctlCommand,
            ref request,
            (uint)Marshal.SizeOf<DriverProtocol.DriverCommandRequestRaw>(),
            IntPtr.Zero,
            0,
            out _,
            IntPtr.Zero))
        {
            var code = Marshal.GetLastWin32Error();
            message = $"command {command} pid={processId} failed: {new Win32Exception(code).Message} ({code})";
            return false;
        }

        message = $"command {command} pid={processId} ok";
        return true;
    }

    private SafeFileHandle CreateDeviceHandle()
    {
        return CreateFile(
            _devicePath,
            GenericRead | GenericWrite,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            FileAttributeNormal,
            IntPtr.Zero);
    }

    private string BuildTransportBaseName()
    {
        var sanitized = new StringBuilder(_devicePath.Length + 32);
        foreach (var ch in _devicePath)
        {
            sanitized.Append(char.IsLetterOrDigit(ch) ? ch : '_');
        }

        return $"RollbackGuard_{sanitized}_{Environment.ProcessId}";
    }

    private void CleanupAdvancedTransport()
    {
        _advancedTransportReady = false;

        try
        {
            if (_controlHandle is { IsInvalid: false, IsClosed: false })
            {
                CancelIoEx(_controlHandle, IntPtr.Zero);
            }
        }
        catch
        {
            // Ignore teardown races.
        }

        _controlHandle?.Dispose();
        _controlHandle = null;

        if (_controlThread is { IsAlive: true } && Thread.CurrentThread != _controlThread)
        {
            _controlThread.Join(500);
        }

        _controlThread = null;
        _telemetryView?.Dispose();
        _telemetryView = null;
        _telemetryMapping?.Dispose();
        _telemetryMapping = null;
        _telemetrySignal?.Dispose();
        _telemetrySignal = null;
        _nextReadSequence = 0;

        lock (_pendingSync)
        {
            _pendingEvents.Clear();
            _trackedControlSequences.Clear();
            _trackedControlSequenceOrder.Clear();
        }
    }

    private static T ReadStruct<T>(byte[] bytes, int offset) where T : struct
    {
        var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try
        {
            return Marshal.PtrToStructure<T>(IntPtr.Add(handle.AddrOfPinnedObject(), offset));
        }
        finally
        {
            handle.Free();
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CancelIoEx(
        SafeFileHandle hFile,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        byte[] lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        ref DriverProtocol.DriverCommandRequestRaw lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        ref DriverProtocol.DriverTelemetryRegistrationRaw lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        byte[] lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);
}
