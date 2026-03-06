using RollbackGuard.Common.Models;
using RollbackGuard.Common.Protocol;

namespace RollbackGuard.Service.Engine;

internal static class DriverThreadEvidence
{
    public static bool HasStartMetadata(TelemetryEvent evt) =>
        evt.Kind == EventKind.ThreadCreateRemote &&
        HasFlag(evt, DriverProtocol.DriverEventFlags.ThreadStartValid);

    public static bool IsPrivate(TelemetryEvent evt) =>
        HasFlag(evt, DriverProtocol.DriverEventFlags.ThreadPrivate);

    public static bool IsExecutable(TelemetryEvent evt) =>
        HasFlag(evt, DriverProtocol.DriverEventFlags.ThreadExecutable);

    public static bool IsWritable(TelemetryEvent evt) =>
        HasFlag(evt, DriverProtocol.DriverEventFlags.ThreadWritable);

    public static bool IsWriteExecute(TelemetryEvent evt) =>
        HasFlag(evt, DriverProtocol.DriverEventFlags.ThreadWriteExecute);

    public static bool IsUnbacked(TelemetryEvent evt) =>
        HasFlag(evt, DriverProtocol.DriverEventFlags.ThreadUnbacked);

    public static bool IsImageBacked(TelemetryEvent evt) =>
        HasFlag(evt, DriverProtocol.DriverEventFlags.ThreadMemImage);

    public static bool IsHighConfidenceExecutionTransfer(TelemetryEvent evt) =>
        evt.Kind == EventKind.ThreadCreateRemote &&
        IsExecutable(evt) &&
        (IsWriteExecute(evt) || (IsUnbacked(evt) && IsPrivate(evt)));

    public static string Describe(TelemetryEvent evt)
    {
        if (!HasStartMetadata(evt))
        {
            return "driver-thread-start-query-missed";
        }

        var parts = new List<string>();
        if (IsUnbacked(evt)) parts.Add("unbacked");
        if (IsPrivate(evt)) parts.Add("private");
        if (IsExecutable(evt)) parts.Add("exec");
        if (IsWritable(evt)) parts.Add("write");
        if (IsWriteExecute(evt)) parts.Add("wx");
        if ((evt.DriverFlags & (uint)DriverProtocol.DriverEventFlags.ThreadMemImage) != 0) parts.Add("image");
        if ((evt.DriverFlags & (uint)DriverProtocol.DriverEventFlags.ThreadMemMapped) != 0) parts.Add("mapped");
        if (evt.VolumeSerialNumber != 0) parts.Add($"start=0x{evt.VolumeSerialNumber:X}");
        if (evt.FileId != 0) parts.Add($"base=0x{evt.FileId:X}");
        return parts.Count == 0 ? "thread-start-known" : string.Join(",", parts);
    }

    private static bool HasFlag(TelemetryEvent evt, DriverProtocol.DriverEventFlags flag) =>
        (evt.DriverFlags & (uint)flag) != 0;
}
