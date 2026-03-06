using RollbackGuard.Common.Models;
using RollbackGuard.Common.Protocol;

namespace RollbackGuard.Service.Engine;

public static class KernelEntropyEvidence
{
    private const uint RelevantFlags =
        (uint)DriverProtocol.DriverEventFlags.KernelHighEntropyRaw |
        (uint)DriverProtocol.DriverEventFlags.KernelLowToHigh |
        (uint)DriverProtocol.DriverEventFlags.KernelAutoBlocked |
        (uint)DriverProtocol.DriverEventFlags.KernelRuleConsecutive |
        (uint)DriverProtocol.DriverEventFlags.KernelRuleCumulative |
        (uint)DriverProtocol.DriverEventFlags.KernelRuleHoneypot;

    public static bool IsRelevant(TelemetryEvent evt) =>
        evt.Kind == EventKind.FileWrite && (evt.DriverFlags & RelevantFlags) != 0;

    public static bool HasHighEntropyRaw(TelemetryEvent evt) =>
        HasFlag(evt, DriverProtocol.DriverEventFlags.KernelHighEntropyRaw);

    public static bool IsLowToHigh(TelemetryEvent evt) =>
        HasFlag(evt, DriverProtocol.DriverEventFlags.KernelLowToHigh);

    public static bool WasAutoBlocked(TelemetryEvent evt) =>
        HasFlag(evt, DriverProtocol.DriverEventFlags.KernelAutoBlocked);

    public static bool TriggeredConsecutiveRule(TelemetryEvent evt) =>
        HasFlag(evt, DriverProtocol.DriverEventFlags.KernelRuleConsecutive);

    public static bool TriggeredCumulativeRule(TelemetryEvent evt) =>
        HasFlag(evt, DriverProtocol.DriverEventFlags.KernelRuleCumulative);

    public static bool TriggeredHoneypotRule(TelemetryEvent evt) =>
        HasFlag(evt, DriverProtocol.DriverEventFlags.KernelRuleHoneypot) ||
        evt.Kind == EventKind.HoneyFileTouched;

    public static string Describe(TelemetryEvent evt)
    {
        if (!IsRelevant(evt) && evt.Kind != EventKind.HoneyFileTouched)
        {
            return "no-kernel-entropy";
        }

        var parts = new List<string>();
        if (HasHighEntropyRaw(evt)) parts.Add("raw-high");
        if (IsLowToHigh(evt)) parts.Add("low-to-high");
        if (TriggeredConsecutiveRule(evt)) parts.Add("rule-consecutive");
        if (TriggeredCumulativeRule(evt)) parts.Add("rule-cumulative");
        if (TriggeredHoneypotRule(evt)) parts.Add("rule-honeypot");
        if (WasAutoBlocked(evt)) parts.Add("auto-blocked");
        return parts.Count == 0 ? "kernel-entropy-seen" : string.Join(",", parts);
    }

    private static bool HasFlag(TelemetryEvent evt, DriverProtocol.DriverEventFlags flag) =>
        (evt.DriverFlags & (uint)flag) != 0;
}
