using RollbackGuard.Common.Models;
using RollbackGuard.Service.Rollback;

namespace RollbackGuard.Service.Interaction;

public enum EnforcementChoice
{
    Ignore = 0,
    Terminate = 1
}

public enum RollbackChoice
{
    Skip = 0,
    Rollback = 1
}

public interface IUserApprovalGate
{
    EnforcementChoice RequestEnforcement(
        TelemetryEvent telemetryEvent,
        ThreatDecision decision,
        string containmentSummary,
        int pendingRollbackEntries,
        out string auditMessage);

    RollbackChoice RequestRollback(
        TelemetryEvent telemetryEvent,
        ThreatDecision decision,
        IReadOnlyList<string> rollbackPreview,
        int pendingRollbackEntries,
        out string auditMessage);

    void ShowRollbackResult(
        TelemetryEvent telemetryEvent,
        ThreatDecision decision,
        int requestedEntries,
        RollbackExecutionResult result);
}
