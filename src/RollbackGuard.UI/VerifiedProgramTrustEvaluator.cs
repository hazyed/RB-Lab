using RollbackGuard.Common.Diagnostics;
using RollbackGuard.Common.Security;

namespace RollbackGuard.UI;

internal readonly record struct VerifiedProgramSignatureTrust(
    bool IsSigned,
    bool IsMicrosoftSigned,
    PublisherTrustLevel PublisherTrustLevel,
    string PublisherName,
    string StatusSummary);

internal static class VerifiedProgramTrustEvaluator
{
    public static bool TryNormalizeDisplayPath(string? rawPath, out string normalizedPath)
    {
        var ok = AuthenticodeTrustVerifier.TryNormalizeDisplayPath(rawPath, out normalizedPath);
        StartupLog.WriteSign(
            "TrustFlow-UI",
            $"ui-normalize-path ok={ok}, rawPath={SafeTrustText(rawPath)}, normalizedPath={SafeTrustText(normalizedPath)}");
        return ok;
    }

    public static bool TryGetTrust(string? rawPath, out string normalizedPath, out VerifiedProgramSignatureTrust trust)
    {
        trust = default;
        normalizedPath = string.Empty;

        StartupLog.WriteSign(
            "TrustFlow-UI",
            $"ui-trust-probe-start rawPath={SafeTrustText(rawPath)}");

        if (!AuthenticodeTrustVerifier.TryNormalizeDisplayPath(rawPath, out var candidatePath))
        {
            StartupLog.WriteSign(
                "TrustFlow-UI",
                $"ui-trust-probe-normalize-failed rawPath={SafeTrustText(rawPath)}");
            return false;
        }

        normalizedPath = candidatePath;
        if (!AuthenticodeTrustVerifier.TryGetTrust(rawPath, out var result))
        {
            StartupLog.WriteSign(
                "TrustFlow-UI",
                $"ui-trust-probe-authenticode-failed rawPath={SafeTrustText(rawPath)}, normalizedPath={SafeTrustText(candidatePath)}");
            return false;
        }

        normalizedPath = result.ResolvedPath;
        trust = new VerifiedProgramSignatureTrust(
            result.IsSigned,
            result.IsMicrosoftSigned,
            result.PublisherTrustLevel,
            result.PublisherName,
            result.StatusSummary);

        StartupLog.WriteSign(
            "TrustFlow-UI",
            $"ui-trust-verdict rawPath={SafeTrustText(rawPath)}, normalizedPath={SafeTrustText(normalizedPath)}, isSigned={result.IsSigned}, isMicrosoftSigned={result.IsMicrosoftSigned}, publisher={SafeTrustText(result.PublisherName)}, publisherTrust={result.PublisherTrustLevel}, chainValid={result.ChainValid}, revoked={result.IsRevoked}, revocationChecked={result.RevocationChecked}, hasTimestamp={result.HasTimestampSignature}, pathPolicySatisfied={result.PathPolicySatisfied}, pathPolicy={SafeTrustText(result.PathPolicyName)}, status={SafeTrustText(result.StatusSummary)}");
        return true;
    }

    private static string SafeTrustText(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "(empty)";
        }

        return value.Trim().TrimEnd('\0').Replace('\r', ' ').Replace('\n', ' ');
    }
}
