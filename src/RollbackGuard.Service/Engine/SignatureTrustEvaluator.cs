using RollbackGuard.Common.Security;

namespace RollbackGuard.Service.Engine;

public readonly record struct SignatureTrust(
    bool IsSigned,
    bool IsMicrosoftSigned,
    PublisherTrustLevel PublisherTrustLevel,
    string PublisherName,
    bool HasTimestampSignature,
    bool RevocationChecked,
    bool ChainValid,
    bool IsRevoked,
    bool PathPolicySatisfied,
    string PathPolicyName,
    string StatusSummary,
    SeSigningLevel KernelSigningLevel = SeSigningLevel.Unchecked);

public static class SignatureTrustEvaluator
{
    public static bool TryGetTrust(string? filePath, out SignatureTrust trust)
    {
        trust = default;
        if (!AuthenticodeTrustVerifier.TryResolveReadablePath(filePath, out var resolvedPath))
            return false;

        // ── Primary: kernel SE_SIGNING_LEVEL ──────────────────────────────────────
        // The kernel's Code Integrity subsystem (SeVerifyImageHeader) evaluates the
        // image's embedded Authenticode signature against CI policy and records the
        // result as an SE_SIGNING_LEVEL on the file object.  This verdict is harder
        // to forge than a user-mode WinVerifyTrust call and does not block on network
        // CRL/OCSP endpoints.
        //
        // Levels ≥ Windows (12):  Windows OS component — trust unconditionally.
        // Levels ≥ Microsoft (8): Microsoft-signed per CI — trust unconditionally.
        // Levels  < Authenticode: kernel confirmed unsigned — no Authenticode needed.
        // Levels 4–7:             signed but non-Microsoft; use Authenticode only
        //                         for publisher reputation (name + trust level).
        if (KernelSigningLevelChecker.TryGetSigningLevel(resolvedPath, out var kernelResult))
        {
            var kLevel = kernelResult.Level;

            if (KernelSigningLevelChecker.IsWindowsCoreLevel(kLevel))
            {
                // Windows / WindowsTcb — the kernel's highest trust tier.
                // The CI policy has fully validated the signature chain including
                // revocation; no user-mode Authenticode walk is needed.
                trust = new SignatureTrust(
                    IsSigned:            true,
                    IsMicrosoftSigned:   true,
                    PublisherTrustLevel: PublisherTrustLevel.High,
                    PublisherName:       "Microsoft Windows",
                    HasTimestampSignature: false,
                    RevocationChecked:   true,
                    ChainValid:          true,
                    IsRevoked:           false,
                    PathPolicySatisfied: true,
                    PathPolicyName:      string.Empty,
                    StatusSummary:       kernelResult.StatusSummary,
                    KernelSigningLevel:  kLevel);
                return true;
            }

            if (KernelSigningLevelChecker.IsMicrosoftLevel(kLevel))
            {
                // Microsoft-signed per kernel CI (levels 8–11, e.g. Microsoft or
                // Antimalware / DynamicCodegen policy tiers).
                trust = new SignatureTrust(
                    IsSigned:            true,
                    IsMicrosoftSigned:   true,
                    PublisherTrustLevel: PublisherTrustLevel.High,
                    PublisherName:       "Microsoft Corporation",
                    HasTimestampSignature: false,
                    RevocationChecked:   true,
                    ChainValid:          true,
                    IsRevoked:           false,
                    PathPolicySatisfied: true,
                    PathPolicyName:      string.Empty,
                    StatusSummary:       kernelResult.StatusSummary,
                    KernelSigningLevel:  kLevel);
                return true;
            }

            if (!KernelSigningLevelChecker.IsSignedLevel(kLevel))
            {
                // Kernel confirmed: no valid signature (Unsigned / Unchecked).
                // Running Authenticode cannot change the kernel's verdict.
                trust = new SignatureTrust(
                    IsSigned:            false,
                    IsMicrosoftSigned:   false,
                    PublisherTrustLevel: PublisherTrustLevel.Unknown,
                    PublisherName:       string.Empty,
                    HasTimestampSignature: false,
                    RevocationChecked:   false,
                    ChainValid:          false,
                    IsRevoked:           false,
                    PathPolicySatisfied: true,
                    PathPolicyName:      string.Empty,
                    StatusSummary:       kernelResult.StatusSummary,
                    KernelSigningLevel:  kLevel);
                return true;
            }

            // Authenticode / Store / Antimalware tier (levels 4–7):
            // The kernel confirmed the binary carries a valid signature, but below
            // the Microsoft tier.  Use AuthenticodeTrustVerifier exclusively for
            // reputation data (publisher name + trust-level classification).
            // IsMicrosoftSigned is always false here; the kernel's decision is final.
            // Publisher trust is capped at Medium to prevent Authenticode from
            // elevating a sub-Microsoft kernel level to High.
            var publisherName        = string.Empty;
            var publisherTrustLevel  = PublisherTrustLevel.Low;
            var hasTimestamp         = false;
            var chainValid           = true;
            var pathPolicySatisfied  = true;
            var pathPolicyName       = string.Empty;

            if (AuthenticodeTrustVerifier.TryGetTrust(resolvedPath, out var reputationResult))
            {
                publisherName       = reputationResult.PublisherName;
                publisherTrustLevel = reputationResult.PublisherTrustLevel == PublisherTrustLevel.High
                    ? PublisherTrustLevel.Medium   // never elevate past kernel's non-Microsoft verdict
                    : reputationResult.PublisherTrustLevel;
                hasTimestamp        = reputationResult.HasTimestampSignature;
                chainValid          = reputationResult.ChainValid;
                pathPolicySatisfied = reputationResult.PathPolicySatisfied;
                pathPolicyName      = reputationResult.PathPolicyName;
            }

            trust = new SignatureTrust(
                IsSigned:            true,
                IsMicrosoftSigned:   false,
                PublisherTrustLevel: publisherTrustLevel,
                PublisherName:       publisherName,
                HasTimestampSignature: hasTimestamp,
                RevocationChecked:   true,   // kernel validated revocation via CI policy
                ChainValid:          chainValid,
                IsRevoked:           false,
                PathPolicySatisfied: pathPolicySatisfied,
                PathPolicyName:      pathPolicyName,
                StatusSummary:       kernelResult.StatusSummary,
                KernelSigningLevel:  kLevel);
            return true;
        }

        // ── Fallback: pure Authenticode ───────────────────────────────────────────
        // The kernel signing-level query is unavailable (e.g. the file is not a PE,
        // SEC_IMAGE section creation was denied, or an unexpected NT error occurred).
        // Fall back to the existing WinVerifyTrust-based path.
        if (!AuthenticodeTrustVerifier.TryGetTrust(resolvedPath, out var result))
            return false;

        trust = new SignatureTrust(
            result.IsSigned,
            result.IsMicrosoftSigned,
            result.PublisherTrustLevel,
            result.PublisherName,
            result.HasTimestampSignature,
            result.RevocationChecked,
            result.ChainValid,
            result.IsRevoked,
            result.PathPolicySatisfied,
            result.PathPolicyName,
            result.StatusSummary,
            KernelSigningLevel: SeSigningLevel.Unchecked);
        return true;
    }

    public static bool TryResolveReadablePath(string? rawPath, out string resolvedPath)
        => AuthenticodeTrustVerifier.TryResolveReadablePath(rawPath, out resolvedPath);

    public static bool TryNormalizeDisplayPath(string? rawPath, out string normalizedPath)
        => AuthenticodeTrustVerifier.TryNormalizeDisplayPath(rawPath, out normalizedPath);
}
