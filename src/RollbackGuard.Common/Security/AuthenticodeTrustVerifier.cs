using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography.X509Certificates;

namespace RollbackGuard.Common.Security;

public readonly record struct AuthenticodeFileTrust(
    string ResolvedPath,
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
    string StatusSummary);

public static class AuthenticodeTrustVerifier
{
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeWholeChain = 1;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdRevocationCheckChainExcludeRoot = 0x00000080;
    private const uint WtdLifetimeSigningFlag = 0x00000800;
    // Instructs WinVerifyTrust to use only locally cached CRL/OCSP data and never
    // initiate a network request.  Without this flag the call can block for up to
    // 15 seconds when the CRL endpoint is unreachable (offline/corporate firewall).
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;

    private static readonly Guid WinTrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private static readonly ConcurrentDictionary<string, string> NtPrefixToDrive =
        new(StringComparer.OrdinalIgnoreCase);
    private static readonly string WindowsRoot =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
    private static readonly string ProgramFilesRoot =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).TrimEnd('\\');
    private static readonly PathTrustPolicy[] PathPolicies =
    [
        new(
            "windows-system32",
            Path.Combine(WindowsRoot, "System32"),
            RequireSigned: true,
            RequireMicrosoftPublisher: true),
        new(
            "windows-syswow64",
            Path.Combine(WindowsRoot, "SysWOW64"),
            RequireSigned: true,
            RequireMicrosoftPublisher: true),
        new(
            "windows-winsxs",
            Path.Combine(WindowsRoot, "WinSxS"),
            RequireSigned: true,
            RequireMicrosoftPublisher: true),
        new(
            "windows-servicing",
            Path.Combine(WindowsRoot, "servicing"),
            RequireSigned: true,
            RequireMicrosoftPublisher: true),
        new(
            "windows-defender",
            Path.Combine(ProgramFilesRoot, "Windows Defender"),
            RequireSigned: true,
            RequireMicrosoftPublisher: true)
    ];

    // SHA-1 thumbprints of Microsoft's code-signing root CAs.  Comparing the root of
    // the full certificate chain against this set is far harder to spoof than matching
    // the signer's Subject CN (which can be crafted to normalize to "microsoftcorporation").
    private static readonly HashSet<string> MicrosoftRootThumbprints = new(StringComparer.OrdinalIgnoreCase)
    {
        // Microsoft Root Certificate Authority 2011
        "8f43288ad272f3103b6fb1428485ea3014c0bcfe",
        // Microsoft Root Certificate Authority 2010
        "3b1efd3a66ea28b16697394703a72ca340a05bd5",
        // Microsoft Root Certificate Authority (2001)
        "cdd4eeae6000ac7f40c3802c171e30148030c072",
        // Microsoft Authenticode(tm) Root Authority (legacy)
        "a43489159a520f0d93d032ccaf37e7fe20a8b419",
    };

    private static readonly HashSet<string> HighTrustPublisherNames = new(StringComparer.Ordinal)
    {
        "microsoftcorporation",
        "microsoftwindows",
        "microsoftwindowspublisher",
        "microsoftcorporationiii",
        "microsoft3rdpartyapplicationcomponent"
    };

    private static readonly HashSet<string> MediumTrustPublisherNames = new(StringComparer.Ordinal)
    {
        "googlellc",
        "adobeinc",
        "mozillacorporation",
        "oraclecorporation",
        "nvidiacorporation",
        "intelcorporation",
        "vmwareinc",
        "citrixsystemsinc",
        "dellinc",
        "hpinc",
        "lenovo",
        "appleinc",
        "zoomvideocommunicationsinc",
        "dropboxinc",
        "thedocumentfoundation",
        "videolan",
        "githubinc"
    };

    public static bool TryGetTrust(string? rawPath, out AuthenticodeFileTrust trust)
    {
        trust = default;
        if (!TryResolveReadablePath(rawPath, out var resolvedPath))
        {
            return false;
        }

        trust = EvaluateTrust(resolvedPath);
        return true;
    }

    public static bool TryResolveReadablePath(string? rawPath, out string resolvedPath)
    {
        resolvedPath = string.Empty;
        if (!TryNormalizeDisplayPath(rawPath, out var normalizedPath))
        {
            return false;
        }

        if (!File.Exists(normalizedPath))
        {
            return false;
        }

        resolvedPath = normalizedPath;
        return true;
    }

    public static bool TryNormalizeDisplayPath(string? rawPath, out string normalizedPath)
    {
        normalizedPath = string.Empty;
        if (string.IsNullOrWhiteSpace(rawPath))
        {
            return false;
        }

        var normalized = NormalizePath(rawPath);
        if (normalized.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase) &&
            TryConvertNtPathToDosPath(normalized, out var dosPath))
        {
            normalized = NormalizePath(dosPath);
        }

        if (string.IsNullOrWhiteSpace(normalized))
        {
            return false;
        }

        normalizedPath = normalized;
        return true;
    }

    private static AuthenticodeFileTrust EvaluateTrust(string resolvedPath)
    {
        var winTrustSucceeded = TryEvaluateAuthenticodeTrust(
            resolvedPath,
            out var signerCertificate,
            out var timestampCertificate,
            out var statusCode,
            out var statusSummary);

        signerCertificate ??= TryGetEmbeddedSignerCertificate(resolvedPath);

        var publisherName = GetPublisherName(signerCertificate);
        var publisherTrustLevel = ClassifyPublisherTrustLevel(publisherName);
        // Use root certificate thumbprint to determine Microsoft publisher — string-normalized
        // CN comparison is too weak: a certificate with CN="Microsoft.Corporation" or with
        // Unicode look-alike characters would pass the old check after normalization.
        var isMicrosoftPublisher = signerCertificate is not null && IsSignedByMicrosoftRoot(signerCertificate);
        if (!isMicrosoftPublisher && publisherTrustLevel == PublisherTrustLevel.High)
        {
            // Demote CN-matched entries that failed the root-thumbprint check.
            publisherTrustLevel = PublisherTrustLevel.Low;
        }

        var hasTimestampSignature = timestampCertificate is not null;
        var isRevoked = IsRevokedStatus(statusCode);
        // We only consider revocation truly checked when WinVerifyTrust succeeded
        // with a live CRL/OCSP response (status 0).  Offline/cache-miss errors mean
        // the signature was structurally valid but we couldn't confirm revocation status.
        var revocationChecked = statusCode == 0;

        var policy = EvaluatePathPolicy(
            resolvedPath,
            winTrustSucceeded,
            isMicrosoftPublisher);

        // Keep signature validity independent from path-policy checks so a
        // publisher classification miss does not collapse a validly signed
        // binary into Unsigned.
        var finalSigned = winTrustSucceeded;
        var finalMicrosoftSigned = winTrustSucceeded && isMicrosoftPublisher;

        var summary = statusSummary;
        if (!policy.IsSatisfied)
        {
            summary = string.IsNullOrWhiteSpace(summary)
                ? policy.FailureReason
                : $"{summary}; {policy.FailureReason}";
        }

        if (string.IsNullOrWhiteSpace(summary))
        {
            summary = winTrustSucceeded ? "trusted" : "untrusted";
        }

        return new AuthenticodeFileTrust(
            resolvedPath,
            finalSigned,
            finalMicrosoftSigned,
            publisherTrustLevel,
            publisherName,
            hasTimestampSignature,
            RevocationChecked: revocationChecked,
            ChainValid: winTrustSucceeded,
            IsRevoked: isRevoked,
            PathPolicySatisfied: policy.IsSatisfied,
            PathPolicyName: policy.PolicyName,
            StatusSummary: summary);
    }

    /// <summary>
    /// Verifies the signing chain's root CA thumbprint against the hard-coded set of
    /// Microsoft root certificates.  This is significantly harder to spoof than
    /// comparing the signer's Subject CN string.
    /// </summary>
    private static bool IsSignedByMicrosoftRoot(X509Certificate2 signerCertificate)
    {
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags =
                X509VerificationFlags.AllowUnknownCertificateAuthority |
                X509VerificationFlags.IgnoreNotTimeValid;
            // Build() may return false if the chain is incomplete; we still get ChainElements.
            chain.Build(signerCertificate);
            if (chain.ChainElements.Count == 0)
            {
                return false;
            }

            var root = chain.ChainElements[^1].Certificate;
            return MicrosoftRootThumbprints.Contains(root.Thumbprint);
        }
        catch
        {
            return false;
        }
    }

    private static PathPolicyEvaluation EvaluatePathPolicy(
        string resolvedPath,
        bool winTrustSucceeded,
        bool isMicrosoftPublisher)
    {
        foreach (var policy in PathPolicies)
        {
            if (!PathStartsWith(resolvedPath, policy.DirectoryPrefix))
            {
                continue;
            }

            if (policy.RequireSigned && !winTrustSucceeded)
            {
                return new PathPolicyEvaluation(
                    policy.Name,
                    IsSatisfied: false,
                    $"path-policy={policy.Name}: require-signed");
            }

            if (policy.RequireMicrosoftPublisher && !isMicrosoftPublisher)
            {
                return new PathPolicyEvaluation(
                    policy.Name,
                    IsSatisfied: false,
                    $"path-policy={policy.Name}: require-microsoft");
            }

            return new PathPolicyEvaluation(policy.Name, IsSatisfied: true, string.Empty);
        }

        return new PathPolicyEvaluation(string.Empty, IsSatisfied: true, string.Empty);
    }

    private static bool TryEvaluateAuthenticodeTrust(
        string filePath,
        out X509Certificate2? signerCertificate,
        out X509Certificate2? timestampCertificate,
        out int statusCode,
        out string statusSummary)
    {
        signerCertificate = null;
        timestampCertificate = null;
        statusCode = unchecked((int)0x80004005);
        statusSummary = string.Empty;

        WINTRUST_FILE_INFO fileInfo = new()
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, fDeleteOld: false);

            WINTRUST_DATA trustData = new()
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeWholeChain,
                dwUnionChoice = WtdChoiceFile,
                pInfoStruct = fileInfoPtr,
                dwStateAction = WtdStateActionVerify,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = WtdRevocationCheckChainExcludeRoot | WtdLifetimeSigningFlag | WtdCacheOnlyUrlRetrieval,
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero
            };

            try
            {
                var action = WinTrustActionGenericVerifyV2;
                statusCode = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
                signerCertificate = TryGetSignerCertificate(trustData.hWVTStateData);
                timestampCertificate = TryGetTimestampCertificate(trustData.hWVTStateData);
                statusSummary = DescribeWinTrustStatus(statusCode);
                // Treat revocation-offline codes as a successful signature check with
                // revocation status unknown.  With WTD_CACHE_ONLY_URL_RETRIEVAL the call
                // will never block on the network; these codes simply mean the local CRL
                // cache had no data.  The actual CERT_REVOKED code (0x800B010C) is NOT
                // in this set and will still cause winTrustSucceeded = false.
                return statusCode == 0 || IsRevocationOfflineStatus(statusCode);
            }
            finally
            {
                var action = WinTrustActionGenericVerifyV2;
                trustData.dwStateAction = WtdStateActionClose;
                _ = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
            }
        }
        catch (Exception ex)
        {
            statusSummary = $"wintrust-exception: {ex.Message}";
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    private static X509Certificate2? TryGetSignerCertificate(IntPtr stateData)
    {
        return TryGetProviderCertificate(stateData, isCounterSigner: false);
    }

    private static X509Certificate2? TryGetTimestampCertificate(IntPtr stateData)
    {
        return TryGetProviderCertificate(stateData, isCounterSigner: true);
    }

    private static X509Certificate2? TryGetProviderCertificate(IntPtr stateData, bool isCounterSigner)
    {
        if (stateData == IntPtr.Zero)
        {
            return null;
        }

        var providerData = WTHelperProvDataFromStateData(stateData);
        if (providerData == IntPtr.Zero)
        {
            return null;
        }

        var signerPtr = WTHelperGetProvSignerFromChain(providerData, 0, isCounterSigner, 0);
        if (signerPtr == IntPtr.Zero)
        {
            return null;
        }

        var signer = Marshal.PtrToStructure<CRYPT_PROVIDER_SGNR>(signerPtr);
        if (signer.csCertChain == 0 || signer.pasCertChain == IntPtr.Zero)
        {
            return null;
        }

        var certInfo = Marshal.PtrToStructure<CRYPT_PROVIDER_CERT>(signer.pasCertChain);
        if (certInfo.pCert == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            return new X509Certificate2(certInfo.pCert);
        }
        catch
        {
            return null;
        }
    }

    private static X509Certificate2? TryGetEmbeddedSignerCertificate(string filePath)
    {
        try
        {
#pragma warning disable SYSLIB0057
            var certificate = X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
            return new X509Certificate2(certificate);
        }
        catch
        {
            return null;
        }
    }

    private static string GetPublisherName(X509Certificate2? certificate)
    {
        if (certificate is null)
        {
            return string.Empty;
        }

        var simpleName = certificate.GetNameInfo(X509NameType.SimpleName, false);
        if (!string.IsNullOrWhiteSpace(simpleName))
        {
            return simpleName.Trim();
        }

        return certificate.Subject ?? string.Empty;
    }

    private static PublisherTrustLevel ClassifyPublisherTrustLevel(string publisherName)
    {
        var normalized = NormalizePublisherName(publisherName);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return PublisherTrustLevel.Unknown;
        }

        if (HighTrustPublisherNames.Contains(normalized))
        {
            return PublisherTrustLevel.High;
        }

        if (MediumTrustPublisherNames.Contains(normalized))
        {
            return PublisherTrustLevel.Medium;
        }

        return PublisherTrustLevel.Low;
    }

    private static string NormalizePublisherName(string publisherName)
    {
        if (string.IsNullOrWhiteSpace(publisherName))
        {
            return string.Empty;
        }

        Span<char> buffer = stackalloc char[publisherName.Length];
        var length = 0;
        foreach (var ch in publisherName)
        {
            if (!char.IsLetterOrDigit(ch))
            {
                continue;
            }

            buffer[length++] = char.ToLowerInvariant(ch);
        }

        return new string(buffer[..length]);
    }

    private static bool IsRevokedStatus(int statusCode)
    {
        return unchecked((uint)statusCode) == 0x800B010CUL;
    }

    // These codes indicate that the signature is structurally valid but the CRL/OCSP
    // endpoint could not be reached.  With WtdCacheOnlyUrlRetrieval the network is
    // never contacted, so these are "best-effort" revocation outcomes, not failures.
    private static bool IsRevocationOfflineStatus(int statusCode)
    {
        return unchecked((uint)statusCode) switch
        {
            0x80092013 => true,  // CRYPT_E_REVOCATION_OFFLINE
            0x800B0104 => true,  // CERT_E_REVOCATION_FAILURE (no network path)
            _ => false
        };
    }

    private static string DescribeWinTrustStatus(int statusCode)
    {
        return unchecked((uint)statusCode) switch
        {
            0x00000000 => "trusted",
            0x800B0100 => "no-signature",
            0x800B0101 => "certificate-expired",
            0x800B0104 => "revocation-failure",
            0x800B0109 => "untrusted-root",
            0x800B010A => "certificate-chain-invalid",
            0x800B010C => "certificate-revoked",
            0x80092013 => "revocation-offline",
            0x80096010 => "bad-digest",
            0x800B0111 => "explicit-distrust",
            _ => $"wintrust=0x{unchecked((uint)statusCode):X8}"
        };
    }

    private static bool PathStartsWith(string path, string prefix)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(prefix))
        {
            return false;
        }

        var normalizedPath = path.Trim().Replace('/', '\\');
        var normalizedPrefix = prefix.Trim().Replace('/', '\\').TrimEnd('\\') + "\\";
        return normalizedPath.StartsWith(normalizedPrefix, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePath(string value)
    {
        var trimmed = value.Trim().TrimEnd('\0').Replace('/', '\\');
        if (trimmed.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed[4..];
        }
        else if (trimmed.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed[4..];
        }

        if (trimmed.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = WindowsRoot + trimmed[11..];
        }

        if (TryNormalizeNtDevicePath(trimmed, out var ntPath))
        {
            return ntPath;
        }

        try
        {
            return Path.GetFullPath(trimmed);
        }
        catch
        {
            return trimmed;
        }
    }

    private static bool TryNormalizeNtDevicePath(string path, out string normalizedNtPath)
    {
        normalizedNtPath = string.Empty;
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var trimmed = path.Trim().Replace('/', '\\');
        if (trimmed.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            normalizedNtPath = trimmed;
            return true;
        }

        if (trimmed.Length > 10 &&
            char.IsLetter(trimmed[0]) &&
            trimmed[1] == ':' &&
            trimmed[2] == '\\' &&
            trimmed.AsSpan(3).StartsWith(@"Device\", StringComparison.OrdinalIgnoreCase))
        {
            normalizedNtPath = "\\" + trimmed[3..];
            return true;
        }

        return false;
    }

    private static bool TryConvertNtPathToDosPath(string path, out string dosPath)
    {
        dosPath = string.Empty;
        if (string.IsNullOrWhiteSpace(path) ||
            !path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        foreach (var pair in NtPrefixToDrive)
        {
            if (path.StartsWith(pair.Key, StringComparison.OrdinalIgnoreCase))
            {
                dosPath = BuildDosPath(pair.Value, path, pair.Key);
                return true;
            }
        }

        foreach (var drive in Environment.GetLogicalDrives())
        {
            var driveLetter = drive.TrimEnd('\\');
            var ntPrefix = QueryNtDevicePrefix(driveLetter);
            if (string.IsNullOrWhiteSpace(ntPrefix))
            {
                continue;
            }

            NtPrefixToDrive.TryAdd(ntPrefix, driveLetter);
            if (!path.StartsWith(ntPrefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            dosPath = BuildDosPath(driveLetter, path, ntPrefix);
            return true;
        }

        return TryResolveByDriveProbe(path, out dosPath);
    }

    private static string BuildDosPath(string driveLetter, string ntPath, string ntPrefix)
    {
        var suffix = ntPath.Length > ntPrefix.Length
            ? ntPath[ntPrefix.Length..]
            : string.Empty;

        if (string.IsNullOrEmpty(suffix))
        {
            return driveLetter + "\\";
        }

        return suffix.StartsWith("\\", StringComparison.Ordinal)
            ? driveLetter + suffix
            : driveLetter + "\\" + suffix;
    }

    private static string QueryNtDevicePrefix(string driveLetter)
    {
        var buffer = new char[1024];
        var chars = QueryDosDeviceW(driveLetter, buffer, buffer.Length);
        if (chars == 0)
        {
            return string.Empty;
        }

        var raw = new string(buffer, 0, (int)chars);
        var parts = raw.Split('\0', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length == 0 ? string.Empty : parts[0];
    }

    private static bool TryResolveByDriveProbe(string ntPath, out string dosPath)
    {
        dosPath = string.Empty;
        const string marker = @"\Device\HarddiskVolume";
        if (!ntPath.StartsWith(marker, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var slashAfterVolume = ntPath.IndexOf('\\', marker.Length);
        if (slashAfterVolume < 0 || slashAfterVolume >= ntPath.Length - 1)
        {
            return false;
        }

        var suffix = ntPath[slashAfterVolume..];
        foreach (var drive in Environment.GetLogicalDrives())
        {
            var root = drive.TrimEnd('\\');
            var candidate = root + suffix;
            if (!File.Exists(candidate))
            {
                continue;
            }

            dosPath = candidate;
            return true;
        }

        return false;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDeviceW(
        string lpDeviceName,
        [Out] char[] lpTargetPath,
        int ucchMax);

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd,
        [In] ref Guid pgActionID,
        [In] ref WINTRUST_DATA pWVTData);

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(
        IntPtr pProvData,
        uint idxSigner,
        [MarshalAs(UnmanagedType.Bool)] bool fCounterSigner,
        uint idxCounterSigner);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfoStruct;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CRYPT_PROVIDER_SGNR
    {
        public uint cbStruct;
        public FILETIME sftVerifyAsOf;
        public uint csCertChain;
        public IntPtr pasCertChain;
        public uint dwSignerType;
        public IntPtr psSigner;
        public uint dwError;
        public uint csCounterSigners;
        public IntPtr pasCounterSigners;
        public IntPtr pChainContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CRYPT_PROVIDER_CERT
    {
        public uint cbStruct;
        public IntPtr pCert;
        [MarshalAs(UnmanagedType.Bool)]
        public bool fCommercial;
        [MarshalAs(UnmanagedType.Bool)]
        public bool fTrustedRoot;
        [MarshalAs(UnmanagedType.Bool)]
        public bool fSelfSigned;
        [MarshalAs(UnmanagedType.Bool)]
        public bool fTestCert;
        public uint dwRevokedReason;
        public uint dwConfidence;
        public uint dwError;
        public IntPtr pTrustListContext;
        [MarshalAs(UnmanagedType.Bool)]
        public bool fTrustListSignerCert;
        public IntPtr pCtlContext;
        public uint dwCtlError;
        [MarshalAs(UnmanagedType.Bool)]
        public bool fIsCyclic;
        public IntPtr pChainElement;
    }

    private readonly record struct PathTrustPolicy(
        string Name,
        string DirectoryPrefix,
        bool RequireSigned,
        bool RequireMicrosoftPublisher);

    private readonly record struct PathPolicyEvaluation(
        string PolicyName,
        bool IsSatisfied,
        string FailureReason);
}
