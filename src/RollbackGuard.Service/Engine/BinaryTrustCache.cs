using System.Security.Cryptography;
using System.Text.Json;
using RollbackGuard.Common.Security;
using RollbackGuard.Common.Runtime;
using System.Text;

namespace RollbackGuard.Service.Engine;

public readonly record struct BinaryTrustVerdict(
    string ResolvedPath,
    string FileHash,
    bool IsSigned,
    bool IsMicrosoftSigned,
    ExecutionTrustTier Tier,
    bool CacheHit,
    PublisherTrustLevel PublisherTrustLevel = PublisherTrustLevel.Unknown,
    string PublisherName = "",
    bool HasTimestampSignature = false,
    bool RevocationChecked = false,
    bool ChainValid = false,
    bool IsRevoked = false,
    bool PathPolicySatisfied = true,
    string PathPolicyName = "",
    string StatusSummary = "",
    SeSigningLevel KernelSigningLevel = SeSigningLevel.Unchecked);

public sealed class BinaryTrustCache
{
    private readonly string _cachePath;
    private readonly object _sync = new();
    private readonly Dictionary<string, CachedEntry> _hashCache = new(StringComparer.OrdinalIgnoreCase);
    private bool _loaded;

    public BinaryTrustCache(string? cachePath = null)
    {
        _cachePath = string.IsNullOrWhiteSpace(cachePath)
            ? RuntimePaths.SignatureCachePath
            : cachePath;
    }

    public bool TryGetFastVerdict(string? filePath, out BinaryTrustVerdict verdict)
    {
        verdict = default;
        if (!SignatureTrustEvaluator.TryResolveReadablePath(filePath, out var resolvedPath))
        {
            return false;
        }

        if (!TryComputeSha256(resolvedPath, out var hash))
        {
            return false;
        }

        EnsureLoaded();

        lock (_sync)
        {
            if (!_hashCache.TryGetValue(hash, out var cached))
            {
                return false;
            }

            if (!cached.IsSigned && ShouldForceUnsignedRevalidation(resolvedPath))
            {
                _hashCache.Remove(hash);
                return false;
            }

            TouchCachedEntryUnsafe(resolvedPath, hash);
            verdict = ToVerdict(resolvedPath, cached, cacheHit: true);
            return true;
        }
    }

    public bool TryGetOrAddVerdict(string? filePath, out BinaryTrustVerdict verdict)
    {
        verdict = default;
        if (!SignatureTrustEvaluator.TryResolveReadablePath(filePath, out var resolvedPath))
        {
            return false;
        }

        if (!TryComputeSha256(resolvedPath, out var hash))
        {
            return false;
        }

        EnsureLoaded();

        lock (_sync)
        {
            if (_hashCache.TryGetValue(hash, out var cached))
            {
                if (!cached.IsSigned && ShouldForceUnsignedRevalidation(resolvedPath))
                {
                    _hashCache.Remove(hash);
                }
                else
                {
                    TouchCachedEntryUnsafe(resolvedPath, hash);
                    verdict = ToVerdict(resolvedPath, cached, cacheHit: true);
                    return true;
                }
            }
        }

        if (!SignatureTrustEvaluator.TryGetTrust(resolvedPath, out var trust))
        {
            return false;
        }

        var created = new CachedEntry
        {
            Hash = hash,
            IsSigned = trust.IsSigned,
            IsMicrosoftSigned = trust.IsMicrosoftSigned,
            PublisherTrustLevel = trust.PublisherTrustLevel,
            PublisherName = trust.PublisherName,
            HasTimestampSignature = trust.HasTimestampSignature,
            RevocationChecked = trust.RevocationChecked,
            ChainValid = trust.ChainValid,
            IsRevoked = trust.IsRevoked,
            PathPolicySatisfied = trust.PathPolicySatisfied,
            PathPolicyName = trust.PathPolicyName,
            StatusSummary = trust.StatusSummary,
            KernelSigningLevel = trust.KernelSigningLevel,
            LastSeenPath = resolvedPath,
            LastSeenUtc = DateTimeOffset.UtcNow
        };

        lock (_sync)
        {
            _hashCache[hash] = created;
            TouchCachedEntryUnsafe(resolvedPath, hash);
            SaveUnsafe();
        }

        verdict = ToVerdict(resolvedPath, created, cacheHit: false);
        return true;
    }

    public static BinaryTrustVerdict CreateFallbackUnsigned(string? filePath)
    {
        var path = filePath?.Trim().TrimEnd('\0') ?? string.Empty;
        return new BinaryTrustVerdict(path, string.Empty, false, false, ExecutionTrustTier.Unsigned, false);
    }

    public static BinaryTrustVerdict CreateFallbackUnknown(string? filePath)
    {
        var path = filePath?.Trim().TrimEnd('\0') ?? string.Empty;
        return new BinaryTrustVerdict(
            path,
            string.Empty,
            false,
            false,
            ExecutionTrustTier.Unknown,
            false,
            StatusSummary: "fallback-unknown");
    }

    private void EnsureLoaded()
    {
        lock (_sync)
        {
            if (_loaded)
            {
                return;
            }

            _loaded = true;
            try
            {
                var directory = Path.GetDirectoryName(_cachePath);
                if (!string.IsNullOrWhiteSpace(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                if (!File.Exists(_cachePath))
                {
                    return;
                }

                string? json = null;
                var rawBytes = File.ReadAllBytes(_cachePath);

                // Attempt DPAPI decryption first (current format).
                // Fall back to plain-text JSON to handle pre-DPAPI cache files from
                // older versions — they will be overwritten on the next save.
                try
                {
                    var jsonBytes = ProtectedData.Unprotect(rawBytes, null, DataProtectionScope.CurrentUser);
                    json = Encoding.UTF8.GetString(jsonBytes);
                }
                catch
                {
                    // Could be a plain-text legacy file; try interpreting as UTF-8 JSON.
                    try
                    {
                        json = Encoding.UTF8.GetString(rawBytes);
                    }
                    catch
                    {
                        // Unrecoverable — start with an empty cache.
                        return;
                    }
                }

                var data = JsonSerializer.Deserialize<CacheDocument>(json);
                if (data?.Entries is null)
                {
                    return;
                }

                foreach (var entry in data.Entries)
                {
                    if (string.IsNullOrWhiteSpace(entry.Hash))
                    {
                        continue;
                    }

                    NormalizeLoadedEntry(entry, data.SchemaVersion);
                    _hashCache[entry.Hash] = entry;
                }
            }
            catch
            {
                _hashCache.Clear();
            }
        }
    }

    private void SaveUnsafe()
    {
        var document = new CacheDocument
        {
            SchemaVersion = 3,
            Entries = _hashCache.Values
                .OrderBy(item => item.LastSeenUtc)
                .TakeLast(8192)
                .ToList()
        };

        var json = JsonSerializer.Serialize(document, new JsonSerializerOptions
        {
            WriteIndented = false
        });

        // Protect the cache with DPAPI (CurrentUser scope = the service account,
        // typically SYSTEM).  An attacker with administrator-but-not-SYSTEM rights
        // cannot decrypt and tamper with cached verdicts to inject false "trusted"
        // entries for malicious binaries.
        var jsonBytes = Encoding.UTF8.GetBytes(json);
        var protectedBytes = ProtectedData.Protect(jsonBytes, null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(_cachePath, protectedBytes);
    }

    private void TouchCachedEntryUnsafe(string resolvedPath, string hash)
    {
        if (_hashCache.TryGetValue(hash, out var cached))
        {
            cached.LastSeenPath = resolvedPath;
            cached.LastSeenUtc = DateTimeOffset.UtcNow;
            _hashCache[hash] = cached;
        }
    }

    private static BinaryTrustVerdict ToVerdict(string resolvedPath, CachedEntry entry, bool cacheHit)
    {
        var tier = entry.IsSigned
            ? (entry.IsMicrosoftSigned ? ExecutionTrustTier.MicrosoftSigned : ExecutionTrustTier.Signed)
            : ExecutionTrustTier.Unsigned;
        return new BinaryTrustVerdict(
            resolvedPath,
            entry.Hash,
            entry.IsSigned,
            entry.IsMicrosoftSigned,
            tier,
            cacheHit,
            entry.PublisherTrustLevel,
            entry.PublisherName,
            entry.HasTimestampSignature,
            entry.RevocationChecked,
            entry.ChainValid,
            entry.IsRevoked,
            entry.PathPolicySatisfied,
            entry.PathPolicyName,
            entry.StatusSummary,
            entry.KernelSigningLevel);
    }

    private static bool TryComputeSha256(string path, out string hash)
    {
        hash = string.Empty;
        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(stream);
            hash = Convert.ToHexString(bytes);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool ShouldForceUnsignedRevalidation(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        if (TrustedProcessValidator.IsRollbackGuardBinary(path))
        {
            return true;
        }

        var normalized = path.Trim().Replace('/', '\\');
        return normalized.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase);
    }

    private sealed class CacheDocument
    {
        public int SchemaVersion { get; set; }
        public List<CachedEntry> Entries { get; set; } = [];
    }

    private sealed class CachedEntry
    {
        public string Hash { get; set; } = string.Empty;
        public bool IsSigned { get; set; }
        public bool IsMicrosoftSigned { get; set; }
        public PublisherTrustLevel PublisherTrustLevel { get; set; }
        public string PublisherName { get; set; } = string.Empty;
        public bool HasTimestampSignature { get; set; }
        public bool RevocationChecked { get; set; }
        public bool ChainValid { get; set; }
        public bool IsRevoked { get; set; }
        public bool PathPolicySatisfied { get; set; } = true;
        public string PathPolicyName { get; set; } = string.Empty;
        public string StatusSummary { get; set; } = string.Empty;
        public SeSigningLevel KernelSigningLevel { get; set; }
        public string LastSeenPath { get; set; } = string.Empty;
        public DateTimeOffset LastSeenUtc { get; set; }
    }

    private static void NormalizeLoadedEntry(CachedEntry entry, int schemaVersion)
    {
        // Schema v3 adds KernelSigningLevel (byte enum, defaults to 0 = Unchecked).
        // Entries from v2 cache files deserialise with KernelSigningLevel = Unchecked,
        // which is the correct sentinel: "not yet queried from the kernel".
        if (schemaVersion >= 3)
            return;

        if (schemaVersion >= 2)
        {
            if (entry.IsSigned && !entry.ChainValid)
            {
                entry.ChainValid = true;
            }

            if (string.IsNullOrWhiteSpace(entry.StatusSummary))
            {
                entry.StatusSummary = entry.IsSigned ? "trusted" : "cached-unsigned";
            }

            return;
        }

        entry.PublisherTrustLevel = entry.IsMicrosoftSigned
            ? PublisherTrustLevel.High
            : entry.IsSigned ? PublisherTrustLevel.Low : PublisherTrustLevel.Unknown;
        entry.ChainValid = entry.IsSigned;
        entry.PathPolicySatisfied = true;
        entry.StatusSummary = entry.IsSigned ? "legacy-cache-trusted" : "legacy-cache-unsigned";
    }
}
