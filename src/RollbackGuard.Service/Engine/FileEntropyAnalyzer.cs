namespace RollbackGuard.Service.Engine;

public readonly record struct EntropySample(double Entropy, long SampledBytes, long FileSize);

public static class FileEntropyAnalyzer
{
    private const int DefaultMaxBytes = 256 * 1024;
    private const int MinBytes = 4096;

    public static bool TryMeasure(string? rawPath, out EntropySample sample)
    {
        sample = default;
        if (!SignatureTrustEvaluator.TryResolveReadablePath(rawPath, out var path))
        {
            return false;
        }

        FileInfo info;
        try
        {
            info = new FileInfo(path);
            if (!info.Exists || info.Length < MinBytes)
            {
                return false;
            }
        }
        catch
        {
            return false;
        }

        var freq = new int[256];
        long sampled = 0;

        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var remaining = Math.Min(stream.Length, DefaultMaxBytes);
            var buffer = new byte[8192];
            while (remaining > 0)
            {
                var request = (int)Math.Min(buffer.Length, remaining);
                var read = stream.Read(buffer, 0, request);
                if (read <= 0)
                {
                    break;
                }

                sampled += read;
                remaining -= read;
                for (var i = 0; i < read; i++)
                {
                    freq[buffer[i]]++;
                }
            }
        }
        catch
        {
            return false;
        }

        if (sampled < MinBytes)
        {
            return false;
        }

        var entropy = 0.0;
        for (var i = 0; i < freq.Length; i++)
        {
            var count = freq[i];
            if (count <= 0)
            {
                continue;
            }

            var p = (double)count / sampled;
            entropy -= p * Math.Log2(p);
        }

        sample = new EntropySample(entropy, sampled, info.Length);
        return true;
    }
}
