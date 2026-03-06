using System.IO.Compression;

namespace RollbackGuard.Service.Engine;

public readonly record struct CompressionRatioVerdict(
    bool Sampled,
    bool Confirmed,
    double SavingsRatio,
    int SampleSize,
    string Summary);

public static class CompressionRatioAnalyzer
{
    private const int MinSampleBytes = 1024;
    private const int MaxSampleBytes = 64 * 1024;
    private const double StrongRandomSavingsThreshold = 0.03;

    public static bool TryEvaluate(string? rawPath, out CompressionRatioVerdict verdict)
    {
        verdict = default;
        if (!SignatureTrustEvaluator.TryResolveReadablePath(rawPath, out var path) || !File.Exists(path))
        {
            return false;
        }

        byte[] sample;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var length = (int)Math.Min(MaxSampleBytes, stream.Length);
            if (length < MinSampleBytes)
            {
                verdict = new CompressionRatioVerdict(false, false, 0, length, "sample-too-small");
                return true;
            }

            sample = new byte[length];
            var offset = 0;
            while (offset < sample.Length)
            {
                var read = stream.Read(sample, offset, sample.Length - offset);
                if (read <= 0)
                {
                    break;
                }

                offset += read;
            }

            if (offset < MinSampleBytes)
            {
                verdict = new CompressionRatioVerdict(false, false, 0, offset, "sample-too-small");
                return true;
            }

            if (offset != sample.Length)
            {
                Array.Resize(ref sample, offset);
            }
        }
        catch (Exception ex)
        {
            verdict = new CompressionRatioVerdict(false, false, 0, 0, $"sample-read-failed:{ex.GetType().Name}");
            return true;
        }

        if (LooksCompressedMagic(sample))
        {
            verdict = new CompressionRatioVerdict(true, false, 0, sample.Length, "known-compressed-magic");
            return true;
        }

        try
        {
            using var output = new MemoryStream(sample.Length);
            using (var deflate = new DeflateStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
            {
                deflate.Write(sample, 0, sample.Length);
            }

            var compressedLength = Math.Max(1, (int)output.Length);
            var savingsRatio = 1.0 - ((double)compressedLength / sample.Length);
            var confirmed = savingsRatio <= StrongRandomSavingsThreshold;
            verdict = new CompressionRatioVerdict(
                true,
                confirmed,
                savingsRatio,
                sample.Length,
                confirmed
                    ? $"confirmed-random:deflate-savings={savingsRatio:P2}"
                    : $"deflate-savings={savingsRatio:P2}");
            return true;
        }
        catch (Exception ex)
        {
            verdict = new CompressionRatioVerdict(true, false, 0, sample.Length, $"compress-failed:{ex.GetType().Name}");
            return true;
        }
    }

    private static bool LooksCompressedMagic(IReadOnlyList<byte> sample)
    {
        if (sample.Count < 2)
        {
            return false;
        }

        if (sample.Count >= 4 &&
            sample[0] == (byte)'P' &&
            sample[1] == (byte)'K' &&
            (sample[2] == 0x03 || sample[2] == 0x05 || sample[2] == 0x07) &&
            (sample[3] == 0x04 || sample[3] == 0x06 || sample[3] == 0x08))
        {
            return true;
        }

        if (sample[0] == 0xFF && sample[1] == 0xD8)
        {
            return true;
        }

        if (sample.Count >= 8 &&
            sample[0] == 0x89 &&
            sample[1] == (byte)'P' &&
            sample[2] == (byte)'N' &&
            sample[3] == (byte)'G' &&
            sample[4] == 0x0D &&
            sample[5] == 0x0A &&
            sample[6] == 0x1A &&
            sample[7] == 0x0A)
        {
            return true;
        }

        if (sample.Count >= 6 &&
            sample[0] == 0x37 &&
            sample[1] == 0x7A &&
            sample[2] == 0xBC &&
            sample[3] == 0xAF &&
            sample[4] == 0x27 &&
            sample[5] == 0x1C)
        {
            return true;
        }

        if (sample[0] == 0x1F && sample[1] == 0x8B)
        {
            return true; // GZIP
        }

        // RAR: 52 61 72 21 1A 07
        if (sample.Count >= 4 &&
            sample[0] == 0x52 &&
            sample[1] == 0x61 &&
            sample[2] == 0x72 &&
            sample[3] == 0x21)
        {
            return true;
        }

        // BZ2: 42 5A 68
        if (sample.Count >= 3 &&
            sample[0] == 0x42 &&
            sample[1] == 0x5A &&
            sample[2] == 0x68)
        {
            return true;
        }

        // XZ: FD 37 7A 58 5A 00
        if (sample.Count >= 6 &&
            sample[0] == 0xFD &&
            sample[1] == 0x37 &&
            sample[2] == 0x7A &&
            sample[3] == 0x58 &&
            sample[4] == 0x5A &&
            sample[5] == 0x00)
        {
            return true;
        }

        return false;
    }
}
