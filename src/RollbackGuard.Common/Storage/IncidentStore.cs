using System.Text.Json;
using RollbackGuard.Common.Models;

namespace RollbackGuard.Common.Storage;

public static class IncidentStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    private static readonly object WriteSync = new();

    public static void Append(string path, IncidentLogEntry entry)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var json = JsonSerializer.Serialize(entry, JsonOptions);
        var line = json + Environment.NewLine;

        lock (WriteSync)
        {
            for (var attempt = 1; attempt <= 3; attempt++)
            {
                try
                {
                    using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                    using var writer = new StreamWriter(stream);
                    writer.Write(line);
                    writer.Flush();
                    return;
                }
                catch (IOException) when (attempt < 3)
                {
                    Thread.Sleep(20 * attempt);
                }
            }
        }

        throw new IOException($"append incident failed after retries: {path}");
    }

    public static IReadOnlyList<IncidentLogEntry> ReadLatest(string path, int limit)
    {
        if (!File.Exists(path))
        {
            return [];
        }

        var max = Math.Max(1, limit);
        var ring = new Queue<string>(max + 1);

        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        using (var reader = new StreamReader(stream))
        {
            while (true)
            {
                var line = reader.ReadLine();
                if (line is null)
                {
                    break;
                }

                var normalizedLine = NormalizeJsonLine(line);
                if (string.IsNullOrWhiteSpace(normalizedLine))
                {
                    continue;
                }

                ring.Enqueue(normalizedLine);
                if (ring.Count > max)
                {
                    ring.Dequeue();
                }
            }
        }

        var list = new List<IncidentLogEntry>();
        foreach (var line in ring)
        {
            try
            {
                var parsed = JsonSerializer.Deserialize<IncidentLogEntry>(line, JsonOptions);
                if (parsed is not null)
                {
                    list.Add(parsed);
                }
            }
            catch (JsonException)
            {
                // Skip malformed log lines to keep UI readable even with partial/corrupted writes.
            }
        }

        return list;
    }

    public static IReadOnlyList<IncidentLogEntry> ReadAll(string path)
    {
        if (!File.Exists(path))
        {
            return [];
        }

        var list = new List<IncidentLogEntry>();

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream);
        while (true)
        {
            var line = reader.ReadLine();
            if (line is null)
            {
                break;
            }

            var normalizedLine = NormalizeJsonLine(line);
            if (string.IsNullOrWhiteSpace(normalizedLine))
            {
                continue;
            }

            try
            {
                var parsed = JsonSerializer.Deserialize<IncidentLogEntry>(normalizedLine, JsonOptions);
                if (parsed is not null)
                {
                    list.Add(parsed);
                }
            }
            catch (JsonException)
            {
                // Skip malformed log lines to keep UI readable even with partial/corrupted writes.
            }
        }

        return list;
    }

    public static void Overwrite(string path, IReadOnlyList<IncidentLogEntry> entries)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        lock (WriteSync)
        {
            for (var attempt = 1; attempt <= 3; attempt++)
            {
                try
                {
                    using var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
                    using var writer = new StreamWriter(stream);

                    foreach (var entry in entries)
                    {
                        var json = JsonSerializer.Serialize(entry, JsonOptions);
                        writer.WriteLine(json);
                    }

                    writer.Flush();
                    return;
                }
                catch (IOException) when (attempt < 3)
                {
                    Thread.Sleep(20 * attempt);
                }
            }
        }

        throw new IOException($"overwrite incident failed after retries: {path}");
    }

    private static string NormalizeJsonLine(string? line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return string.Empty;
        }

        var value = line.Trim();
        if (value.IndexOf('\0') >= 0)
        {
            value = value.Replace("\0", string.Empty, StringComparison.Ordinal);
        }

        return value;
    }
}
