using System.Text.Json;
using RollbackGuard.Common.Models;

namespace RollbackGuard.Common.Storage;

public static class StatusStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };
    private static readonly object WriteSync = new();

    public static void Save(string path, RuntimeStatus status)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var json = JsonSerializer.Serialize(status, JsonOptions);

        lock (WriteSync)
        {
            for (var attempt = 1; attempt <= 8; attempt++)
            {
                try
                {
                    using var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
                    using var writer = new StreamWriter(stream);
                    writer.Write(json);
                    writer.Flush();
                    stream.Flush(true);
                    return;
                }
                catch (IOException) when (attempt < 8)
                {
                    Thread.Sleep(25 * attempt);
                }
            }
        }

        throw new IOException($"save status failed after retries: {path}");
    }

    public static RuntimeStatus? TryLoad(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream);
            var json = NormalizeJson(reader.ReadToEnd());
            if (string.IsNullOrWhiteSpace(json))
            {
                return null;
            }

            return JsonSerializer.Deserialize<RuntimeStatus>(json, JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    private static string NormalizeJson(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return string.Empty;
        }

        var json = raw.Trim();
        if (json.IndexOf('\0') >= 0)
        {
            json = json.Replace("\0", string.Empty, StringComparison.Ordinal);
        }

        return json;
    }
}
