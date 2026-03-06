using System.Security.Cryptography;
using System.Text;
using RollbackGuard.Common.Diagnostics;
using RollbackGuard.Service.Infra;

namespace RollbackGuard.Service.Engine;

public sealed class HoneypotManager
{
    private const string HoneypotDocxName = "!00_protect_do_not_modify.docx";
    private const string HoneypotJpgName = "!00_protect_do_not_modify.jpg";

    private static readonly byte[] DocxContent = Encoding.UTF8.GetBytes(
        "This file is protected by RollbackGuard. Do not modify or delete.");

    private static readonly byte[] JpgContent = Encoding.UTF8.GetBytes(
        "RollbackGuard honeypot image file. Protected content.");

    private readonly List<string> _deployedPaths = [];
    private readonly Dictionary<string, byte[]> _expectedHashes = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<string> DeployedPaths => _deployedPaths;

    public void Deploy()
    {
        var directories = GetDeploymentDirectories();

        foreach (var dir in directories)
        {
            try
            {
                DeployFile(dir, HoneypotDocxName, DocxContent);
                DeployFile(dir, HoneypotJpgName, JpgContent);
            }
            catch (Exception ex)
            {
                StartupLog.Write("Honeypot", $"deploy failed: dir={dir}", ex);
            }
        }

        StartupLog.Write("Honeypot", $"deployed {_deployedPaths.Count} honeypot files");
    }

    public void RegisterWithMinifilter(DriverCommandBridge miniBridge)
    {
        if (_deployedPaths.Count == 0)
        {
            return;
        }

        var ok = miniBridge.TrySetHoneyFiles(_deployedPaths.ToArray(), out var message);
        StartupLog.Write("Honeypot", $"minifilter registration: ok={ok}, paths={_deployedPaths.Count}, message={message}");
    }

    public bool IsHoneypotPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        return _deployedPaths.Any(hp => path.Equals(hp, StringComparison.OrdinalIgnoreCase));
    }

    private void DeployFile(string directory, string fileName, byte[] content)
    {
        var fullPath = Path.Combine(directory, fileName);

        if (File.Exists(fullPath))
        {
            // Verify hash
            var hash = ComputeHash(fullPath);
            if (_expectedHashes.TryGetValue(fullPath, out var expected) &&
                hash.SequenceEqual(expected))
            {
                _deployedPaths.Add(fullPath);
                return;
            }
        }

        File.WriteAllBytes(fullPath, content);
        File.SetAttributes(fullPath, FileAttributes.Hidden | FileAttributes.System);

        var computedHash = SHA256.HashData(content);
        _expectedHashes[fullPath] = computedHash;
        _deployedPaths.Add(fullPath);

        StartupLog.Write("Honeypot", $"deployed: {fullPath}");
    }

    private static byte[] ComputeHash(string filePath)
    {
        try
        {
            var bytes = File.ReadAllBytes(filePath);
            return SHA256.HashData(bytes);
        }
        catch
        {
            return [];
        }
    }

    private static List<string> GetDeploymentDirectories()
    {
        var dirs = new List<string>();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        AddIfExists(dirs, Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
        AddIfExists(dirs, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
        AddIfExists(dirs, Path.Combine(userProfile, "Downloads"));
        AddIfExists(dirs, Environment.GetFolderPath(Environment.SpecialFolder.MyPictures));

        return dirs;
    }

    private static void AddIfExists(List<string> dirs, string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        try
        {
            var full = Path.GetFullPath(path);
            if (Directory.Exists(full) &&
                !dirs.Any(d => d.Equals(full, StringComparison.OrdinalIgnoreCase)))
            {
                dirs.Add(full);
            }
        }
        catch
        {
            // ignore
        }
    }
}
