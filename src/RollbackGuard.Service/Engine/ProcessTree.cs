using RollbackGuard.Common.Diagnostics;

namespace RollbackGuard.Service.Engine;

/// <summary>
/// Maintains a full process tree for ancestor chain analysis.
/// Enables detection of multi-level suspicious process chains like:
/// explorer.exe -> cmd.exe -> powershell.exe -> certutil.exe
/// </summary>
public sealed class ProcessTree
{
    private readonly Dictionary<int, ProcessTreeNode> _nodes = [];
    private readonly object _sync = new();
    private const int MaxNodes = 8192;
    private static readonly TimeSpan NodeRetention = TimeSpan.FromMinutes(30);
    private DateTimeOffset _lastPrune = DateTimeOffset.Now;

    public void RegisterProcess(int pid, int ppid, string imagePath, DateTimeOffset createTime)
    {
        lock (_sync)
        {
            var node = new ProcessTreeNode
            {
                PID = pid,
                PPID = ppid,
                ImagePath = imagePath,
                ProcessName = Path.GetFileName(imagePath) ?? string.Empty,
                CreateTime = createTime,
                IsAlive = true
            };

            _nodes[pid] = node;
            PruneIfNeeded();
        }
    }

    public void MarkTerminated(int pid)
    {
        lock (_sync)
        {
            if (_nodes.TryGetValue(pid, out var node))
            {
                node.IsAlive = false;
                node.TerminateTime = DateTimeOffset.Now;
            }
        }
    }

    /// <summary>
    /// Gets the full ancestor chain from the given PID up to the root.
    /// Returns [self, parent, grandparent, ...].
    /// </summary>
    public List<ProcessTreeNode> GetAncestorChain(int pid, int maxDepth = 16)
    {
        var chain = new List<ProcessTreeNode>();
        lock (_sync)
        {
            var currentPid = pid;
            var visited = new HashSet<int>();

            while (currentPid > 4 && chain.Count < maxDepth && visited.Add(currentPid))
            {
                if (!_nodes.TryGetValue(currentPid, out var node))
                    break;

                chain.Add(node);
                currentPid = node.PPID;
            }
        }
        return chain;
    }

    /// <summary>
    /// Gets all children of a process (direct children only).
    /// </summary>
    public List<ProcessTreeNode> GetChildren(int pid)
    {
        lock (_sync)
        {
            return _nodes.Values.Where(n => n.PPID == pid).ToList();
        }
    }

    /// <summary>
    /// Checks if the process has an abnormal parent (e.g., svchost spawning cmd.exe).
    /// </summary>
    public AncestorAnalysis AnalyzeAncestors(int pid)
    {
        var chain = GetAncestorChain(pid);
        if (chain.Count < 2)
            return new AncestorAnalysis(false, 0, string.Empty, []);

        var self = chain[0];
        var parent = chain[1];
        var chainNames = chain.Select(n => n.ProcessName).ToList();

        var suspicionScore = 0;
        var reasons = new List<string>();

        // Check for abnormal parent-child relationships
        if (IsAbnormalParent(parent.ProcessName, self.ProcessName))
        {
            suspicionScore += 25;
            reasons.Add($"abnormal-parent({parent.ProcessName}->{self.ProcessName})");
        }

        // Check for LOLBin chains
        var lolBinDepth = 0;
        foreach (var node in chain)
        {
            var match = LolBinDetector.Evaluate(node.ImagePath);
            if (match != null) lolBinDepth++;
        }
        if (lolBinDepth >= 2)
        {
            suspicionScore += 20 * (lolBinDepth - 1);
            reasons.Add($"lolbin-chain-depth({lolBinDepth})");
        }

        // Check for deep process chain (many levels of spawning)
        if (chain.Count >= 5)
        {
            suspicionScore += 10;
            reasons.Add($"deep-chain({chain.Count})");
        }

        // Check for Office -> script host -> LOLBin chain
        if (chain.Count >= 3)
        {
            for (var i = 2; i < chain.Count; i++)
            {
                var grandParent = chain[i].ProcessName.ToLowerInvariant();
                if (grandParent is "winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe")
                {
                    suspicionScore += 30;
                    reasons.Add($"office-descendant({grandParent})");
                    break;
                }
            }
        }

        return new AncestorAnalysis(
            suspicionScore > 0,
            suspicionScore,
            string.Join(";", reasons),
            chainNames);
    }

    private static bool IsAbnormalParent(string parentName, string childName)
    {
        var parent = parentName.ToLowerInvariant();
        var child = childName.ToLowerInvariant();

        // svchost.exe should not directly spawn command interpreters
        if (parent == "svchost.exe" && child is "cmd.exe" or "powershell.exe" or "pwsh.exe" or "wscript.exe" or "cscript.exe")
            return true;

        // winlogon.exe should not spawn scripting hosts
        if (parent == "winlogon.exe" && child is "cmd.exe" or "powershell.exe" or "mshta.exe")
            return true;

        // lsass.exe should never spawn child processes in normal operation
        if (parent == "lsass.exe" && child is not "svchost.exe")
            return true;

        // smss.exe should only spawn csrss.exe and winlogon.exe
        if (parent == "smss.exe" && child is not ("csrss.exe" or "winlogon.exe"))
            return true;

        // csrss.exe should rarely spawn children
        if (parent == "csrss.exe" && child is "cmd.exe" or "powershell.exe" or "mshta.exe")
            return true;

        // services.exe should only spawn svchost.exe and service executables
        if (parent == "services.exe" && child is "cmd.exe" or "powershell.exe" or "mshta.exe")
            return true;

        return false;
    }

    private void PruneIfNeeded()
    {
        var now = DateTimeOffset.Now;
        if (now - _lastPrune < TimeSpan.FromSeconds(60) && _nodes.Count < MaxNodes)
            return;

        _lastPrune = now;

        var toRemove = _nodes
            .Where(kv => !kv.Value.IsAlive &&
                         kv.Value.TerminateTime.HasValue &&
                         now - kv.Value.TerminateTime.Value > NodeRetention)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var pid in toRemove)
            _nodes.Remove(pid);

        // If still over limit, remove oldest terminated
        if (_nodes.Count > MaxNodes)
        {
            var extras = _nodes
                .Where(kv => !kv.Value.IsAlive)
                .OrderBy(kv => kv.Value.CreateTime)
                .Take(_nodes.Count - MaxNodes + 512)
                .Select(kv => kv.Key)
                .ToList();

            foreach (var pid in extras)
                _nodes.Remove(pid);
        }
    }
}

public sealed class ProcessTreeNode
{
    public int PID { get; init; }
    public int PPID { get; init; }
    public string ImagePath { get; init; } = string.Empty;
    public string ProcessName { get; init; } = string.Empty;
    public DateTimeOffset CreateTime { get; init; }
    public bool IsAlive { get; set; }
    public DateTimeOffset? TerminateTime { get; set; }
}

public sealed record AncestorAnalysis(
    bool IsSuspicious,
    int SuspicionScore,
    string Reason,
    List<string> ChainNames);
