using System.Runtime.InteropServices;

namespace RollbackGuard.Service.Engine;

public sealed class ShellcodeRemediator
{
    private readonly MemoryScanner? _verifier;
    private const uint ProcessVmOperation = 0x0008;
    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessVmWrite = 0x0020;
    private const uint ProcessQueryInformation = 0x0400;
    private const uint PageNoAccess = 0x01;
    private const uint PageReadWrite = 0x04;
    private const uint ThreadSuspendResume = 0x0002;
    private const uint Th32csSnapThread = 0x00000004;
    private const int ZeroChunkBytes = 64 * 1024;
    private const int SuspendPasses = 3;

    public ShellcodeRemediator(MemoryScanner? verifier = null)
    {
        _verifier = verifier;
    }

    public RemediationResult Remediate(int pid, MemoryScanResult scanResult, ProcessContext context)
    {
        var result = new RemediationResult { ProcessId = pid };
        if (pid <= 4 || scanResult.SuspiciousRegions.Count == 0)
        {
            result.Success = false;
            result.Error = "no-suspicious-region";
            return result;
        }

        var processHandle = OpenProcess(
            ProcessVmOperation | ProcessVmRead | ProcessVmWrite | ProcessQueryInformation,
            false,
            (uint)pid);
        if (processHandle == IntPtr.Zero)
        {
            result.Success = false;
            result.Error = $"OpenProcess failed: {Marshal.GetLastWin32Error()}";
            return result;
        }

        List<IntPtr> suspendedThreads = [];
        try
        {
            suspendedThreads = SuspendProcessThreads(pid);

            foreach (var region in scanResult.SuspiciousRegions)
            {
                if (region.Size <= 0)
                {
                    continue;
                }

                var regionZeroed = false;
                var regionProtected = false;
                long bytesZeroed = 0;
                for (long offset = 0; offset < region.Size; offset += ZeroChunkBytes)
                {
                    var bytesToZero = (int)Math.Min(ZeroChunkBytes, region.Size - offset);
                    if (bytesToZero <= 0)
                    {
                        break;
                    }

                    var address = new IntPtr((long)region.BaseAddress + offset);
                    var makeWritableOk = VirtualProtectEx(
                        processHandle,
                        address,
                        (UIntPtr)bytesToZero,
                        PageReadWrite,
                        out var previousProtect);

                    var buffer = new byte[bytesToZero];
                    var zeroed = WriteProcessMemory(
                        processHandle,
                        address,
                        buffer,
                        bytesToZero,
                        out var written);

                    var zeroedBytes = written.ToInt64();
                    if (zeroed && zeroedBytes > 0)
                    {
                        bytesZeroed += zeroedBytes;
                        regionZeroed = true;
                    }

                    var protectedOk = VirtualProtectEx(
                        processHandle,
                        address,
                        (UIntPtr)bytesToZero,
                        PageNoAccess,
                        out _);
                    regionProtected |= protectedOk;

                    if (!protectedOk && makeWritableOk)
                    {
                        _ = VirtualProtectEx(
                            processHandle,
                            address,
                            (UIntPtr)bytesToZero,
                            previousProtect,
                            out _);
                    }
                }

                result.RegionsRemediated.Add(new RegionRemediationEntry(
                    region.BaseAddress,
                    region.Size,
                    region.Reason,
                    regionZeroed,
                    regionProtected,
                    bytesZeroed));

                context.AddRemediationRecord(
                    "memory-zero-and-noaccess",
                    $"0x{region.BaseAddress:X} size={region.Size} reason={region.Reason} zeroed={regionZeroed} bytes={bytesZeroed} protect={regionProtected}",
                    regionZeroed || regionProtected);
            }

            if (_verifier != null)
            {
                var verificationPassed = VerifyRemediation(pid, scanResult.SuspiciousRegions, out var verificationMessage);
                result.VerificationPassed = verificationPassed;
                result.VerificationMessage = verificationMessage;
            }
            else
            {
                result.VerificationPassed = true;
                result.VerificationMessage = "verification-skipped";
            }

            result.Success = result.RegionsRemediated.Count > 0 &&
                             result.RegionsRemediated.All(entry => entry.Zeroed || entry.ProtectedNoAccess) &&
                             result.VerificationPassed;
            if (!result.Success && string.IsNullOrWhiteSpace(result.Error))
            {
                result.Error = result.VerificationMessage ?? "remediation-no-op";
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }
        finally
        {
            ResumeProcessThreads(suspendedThreads);
            CloseHandle(processHandle);
        }

        return result;
    }

    private bool VerifyRemediation(
        int pid,
        IReadOnlyList<SuspiciousMemoryRegion> originalRegions,
        out string verificationMessage)
    {
        if (_verifier == null)
        {
            verificationMessage = "verification-skipped";
            return true;
        }

        var postScan = _verifier.ScanProcess(pid);
        if (!string.IsNullOrWhiteSpace(postScan.Error))
        {
            verificationMessage = $"verification-scan-failed: {postScan.Error}";
            return false;
        }

        var overlapping = postScan.SuspiciousRegions
            .Where(region => originalRegions.Any(original => RegionsOverlap(original, region)))
            .Take(8)
            .ToList();
        if (overlapping.Count > 0)
        {
            verificationMessage = "verification-overlap-remains: " + string.Join(
                " | ",
                overlapping.Select(region => $"0x{region.BaseAddress:X} size={region.Size} {region.Reason}"));
            return false;
        }

        verificationMessage = $"verification-clear remaining={postScan.SuspiciousRegions.Count}";
        return true;
    }

    private static bool RegionsOverlap(SuspiciousMemoryRegion left, SuspiciousMemoryRegion right)
    {
        var leftStart = left.BaseAddress;
        var leftEnd = left.BaseAddress + (ulong)Math.Max(0, left.Size);
        var rightStart = right.BaseAddress;
        var rightEnd = right.BaseAddress + (ulong)Math.Max(0, right.Size);
        return leftStart < rightEnd && rightStart < leftEnd;
    }

    private static List<IntPtr> SuspendProcessThreads(int pid)
    {
        var handles = new List<IntPtr>();
        var seenThreadIds = new HashSet<uint>();
        for (var pass = 0; pass < SuspendPasses; pass++)
        {
            var suspendedThisPass = 0;
            var snapshot = CreateToolhelp32Snapshot(Th32csSnapThread, 0);
            if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
            {
                break;
            }

            try
            {
                var entry = new THREADENTRY32
                {
                    dwSize = (uint)Marshal.SizeOf<THREADENTRY32>()
                };

                if (!Thread32First(snapshot, ref entry))
                {
                    continue;
                }

                do
                {
                    if (entry.th32OwnerProcessID != (uint)pid || !seenThreadIds.Add(entry.th32ThreadID))
                    {
                        continue;
                    }

                    var threadHandle = OpenThread(ThreadSuspendResume, false, entry.th32ThreadID);
                    if (threadHandle == IntPtr.Zero)
                    {
                        continue;
                    }

                    if (SuspendThread(threadHandle) == uint.MaxValue)
                    {
                        _ = CloseHandle(threadHandle);
                        continue;
                    }

                    handles.Add(threadHandle);
                    suspendedThisPass++;
                } while (Thread32Next(snapshot, ref entry));
            }
            finally
            {
                _ = CloseHandle(snapshot);
            }

            if (suspendedThisPass == 0)
            {
                break;
            }
        }

        return handles;
    }

    private static void ResumeProcessThreads(IEnumerable<IntPtr> handles)
    {
        foreach (var handle in handles)
        {
            try
            {
                while (ResumeThread(handle) > 0)
                {
                }
            }
            catch
            {
                // ignore resume failures during cleanup
            }
            finally
            {
                _ = CloseHandle(handle);
            }
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(
        IntPtr processHandle,
        IntPtr baseAddress,
        byte[] buffer,
        int size,
        out IntPtr bytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtectEx(
        IntPtr processHandle,
        IntPtr address,
        UIntPtr size,
        uint newProtect,
        out uint oldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint desiredAccess, bool inheritHandle, uint threadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint SuspendThread(IntPtr threadHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr threadHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Thread32First(IntPtr snapshot, ref THREADENTRY32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Thread32Next(IntPtr snapshot, ref THREADENTRY32 entry);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct THREADENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ThreadID;
        public uint th32OwnerProcessID;
        public int tpBasePri;
        public int tpDeltaPri;
        public uint dwFlags;
    }
}

public sealed class RemediationResult
{
    public int ProcessId { get; init; }
    public bool Success { get; set; }
    public string? Error { get; set; }
    public bool VerificationPassed { get; set; }
    public string? VerificationMessage { get; set; }
    public List<RegionRemediationEntry> RegionsRemediated { get; } = [];
}

public sealed record RegionRemediationEntry(
    ulong BaseAddress,
    long Size,
    string Reason,
    bool Zeroed,
    bool ProtectedNoAccess,
    long BytesZeroed);
