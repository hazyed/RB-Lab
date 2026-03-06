using System.Runtime.InteropServices;
using RollbackGuard.Common.Diagnostics;

namespace RollbackGuard.Service.Engine;

public sealed class MemoryScanner
{
    private readonly AmsiScanner? _amsiScanner;
    private readonly Dictionary<int, Dictionary<ulong, uint>> _previousProtections = [];
    private const int MaxRegionScanBytes = 10 * 1024 * 1024;
    private const int ReadChunkBytes = 64 * 1024;
    private const uint BaseProtectMask = 0xFF;
    private const uint PageReadWrite = 0x04;
    private const uint PageWriteCopy = 0x08;
    private const uint PageExecute = 0x10;
    private const uint PageExecuteRead = 0x20;
    private const uint PageExecuteReadWrite = 0x40;
    private const uint PageExecuteWriteCopy = 0x80;

    private static readonly byte[][] ShellcodePrologueX64 =
    [
        [0x48, 0x31, 0xC9, 0x48, 0x81, 0xE9],
        [0xFC, 0x48, 0x83, 0xE4, 0xF0],
        [0x48, 0x89, 0xCE, 0x48, 0x89, 0xD7],
        [0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0xE4, 0xF0],
        [0x49, 0x89, 0xD8, 0x48, 0x83, 0xEC],
        [0x48, 0x8B, 0x41, 0x30, 0x48, 0x8B, 0x40, 0x0C]
    ];

    private static readonly byte[][] ShellcodePrologueX86 =
    [
        [0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00],
        [0x60, 0x89, 0xE5, 0x31, 0xD2, 0x64],
        [0x6A, 0x60, 0x5A, 0x68, 0x63, 0x6D, 0x64],
        [0x64, 0x8B, 0x52, 0x30, 0x8B, 0x52, 0x0C],
        [0xAD, 0x96, 0xAD, 0x8B, 0x58, 0x10]
    ];

    private static readonly byte[][] PebWalkSignatures =
    [
        [0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00],
        [0x65, 0x4C, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00],
        [0x64, 0xA1, 0x30, 0x00, 0x00, 0x00],
        [0x64, 0x8B, 0x1D, 0x30, 0x00, 0x00, 0x00],
        [0x64, 0x8B, 0x35, 0x30, 0x00, 0x00, 0x00],
        [0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x70, 0x10],
        [0x48, 0x8B, 0x58, 0x20, 0x48, 0x8B, 0x1B]
    ];

    private static readonly byte[][] ApiHashSignatures =
    [
        [0x41, 0xC1, 0xCF, 0x0D, 0x41, 0x01, 0xC7],
        [0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1],
        [0x03, 0xF8, 0xC1, 0xCF, 0x0D, 0x8B, 0xC7],
        [0xC1, 0xCF, 0x0D, 0x03, 0xF8, 0x85, 0xC0],
        [0x33, 0xC9, 0x41, 0x8A, 0x04, 0x08, 0x84, 0xC0]
    ];

    private static readonly byte[][] SyscallStubSignatures =
    [
        [0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3],
        [0x49, 0x89, 0xCA, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3],
        [0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x34, 0xC3],
        [0x0F, 0x05, 0xC3, 0xCC, 0xCC],
        [0x0F, 0x34, 0xC3, 0xCC, 0xCC]
    ];

    private static readonly byte[][] BeaconSignatures =
    [
        [0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC8, 0x00, 0x00, 0x00],
        [0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xCC, 0x00, 0x00, 0x00],
        [0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2]
    ];

    private static readonly byte[][] MeterpreterSignatures =
    [
        [0x6A, 0x40, 0x68, 0x00, 0x10, 0x00, 0x00],
        [0x68, 0x63, 0x6D, 0x64, 0x00],
        [0x6A, 0x00, 0x53, 0xFF, 0xD5],
        [0x68, 0x57, 0x69, 0x6E, 0x45]
    ];

    private static readonly byte[][] DonutSignatures =
    [
        [0x48, 0xB8, 0x41, 0x6D, 0x73, 0x69],
        [0x4C, 0x8B, 0x02, 0x4D, 0x31, 0xC9],
        [0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xE8],
        [0x48, 0x83, 0xEC, 0x28, 0x33, 0xC0, 0x48, 0x8D]
    ];

    private static readonly byte[][] ReflectiveDllSignatures =
    [
        [0x4D, 0x5A],
        [0x50, 0x45, 0x00, 0x00],
        [0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C]
    ];

    public MemoryScanner(AmsiScanner? amsiScanner = null)
    {
        _amsiScanner = amsiScanner;
    }

    public MemoryScanResult ScanProcess(int processId)
    {
        var result = new MemoryScanResult { ProcessId = processId };
        IntPtr processHandle;

        try
        {
            processHandle = OpenProcess(
                0x0010 | 0x0400,
                false,
                (uint)processId);
            if (processHandle == IntPtr.Zero)
            {
                result.Error = $"OpenProcess failed: {Marshal.GetLastWin32Error()}";
                return result;
            }
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
            return result;
        }

        try
        {
            var moduleRanges = GetModuleRanges(processHandle);
            var currentProtections = new Dictionary<ulong, uint>();
            var suspiciousRegions = new List<SuspiciousMemoryRegion>();
            var liveWxAddresses = new HashSet<ulong>();
            var address = IntPtr.Zero;
            var infoSize = Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

            while (true)
            {
                var queryResult = VirtualQueryEx(processHandle, address, out var mbi, (uint)infoSize);
                if (queryResult == 0)
                {
                    break;
                }

                var baseAddr = (ulong)mbi.BaseAddress;
                var regionSize = (long)mbi.RegionSize;
                if (mbi.State == MemCommit)
                {
                    currentProtections[baseAddr] = mbi.Protect;
                    if (IsExecutable(mbi.Protect))
                    {
                        result.TotalExecutableRegions++;
                        var isRwx = IsReadWriteExecute(mbi.Protect);

                        if (isRwx)
                        {
                            result.RwxRegionCount++;
                            AddSuspiciousRegion(
                                suspiciousRegions,
                                baseAddr,
                                regionSize,
                                mbi,
                                "RWX-memory");
                        }

                        var isBackedByModule = moduleRanges.Any(range => range.Contains(baseAddr));
                        var isImage = mbi.Type == MemImage;
                        if (!isBackedByModule && !isImage)
                        {
                            result.UnbackedExecRegionCount++;
                            AddSuspiciousRegion(
                                suspiciousRegions,
                                baseAddr,
                                regionSize,
                                mbi,
                                "unbacked-executable");
                        }

                        if (!isRwx && LooksLikeLiveWxTransition(mbi))
                        {
                            result.WxTransitionCount++;
                            liveWxAddresses.Add(baseAddr);
                            AddSuspiciousRegion(
                                suspiciousRegions,
                                baseAddr,
                                regionSize,
                                mbi,
                                "wx-transition-live");
                        }

                        if (ShouldScanRegionContent(mbi, isBackedByModule))
                        {
                            if (mbi.Type == MemPrivate)
                            {
                                result.PrivateExecutableRegions++;
                            }

                            ScanRegionContent(processHandle, processId, mbi, result, suspiciousRegions);
                        }
                    }
                }

                var nextAddress = (long)mbi.BaseAddress + regionSize;
                if (nextAddress <= (long)address)
                {
                    break;
                }

                address = (IntPtr)nextAddress;
            }

            result.WxTransitionCount += DetectWxTransitions(processId, currentProtections, liveWxAddresses);
            result.SuspiciousRegions = suspiciousRegions;
            result.IsSuspicious = suspiciousRegions.Count > 0 || result.CalculateScore() >= 40;
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
            StartupLog.Write("MemScan", $"scan exception pid={processId}: {ex.Message}");
        }
        finally
        {
            CloseHandle(processHandle);
        }

        return result;
    }

    private void ScanRegionContent(
        IntPtr processHandle,
        int processId,
        MEMORY_BASIC_INFORMATION mbi,
        MemoryScanResult result,
        List<SuspiciousMemoryRegion> suspiciousRegions)
    {
        var regionSize = (long)mbi.RegionSize;
        if (regionSize is <= 0 or > MaxRegionScanBytes)
        {
            return;
        }

        var regionData = TryReadMemoryRegion(processHandle, mbi.BaseAddress, (int)regionSize);
        if (regionData == null || regionData.Length < 32)
        {
            return;
        }

        var baseAddr = (ulong)mbi.BaseAddress;
        var entropy = CalculateShannonEntropy(regionData);
        var heuristic = AnalyzeHeuristics(regionData);
        var suspiciousExecSurface =
            IsPrivateExecutableRegion(mbi) ||
            IsReadWriteExecute(mbi.Protect) ||
            LooksLikeLiveWxTransition(mbi);
        var hasStrongShellcodeFamilySignature =
            ContainsAnySignature(regionData, BeaconSignatures) ||
            ContainsAnySignature(regionData, MeterpreterSignatures) ||
            ContainsAnySignature(regionData, DonutSignatures);
        var hasGenericShellcodeSignature =
            ContainsAnySignature(regionData, ShellcodePrologueX64) ||
            ContainsAnySignature(regionData, ShellcodePrologueX86);
        var hasExecutionStyleResolverPattern =
            heuristic.HasPebWalkPattern ||
            heuristic.HasApiHashPattern ||
            heuristic.HasSyscallStub;

        // Generic compiler output often matches short opcode fragments. Only treat them as
        // shellcode when they land in a suspicious execution surface and are accompanied by
        // resolver/syscall-style behavior. Strong family signatures still score directly.
        if (hasStrongShellcodeFamilySignature ||
            (hasGenericShellcodeSignature && suspiciousExecSurface && hasExecutionStyleResolverPattern))
        {
            result.ShellcodePatternCount++;
            AddSuspiciousRegion(suspiciousRegions, baseAddr, regionSize, mbi, "shellcode-signature", entropy, heuristic.NullByteRatio);
        }

        if (ContainsAnySignature(regionData, PebWalkSignatures) || heuristic.HasPebWalkPattern)
        {
            result.PebWalkPatternCount++;
            AddSuspiciousRegion(suspiciousRegions, baseAddr, regionSize, mbi, "peb-walk-pattern", entropy, heuristic.NullByteRatio);
        }

        suspiciousExecSurface = suspiciousExecSurface ||
                                result.UnbackedExecRegionCount > 0 ||
                                result.WxTransitionCount > 0 ||
                                result.RwxRegionCount > 0;

        if (suspiciousExecSurface && (ContainsAnySignature(regionData, ApiHashSignatures) || heuristic.HasApiHashPattern))
        {
            result.ApiHashPatternCount++;
            AddSuspiciousRegion(suspiciousRegions, baseAddr, regionSize, mbi, "api-hash-resolution", entropy, heuristic.NullByteRatio);
        }

        if (suspiciousExecSurface && (ContainsAnySignature(regionData, SyscallStubSignatures) || heuristic.HasSyscallStub))
        {
            result.SyscallStubCount++;
            AddSuspiciousRegion(suspiciousRegions, baseAddr, regionSize, mbi, "direct-syscall", entropy, heuristic.NullByteRatio);
        }

        if (ContainsReflectiveDll(regionData))
        {
            result.ReflectiveDllCount++;
            AddSuspiciousRegion(suspiciousRegions, baseAddr, regionSize, mbi, "reflective-dll", entropy, heuristic.NullByteRatio);
        }

        if (entropy >= 6.5 && regionData.Length >= 256)
        {
            result.HighEntropyRegionCount++;
            if (heuristic.IsHighEntropy || heuristic.IsLowNullDensity)
            {
                AddSuspiciousRegion(suspiciousRegions, baseAddr, regionSize, mbi, "high-entropy-executable", entropy, heuristic.NullByteRatio);
            }
        }

        if (_amsiScanner != null && regionData.Length >= 64)
        {
            var scanBytes = regionData.Length > 65536 ? regionData[..65536] : regionData;
            var amsiResult = _amsiScanner.ScanBuffer(scanBytes, $"memory-pid{processId}-0x{baseAddr:X}");
            if (amsiResult == AmsiScanResult.Malicious)
            {
                result.AmsiDetectionCount++;
                AddSuspiciousRegion(suspiciousRegions, baseAddr, regionSize, mbi, "amsi-malicious-memory", entropy, heuristic.NullByteRatio);
            }
        }
    }

    public ShellcodeHeuristicResult AnalyzeHeuristics(byte[] data)
    {
        var result = new ShellcodeHeuristicResult
        {
            Entropy = CalculateShannonEntropy(data),
            NullByteRatio = CalculateNullByteRatio(data)
        };

        result.HasPebWalkPattern =
            ContainsAnySignature(data, PebWalkSignatures) ||
            ContainsSequence(data, [0x48, 0x8B, 0x40, 0x18]) ||
            ContainsSequence(data, [0x8B, 0x52, 0x0C, 0x8B, 0x52, 0x14]);

        result.HasApiHashPattern = ContainsAnySignature(data, ApiHashSignatures);

        result.HasSyscallStub = ContainsAnySignature(data, SyscallStubSignatures);

        result.IsHighEntropy = result.Entropy >= 6.5;
        result.IsLowNullDensity = result.NullByteRatio <= 0.02;
        return result;
    }

    private int DetectWxTransitions(
        int processId,
        Dictionary<ulong, uint> currentProtections,
        IReadOnlySet<ulong> liveWxAddresses)
    {
        var count = 0;
        if (_previousProtections.TryGetValue(processId, out var previous))
        {
            foreach (var (address, newProtect) in currentProtections)
            {
                if (liveWxAddresses.Contains(address))
                {
                    continue;
                }

                if (!previous.TryGetValue(address, out var oldProtect))
                {
                    continue;
                }

                if (!IsExecutable(oldProtect) && IsExecutable(newProtect))
                {
                    count++;
                }
            }
        }

        _previousProtections[processId] = currentProtections;
        return count;
    }

    private static List<ModuleRange> GetModuleRanges(IntPtr processHandle)
    {
        var ranges = new List<ModuleRange>();
        var modules = new IntPtr[1024];
        if (!EnumProcessModulesEx(
                processHandle,
                modules,
                (uint)(modules.Length * IntPtr.Size),
                out var needed,
                0x03))
        {
            return ranges;
        }

        var count = Math.Min((int)needed / IntPtr.Size, modules.Length);
        for (var i = 0; i < count; i++)
        {
            if (!GetModuleInformation(
                    processHandle,
                    modules[i],
                    out var info,
                    (uint)Marshal.SizeOf<MODULEINFO>()))
            {
                continue;
            }

            ranges.Add(new ModuleRange((ulong)info.lpBaseOfDll, info.SizeOfImage));
        }

        return ranges;
    }

    private static bool ContainsReflectiveDll(byte[] data)
    {
        if (data.Length < 64)
        {
            return false;
        }

        if (!ContainsAnySignature(data, ReflectiveDllSignatures))
        {
            return false;
        }

        if (TryFindEmbeddedPeImage(data))
        {
            return true;
        }

        return TryFindDetachedPeHeader(data);
    }

    private static bool TryFindEmbeddedPeImage(byte[] data)
    {
        for (var offset = 0; offset <= data.Length - 64; offset++)
        {
            if (data[offset] != 0x4D || data[offset + 1] != 0x5A)
            {
                continue;
            }

            if (offset + 0x40 > data.Length)
            {
                continue;
            }

            var peOffset = BitConverter.ToInt32(data, offset + 0x3C);
            if (peOffset <= 0)
            {
                continue;
            }

            var peHeaderOffset = offset + peOffset;
            if (peHeaderOffset + 4 > data.Length)
            {
                continue;
            }

            if (LooksLikePeHeader(data, peHeaderOffset))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryFindDetachedPeHeader(byte[] data)
    {
        for (var offset = 0; offset <= data.Length - 256; offset++)
        {
            if (!LooksLikePeHeader(data, offset))
            {
                continue;
            }

            return true;
        }

        return false;
    }

    private static bool LooksLikePeHeader(byte[] data, int peHeaderOffset)
    {
        if (peHeaderOffset < 0 || peHeaderOffset + 24 >= data.Length)
        {
            return false;
        }

        if (data[peHeaderOffset] != 0x50 ||
            data[peHeaderOffset + 1] != 0x45 ||
            data[peHeaderOffset + 2] != 0x00 ||
            data[peHeaderOffset + 3] != 0x00)
        {
            return false;
        }

        var machine = BitConverter.ToUInt16(data, peHeaderOffset + 4);
        if (machine is not (0x14C or 0x8664))
        {
            return false;
        }

        var sectionCount = BitConverter.ToUInt16(data, peHeaderOffset + 6);
        if (sectionCount == 0 || sectionCount > 96)
        {
            return false;
        }

        var optionalHeaderSize = BitConverter.ToUInt16(data, peHeaderOffset + 20);
        var optionalHeaderOffset = peHeaderOffset + 24;
        if (optionalHeaderOffset + optionalHeaderSize > data.Length || optionalHeaderSize < 0x60)
        {
            return false;
        }

        var magic = BitConverter.ToUInt16(data, optionalHeaderOffset);
        if (magic is not (0x10B or 0x20B))
        {
            return false;
        }

        var sectionTableOffset = optionalHeaderOffset + optionalHeaderSize;
        if (sectionTableOffset + (sectionCount * 40) > data.Length)
        {
            return false;
        }

        return true;
    }

    internal static double CalculateShannonEntropy(byte[] data)
    {
        if (data.Length == 0)
        {
            return 0;
        }

        var freq = new int[256];
        foreach (var b in data)
        {
            freq[b]++;
        }

        var entropy = 0.0;
        var length = (double)data.Length;
        for (var i = 0; i < 256; i++)
        {
            if (freq[i] == 0)
            {
                continue;
            }

            var probability = freq[i] / length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    private static double CalculateNullByteRatio(byte[] data)
    {
        if (data.Length == 0)
        {
            return 1;
        }

        var nullCount = CountByte(data, 0x00);
        return (double)nullCount / data.Length;
    }

    private static int CountByte(byte[] data, byte value)
    {
        var count = 0;
        foreach (var b in data)
        {
            if (b == value)
            {
                count++;
            }
        }

        return count;
    }

    private static bool IsExecutable(uint protect)
    {
        var normalized = NormalizeProtect(protect);
        return normalized is PageExecute or PageExecuteRead or PageExecuteReadWrite or PageExecuteWriteCopy or 0xC0;
    }

    private static bool IsWritable(uint protect)
    {
        var normalized = NormalizeProtect(protect);
        return normalized is PageReadWrite or PageWriteCopy or PageExecuteReadWrite or PageExecuteWriteCopy or 0xC0;
    }

    private static bool IsReadWriteExecute(uint protect)
    {
        var normalized = NormalizeProtect(protect);
        return normalized is PageExecuteReadWrite or PageExecuteWriteCopy or 0xC0;
    }

    private static uint NormalizeProtect(uint protect) => protect & BaseProtectMask;

    private static bool LooksLikeLiveWxTransition(MEMORY_BASIC_INFORMATION mbi)
    {
        var current = NormalizeProtect(mbi.Protect);
        var allocation = NormalizeProtect(mbi.AllocationProtect);
        if (!IsExecutable(current))
        {
            return false;
        }

        if (IsWritable(current))
        {
            return true;
        }

        return IsWritable(allocation) && !IsExecutable(allocation);
    }

    private static bool IsPrivateExecutableRegion(MEMORY_BASIC_INFORMATION mbi)
    {
        return mbi.Type == MemPrivate && IsExecutable(mbi.Protect);
    }

    private static bool ShouldScanRegionContent(MEMORY_BASIC_INFORMATION mbi, bool isBackedByModule)
    {
        if ((long)mbi.RegionSize is <= 0 or > MaxRegionScanBytes)
        {
            return false;
        }

        if (mbi.Type is MemPrivate or MemMapped)
        {
            return true;
        }

        if (mbi.Type == MemImage)
        {
            return IsWritable(mbi.AllocationProtect) || IsWritable(mbi.Protect);
        }

        return !isBackedByModule;
    }

    private static bool ContainsAnySignature(byte[] data, byte[][] signatures)
    {
        if (data.Length < 3)
        {
            return false;
        }

        var searchLength = data.Length;
        foreach (var signature in signatures)
        {
            if (searchLength < signature.Length)
            {
                continue;
            }

            for (var i = 0; i <= searchLength - signature.Length; i++)
            {
                var match = true;
                for (var j = 0; j < signature.Length; j++)
                {
                    if (data[i + j] != signature[j])
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool ContainsSequence(byte[] data, byte[] needle)
    {
        if (needle.Length == 0 || data.Length < needle.Length)
        {
            return false;
        }

        for (var i = 0; i <= data.Length - needle.Length; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (data[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                return true;
            }
        }

        return false;
    }

    private static byte[]? TryReadMemoryRegion(IntPtr processHandle, IntPtr baseAddress, int size)
    {
        try
        {
            var clampedSize = Math.Min(size, MaxRegionScanBytes);
            if (clampedSize <= 0)
            {
                return null;
            }

            var aggregate = new byte[clampedSize];
            var totalRead = 0;
            while (totalRead < clampedSize)
            {
                var chunkSize = Math.Min(ReadChunkBytes, clampedSize - totalRead);
                var chunk = new byte[chunkSize];
                if (!ReadProcessMemory(
                        processHandle,
                        IntPtr.Add(baseAddress, totalRead),
                        chunk,
                        (uint)chunkSize,
                        out var bytesRead) ||
                    bytesRead == 0)
                {
                    break;
                }

                Buffer.BlockCopy(chunk, 0, aggregate, totalRead, (int)bytesRead);
                totalRead += (int)bytesRead;
                if (bytesRead < chunkSize)
                {
                    break;
                }
            }

            if (totalRead <= 0)
            {
                return null;
            }

            if (totalRead < aggregate.Length)
            {
                Array.Resize(ref aggregate, totalRead);
            }

            return aggregate;
        }
        catch
        {
        }

        return null;
    }

    private static void AddSuspiciousRegion(
        List<SuspiciousMemoryRegion> suspiciousRegions,
        ulong baseAddress,
        long size,
        MEMORY_BASIC_INFORMATION mbi,
        string reason,
        double entropy = 0,
        double nullByteRatio = 0)
    {
        if (suspiciousRegions.Any(region =>
                region.BaseAddress == baseAddress &&
                region.Size == size &&
                region.Reason.Equals(reason, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        suspiciousRegions.Add(new SuspiciousMemoryRegion
        {
            BaseAddress = baseAddress,
            Size = size,
            Protection = mbi.Protect,
            Type = mbi.Type,
            Reason = reason,
            Entropy = entropy,
            NullByteRatio = nullByteRatio
        });
    }

    private const uint MemCommit = 0x1000;
    private const uint MemImage = 0x1000000;
    private const uint MemMapped = 0x40000;
    private const uint MemPrivate = 0x20000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint VirtualQueryEx(
        IntPtr processHandle,
        IntPtr address,
        out MEMORY_BASIC_INFORMATION buffer,
        uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr processHandle,
        IntPtr baseAddress,
        byte[] buffer,
        uint size,
        out uint bytesRead);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModulesEx(
        IntPtr processHandle,
        [Out] IntPtr[] modules,
        uint bytes,
        out uint needed,
        uint filterFlag);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool GetModuleInformation(
        IntPtr processHandle,
        IntPtr module,
        out MODULEINFO moduleInfo,
        uint size);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MODULEINFO
    {
        public IntPtr lpBaseOfDll;
        public uint SizeOfImage;
        public IntPtr EntryPoint;
    }

    private sealed record ModuleRange(ulong BaseAddress, uint Size)
    {
        public bool Contains(ulong address) => address >= BaseAddress && address < BaseAddress + Size;
    }
}

public sealed class MemoryScanResult
{
    public int ProcessId { get; init; }
    public bool IsSuspicious { get; set; }
    public int TotalExecutableRegions { get; set; }
    public int PrivateExecutableRegions { get; set; }
    public int RwxRegionCount { get; set; }
    public int ShellcodePatternCount { get; set; }
    public int AmsiDetectionCount { get; set; }
    public int UnbackedExecRegionCount { get; set; }
    public int HighEntropyRegionCount { get; set; }
    public int WxTransitionCount { get; set; }
    public int ReflectiveDllCount { get; set; }
    public int PebWalkPatternCount { get; set; }
    public int ApiHashPatternCount { get; set; }
    public int SyscallStubCount { get; set; }
    public List<SuspiciousMemoryRegion> SuspiciousRegions { get; set; } = [];
    public string? Error { get; set; }

    public int CalculateScore()
    {
        var score = 0;
        score += RwxRegionCount * 20;
        score += ShellcodePatternCount * 40;
        score += AmsiDetectionCount * 90;
        score += UnbackedExecRegionCount * 50;
        score += WxTransitionCount * 70;
        score += ReflectiveDllCount * 90;

        var hasExecutionTransferEvidence =
            UnbackedExecRegionCount > 0 ||
            WxTransitionCount > 0 ||
            ReflectiveDllCount > 0 ||
            ShellcodePatternCount > 0 ||
            AmsiDetectionCount > 0 ||
            RwxRegionCount > 0;

        if (hasExecutionTransferEvidence && (PebWalkPatternCount + ApiHashPatternCount) > 0)
        {
            score += 25;
        }

        if (hasExecutionTransferEvidence && SyscallStubCount > 0)
        {
            score += Math.Min(30, SyscallStubCount * 10);
        }

        if (PrivateExecutableRegions > 5)
        {
            score += 15;
        }

        if (HighEntropyRegionCount > 3)
        {
            score += 35;
        }

        return score;
    }
}

public sealed class SuspiciousMemoryRegion
{
    public ulong BaseAddress { get; init; }
    public long Size { get; init; }
    public uint Protection { get; init; }
    public uint Type { get; init; }
    public string Reason { get; init; } = string.Empty;
    public double Entropy { get; init; }
    public double NullByteRatio { get; init; }
}

public sealed class ShellcodeHeuristicResult
{
    public bool HasPebWalkPattern { get; set; }
    public bool HasApiHashPattern { get; set; }
    public bool HasSyscallStub { get; set; }
    public bool IsHighEntropy { get; set; }
    public bool IsLowNullDensity { get; set; }
    public double Entropy { get; set; }
    public double NullByteRatio { get; set; }
}
