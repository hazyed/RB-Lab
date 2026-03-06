using System.Runtime.InteropServices;

namespace RollbackGuard.Service.Engine;

public readonly record struct CallStackInspectionVerdict(
    bool Sampled,
    bool HasAnomalousFrame,
    int ThreadCount,
    int FrameCount,
    int UnbackedFrameCount,
    string Summary);

public static unsafe class ProcessCallStackInspector
{
    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessQueryInformation = 0x0400;
    private const uint Th32csSnapThread = 0x00000004;
    private const uint ThreadGetContext = 0x0008;
    private const uint ThreadSuspendResume = 0x0002;
    private const uint ThreadQueryInformation = 0x0040;
    private const uint ContextAmd64 = 0x00100000;
    private const uint ContextControl = ContextAmd64 | 0x00000001;
    private const uint ContextInteger = ContextAmd64 | 0x00000002;
    private const uint ContextFull = ContextControl | ContextInteger;
    private const uint ImageFileMachineAmd64 = 0x8664;
    private const uint SymoptUndname = 0x00000002;
    private const uint SymoptDeferredLoads = 0x00000004;
    private const uint SymoptFailCriticalErrors = 0x00000200;
    private const int MaxThreadsToInspect = 4;
    private const int MaxFramesPerThread = 12;
    private const ulong MinimumUserAddress = 0x10000;

    private static readonly ReadProcessMemoryRoutine64 ReadProcessMemoryThunk = ReadMemory;
    private static readonly FunctionTableAccessRoutine64 FunctionTableAccessThunk = FunctionTableAccess;
    private static readonly GetModuleBaseRoutine64 GetModuleBaseThunk = GetModuleBase;

    public static bool TryInspect(int processId, out CallStackInspectionVerdict verdict)
    {
        verdict = default;
        if (!Environment.Is64BitProcess || processId <= 4)
        {
            return false;
        }

        var processHandle = OpenProcess(ProcessVmRead | ProcessQueryInformation, false, (uint)processId);
        if (processHandle == IntPtr.Zero)
        {
            return false;
        }

        try
        {
            if (IsWow64Process(processHandle, out var wow64) && wow64)
            {
                verdict = new CallStackInspectionVerdict(false, false, 0, 0, 0, "wow64-skip");
                return true;
            }

            SymSetOptions(SymoptUndname | SymoptDeferredLoads | SymoptFailCriticalErrors);
            if (!SymInitialize(processHandle, null, true))
            {
                verdict = new CallStackInspectionVerdict(false, false, 0, 0, 0, $"syminitialize-failed:{Marshal.GetLastWin32Error()}");
                return true;
            }

            try
            {
                var threadIds = EnumerateThreadIds(processId).Take(MaxThreadsToInspect).ToList();
                if (threadIds.Count == 0)
                {
                    verdict = new CallStackInspectionVerdict(false, false, 0, 0, 0, "no-threads");
                    return true;
                }

                var inspectedThreads = 0;
                var inspectedFrames = 0;
                var unbackedFrames = 0;
                var suspiciousFrames = new List<string>();

                foreach (var threadId in threadIds)
                {
                    var threadHandle = OpenThread(ThreadSuspendResume | ThreadGetContext | ThreadQueryInformation, false, threadId);
                    if (threadHandle == IntPtr.Zero)
                    {
                        continue;
                    }

                    try
                    {
                        if (SuspendThread(threadHandle) == uint.MaxValue)
                        {
                            continue;
                        }

                        try
                        {
                            var context = CreateContext();
                            if (!GetThreadContext(threadHandle, ref context))
                            {
                                continue;
                            }

                            inspectedThreads++;

                            var stackFrame = new STACKFRAME64
                            {
                                AddrPC = new ADDRESS64 { Mode = AddressMode.AddrModeFlat, Offset = context.Rip },
                                AddrFrame = new ADDRESS64 { Mode = AddressMode.AddrModeFlat, Offset = context.Rbp },
                                AddrStack = new ADDRESS64 { Mode = AddressMode.AddrModeFlat, Offset = context.Rsp },
                                AddrReturn = new ADDRESS64 { Mode = AddressMode.AddrModeFlat },
                                AddrBStore = new ADDRESS64 { Mode = AddressMode.AddrModeFlat },
                                Params = new ulong[4],
                                Reserved = new ulong[3]
                            };

                            ulong previousAddress = 0;
                            for (var frameIndex = 0; frameIndex < MaxFramesPerThread; frameIndex++)
                            {
                                if (!StackWalk64(
                                    ImageFileMachineAmd64,
                                    processHandle,
                                    threadHandle,
                                    ref stackFrame,
                                    ref context,
                                    ReadProcessMemoryThunk,
                                    FunctionTableAccessThunk,
                                    GetModuleBaseThunk,
                                    IntPtr.Zero))
                                {
                                    break;
                                }

                                var address = stackFrame.AddrPC.Offset;
                                if (address < MinimumUserAddress || address == previousAddress)
                                {
                                    break;
                                }

                                previousAddress = address;
                                inspectedFrames++;

                                var moduleBase = SymGetModuleBase64(processHandle, address);
                                if (moduleBase != 0)
                                {
                                    continue;
                                }

                                unbackedFrames++;
                                if (suspiciousFrames.Count < 4)
                                {
                                    var symbolName = TryResolveSymbol(processHandle, address);
                                    suspiciousFrames.Add(
                                        string.IsNullOrWhiteSpace(symbolName)
                                            ? $"tid={threadId}:0x{address:X}"
                                            : $"tid={threadId}:0x{address:X}:{symbolName}");
                                }
                            }
                        }
                        finally
                        {
                            while (ResumeThread(threadHandle) > 0)
                            {
                            }
                        }
                    }
                    finally
                    {
                        _ = CloseHandle(threadHandle);
                    }
                }

                var summary = suspiciousFrames.Count == 0
                    ? $"frames={inspectedFrames},threads={inspectedThreads},unbacked=0"
                    : $"frames={inspectedFrames},threads={inspectedThreads},unbacked={unbackedFrames},hits={string.Join(" | ", suspiciousFrames)}";
                verdict = new CallStackInspectionVerdict(
                    inspectedThreads > 0,
                    unbackedFrames > 0,
                    inspectedThreads,
                    inspectedFrames,
                    unbackedFrames,
                    summary);
                return true;
            }
            finally
            {
                _ = SymCleanup(processHandle);
            }
        }
        finally
        {
            _ = CloseHandle(processHandle);
        }
    }

    private static CONTEXT64 CreateContext() => new()
    {
        ContextFlags = ContextFull,
        VectorRegister = new M128A[26]
    };

    private static IEnumerable<uint> EnumerateThreadIds(int processId)
    {
        var snapshot = CreateToolhelp32Snapshot(Th32csSnapThread, 0);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
        {
            yield break;
        }

        try
        {
            var entry = new THREADENTRY32
            {
                dwSize = (uint)Marshal.SizeOf<THREADENTRY32>()
            };

            if (!Thread32First(snapshot, ref entry))
            {
                yield break;
            }

            do
            {
                if (entry.th32OwnerProcessID == (uint)processId)
                {
                    yield return entry.th32ThreadID;
                }
            } while (Thread32Next(snapshot, ref entry));
        }
        finally
        {
            _ = CloseHandle(snapshot);
        }
    }

    private static string TryResolveSymbol(IntPtr processHandle, ulong address)
    {
        const int maxNameLength = 256;
        var symbolInfoSize = Marshal.SizeOf<SYMBOL_INFO>();
        var buffer = stackalloc byte[symbolInfoSize + maxNameLength];
        UnsafeInitBlock(buffer, 0, (uint)(symbolInfoSize + maxNameLength));

        var symbolInfo = (SYMBOL_INFO*)buffer;
        symbolInfo->SizeOfStruct = (uint)symbolInfoSize;
        symbolInfo->MaxNameLen = maxNameLength;

        if (!SymFromAddr(processHandle, address, out _, (IntPtr)symbolInfo))
        {
            return string.Empty;
        }

        var namePtr = (IntPtr)(buffer + symbolInfoSize);
        return Marshal.PtrToStringAnsi(namePtr, (int)symbolInfo->NameLen) ?? string.Empty;
    }

    private static bool ReadMemory(
        IntPtr processHandle,
        ulong baseAddress,
        IntPtr buffer,
        uint size,
        out uint bytesRead)
    {
        bytesRead = 0;
        if (size == 0)
        {
            return true;
        }

        var local = new byte[(int)size];
        if (!ReadProcessMemory(processHandle, (IntPtr)baseAddress, local, (int)size, out var nativeBytesRead))
        {
            return false;
        }

        bytesRead = (uint)nativeBytesRead;
        if (bytesRead == 0)
        {
            return false;
        }

        Marshal.Copy(local, 0, buffer, (int)bytesRead);
        return true;
    }

    private static IntPtr FunctionTableAccess(IntPtr processHandle, ulong address) =>
        SymFunctionTableAccess64(processHandle, address);

    private static ulong GetModuleBase(IntPtr processHandle, ulong address) =>
        SymGetModuleBase64(processHandle, address);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint desiredAccess, bool inheritHandle, uint threadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint SuspendThread(IntPtr threadHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr threadHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetThreadContext(IntPtr threadHandle, ref CONTEXT64 context);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr processHandle,
        IntPtr baseAddress,
        byte[] buffer,
        int size,
        out IntPtr bytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Thread32First(IntPtr snapshot, ref THREADENTRY32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Thread32Next(IntPtr snapshot, ref THREADENTRY32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr processHandle, out bool wow64Process);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool SymInitialize(IntPtr processHandle, string? userSearchPath, bool invadeProcess);

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool SymCleanup(IntPtr processHandle);

    [DllImport("dbghelp.dll")]
    private static extern uint SymSetOptions(uint symOptions);

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool SymFromAddr(IntPtr processHandle, ulong address, out ulong displacement, IntPtr symbol);

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern IntPtr SymFunctionTableAccess64(IntPtr processHandle, ulong addrBase);

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern ulong SymGetModuleBase64(IntPtr processHandle, ulong address);

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool StackWalk64(
        uint machineType,
        IntPtr processHandle,
        IntPtr threadHandle,
        ref STACKFRAME64 stackFrame,
        ref CONTEXT64 contextRecord,
        ReadProcessMemoryRoutine64 readMemoryRoutine,
        FunctionTableAccessRoutine64 functionTableAccessRoutine,
        GetModuleBaseRoutine64 getModuleBaseRoutine,
        IntPtr translateAddress);

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

    [StructLayout(LayoutKind.Sequential)]
    private struct ADDRESS64
    {
        public ulong Offset;
        public ushort Segment;
        public AddressMode Mode;
    }

    private enum AddressMode : uint
    {
        AddrMode1616,
        AddrMode1632,
        AddrModeReal,
        AddrModeFlat
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KDHELP64
    {
        public ulong Thread;
        public uint ThCallbackStack;
        public uint ThCallbackBStore;
        public uint NextCallback;
        public uint FramePointer;
        public ulong KiCallUserMode;
        public ulong KeUserCallbackDispatcher;
        public ulong SystemRangeStart;
        public ulong KiUserExceptionDispatcher;
        public ulong StackBase;
        public ulong StackLimit;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
        public ulong[] Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct STACKFRAME64
    {
        public ADDRESS64 AddrPC;
        public ADDRESS64 AddrReturn;
        public ADDRESS64 AddrFrame;
        public ADDRESS64 AddrStack;
        public ADDRESS64 AddrBStore;
        public IntPtr FuncTableEntry;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ulong[] Params;
        public int Far;
        public int Virtual;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public ulong[] Reserved;
        public KDHELP64 KdHelp;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct M128A
    {
        public ulong Low;
        public long High;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    private struct CONTEXT64
    {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;
        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;
        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
        public M128A[] VectorRegister;
        public ulong VectorControl;
        public ulong DebugControl;
        public ulong LastBranchToRip;
        public ulong LastBranchFromRip;
        public ulong LastExceptionToRip;
        public ulong LastExceptionFromRip;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYMBOL_INFO
    {
        public uint SizeOfStruct;
        public uint TypeIndex;
        public ulong Reserved1;
        public ulong Reserved2;
        public uint Index;
        public uint Size;
        public ulong ModBase;
        public uint Flags;
        public ulong Value;
        public ulong Address;
        public uint Register;
        public uint Scope;
        public uint Tag;
        public uint NameLen;
        public uint MaxNameLen;
    }

    private delegate bool ReadProcessMemoryRoutine64(
        IntPtr processHandle,
        ulong baseAddress,
        IntPtr buffer,
        uint size,
        out uint bytesRead);

    private delegate IntPtr FunctionTableAccessRoutine64(IntPtr processHandle, ulong address);

    private delegate ulong GetModuleBaseRoutine64(IntPtr processHandle, ulong address);

    private static void UnsafeInitBlock(byte* startAddress, byte value, uint byteCount)
    {
        for (uint i = 0; i < byteCount; i++)
        {
            startAddress[i] = value;
        }
    }
}
