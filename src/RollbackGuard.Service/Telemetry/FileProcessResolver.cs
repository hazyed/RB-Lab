using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;

namespace RollbackGuard.Service.Telemetry;

public sealed class FileProcessResolver
{
    private const int ErrorSuccess = 0;
    private const int ErrorMoreData = 234;
    private const int CchRmSessionKey = 32;
    private const int CchRmMaxAppName = 255;
    private const int CchRmMaxSvcName = 63;

    public IReadOnlyList<FileProcessCandidate> Resolve(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return [];
        }

        uint handle = 0;
        var sessionKey = new StringBuilder(CchRmSessionKey + 1);
        var startResult = RmStartSession(out handle, 0, sessionKey);
        if (startResult != ErrorSuccess)
        {
            return [];
        }

        try
        {
            var resources = new[] { path };
            var registerResult = RmRegisterResources(handle, (uint)resources.Length, resources, 0, null, 0, null);
            if (registerResult != ErrorSuccess)
            {
                return [];
            }

            uint processInfoNeeded = 0;
            uint processInfo = 0;
            uint rebootReasons = 0;

            var queryResult = RmGetList(handle, out processInfoNeeded, ref processInfo, null, ref rebootReasons);
            if (queryResult == ErrorSuccess)
            {
                return [];
            }

            if (queryResult != ErrorMoreData || processInfoNeeded == 0)
            {
                return [];
            }

            var infos = new RmProcessInfo[processInfoNeeded];
            processInfo = processInfoNeeded;
            queryResult = RmGetList(handle, out processInfoNeeded, ref processInfo, infos, ref rebootReasons);
            if (queryResult != ErrorSuccess)
            {
                return [];
            }

            var list = new List<FileProcessCandidate>((int)processInfo);
            for (var i = 0; i < processInfo; i++)
            {
                var candidate = BuildCandidate(in infos[i]);
                if (candidate.ProcessId > 0)
                {
                    list.Add(candidate);
                }
            }

            return list;
        }
        finally
        {
            RmEndSession(handle);
        }
    }

    private static FileProcessCandidate BuildCandidate(in RmProcessInfo info)
    {
        var pid = info.Process.dwProcessId;
        if (pid <= 0)
        {
            return FileProcessCandidate.Empty;
        }

        var processPath = string.Empty;
        var processName = string.Empty;
        var startTime = ConvertFileTime(info.Process.ProcessStartTime);

        try
        {
            using var process = Process.GetProcessById(pid);
            processName = process.ProcessName;
            processPath = process.MainModule?.FileName ?? string.Empty;

            if (startTime == DateTime.MinValue)
            {
                try
                {
                    startTime = process.StartTime;
                }
                catch
                {
                    startTime = DateTime.MinValue;
                }
            }
        }
        catch
        {
            // process may exit or be inaccessible
        }

        if (string.IsNullOrWhiteSpace(processName))
        {
            processName = info.strAppName ?? string.Empty;
        }

        return new FileProcessCandidate(pid, processName, processPath, startTime);
    }

    private static DateTime ConvertFileTime(FILETIME fileTime)
    {
        try
        {
            var high = (long)fileTime.dwHighDateTime << 32;
            var low = (uint)fileTime.dwLowDateTime;
            var ticks = high | low;
            if (ticks <= 0)
            {
                return DateTime.MinValue;
            }

            return DateTime.FromFileTimeUtc(ticks).ToLocalTime();
        }
        catch
        {
            return DateTime.MinValue;
        }
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, StringBuilder strSessionKey);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(
        uint dwSessionHandle,
        uint nFiles,
        string[]? rgsFileNames,
        uint nApplications,
        [In] RmUniqueProcess[]? rgApplications,
        uint nServices,
        string[]? rgsServiceNames);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmGetList(
        uint dwSessionHandle,
        out uint pnProcInfoNeeded,
        ref uint pnProcInfo,
        [In, Out] RmProcessInfo[]? rgAffectedApps,
        ref uint lpdwRebootReasons);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint pSessionHandle);

    [StructLayout(LayoutKind.Sequential)]
    private struct RmUniqueProcess
    {
        public int dwProcessId;
        public FILETIME ProcessStartTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RmProcessInfo
    {
        public RmUniqueProcess Process;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CchRmMaxAppName + 1)]
        public string strAppName;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CchRmMaxSvcName + 1)]
        public string strServiceShortName;

        public RmAppType ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;

        [MarshalAs(UnmanagedType.Bool)]
        public bool bRestartable;
    }

    private enum RmAppType
    {
        UnknownApp = 0,
        MainWindow = 1,
        OtherWindow = 2,
        Service = 3,
        Explorer = 4,
        Console = 5,
        Critical = 1000
    }
}

public readonly record struct FileProcessCandidate(
    int ProcessId,
    string ProcessName,
    string ProcessPath,
    DateTime StartTime)
{
    public static FileProcessCandidate Empty => new(0, string.Empty, string.Empty, DateTime.MinValue);
}
