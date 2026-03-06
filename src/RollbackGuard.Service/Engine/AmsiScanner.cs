using System.Runtime.InteropServices;
using RollbackGuard.Common.Diagnostics;

namespace RollbackGuard.Service.Engine;

/// <summary>
/// Integrates with Windows Antimalware Scan Interface (AMSI) to scan
/// content for malicious patterns. Provides on-demand scanning for
/// script blocks, memory buffers, and file content.
/// </summary>
public sealed class AmsiScanner : IDisposable
{
    private IntPtr _amsiContext;
    private IntPtr _amsiSession;
    private bool _initialized;
    private bool _disposed;
    private readonly object _sync = new();

    public bool Initialize()
    {
        lock (_sync)
        {
            if (_initialized) return true;

            try
            {
                var hr = AmsiInitialize("RollbackGuard", out _amsiContext);
                if (hr != 0)
                {
                    StartupLog.Write("AMSI", $"AmsiInitialize failed: hr=0x{hr:X8}");
                    return false;
                }

                hr = AmsiOpenSession(_amsiContext, out _amsiSession);
                if (hr != 0)
                {
                    StartupLog.Write("AMSI", $"AmsiOpenSession failed: hr=0x{hr:X8}");
                    AmsiUninitialize(_amsiContext);
                    _amsiContext = IntPtr.Zero;
                    return false;
                }

                _initialized = true;
                StartupLog.Write("AMSI", "AMSI initialized successfully");
                return true;
            }
            catch (Exception ex)
            {
                StartupLog.Write("AMSI", $"AMSI init exception: {ex.Message}");
                return false;
            }
        }
    }

    /// <summary>
    /// Scans a string content (e.g., script block) for malicious content.
    /// </summary>
    public AmsiScanResult ScanString(string content, string contentName = "script")
    {
        if (!_initialized || string.IsNullOrEmpty(content))
            return AmsiScanResult.Clean;

        lock (_sync)
        {
            try
            {
                var hr = AmsiScanString(_amsiContext, content, contentName, _amsiSession, out var result);
                if (hr != 0)
                    return AmsiScanResult.Error;

                return ClassifyResult(result);
            }
            catch (Exception ex)
            {
                StartupLog.Write("AMSI", $"ScanString error: {ex.Message}");
                return AmsiScanResult.Error;
            }
        }
    }

    /// <summary>
    /// Scans a byte buffer for malicious content.
    /// </summary>
    public AmsiScanResult ScanBuffer(byte[] buffer, string contentName = "buffer")
    {
        if (!_initialized || buffer == null || buffer.Length == 0)
            return AmsiScanResult.Clean;

        lock (_sync)
        {
            try
            {
                var hr = AmsiScanBuffer(_amsiContext, buffer, (uint)buffer.Length,
                    contentName, _amsiSession, out var result);
                if (hr != 0)
                    return AmsiScanResult.Error;

                return ClassifyResult(result);
            }
            catch (Exception ex)
            {
                StartupLog.Write("AMSI", $"ScanBuffer error: {ex.Message}");
                return AmsiScanResult.Error;
            }
        }
    }

    /// <summary>
    /// Scans a file's content for malicious patterns.
    /// Reads the first portion of the file and scans via AMSI.
    /// </summary>
    public AmsiScanResult ScanFile(string filePath, int maxReadBytes = 1024 * 1024)
    {
        if (!_initialized || string.IsNullOrWhiteSpace(filePath))
            return AmsiScanResult.Clean;

        try
        {
            if (!File.Exists(filePath))
                return AmsiScanResult.Clean;

            byte[] buffer;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var readSize = (int)Math.Min(fs.Length, maxReadBytes);
                buffer = new byte[readSize];
                _ = fs.Read(buffer, 0, readSize);
            }

            return ScanBuffer(buffer, filePath);
        }
        catch (Exception ex)
        {
            StartupLog.Write("AMSI", $"ScanFile error for {filePath}: {ex.Message}");
            return AmsiScanResult.Error;
        }
    }

    private static AmsiScanResult ClassifyResult(int result)
    {
        // AMSI_RESULT values:
        // 0 = Clean
        // 1 = Not detected
        // 16384 = Blocked by admin policy
        // 32768 = Malware detected
        return result switch
        {
            >= 32768 => AmsiScanResult.Malicious,
            >= 16384 => AmsiScanResult.BlockedByPolicy,
            1 => AmsiScanResult.Clean,
            0 => AmsiScanResult.Clean,
            _ => AmsiScanResult.Suspicious
        };
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        lock (_sync)
        {
            if (_amsiSession != IntPtr.Zero)
            {
                AmsiCloseSession(_amsiContext, _amsiSession);
                _amsiSession = IntPtr.Zero;
            }

            if (_amsiContext != IntPtr.Zero)
            {
                AmsiUninitialize(_amsiContext);
                _amsiContext = IntPtr.Zero;
            }
        }
    }

    #region P/Invoke

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

    [DllImport("amsi.dll")]
    private static extern void AmsiUninitialize(IntPtr amsiContext);

    [DllImport("amsi.dll")]
    private static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr session);

    [DllImport("amsi.dll")]
    private static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr session);

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiScanString(IntPtr amsiContext, string content,
        string contentName, IntPtr session, out int result);

    [DllImport("amsi.dll")]
    private static extern int AmsiScanBuffer(IntPtr amsiContext, byte[] buffer,
        uint length, string contentName, IntPtr session, out int result);

    #endregion
}

public enum AmsiScanResult
{
    Clean = 0,
    Suspicious = 1,
    Malicious = 2,
    BlockedByPolicy = 3,
    Error = -1
}
