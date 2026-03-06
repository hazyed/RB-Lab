using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RollbackGuard.Common.Security;

/// <summary>
/// SE_SIGNING_LEVEL values as defined in the Windows DDK (ntimage.h / wdm.h).
/// These represent the code-integrity trust tier assigned to a PE image by the
/// kernel's Code Integrity (CI) subsystem.
/// </summary>
public enum SeSigningLevel : byte
{
    Unchecked      = 0,   // Not yet validated by CI
    Unsigned       = 1,   // No valid signature present
    Enterprise     = 2,   // Enterprise certificate
    Developer      = 3,   // SE_SIGNING_LEVEL_CUSTOM_1 / developer/sideload
    Authenticode   = 4,   // Standard Authenticode chain
    Custom2        = 5,
    Store          = 6,   // Windows Store / MSIX package signature
    Antimalware    = 7,   // PPL-Antimalware trust (e.g. Defender)
    Microsoft      = 8,   // Microsoft corporation code-signing certificate
    Custom4        = 9,
    Custom5        = 10,
    DynamicCodegen = 11,  // Dynamic code generation policy
    Windows        = 12,  // Windows operating-system component
    Custom7        = 13,
    WindowsTcb     = 14,  // Windows Trusted Computing Base (boot / kernel drivers)
    Custom6        = 15
}

/// <summary>The result of a kernel-level signing-level query.</summary>
public readonly record struct KernelSigningResult(
    SeSigningLevel Level,
    bool IsKernelVerified,
    string StatusSummary);

/// <summary>
/// Queries the Windows kernel's Code Integrity subsystem for the SE_SIGNING_LEVEL
/// of a PE image using <c>NtGetCachedSigningLevel</c>.
///
/// When the level is not yet cached the method forces kernel evaluation by creating
/// a temporary image section via <c>NtCreateSection(SEC_IMAGE)</c>, which internally
/// invokes <c>SeVerifyImageHeader</c> and stores the verified level in the file
/// object.  The cached level is then re-queried from the same open file handle,
/// avoiding any TOCTOU window between path-based checks.
/// </summary>
public static class KernelSigningLevelChecker
{
    /// <summary>True when the level represents a Windows operating-system component (≥ Windows).</summary>
    public static bool IsWindowsCoreLevel(SeSigningLevel level) => level >= SeSigningLevel.Windows;

    /// <summary>True when the level represents a Microsoft-signed binary (≥ Microsoft tier).</summary>
    public static bool IsMicrosoftLevel(SeSigningLevel level) => level >= SeSigningLevel.Microsoft;

    /// <summary>True when the level represents any signed binary (≥ Authenticode tier).</summary>
    public static bool IsSignedLevel(SeSigningLevel level) => level >= SeSigningLevel.Authenticode;

    /// <summary>
    /// Attempts to obtain the kernel's cached signing level for the PE at
    /// <paramref name="filePath"/>.
    ///
    /// Returns <c>false</c> when the query is unavailable — for example when the
    /// file is not a valid PE image, or when an unexpected NT error prevents the
    /// image-section creation required to force CI evaluation.
    /// </summary>
    public static bool TryGetSigningLevel(string? filePath, out KernelSigningResult result)
    {
        result = default;
        if (string.IsNullOrWhiteSpace(filePath))
            return false;

        try
        {
            using var hFile = NativeMethods.OpenFileForRead(filePath);
            if (hFile.IsInvalid)
                return false;

            // Fast path: the signing level was already validated and cached by a
            // prior image-section creation (e.g. this file was previously loaded as
            // an executable or DLL by any process on the system).
            if (TryQueryCachedLevel(hFile, out var level))
            {
                result = new KernelSigningResult(level, IsKernelVerified: true, DescribeLevel(level));
                return true;
            }

            // Slow path: the signing level is not yet cached.  NtCreateSection with
            // SEC_IMAGE forces the kernel to parse the PE's certificate table and run
            // it through SeVerifyImageHeader (the Code Integrity policy engine).  On
            // success the verified level is stored in the file object for future
            // queries.  We do NOT map the section into any address space — creating
            // the section object is sufficient to trigger the CI evaluation.
            if (!TryCreateImageSection(hFile, out var hSection))
                return false;

            try
            {
                if (TryQueryCachedLevel(hFile, out level))
                {
                    result = new KernelSigningResult(level, IsKernelVerified: true, DescribeLevel(level));
                    return true;
                }
            }
            finally
            {
                _ = NativeMethods.NtClose(hSection);
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryQueryCachedLevel(SafeFileHandle hFile, out SeSigningLevel level)
    {
        level = SeSigningLevel.Unchecked;
        // Pass IntPtr.Zero for optional thumbprint output parameters to avoid
        // allocating a buffer — we only need the scalar signing-level byte.
        var status = NativeMethods.NtGetCachedSigningLevel(
            hFile,
            out _,
            out var rawLevel,
            IntPtr.Zero,
            IntPtr.Zero,
            IntPtr.Zero);

        if (status == 0) // STATUS_SUCCESS
        {
            level = (SeSigningLevel)rawLevel;
            return true;
        }

        // STATUS_INVALID_CACHED_SIGNING_LEVEL (0xC0000491): level not set yet.
        // Any other non-zero status: unexpected error — treat as unavailable.
        return false;
    }

    private static bool TryCreateImageSection(SafeFileHandle hFile, out IntPtr hSection)
    {
        hSection = IntPtr.Zero;
        // PAGE_EXECUTE (0x10) + SEC_IMAGE (0x01000000): creates a read-only image
        // section that triggers SeVerifyImageHeader without mapping pages.
        var status = NativeMethods.NtCreateSection(
            out hSection,
            NativeMethods.SectionQuery,
            IntPtr.Zero,   // no name / default security descriptor
            IntPtr.Zero,   // maximum size = file size
            NativeMethods.PageExecute,
            NativeMethods.SecImage,
            hFile);
        return status == 0;
    }

    private static string DescribeLevel(SeSigningLevel level) => level switch
    {
        SeSigningLevel.WindowsTcb    => "kernel-windows-tcb",
        SeSigningLevel.Windows       => "kernel-windows",
        SeSigningLevel.DynamicCodegen => "kernel-dynamic-codegen",
        SeSigningLevel.Microsoft     => "kernel-microsoft",
        SeSigningLevel.Antimalware   => "kernel-antimalware",
        SeSigningLevel.Store         => "kernel-store",
        SeSigningLevel.Authenticode  => "kernel-authenticode",
        SeSigningLevel.Enterprise    => "kernel-enterprise",
        SeSigningLevel.Developer     => "kernel-developer",
        SeSigningLevel.Unsigned      => "kernel-unsigned",
        SeSigningLevel.Unchecked     => "kernel-unchecked",
        _                            => $"kernel-level-{(byte)level}"
    };

    private static class NativeMethods
    {
        internal const uint SectionQuery = 0x0001;
        internal const uint PageExecute  = 0x10;
        internal const uint SecImage     = 0x01000000;

        private const uint GenericRead        = 0x80000000;
        private const uint FileShareRead      = 0x00000001;
        private const uint FileShareWrite     = 0x00000002;
        private const uint FileShareDelete    = 0x00000004;
        private const uint OpenExisting       = 3;
        private const uint FileAttributeNormal = 0x80;

        internal static SafeFileHandle OpenFileForRead(string path)
            => CreateFileW(
                path,
                GenericRead,
                FileShareRead | FileShareWrite | FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                FileAttributeNormal,
                IntPtr.Zero);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string   lpFileName,
            uint     dwDesiredAccess,
            uint     dwShareMode,
            IntPtr   lpSecurityAttributes,
            uint     dwCreationDisposition,
            uint     dwFlagsAndAttributes,
            IntPtr   hTemplateFile);

        /// <summary>
        /// Retrieves the kernel-cached SE_SIGNING_LEVEL for an open file handle.
        /// Returns STATUS_SUCCESS (0) when the level is available.
        /// Returns STATUS_INVALID_CACHED_SIGNING_LEVEL (0xC0000491) when the level
        /// has not yet been computed for this file object.
        /// </summary>
        [DllImport("ntdll.dll")]
        internal static extern int NtGetCachedSigningLevel(
            SafeFileHandle FileHandle,
            out uint       Flags,
            out byte       SigningLevel,
            IntPtr         Thumbprint,           // IntPtr.Zero = do not return thumbprint
            IntPtr         ThumbprintSize,       // IntPtr.Zero = do not return thumbprint size
            IntPtr         ThumbprintAlgorithm); // IntPtr.Zero = do not return algorithm

        /// <summary>
        /// Creates a section object backed by <paramref name="FileHandle"/>.
        /// Using SEC_IMAGE + PAGE_EXECUTE forces the kernel's Code Integrity
        /// subsystem to validate the PE certificate table and cache the resulting
        /// signing level on the file object before returning.
        /// </summary>
        [DllImport("ntdll.dll")]
        internal static extern int NtCreateSection(
            out IntPtr     SectionHandle,
            uint           DesiredAccess,
            IntPtr         ObjectAttributes,       // null = anonymous, default security
            IntPtr         MaximumSize,            // null = backed by full file size
            uint           SectionPageProtection,
            uint           AllocationAttributes,
            SafeFileHandle FileHandle);

        [DllImport("ntdll.dll")]
        internal static extern int NtClose(IntPtr Handle);
    }
}
