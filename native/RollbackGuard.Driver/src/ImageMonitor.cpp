#include "../include/DriverContracts.h"

typedef UCHAR ROLLBACKGUARD_IMAGE_SIGNING_LEVEL;
typedef NTSTATUS (NTAPI* ROLLBACKGUARD_SE_GET_CACHED_SIGNING_LEVEL)(
    _In_ PFILE_OBJECT FileObject,
    _Out_opt_ PULONG Flags,
    _Out_ ROLLBACKGUARD_IMAGE_SIGNING_LEVEL* SigningLevel,
    _Out_writes_bytes_to_opt_(*ThumbprintSize, *ThumbprintSize) PUCHAR Thumbprint,
    _Inout_opt_ PULONG ThumbprintSize,
    _Out_opt_ PULONG ThumbprintAlgorithm);

static ROLLBACKGUARD_SE_GET_CACHED_SIGNING_LEVEL g_ImageSeGetCachedSigningLevel = nullptr;
static BOOLEAN g_ImageSigningResolverInitialized = FALSE;

#ifndef SE_SIGNING_LEVEL_UNCHECKED
#define SE_SIGNING_LEVEL_UNCHECKED         0x00
#define SE_SIGNING_LEVEL_UNSIGNED          0x01
#define SE_SIGNING_LEVEL_ENTERPRISE        0x02
#define SE_SIGNING_LEVEL_DEVELOPER         0x03
#define SE_SIGNING_LEVEL_AUTHENTICODE      0x04
#define SE_SIGNING_LEVEL_STORE             0x06
#define SE_SIGNING_LEVEL_ANTIMALWARE       0x07
#define SE_SIGNING_LEVEL_MICROSOFT         0x08
#define SE_SIGNING_LEVEL_DYNAMIC_CODEGEN   0x0B
#define SE_SIGNING_LEVEL_WINDOWS           0x0C
#define SE_SIGNING_LEVEL_WINDOWS_TCB       0x0E
#endif

static VOID RollbackGuardResolveImageSigningRoutine()
{
    if (g_ImageSigningResolverInitialized)
    {
        return;
    }

    g_ImageSigningResolverInitialized = TRUE;

    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"SeGetCachedSigningLevel");
    g_ImageSeGetCachedSigningLevel = reinterpret_cast<ROLLBACKGUARD_SE_GET_CACHED_SIGNING_LEVEL>(
        MmGetSystemRoutineAddress(&routineName));
}

static BOOLEAN RollbackGuardQueryImageSigningLevel(
    _In_opt_ PIMAGE_INFO imageInfo,
    _In_opt_ PUNICODE_STRING fullImageName,
    _Out_ ROLLBACKGUARD_IMAGE_SIGNING_LEVEL* signingLevel)
{
    if (signingLevel == nullptr)
    {
        return FALSE;
    }

    *signingLevel = SE_SIGNING_LEVEL_UNCHECKED;

    if (imageInfo == nullptr)
    {
        return FALSE;
    }

    // First preference: ask CI for cached signing level via file object.
    // ImageInfo->ImageSignatureLevel is often 0 in load notifications even for
    // signed images; SeGetCachedSigningLevel provides the authoritative verdict.
    if (imageInfo->ExtendedInfoPresent != 0)
    {
        auto* infoEx = CONTAINING_RECORD(imageInfo, IMAGE_INFO_EX, ImageInfo);
        if (infoEx != nullptr && infoEx->FileObject != nullptr)
        {
            RollbackGuardResolveImageSigningRoutine();
            if (g_ImageSeGetCachedSigningLevel != nullptr)
            {
                ULONG cachedFlags = 0;
                ROLLBACKGUARD_IMAGE_SIGNING_LEVEL cachedLevel = SE_SIGNING_LEVEL_UNCHECKED;
                const NTSTATUS status = g_ImageSeGetCachedSigningLevel(
                    infoEx->FileObject,
                    &cachedFlags,
                    &cachedLevel,
                    nullptr,
                    nullptr,
                    nullptr);
                if (NT_SUCCESS(status))
                {
                    *signingLevel = cachedLevel;
                    return TRUE;
                }
            }
        }
    }

    // Fallback: use ImageInfo field provided by loader callback.
    // Keep Unknown/Unchecked if still unavailable.
    *signingLevel = static_cast<ROLLBACKGUARD_IMAGE_SIGNING_LEVEL>(imageInfo->ImageSignatureLevel);
    UNREFERENCED_PARAMETER(fullImageName);
    return TRUE;
}

static ULONG RollbackGuardImageSigningLevelToEventFlags(_In_ ROLLBACKGUARD_IMAGE_SIGNING_LEVEL signingLevel)
{
    // Encode the raw SE_SIGNING_LEVEL in bits 24-27 so the service can use the
    // authoritative 4-bit kernel value instead of the coarse binary hint flags.
    ULONG flags = ROLLBACKGUARD_EVENT_ENCODE_SIGNING_LEVEL(signingLevel);

    // Important: UNCHECKED means "no reliable kernel verdict available yet",
    // not "confirmed unsigned". Treating UNCHECKED as unsigned downgrades
    // trusted system DLLs (e.g. ntdll) to Unsigned on the service side.
    if (signingLevel == SE_SIGNING_LEVEL_UNSIGNED)
    {
        return flags | ROLLBACKGUARD_EVENT_FLAG_UNSIGNED_PROCESS;
    }

    if (signingLevel == SE_SIGNING_LEVEL_UNCHECKED)
    {
        return flags;
    }

    flags |= ROLLBACKGUARD_EVENT_FLAG_SIGNED_HINT;

    // Antimalware (7) and above are all Microsoft-ecosystem trust tiers.
    if (signingLevel >= SE_SIGNING_LEVEL_ANTIMALWARE)
    {
        flags |= ROLLBACKGUARD_EVENT_FLAG_MS_HINT;
    }

    return flags;
}

static VOID RollbackGuardOnLoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{
    // Skip kernel-mode image loads
    if (ImageInfo->SystemModeImage)
    {
        return;
    }

    // Skip if no image name
    if (FullImageName == nullptr || FullImageName->Buffer == nullptr || FullImageName->Length == 0)
    {
        return;
    }

    ROLLBACKGUARD_DRIVER_EVENT_RECORD record = {};
    record.ProcessId = HandleToULong(ProcessId);
    record.ThreadId = HandleToULong(PsGetCurrentThreadId());
    record.TimestampUnixMs = RollbackGuardGetUnixTimeMs();

    RollbackGuardCopyUnicodeToAnsiBuffer(FullImageName, record.TargetPath, ROLLBACKGUARD_PATH_CHARS);
    record.ProcessPath[0] = '\0';
    record.SourcePath[0] = '\0';
    ROLLBACKGUARD_IMAGE_SIGNING_LEVEL signingLevel = SE_SIGNING_LEVEL_UNCHECKED;
    (void)RollbackGuardQueryImageSigningLevel(ImageInfo, FullImageName, &signingLevel);
    record.Flags = RollbackGuardImageSigningLevelToEventFlags(signingLevel);
    record.Kind = signingLevel == SE_SIGNING_LEVEL_UNSIGNED
        ? RollbackGuardEventImageLoadUnsigned
        : RollbackGuardEventImageLoad;

    RollbackGuardQueueEvent(&record);
}

_Use_decl_annotations_
NTSTATUS RegisterImageMonitor(PROLLBACKGUARD_DEVICE_CONTEXT context)
{
    UNREFERENCED_PARAMETER(context);
    return PsSetLoadImageNotifyRoutine(RollbackGuardOnLoadImageNotify);
}

_Use_decl_annotations_
VOID UnregisterImageMonitor(PROLLBACKGUARD_DEVICE_CONTEXT context)
{
    UNREFERENCED_PARAMETER(context);
    PsRemoveLoadImageNotifyRoutine(RollbackGuardOnLoadImageNotify);
}
