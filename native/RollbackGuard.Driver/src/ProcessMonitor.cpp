#include "../include/DriverContracts.h"

extern "C" NTKERNELAPI NTSTATUS PsSuspendProcess(_In_ PEPROCESS Process);
extern "C" NTKERNELAPI NTSTATUS PsResumeProcess(_In_ PEPROCESS Process);
extern "C" NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);
extern "C" NTKERNELAPI PACCESS_TOKEN PsReferencePrimaryToken(_In_ PEPROCESS Process);
extern "C" NTKERNELAPI VOID PsDereferencePrimaryToken(_In_ PACCESS_TOKEN PrimaryToken);

typedef UCHAR ROLLBACKGUARD_SE_SIGNING_LEVEL;
typedef NTSTATUS (NTAPI* ROLLBACKGUARD_SE_GET_CACHED_SIGNING_LEVEL)(
    _In_ PFILE_OBJECT FileObject,
    _Out_opt_ PULONG Flags,
    _Out_ ROLLBACKGUARD_SE_SIGNING_LEVEL* SigningLevel,
    _Out_writes_bytes_to_opt_(*ThumbprintSize, *ThumbprintSize) PUCHAR Thumbprint,
    _Inout_opt_ PULONG ThumbprintSize,
    _Out_opt_ PULONG ThumbprintAlgorithm);

// Undocumented CI export in ci.dll. Signature is intentionally minimal and
// guarded by runtime probing + status checks.
typedef NTSTATUS (NTAPI* ROLLBACKGUARD_CI_VALIDATE_FILE_OBJECT)(
    _In_ PFILE_OBJECT FileObject,
    _Out_opt_ PVOID PolicyInfo,
    _In_ ULONG PolicyInfoSize,
    _Out_opt_ PULONG ValidationFlags);

typedef struct _ROLLBACKGUARD_PS_PROTECTION
{
    union
    {
        UCHAR Level;
        struct
        {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} ROLLBACKGUARD_PS_PROTECTION, *PROLLBACKGUARD_PS_PROTECTION;

extern "C" NTKERNELAPI ROLLBACKGUARD_PS_PROTECTION PsGetProcessProtection(_In_ PEPROCESS Process);

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

#ifndef SECURITY_MANDATORY_LOW_RID
#define SECURITY_MANDATORY_LOW_RID         (0x00001000L)
#define SECURITY_MANDATORY_MEDIUM_RID      (0x00002000L)
#define SECURITY_MANDATORY_HIGH_RID        (0x00003000L)
#endif

static ROLLBACKGUARD_SE_GET_CACHED_SIGNING_LEVEL g_SeGetCachedSigningLevel = nullptr;
static ROLLBACKGUARD_CI_VALIDATE_FILE_OBJECT g_CiValidateFileObject = nullptr;
static BOOLEAN g_SigningResolverInitialized = FALSE;
static BOOLEAN g_CiResolverInitialized = FALSE;
static constexpr TOKEN_INFORMATION_CLASS RollbackGuardTokenIntegrityClass =
    static_cast<TOKEN_INFORMATION_CLASS>(25);

enum ROLLBACKGUARD_SIGNING_SOURCE : ULONG
{
    RollbackGuardSigningSourceNone = ROLLBACKGUARD_EVENT_SIGNING_SOURCE_NONE,
    RollbackGuardSigningSourcePpl = ROLLBACKGUARD_EVENT_SIGNING_SOURCE_PPL,
    RollbackGuardSigningSourceCache = ROLLBACKGUARD_EVENT_SIGNING_SOURCE_CACHE,
    RollbackGuardSigningSourceActiveCi = ROLLBACKGUARD_EVENT_SIGNING_SOURCE_ACTIVE_CI
};

enum ROLLBACKGUARD_SIGNING_STATUS : ULONG
{
    RollbackGuardSigningStatusUnknown = ROLLBACKGUARD_EVENT_SIGNING_STATUS_UNKNOWN,
    RollbackGuardSigningStatusVerified = ROLLBACKGUARD_EVENT_SIGNING_STATUS_VERIFIED,
    RollbackGuardSigningStatusUnsigned = ROLLBACKGUARD_EVENT_SIGNING_STATUS_UNSIGNED,
    RollbackGuardSigningStatusError = ROLLBACKGUARD_EVENT_SIGNING_STATUS_ERROR
};

static VOID RollbackGuardResolveSigningRoutine()
{
    if (g_SigningResolverInitialized)
    {
        return;
    }

    g_SigningResolverInitialized = TRUE;

    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"SeGetCachedSigningLevel");
    g_SeGetCachedSigningLevel = reinterpret_cast<ROLLBACKGUARD_SE_GET_CACHED_SIGNING_LEVEL>(
        MmGetSystemRoutineAddress(&routineName));
}

static VOID RollbackGuardResolveCiValidateRoutine()
{
    if (g_CiResolverInitialized)
    {
        return;
    }

    g_CiResolverInitialized = TRUE;

    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"CiValidateFileObject");
    g_CiValidateFileObject = reinterpret_cast<ROLLBACKGUARD_CI_VALIDATE_FILE_OBJECT>(
        MmGetSystemRoutineAddress(&routineName));
}

static ULONG RollbackGuardBuildSigningFlags(
    _In_ ROLLBACKGUARD_SE_SIGNING_LEVEL signingLevel,
    _In_ ROLLBACKGUARD_SIGNING_SOURCE source,
    _In_ ROLLBACKGUARD_SIGNING_STATUS status)
{
    ULONG flags = ROLLBACKGUARD_EVENT_ENCODE_SIGNING_LEVEL(signingLevel) |
        ROLLBACKGUARD_EVENT_ENCODE_SIGNING_SOURCE(source) |
        ROLLBACKGUARD_EVENT_ENCODE_SIGNING_STATUS(status);

    if (signingLevel == SE_SIGNING_LEVEL_UNSIGNED || status == RollbackGuardSigningStatusUnsigned)
    {
        flags |= ROLLBACKGUARD_EVENT_FLAG_UNSIGNED_PROCESS;
        return flags;
    }

    if (signingLevel != SE_SIGNING_LEVEL_UNCHECKED || status == RollbackGuardSigningStatusVerified)
    {
        flags |= ROLLBACKGUARD_EVENT_FLAG_SIGNED_HINT;
    }

    if (signingLevel >= SE_SIGNING_LEVEL_ANTIMALWARE || source == RollbackGuardSigningSourcePpl)
    {
        flags |= ROLLBACKGUARD_EVENT_FLAG_MS_HINT;
    }

    return flags;
}

static BOOLEAN RollbackGuardTryReadCachedSigningLevel(
    _In_opt_ PFILE_OBJECT fileObject,
    _Out_ ROLLBACKGUARD_SE_SIGNING_LEVEL* signingLevel)
{
    if (signingLevel == nullptr)
    {
        return FALSE;
    }

    *signingLevel = SE_SIGNING_LEVEL_UNCHECKED;

    if (fileObject == nullptr)
    {
        return FALSE;
    }

    RollbackGuardResolveSigningRoutine();
    if (g_SeGetCachedSigningLevel == nullptr)
    {
        return FALSE;
    }

    ULONG cachedFlags = 0;
    const NTSTATUS status = g_SeGetCachedSigningLevel(
        fileObject,
        &cachedFlags,
        signingLevel,
        nullptr,
        nullptr,
        nullptr);

    return NT_SUCCESS(status);
}

static BOOLEAN RollbackGuardTryValidateByPpl(
    _In_opt_ PEPROCESS process,
    _Out_ ROLLBACKGUARD_SE_SIGNING_LEVEL* signingLevel)
{
    if (process == nullptr || signingLevel == nullptr)
    {
        return FALSE;
    }

    const ROLLBACKGUARD_PS_PROTECTION protection = PsGetProcessProtection(process);
    if (protection.Type == 0)
    {
        return FALSE;
    }

    *signingLevel = SE_SIGNING_LEVEL_WINDOWS;
    return TRUE;
}

static BOOLEAN RollbackGuardTryForceCiValidation(_In_opt_ PFILE_OBJECT fileObject)
{
    if (fileObject == nullptr)
    {
        return FALSE;
    }

    RollbackGuardResolveCiValidateRoutine();
    if (g_CiValidateFileObject == nullptr)
    {
        return FALSE;
    }

    ULONG ciFlags = 0;
    const NTSTATUS ciStatus = g_CiValidateFileObject(fileObject, nullptr, 0, &ciFlags);
    return NT_SUCCESS(ciStatus);
}

static ULONG RollbackGuardQueryProcessSigningHint(_In_opt_ PEPROCESS process, _In_opt_ PFILE_OBJECT fileObject)
{
    ROLLBACKGUARD_SE_SIGNING_LEVEL level = SE_SIGNING_LEVEL_UNCHECKED;

    // Tier 1: PPL is highest-priority fast-path.
    if (RollbackGuardTryValidateByPpl(process, &level))
    {
        return RollbackGuardBuildSigningFlags(level, RollbackGuardSigningSourcePpl, RollbackGuardSigningStatusVerified);
    }

    // Tier 2: cached CI signing level.
    if (RollbackGuardTryReadCachedSigningLevel(fileObject, &level))
    {
        if (level == SE_SIGNING_LEVEL_UNSIGNED)
        {
            return RollbackGuardBuildSigningFlags(level, RollbackGuardSigningSourceCache, RollbackGuardSigningStatusUnsigned);
        }

        if (level != SE_SIGNING_LEVEL_UNCHECKED)
        {
            return RollbackGuardBuildSigningFlags(level, RollbackGuardSigningSourceCache, RollbackGuardSigningStatusVerified);
        }
    }

    // Tier 3: active CI validation + cache re-read.
    if (RollbackGuardTryForceCiValidation(fileObject))
    {
        ROLLBACKGUARD_SE_SIGNING_LEVEL validatedLevel = SE_SIGNING_LEVEL_UNCHECKED;
        if (RollbackGuardTryReadCachedSigningLevel(fileObject, &validatedLevel))
        {
            if (validatedLevel == SE_SIGNING_LEVEL_UNSIGNED)
            {
                return RollbackGuardBuildSigningFlags(validatedLevel, RollbackGuardSigningSourceActiveCi, RollbackGuardSigningStatusUnsigned);
            }

            if (validatedLevel != SE_SIGNING_LEVEL_UNCHECKED)
            {
                return RollbackGuardBuildSigningFlags(validatedLevel, RollbackGuardSigningSourceActiveCi, RollbackGuardSigningStatusVerified);
            }

            return RollbackGuardBuildSigningFlags(validatedLevel, RollbackGuardSigningSourceActiveCi, RollbackGuardSigningStatusUnknown);
        }

        return RollbackGuardBuildSigningFlags(SE_SIGNING_LEVEL_UNCHECKED, RollbackGuardSigningSourceActiveCi, RollbackGuardSigningStatusError);
    }

    return RollbackGuardBuildSigningFlags(SE_SIGNING_LEVEL_UNCHECKED, RollbackGuardSigningSourceNone, RollbackGuardSigningStatusUnknown);
}

static ULONG RollbackGuardQueryProcessIntegrityHint(_In_opt_ PEPROCESS process)
{
    typedef struct _ROLLBACKGUARD_TOKEN_MANDATORY_LABEL
    {
        SID_AND_ATTRIBUTES Label;
    } ROLLBACKGUARD_TOKEN_MANDATORY_LABEL, *PROLLBACKGUARD_TOKEN_MANDATORY_LABEL;

    if (process == nullptr)
    {
        return ROLLBACKGUARD_EVENT_ENCODE_INTEGRITY(ROLLBACKGUARD_EVENT_INTEGRITY_UNKNOWN);
    }

    PACCESS_TOKEN token = PsReferencePrimaryToken(process);
    if (token == nullptr)
    {
        return ROLLBACKGUARD_EVENT_ENCODE_INTEGRITY(ROLLBACKGUARD_EVENT_INTEGRITY_UNKNOWN);
    }

    HANDLE tokenHandle = nullptr;
    NTSTATUS status = ObOpenObjectByPointer(
        token,
        OBJ_KERNEL_HANDLE,
        nullptr,
        TOKEN_QUERY,
        nullptr,
        KernelMode,
        &tokenHandle);
    PsDereferencePrimaryToken(token);

    if (!NT_SUCCESS(status) || tokenHandle == nullptr)
    {
        return ROLLBACKGUARD_EVENT_ENCODE_INTEGRITY(ROLLBACKGUARD_EVENT_INTEGRITY_UNKNOWN);
    }

    ULONG required = 0;
    status = ZwQueryInformationToken(tokenHandle, RollbackGuardTokenIntegrityClass, nullptr, 0, &required);
    if (status != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(status))
    {
        ZwClose(tokenHandle);
        return ROLLBACKGUARD_EVENT_ENCODE_INTEGRITY(ROLLBACKGUARD_EVENT_INTEGRITY_UNKNOWN);
    }

    auto* label = static_cast<PROLLBACKGUARD_TOKEN_MANDATORY_LABEL>(ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        required,
        'IpgR'));
    if (label == nullptr)
    {
        ZwClose(tokenHandle);
        return ROLLBACKGUARD_EVENT_ENCODE_INTEGRITY(ROLLBACKGUARD_EVENT_INTEGRITY_UNKNOWN);
    }

    RtlZeroMemory(label, required);
    status = ZwQueryInformationToken(tokenHandle, RollbackGuardTokenIntegrityClass, label, required, &required);
    ZwClose(tokenHandle);
    if (!NT_SUCCESS(status) || label->Label.Sid == nullptr || !RtlValidSid(label->Label.Sid))
    {
        ExFreePoolWithTag(label, 'IpgR');
        return ROLLBACKGUARD_EVENT_ENCODE_INTEGRITY(ROLLBACKGUARD_EVENT_INTEGRITY_UNKNOWN);
    }

    const UCHAR subAuthorityCount = *RtlSubAuthorityCountSid(label->Label.Sid);
    ULONG rid = 0;
    if (subAuthorityCount > 0)
    {
        rid = *RtlSubAuthoritySid(label->Label.Sid, subAuthorityCount - 1);
    }

    ExFreePoolWithTag(label, 'IpgR');

    ULONG integrityCode = ROLLBACKGUARD_EVENT_INTEGRITY_UNKNOWN;
    if (rid >= SECURITY_MANDATORY_HIGH_RID)
    {
        integrityCode = ROLLBACKGUARD_EVENT_INTEGRITY_HIGH;
    }
    else if (rid >= SECURITY_MANDATORY_MEDIUM_RID)
    {
        integrityCode = ROLLBACKGUARD_EVENT_INTEGRITY_MEDIUM;
    }
    else if (rid >= SECURITY_MANDATORY_LOW_RID)
    {
        integrityCode = ROLLBACKGUARD_EVENT_INTEGRITY_LOW;
    }

    return ROLLBACKGUARD_EVENT_ENCODE_INTEGRITY(integrityCode);
}

static BOOLEAN RollbackGuardAnsiContainsInsensitive(
    _In_z_ const CHAR* haystack,
    _In_z_ const CHAR* needle)
{
    if (haystack == nullptr || needle == nullptr)
    {
        return FALSE;
    }

    for (SIZE_T i = 0; haystack[i] != '\0'; ++i)
    {
        BOOLEAN match = TRUE;
        for (SIZE_T j = 0; needle[j] != '\0'; ++j)
        {
            CHAR h = haystack[i + j];
            CHAR n = needle[j];
            if (h == '\0')
            {
                match = FALSE;
                break;
            }

            if (h >= 'A' && h <= 'Z')
            {
                h += ('a' - 'A');
            }

            if (n >= 'A' && n <= 'Z')
            {
                n += ('a' - 'A');
            }

            if (h != n)
            {
                match = FALSE;
                break;
            }
        }

        if (match)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN RollbackGuardIsShadowDeleteCommand(_In_z_ const CHAR* commandLine)
{
    if (commandLine == nullptr || commandLine[0] == '\0')
    {
        return FALSE;
    }

    if (RollbackGuardAnsiContainsInsensitive(commandLine, "vssadmin") &&
        RollbackGuardAnsiContainsInsensitive(commandLine, "delete") &&
        RollbackGuardAnsiContainsInsensitive(commandLine, "shadows"))
    {
        return TRUE;
    }

    if (RollbackGuardAnsiContainsInsensitive(commandLine, "wbadmin") &&
        RollbackGuardAnsiContainsInsensitive(commandLine, "delete"))
    {
        return TRUE;
    }

    if (RollbackGuardAnsiContainsInsensitive(commandLine, "wmic") &&
        RollbackGuardAnsiContainsInsensitive(commandLine, "shadowcopy") &&
        RollbackGuardAnsiContainsInsensitive(commandLine, "delete"))
    {
        return TRUE;
    }

    if (RollbackGuardAnsiContainsInsensitive(commandLine, "bcdedit") &&
        RollbackGuardAnsiContainsInsensitive(commandLine, "recoveryenabled") &&
        RollbackGuardAnsiContainsInsensitive(commandLine, "no"))
    {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN RollbackGuardPathEndsWithInsensitive(_In_z_ const CHAR* value, _In_z_ const CHAR* suffix)
{
    if (value == nullptr || suffix == nullptr)
    {
        return FALSE;
    }

    SIZE_T valueLen = 0;
    while (value[valueLen] != '\0')
    {
        valueLen++;
    }

    SIZE_T suffixLen = 0;
    while (suffix[suffixLen] != '\0')
    {
        suffixLen++;
    }

    if (suffixLen == 0 || suffixLen > valueLen)
    {
        return FALSE;
    }

    const SIZE_T offset = valueLen - suffixLen;
    for (SIZE_T i = 0; i < suffixLen; ++i)
    {
        CHAR left = value[offset + i];
        CHAR right = suffix[i];
        if (left >= 'A' && left <= 'Z')
        {
            left += ('a' - 'A');
        }
        if (right >= 'A' && right <= 'Z')
        {
            right += ('a' - 'A');
        }
        if (left != right)
        {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN RollbackGuardIsStabilityCriticalProcessPath(_In_z_ const CHAR* processPath)
{
    if (processPath == nullptr || processPath[0] == '\0')
    {
        return FALSE;
    }

    if (!RollbackGuardAnsiContainsInsensitive(processPath, "\\windows\\"))
    {
        return FALSE;
    }

    static const CHAR* kCriticalSuffixes[] =
    {
        "\\explorer.exe",
        "\\dwm.exe",
        "\\winlogon.exe",
        "\\csrss.exe",
        "\\smss.exe",
        "\\lsass.exe",
        "\\services.exe",
        "\\svchost.exe",
        "\\taskhostw.exe",
        "\\sihost.exe",
        "\\startmenuexperiencehost.exe",
        "\\shellexperiencehost.exe",
        "\\searchhost.exe",
        "\\searchindexer.exe",
        "\\runtimebroker.exe",
        "\\ctfmon.exe"
    };

    for (SIZE_T i = 0; i < RTL_NUMBER_OF(kCriticalSuffixes); ++i)
    {
        if (RollbackGuardPathEndsWithInsensitive(processPath, kCriticalSuffixes[i]))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN RollbackGuardIsProductSelfProcessPath(_In_z_ const CHAR* processPath)
{
    if (processPath == nullptr || processPath[0] == '\0')
    {
        return FALSE;
    }

    static const CHAR* kSelfSuffixes[] =
    {
        "\\rollbackguard.service.exe",
        "\\rollbackguard.ui.exe",
        "\\rollbackguard.cli.exe"
    };

    for (SIZE_T i = 0; i < RTL_NUMBER_OF(kSelfSuffixes); ++i)
    {
        if (RollbackGuardPathEndsWithInsensitive(processPath, kSelfSuffixes[i]))
        {
            return TRUE;
        }
    }

    return FALSE;
}

typedef struct _ROLLBACKGUARD_AUTO_RESUME_WORKITEM_CONTEXT
{
    WORK_QUEUE_ITEM WorkItem;
    HANDLE ProcessId;
} ROLLBACKGUARD_AUTO_RESUME_WORKITEM_CONTEXT, *PROLLBACKGUARD_AUTO_RESUME_WORKITEM_CONTEXT;

static constexpr LONGLONG RollbackGuardAutoResumeTimeout100ns = -5LL * 1000LL * 1000LL * 10LL;

static VOID RollbackGuardAutoResumeWorker(_In_ PVOID parameter)
{
    auto* context = static_cast<PROLLBACKGUARD_AUTO_RESUME_WORKITEM_CONTEXT>(parameter);
    if (context == nullptr)
    {
        return;
    }

    LARGE_INTEGER interval = {};
    interval.QuadPart = RollbackGuardAutoResumeTimeout100ns;
    KeDelayExecutionThread(KernelMode, FALSE, &interval);

    PEPROCESS process = nullptr;
    if (NT_SUCCESS(PsLookupProcessByProcessId(context->ProcessId, &process)))
    {
        (VOID)PsResumeProcess(process);
        ObDereferenceObject(process);
    }

    ExFreePoolWithTag(context, 'RagR');
}

static VOID RollbackGuardScheduleAutoResume(_In_ HANDLE processId)
{
    auto* context = static_cast<PROLLBACKGUARD_AUTO_RESUME_WORKITEM_CONTEXT>(ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(ROLLBACKGUARD_AUTO_RESUME_WORKITEM_CONTEXT),
        'RagR'));
    if (context == nullptr)
    {
        return;
    }

    RtlZeroMemory(context, sizeof(*context));
    context->ProcessId = processId;
    ExInitializeWorkItem(&context->WorkItem, RollbackGuardAutoResumeWorker, context);
    ExQueueWorkItem(&context->WorkItem, DelayedWorkQueue);
}

static VOID RollbackGuardOnProcessNotifyEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    ROLLBACKGUARD_DRIVER_EVENT_RECORD record = {};
    record.ProcessId = HandleToULong(ProcessId);
    record.ThreadId = 0;
    record.TimestampUnixMs = RollbackGuardGetUnixTimeMs();

    if (CreateInfo == nullptr)
    {
        record.Kind = RollbackGuardEventProcessTerminate;
        record.Flags = 0;
        record.ProcessPath[0] = '\0';
        record.TargetPath[0] = '\0';
        record.SourcePath[0] = '\0';
        RollbackGuardQueueEvent(&record);
        return;
    }

    record.Kind = RollbackGuardEventProcessCreate;
    record.Flags = 0;

    RollbackGuardCopyUnicodeToAnsiBuffer(CreateInfo->ImageFileName, record.ProcessPath, ROLLBACKGUARD_PROCESS_PATH_CHARS);
    RollbackGuardCopyUnicodeToAnsiBuffer(CreateInfo->CommandLine, record.TargetPath, ROLLBACKGUARD_PATH_CHARS);

    ULONG parentPid = HandleToULong(CreateInfo->ParentProcessId);
    CHAR ppidBuffer[16] = {};
    ULONG ppidVal = parentPid;
    int pos = 0;
    CHAR digits[16] = {};
    int digitCount = 0;

    if (ppidVal == 0)
    {
        digits[0] = '0';
        digitCount = 1;
    }
    else
    {
        while (ppidVal > 0 && digitCount < 15)
        {
            digits[digitCount++] = '0' + (CHAR)(ppidVal % 10);
            ppidVal /= 10;
        }
    }

    for (int i = digitCount - 1; i >= 0 && pos < 15; --i)
    {
        ppidBuffer[pos++] = digits[i];
    }
    ppidBuffer[pos] = '\0';

    RollbackGuardCopyAnsiToBuffer(ppidBuffer, record.SourcePath, ROLLBACKGUARD_PATH_CHARS);
    record.Flags |= RollbackGuardQueryProcessSigningHint(Process, CreateInfo->FileObject);
    record.Flags |= RollbackGuardQueryProcessIntegrityHint(Process);

    if (CreateInfo->CreationStatus == STATUS_SUCCESS &&
        CreateInfo->IsSubsystemProcess == FALSE &&
        !RollbackGuardIsStabilityCriticalProcessPath(record.ProcessPath) &&
        !RollbackGuardIsProductSelfProcessPath(record.ProcessPath))
    {
        const NTSTATUS suspendStatus = PsSuspendProcess(Process);
        if (NT_SUCCESS(suspendStatus))
        {
            record.Flags |= ROLLBACKGUARD_EVENT_FLAG_SUSPENDED;
            RollbackGuardScheduleAutoResume(ProcessId);
        }
    }

    RollbackGuardQueueEvent(&record);

    if (record.TargetPath[0] != '\0' && RollbackGuardIsShadowDeleteCommand(record.TargetPath))
    {
        ROLLBACKGUARD_DRIVER_EVENT_RECORD shadowRecord = {};
        shadowRecord.Kind = RollbackGuardEventShadowDeleteAttempt;
        shadowRecord.ProcessId = HandleToULong(ProcessId);
        shadowRecord.ThreadId = 0;
        shadowRecord.TimestampUnixMs = RollbackGuardGetUnixTimeMs();
        shadowRecord.Flags = 0;

        RollbackGuardCopyAnsiToBuffer(record.ProcessPath, shadowRecord.ProcessPath, ROLLBACKGUARD_PROCESS_PATH_CHARS);
        RollbackGuardCopyAnsiToBuffer(record.TargetPath, shadowRecord.TargetPath, ROLLBACKGUARD_PATH_CHARS);
        shadowRecord.SourcePath[0] = '\0';

        RollbackGuardQueueEvent(&shadowRecord);
    }
}

_Use_decl_annotations_
NTSTATUS RegisterProcessMonitor(PROLLBACKGUARD_DEVICE_CONTEXT context)
{
    UNREFERENCED_PARAMETER(context);
    return PsSetCreateProcessNotifyRoutineEx(RollbackGuardOnProcessNotifyEx, FALSE);
}

_Use_decl_annotations_
VOID UnregisterProcessMonitor(PROLLBACKGUARD_DEVICE_CONTEXT context)
{
    UNREFERENCED_PARAMETER(context);
    PsSetCreateProcessNotifyRoutineEx(RollbackGuardOnProcessNotifyEx, TRUE);
}
