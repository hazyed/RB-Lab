#include "../include/DriverContracts.h"

// ObRegisterCallbacks is declared in wdm.h (included via ntddk.h)
// We need PsGetProcessImageFileName from ntifs.h
extern "C" NTKERNELAPI UCHAR* PsGetProcessImageFileName(_In_ PEPROCESS Process);
extern "C" NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process);
extern "C" NTKERNELAPI PEPROCESS PsGetThreadProcess(_In_ PETHREAD Thread);

static PVOID g_ObCallbackHandle = nullptr;
static KSPIN_LOCK g_RecentHandleEventLock;

typedef struct _ROLLBACKGUARD_RECENT_HANDLE_EVENT
{
    ULONG SourcePid;
    ULONG TargetPid;
    ULONG Kind;
    ACCESS_MASK DesiredAccess;
    LONGLONG TimestampUnixMs;
    BOOLEAN Active;
} ROLLBACKGUARD_RECENT_HANDLE_EVENT;

static ROLLBACKGUARD_RECENT_HANDLE_EVENT g_RecentHandleEvents[128] = {};

// Access rights that indicate injection intent
// PROCESS_VM_OPERATION (0x0008) + PROCESS_VM_WRITE (0x0020) = VirtualAllocEx + WriteProcessMemory
// PROCESS_CREATE_THREAD (0x0002) = CreateRemoteThread
#define INJECTION_PROCESS_ACCESS  (0x0008 | 0x0020)  // VM_OPERATION | VM_WRITE
#define REMOTE_THREAD_ACCESS      (0x0002)            // CREATE_THREAD

// Thread access for SetThreadContext / QueueUserAPC / NtResumeThread chains.
// THREAD_SUSPEND_RESUME (0x0002) | THREAD_GET_CONTEXT (0x0008) | THREAD_SET_CONTEXT (0x0010)
#define HIJACK_THREAD_ACCESS      (0x0002 | 0x0008 | 0x0010)
#define HANDLE_EVENT_DEDUP_WINDOW_MS 1500

// Known system process names to skip (15-char truncated image name)
static bool IsKnownSystemProcess(const UCHAR* imageName)
{
    if (imageName == nullptr) return true;

    // PsGetProcessImageFileName returns max 15 chars, null-terminated
    static const char* systemNames[] = {
        "System",
        "csrss.exe",
        "smss.exe",
        "services.exe",
        "lsass.exe",
        "wininit.exe",
        "winlogon.exe",
        "svchost.exe",
        "MsMpEng.exe",    // Windows Defender
        "NisSrv.exe",     // Defender NIS
        "SecurityHealth",  // Security Health (truncated at 15)
        "WmiPrvSE.exe",
        "taskhostw.exe",
        "RuntimeBroker.",  // truncated
        "SearchIndexer",   // truncated
        "dwm.exe",
        nullptr
    };

    for (int i = 0; systemNames[i] != nullptr; i++)
    {
        // Case-insensitive compare
        const char* a = (const char*)imageName;
        const char* b = systemNames[i];
        bool match = true;
        int j = 0;
        while (b[j] != '\0')
        {
            char ca = a[j];
            char cb = b[j];
            // Simple tolower for ASCII
            if (ca >= 'A' && ca <= 'Z') ca += 32;
            if (cb >= 'A' && cb <= 'Z') cb += 32;
            if (ca != cb) { match = false; break; }
            j++;
        }
        if (match && (a[j] == '\0' || a[j] == '.'))
            return true;
    }

    return false;
}

static void UlongToAnsiBuffer(ULONG value, CHAR* buffer, SIZE_T bufferSize)
{
    CHAR digits[16] = {};
    int digitCount = 0;

    if (value == 0)
    {
        digits[0] = '0';
        digitCount = 1;
    }
    else
    {
        while (value > 0 && digitCount < 15)
        {
            digits[digitCount++] = '0' + (CHAR)(value % 10);
            value /= 10;
        }
    }

    int pos = 0;
    for (int i = digitCount - 1; i >= 0 && pos + 1 < (int)bufferSize; --i)
    {
        buffer[pos++] = digits[i];
    }
    buffer[pos] = '\0';
}

static ACCESS_MASK GetDesiredAccess(_In_ POB_PRE_OPERATION_INFORMATION operationInfo)
{
    if (operationInfo->Operation == OB_OPERATION_HANDLE_CREATE)
    {
        return operationInfo->Parameters->CreateHandleInformation.DesiredAccess;
    }

    if (operationInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
    {
        return operationInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
    }

    return 0;
}

static BOOLEAN ShouldEmitHandleEvent(
    _In_ ULONG sourcePid,
    _In_ ULONG targetPid,
    _In_ ULONG kind,
    _In_ ACCESS_MASK desiredAccess)
{
    const LONGLONG nowMs = RollbackGuardGetUnixTimeMs();
    BOOLEAN shouldEmit = TRUE;
    ULONG replaceIndex = 0;
    LONGLONG oldestTimestamp = MAXLONGLONG;

    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_RecentHandleEventLock, &oldIrql);

    for (ULONG i = 0; i < RTL_NUMBER_OF(g_RecentHandleEvents); ++i)
    {
        auto* slot = &g_RecentHandleEvents[i];
        if (!slot->Active)
        {
            replaceIndex = i;
            oldestTimestamp = 0;
            break;
        }

        if (slot->TimestampUnixMs < oldestTimestamp)
        {
            oldestTimestamp = slot->TimestampUnixMs;
            replaceIndex = i;
        }

        if (slot->SourcePid == sourcePid &&
            slot->TargetPid == targetPid &&
            slot->Kind == kind &&
            slot->DesiredAccess == desiredAccess &&
            (nowMs - slot->TimestampUnixMs) <= HANDLE_EVENT_DEDUP_WINDOW_MS)
        {
            shouldEmit = FALSE;
            break;
        }
    }

    if (shouldEmit)
    {
        g_RecentHandleEvents[replaceIndex].SourcePid = sourcePid;
        g_RecentHandleEvents[replaceIndex].TargetPid = targetPid;
        g_RecentHandleEvents[replaceIndex].Kind = kind;
        g_RecentHandleEvents[replaceIndex].DesiredAccess = desiredAccess;
        g_RecentHandleEvents[replaceIndex].TimestampUnixMs = nowMs;
        g_RecentHandleEvents[replaceIndex].Active = TRUE;
    }

    KeReleaseSpinLock(&g_RecentHandleEventLock, oldIrql);
    return shouldEmit;
}

static OB_PREOP_CALLBACK_STATUS RollbackGuardProcessObjectPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInfo->Operation != OB_OPERATION_HANDLE_CREATE &&
        OperationInfo->Operation != OB_OPERATION_HANDLE_DUPLICATE)
    {
        return OB_PREOP_SUCCESS;
    }

    // Only flag user-mode callers
    if (OperationInfo->KernelHandle)
    {
        return OB_PREOP_SUCCESS;
    }

    // Get the access being requested
    ACCESS_MASK desiredAccess = GetDesiredAccess(OperationInfo);

    // Check if access includes injection-capable rights
    bool hasInjectionAccess = (desiredAccess & INJECTION_PROCESS_ACCESS) == INJECTION_PROCESS_ACCESS;
    bool hasRemoteThreadAccess = (desiredAccess & REMOTE_THREAD_ACCESS) != 0;

    if (!hasInjectionAccess && !hasRemoteThreadAccess)
    {
        return OB_PREOP_SUCCESS;
    }

    // Get source and target process info
    PEPROCESS sourceProcess = PsGetCurrentProcess();
    PEPROCESS targetProcess = (PEPROCESS)OperationInfo->Object;

    if (sourceProcess == targetProcess)
    {
        return OB_PREOP_SUCCESS; // Self-access
    }

    ULONG sourcePid = HandleToULong(PsGetProcessId(sourceProcess));
    ULONG targetPid = HandleToULong(PsGetProcessId(targetProcess));

    // Skip PID 0, 4 (System)
    if (sourcePid <= 4 || targetPid <= 4)
    {
        return OB_PREOP_SUCCESS;
    }

    // Skip known system processes as sources (they legitimately do cross-process ops)
    UCHAR* sourceImageName = PsGetProcessImageFileName(sourceProcess);
    if (IsKnownSystemProcess(sourceImageName))
    {
        return OB_PREOP_SUCCESS;
    }

    if (!ShouldEmitHandleEvent(sourcePid, targetPid, RollbackGuardEventSuspiciousHandleProcess, desiredAccess))
    {
        return OB_PREOP_SUCCESS;
    }

    // Build and queue event record
    ROLLBACKGUARD_DRIVER_EVENT_RECORD record = {};
    record.Kind = RollbackGuardEventSuspiciousHandleProcess;
    record.ProcessId = sourcePid;
    record.ThreadId = HandleToULong(PsGetCurrentThreadId());
    record.TimestampUnixMs = RollbackGuardGetUnixTimeMs();
    record.Flags = (ULONG)desiredAccess; // Store access mask in flags

    // Source process name in ProcessPath
    if (sourceImageName != nullptr)
    {
        RollbackGuardCopyAnsiToBuffer(
            (const CHAR*)sourceImageName,
            record.ProcessPath,
            ROLLBACKGUARD_PROCESS_PATH_CHARS);
    }

    // Target PID in TargetPath (same encoding as ThreadMonitor)
    CHAR targetPidStr[16] = {};
    UlongToAnsiBuffer(targetPid, targetPidStr, sizeof(targetPidStr));
    RollbackGuardCopyAnsiToBuffer(targetPidStr, record.TargetPath, ROLLBACKGUARD_PATH_CHARS);

    // Source PID in SourcePath
    CHAR sourcePidStr[16] = {};
    UlongToAnsiBuffer(sourcePid, sourcePidStr, sizeof(sourcePidStr));
    RollbackGuardCopyAnsiToBuffer(sourcePidStr, record.SourcePath, ROLLBACKGUARD_PATH_CHARS);

    RollbackGuardQueueEvent(&record);

    return OB_PREOP_SUCCESS;
}

static OB_PREOP_CALLBACK_STATUS RollbackGuardThreadObjectPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInfo->Operation != OB_OPERATION_HANDLE_CREATE &&
        OperationInfo->Operation != OB_OPERATION_HANDLE_DUPLICATE)
    {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInfo->KernelHandle)
    {
        return OB_PREOP_SUCCESS;
    }

    ACCESS_MASK desiredAccess = GetDesiredAccess(OperationInfo);

    // Check for THREAD_SET_CONTEXT (used in process hollowing / thread hijacking)
    if ((desiredAccess & HIJACK_THREAD_ACCESS) == 0)
    {
        return OB_PREOP_SUCCESS;
    }

    // Get the thread's owning process
    PEPROCESS targetProcess = PsGetThreadProcess((PETHREAD)OperationInfo->Object);
    PEPROCESS sourceProcess = PsGetCurrentProcess();

    if (sourceProcess == targetProcess)
    {
        return OB_PREOP_SUCCESS; // Self-access
    }

    ULONG sourcePid = HandleToULong(PsGetProcessId(sourceProcess));
    ULONG targetPid = HandleToULong(PsGetProcessId(targetProcess));

    if (sourcePid <= 4 || targetPid <= 4)
    {
        return OB_PREOP_SUCCESS;
    }

    UCHAR* sourceImageName = PsGetProcessImageFileName(sourceProcess);
    if (IsKnownSystemProcess(sourceImageName))
    {
        return OB_PREOP_SUCCESS;
    }

    if (!ShouldEmitHandleEvent(sourcePid, targetPid, RollbackGuardEventSuspiciousHandleThread, desiredAccess))
    {
        return OB_PREOP_SUCCESS;
    }

    ROLLBACKGUARD_DRIVER_EVENT_RECORD record = {};
    record.Kind = RollbackGuardEventSuspiciousHandleThread;
    record.ProcessId = sourcePid;
    record.ThreadId = HandleToULong(PsGetCurrentThreadId());
    record.TimestampUnixMs = RollbackGuardGetUnixTimeMs();
    record.Flags = (ULONG)desiredAccess;

    if (sourceImageName != nullptr)
    {
        RollbackGuardCopyAnsiToBuffer(
            (const CHAR*)sourceImageName,
            record.ProcessPath,
            ROLLBACKGUARD_PROCESS_PATH_CHARS);
    }

    CHAR targetPidStr[16] = {};
    UlongToAnsiBuffer(targetPid, targetPidStr, sizeof(targetPidStr));
    RollbackGuardCopyAnsiToBuffer(targetPidStr, record.TargetPath, ROLLBACKGUARD_PATH_CHARS);

    CHAR sourcePidStr[16] = {};
    UlongToAnsiBuffer(sourcePid, sourcePidStr, sizeof(sourcePidStr));
    RollbackGuardCopyAnsiToBuffer(sourcePidStr, record.SourcePath, ROLLBACKGUARD_PATH_CHARS);

    RollbackGuardQueueEvent(&record);

    return OB_PREOP_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS RegisterObjectMonitor(PROLLBACKGUARD_DEVICE_CONTEXT context)
{
    UNREFERENCED_PARAMETER(context);

    KeInitializeSpinLock(&g_RecentHandleEventLock);
    RtlZeroMemory(g_RecentHandleEvents, sizeof(g_RecentHandleEvents));

    // Build registration for process and thread object types
    OB_OPERATION_REGISTRATION opRegistration[2] = {};

    // Process object callback
    opRegistration[0].ObjectType = PsProcessType;
    opRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opRegistration[0].PreOperation = RollbackGuardProcessObjectPreCallback;
    opRegistration[0].PostOperation = nullptr;

    // Thread object callback
    opRegistration[1].ObjectType = PsThreadType;
    opRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opRegistration[1].PreOperation = RollbackGuardThreadObjectPreCallback;
    opRegistration[1].PostOperation = nullptr;

    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"321000");

    OB_CALLBACK_REGISTRATION callbackRegistration = {};
    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = 2;
    callbackRegistration.Altitude = altitude;
    callbackRegistration.RegistrationContext = nullptr;
    callbackRegistration.OperationRegistration = opRegistration;

    NTSTATUS status = ObRegisterCallbacks(&callbackRegistration, &g_ObCallbackHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[RollbackGuard] ObRegisterCallbacks failed: 0x%08X\n", status);
        g_ObCallbackHandle = nullptr;
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[RollbackGuard] ObjectMonitor registered (process + thread handle callbacks)\n");
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID UnregisterObjectMonitor(PROLLBACKGUARD_DEVICE_CONTEXT context)
{
    UNREFERENCED_PARAMETER(context);

    if (g_ObCallbackHandle != nullptr)
    {
        ObUnRegisterCallbacks(g_ObCallbackHandle);
        g_ObCallbackHandle = nullptr;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[RollbackGuard] ObjectMonitor unregistered\n");
    }
}
