#include "../include/DriverContracts.h"
#include <ntstrsafe.h>

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION (0x0400)
#endif

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ (0x0010)
#endif

#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION (0x0040)
#endif

extern "C" NTSYSCALLAPI NTSTATUS NTAPI ZwOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PCLIENT_ID ClientId);
extern "C" NTSYSCALLAPI NTSTATUS NTAPI ZwOpenThread(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PCLIENT_ID ClientId);
extern "C" NTSYSCALLAPI NTSTATUS NTAPI ZwQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength);

enum : ULONG
{
    RollbackGuardThreadQuerySetWin32StartAddress = 9,
    RollbackGuardMemPrivate = 0x00020000,
    RollbackGuardMemMapped = 0x00040000,
    RollbackGuardMemImage = 0x01000000
};

typedef struct _ROLLBACKGUARD_MEMORY_BASIC_INFORMATION
{
    PVOID BaseAddress;
    PVOID AllocationBase;
    ULONG AllocationProtect;
    USHORT PartitionId;
    SIZE_T RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
} ROLLBACKGUARD_MEMORY_BASIC_INFORMATION;

typedef struct _ROLLBACKGUARD_THREAD_REGION_INFO
{
    PVOID StartAddress;
    PVOID RegionBase;
    SIZE_T RegionSize;
    ULONG Protect;
    ULONG Type;
    BOOLEAN QuerySucceeded;
} ROLLBACKGUARD_THREAD_REGION_INFO;

static VOID RollbackGuardUlongToAnsi(
    _In_ ULONG value,
    _Out_writes_(bufferChars) CHAR* buffer,
    _In_ SIZE_T bufferChars)
{
    if (buffer == nullptr || bufferChars == 0)
    {
        return;
    }

    CHAR digits[16] = {};
    int digitCount = 0;
    if (value == 0)
    {
        digits[digitCount++] = '0';
    }
    else
    {
        while (value > 0 && digitCount < ARRAYSIZE(digits))
        {
            digits[digitCount++] = static_cast<CHAR>('0' + (value % 10));
            value /= 10;
        }
    }

    SIZE_T pos = 0;
    for (int i = digitCount - 1; i >= 0 && pos + 1 < bufferChars; --i)
    {
        buffer[pos++] = digits[i];
    }

    buffer[pos] = '\0';
}

static ULONG RollbackGuardNormalizeProtect(_In_ ULONG protect)
{
    return protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
}

static BOOLEAN RollbackGuardIsExecutableProtect(_In_ ULONG protect)
{
    const ULONG normalized = RollbackGuardNormalizeProtect(protect);
    return normalized == PAGE_EXECUTE ||
        normalized == PAGE_EXECUTE_READ ||
        normalized == PAGE_EXECUTE_READWRITE ||
        normalized == PAGE_EXECUTE_WRITECOPY;
}

static BOOLEAN RollbackGuardIsWritableProtect(_In_ ULONG protect)
{
    const ULONG normalized = RollbackGuardNormalizeProtect(protect);
    return normalized == PAGE_READWRITE ||
        normalized == PAGE_WRITECOPY ||
        normalized == PAGE_EXECUTE_READWRITE ||
        normalized == PAGE_EXECUTE_WRITECOPY;
}

static NTSTATUS RollbackGuardQueryThreadStartAddress(
    _In_ HANDLE processId,
    _In_ HANDLE threadId,
    _Out_ PVOID* startAddress)
{
    if (startAddress == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *startAddress = nullptr;

    CLIENT_ID clientId = {};
    clientId.UniqueProcess = processId;
    clientId.UniqueThread = threadId;

    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

    HANDLE threadHandle = nullptr;
    NTSTATUS status = ZwOpenThread(&threadHandle, THREAD_QUERY_INFORMATION, &attributes, &clientId);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PVOID queriedStart = nullptr;
    status = ZwQueryInformationThread(
        threadHandle,
        RollbackGuardThreadQuerySetWin32StartAddress,
        &queriedStart,
        sizeof(queriedStart),
        nullptr);

    ZwClose(threadHandle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    *startAddress = queriedStart;
    return STATUS_SUCCESS;
}

static NTSTATUS RollbackGuardQueryThreadRegionInfo(
    _In_ HANDLE processId,
    _In_ PVOID startAddress,
    _Out_ ROLLBACKGUARD_THREAD_REGION_INFO* info)
{
    if (startAddress == nullptr || info == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(info, sizeof(*info));
    info->StartAddress = startAddress;

    CLIENT_ID clientId = {};
    clientId.UniqueProcess = processId;
    clientId.UniqueThread = nullptr;

    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

    HANDLE processHandle = nullptr;
    NTSTATUS status = ZwOpenProcess(
        &processHandle,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        &attributes,
        &clientId);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    ROLLBACKGUARD_MEMORY_BASIC_INFORMATION mbi = {};
    SIZE_T returnedLength = 0;
    status = ZwQueryVirtualMemory(
        processHandle,
        startAddress,
        MemoryBasicInformation,
        &mbi,
        sizeof(mbi),
        &returnedLength);

    ZwClose(processHandle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    info->RegionBase = mbi.BaseAddress;
    info->RegionSize = mbi.RegionSize;
    info->Protect = mbi.Protect;
    info->Type = mbi.Type;
    info->QuerySucceeded = TRUE;
    return STATUS_SUCCESS;
}

static ULONG RollbackGuardBuildThreadFlags(_In_ const ROLLBACKGUARD_THREAD_REGION_INFO* info)
{
    if (info == nullptr || !info->QuerySucceeded)
    {
        return 0;
    }

    ULONG flags = ROLLBACKGUARD_EVENT_FLAG_THREAD_START_VALID;
    const BOOLEAN isExecutable = RollbackGuardIsExecutableProtect(info->Protect);
    const BOOLEAN isWritable = RollbackGuardIsWritableProtect(info->Protect);

    if (info->Type == RollbackGuardMemPrivate)
    {
        flags |= ROLLBACKGUARD_EVENT_FLAG_THREAD_PRIVATE | ROLLBACKGUARD_EVENT_FLAG_THREAD_UNBACKED;
    }
    else if (info->Type == RollbackGuardMemImage)
    {
        flags |= ROLLBACKGUARD_EVENT_FLAG_THREAD_MEM_IMAGE;
    }
    else if (info->Type == RollbackGuardMemMapped)
    {
        flags |= ROLLBACKGUARD_EVENT_FLAG_THREAD_MEM_MAPPED;
    }

    if (isExecutable)
    {
        flags |= ROLLBACKGUARD_EVENT_FLAG_THREAD_EXECUTABLE;
    }

    if (isWritable)
    {
        flags |= ROLLBACKGUARD_EVENT_FLAG_THREAD_WRITABLE;
    }

    if (isExecutable && isWritable)
    {
        flags |= ROLLBACKGUARD_EVENT_FLAG_THREAD_WX;
    }

    return flags;
}

static VOID RollbackGuardBuildThreadSourceMetadata(
    _In_ const ROLLBACKGUARD_THREAD_REGION_INFO* info,
    _Out_writes_(destChars) CHAR* dest,
    _In_ SIZE_T destChars)
{
    if (dest == nullptr || destChars == 0)
    {
        return;
    }

    dest[0] = '\0';
    if (info == nullptr || !info->QuerySucceeded)
    {
        RollbackGuardCopyAnsiToBuffer("thread-start=query-failed", dest, destChars);
        return;
    }

    const BOOLEAN isExecutable = RollbackGuardIsExecutableProtect(info->Protect);
    const BOOLEAN isWritable = RollbackGuardIsWritableProtect(info->Protect);
    const BOOLEAN isWx = isExecutable && isWritable;
    const ULONG isPrivate = info->Type == RollbackGuardMemPrivate ? 1UL : 0UL;
    const ULONG isUnbacked = info->Type == RollbackGuardMemPrivate ? 1UL : 0UL;

    RtlStringCchPrintfA(
        dest,
        destChars,
        "thread-start=0x%p;base=0x%p;size=0x%Ix;protect=0x%08X;type=0x%08X;private=%lu;exec=%lu;write=%lu;wx=%lu;unbacked=%lu",
        info->StartAddress,
        info->RegionBase,
        info->RegionSize,
        info->Protect,
        info->Type,
        isPrivate,
        isExecutable ? 1UL : 0UL,
        isWritable ? 1UL : 0UL,
        isWx ? 1UL : 0UL,
        isUnbacked);
}

static VOID RollbackGuardOnThreadNotify(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create)
{
    if (!Create)
    {
        return;
    }

    const ULONG targetPid = HandleToULong(ProcessId);
    const ULONG creatorPid = HandleToULong(PsGetCurrentProcessId());
    if (creatorPid == targetPid)
    {
        return;
    }

    ROLLBACKGUARD_THREAD_REGION_INFO regionInfo = {};
    PVOID startAddress = nullptr;
    if (NT_SUCCESS(RollbackGuardQueryThreadStartAddress(ProcessId, ThreadId, &startAddress)) &&
        startAddress != nullptr)
    {
        (VOID)RollbackGuardQueryThreadRegionInfo(ProcessId, startAddress, &regionInfo);
    }

    ROLLBACKGUARD_DRIVER_EVENT_RECORD record = {};
    record.Kind = RollbackGuardEventThreadCreateRemote;
    record.ProcessId = creatorPid;
    record.ThreadId = HandleToULong(ThreadId);
    record.TimestampUnixMs = RollbackGuardGetUnixTimeMs();
    record.Flags = RollbackGuardBuildThreadFlags(&regionInfo);
    record.VolumeSerialNumber = reinterpret_cast<ULONGLONG>(regionInfo.StartAddress);
    record.FileId = reinterpret_cast<ULONGLONG>(regionInfo.RegionBase);
    record.ProcessPath[0] = '\0';

    CHAR pidBuffer[16] = {};
    RollbackGuardUlongToAnsi(targetPid, pidBuffer, ARRAYSIZE(pidBuffer));
    RollbackGuardCopyAnsiToBuffer(pidBuffer, record.TargetPath, ROLLBACKGUARD_PATH_CHARS);

    CHAR metadata[ROLLBACKGUARD_PATH_CHARS] = {};
    RollbackGuardBuildThreadSourceMetadata(&regionInfo, metadata, ARRAYSIZE(metadata));
    RollbackGuardCopyAnsiToBuffer(metadata, record.SourcePath, ROLLBACKGUARD_PATH_CHARS);

    RollbackGuardQueueEvent(&record);
}

_Use_decl_annotations_
NTSTATUS RegisterThreadMonitor(PROLLBACKGUARD_DEVICE_CONTEXT context)
{
    UNREFERENCED_PARAMETER(context);
    return PsSetCreateThreadNotifyRoutine(RollbackGuardOnThreadNotify);
}

_Use_decl_annotations_
VOID UnregisterThreadMonitor(PROLLBACKGUARD_DEVICE_CONTEXT context)
{
    UNREFERENCED_PARAMETER(context);
    PsRemoveCreateThreadNotifyRoutine(RollbackGuardOnThreadNotify);
}
