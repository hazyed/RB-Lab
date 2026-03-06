#include <fltKernel.h>
#include <ntstrsafe.h>

#define ROLLBACKGUARD_MINIFILTER_DEVICE_NAME L"\\Device\\RollbackGuardMiniFilter"
#define ROLLBACKGUARD_MINIFILTER_DOS_NAME L"\\DosDevices\\RollbackGuardMiniFilter"

extern "C" UCHAR* PsGetProcessImageFileName(_In_ PEPROCESS Process);

#define ROLLBACKGUARD_EVENT_QUEUE_CAPACITY 256
#define ROLLBACKGUARD_CONTROL_QUEUE_CAPACITY 256
#define ROLLBACKGUARD_EVENT_QUEUE_TAG 'EmgR'
#define ROLLBACKGUARD_CONTROL_QUEUE_TAG 'CmgR'
#define ROLLBACKGUARD_PROCESS_PATH_CHARS 260
#define ROLLBACKGUARD_PATH_CHARS 520
#define ROLLBACKGUARD_OBJECT_NAME_CHARS 128
#define ROLLBACKGUARD_MAX_EVENTS 128
#define ROLLBACKGUARD_MAX_HONEY_PATHS 64
#define ROLLBACKGUARD_BLOCKED_PROCESS_CAPACITY 256
#define ROLLBACKGUARD_RESTRICTED_PROCESS_CAPACITY 256
#define ROLLBACKGUARD_EVENT_FLAG_PRE_OPERATION 0x00000010UL
#define ROLLBACKGUARD_EVENT_FLAG_KERNEL_HIGH_ENTROPY_RAW 0x00010000UL
#define ROLLBACKGUARD_EVENT_FLAG_KERNEL_LOW_TO_HIGH 0x00020000UL
#define ROLLBACKGUARD_EVENT_FLAG_KERNEL_AUTO_BLOCKED 0x00040000UL
#define ROLLBACKGUARD_EVENT_FLAG_KERNEL_RULE_CONSECUTIVE 0x00080000UL
#define ROLLBACKGUARD_EVENT_FLAG_KERNEL_RULE_CUMULATIVE 0x00100000UL
#define ROLLBACKGUARD_EVENT_FLAG_KERNEL_RULE_HONEYPOT 0x00200000UL
#define ROLLBACKGUARD_SHARED_TELEMETRY_VERSION 2
#define ROLLBACKGUARD_BACKUP_COPY_CHUNK (64 * 1024)
#define ROLLBACKGUARD_BACKUP_ROOT_NT L"\\??\\C:\\ProgramData\\RollbackGuard\\rollback\\files\\"
#define ROLLBACKGUARD_BACKUP_ROOT_DOSA "C:\\ProgramData\\RollbackGuard\\rollback\\files\\"
#define ROLLBACKGUARD_BACKUP_ROOT_DOSW L"C:\\ProgramData\\RollbackGuard\\rollback\\files\\"
#define RGMINI_ENTROPY_SAMPLE_BYTES 4096
#define RGMINI_ENTROPY_MIN_WRITE_BYTES 512
#define RGMINI_ENTROPY_HIGH_CHI_THRESHOLD 300ULL
#define RGMINI_ENTROPY_LOW_CHI_THRESHOLD 1000ULL
#define RGMINI_ENTROPY_PROCESS_CAPACITY 512
#define RGMINI_ENTROPY_FILE_HASH_CAPACITY 16
#define RGMINI_ENTROPY_DIRECTORY_HASH_CAPACITY 8
#define RGMINI_ENTROPY_ENTRY_EXPIRY_MS (10LL * 60LL * 1000LL)
#define RGMINI_ENTROPY_TABLE_TAG 'TegR'

#define IOCTL_ROLLBACKGUARD_GET_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ROLLBACKGUARD_COMMAND    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ROLLBACKGUARD_REGISTER_TELEMETRY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ROLLBACKGUARD_WAIT_CONTROL_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ROLLBACKGUARD_SET_HONEY_PATHS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef enum _ROLLBACKGUARD_EVENT_KIND
{
    RollbackGuardEventUnknown = 0,
    RollbackGuardEventFileWrite = 1,
    RollbackGuardEventFileRename = 2,
    RollbackGuardEventFileDelete = 3,
    RollbackGuardEventHoneyFileTouched = 14
} ROLLBACKGUARD_EVENT_KIND;

typedef enum _ROLLBACKGUARD_DRIVER_COMMAND
{
    RollbackGuardCommandBlock = 1,
    RollbackGuardCommandTerminate = 2,
    RollbackGuardCommandEnableRollback = 3,
    RollbackGuardCommandSuspend = 4,
    RollbackGuardCommandResume = 5,
    RollbackGuardCommandSetRestricted = 6,
    RollbackGuardCommandClearRestricted = 7,
    RollbackGuardCommandSetProcessTrust = 8,
    RollbackGuardCommandClearProcessTrust = 9
} ROLLBACKGUARD_DRIVER_COMMAND;

typedef enum _RGMINI_PROCESS_TRUST_LEVEL
{
    RgMiniProcessTrustUnknown = 0,
    RgMiniProcessTrustMicrosoftSigned = 1,
    RgMiniProcessTrustSigned = 2,
    RgMiniProcessTrustUnsigned = 3
} RGMINI_PROCESS_TRUST_LEVEL;

#pragma pack(push, 1)
typedef struct _ROLLBACKGUARD_DRIVER_EVENT_RECORD
{
    ULONG Kind;
    ULONG ProcessId;
    ULONG ThreadId;
    LONGLONG TimestampUnixMs;
    ULONG Flags;
    ULONGLONG VolumeSerialNumber;
    ULONGLONG FileId;
    ULONGLONG SequenceId;
    CHAR ProcessPath[ROLLBACKGUARD_PROCESS_PATH_CHARS];
    CHAR TargetPath[ROLLBACKGUARD_PATH_CHARS];
    CHAR SourcePath[ROLLBACKGUARD_PATH_CHARS];
} ROLLBACKGUARD_DRIVER_EVENT_RECORD, *PROLLBACKGUARD_DRIVER_EVENT_RECORD;

typedef struct _ROLLBACKGUARD_DRIVER_EVENT_BATCH
{
    ULONG Count;
    ROLLBACKGUARD_DRIVER_EVENT_RECORD Events[ROLLBACKGUARD_MAX_EVENTS];
} ROLLBACKGUARD_DRIVER_EVENT_BATCH, *PROLLBACKGUARD_DRIVER_EVENT_BATCH;

typedef struct _ROLLBACKGUARD_DRIVER_COMMAND_REQUEST
{
    ULONG Command;
    ULONG ProcessId;
    ULONG Reserved;
} ROLLBACKGUARD_DRIVER_COMMAND_REQUEST, *PROLLBACKGUARD_DRIVER_COMMAND_REQUEST;

typedef struct _ROLLBACKGUARD_TELEMETRY_REGISTRATION_REQUEST
{
    ULONG Version;
    ULONG RingCapacity;
    ULONG SectionBytes;
    ULONG Reserved;
    WCHAR SectionName[ROLLBACKGUARD_OBJECT_NAME_CHARS];
    WCHAR SignalEventName[ROLLBACKGUARD_OBJECT_NAME_CHARS];
} ROLLBACKGUARD_TELEMETRY_REGISTRATION_REQUEST, *PROLLBACKGUARD_TELEMETRY_REGISTRATION_REQUEST;
#pragma pack(pop)

typedef struct DECLSPEC_ALIGN(8) _ROLLBACKGUARD_SHARED_TELEMETRY_HEADER
{
    ULONG Version;
    ULONG RecordSize;
    ULONG Capacity;
    ULONG Reserved;
    volatile ULONGLONG WriteSequence;
    volatile ULONGLONG OverwriteCount;
} ROLLBACKGUARD_SHARED_TELEMETRY_HEADER, *PROLLBACKGUARD_SHARED_TELEMETRY_HEADER;

static_assert(sizeof(ROLLBACKGUARD_DRIVER_EVENT_RECORD) == 1348, "wire protocol record size mismatch");
static_assert(
    sizeof(ROLLBACKGUARD_DRIVER_EVENT_BATCH) == (sizeof(ULONG) + (ROLLBACKGUARD_MAX_EVENTS * sizeof(ROLLBACKGUARD_DRIVER_EVENT_RECORD))),
    "wire protocol batch size mismatch");
static_assert(sizeof(ROLLBACKGUARD_DRIVER_COMMAND_REQUEST) == 12, "wire protocol command size mismatch");
static_assert(sizeof(ROLLBACKGUARD_TELEMETRY_REGISTRATION_REQUEST) == 528, "wire protocol telemetry registration size mismatch");
static_assert(sizeof(ROLLBACKGUARD_SHARED_TELEMETRY_HEADER) == 32, "wire protocol telemetry header size mismatch");

typedef struct _RGMINI_EVENT_QUEUE
{
    KSPIN_LOCK Lock;
    ULONG Head;
    ULONG Count;
    ROLLBACKGUARD_DRIVER_EVENT_RECORD Events[ROLLBACKGUARD_EVENT_QUEUE_CAPACITY];
} RGMINI_EVENT_QUEUE, *PRGMINI_EVENT_QUEUE;

typedef struct _RGMINI_TELEMETRY_CHANNEL
{
    FAST_MUTEX Lock;
    PROLLBACKGUARD_SHARED_TELEMETRY_HEADER Header;
    PROLLBACKGUARD_DRIVER_EVENT_RECORD Records;
    ULONG Capacity;
    SIZE_T ViewBytes;
    PKEVENT SignalEvent;
} RGMINI_TELEMETRY_CHANNEL;

typedef struct _RGMINI_CONTROL_CHANNEL
{
    KSPIN_LOCK Lock;
    ULONG Head;
    ULONG Count;
    PIRP PendingIrp;
    ROLLBACKGUARD_DRIVER_EVENT_RECORD Events[ROLLBACKGUARD_CONTROL_QUEUE_CAPACITY];
} RGMINI_CONTROL_CHANNEL, *PRGMINI_CONTROL_CHANNEL;

typedef struct _RGMINI_BLOCKED_PROCESS_ENTRY
{
    ULONG ProcessId;
    PEPROCESS ProcessObject;
    BOOLEAN Active;
} RGMINI_BLOCKED_PROCESS_ENTRY;

typedef struct _RGMINI_RESTRICTED_PROCESS_ENTRY
{
    ULONG ProcessId;
    LONGLONG DelayUntilMs;
    BOOLEAN Active;
} RGMINI_RESTRICTED_PROCESS_ENTRY;

typedef struct _RGMINI_PROCESS_TRUST_ENTRY
{
    ULONG ProcessId;
    ULONG TrustLevel;
    BOOLEAN Active;
    UCHAR Reserved[3];
} RGMINI_PROCESS_TRUST_ENTRY;

typedef struct _RGMINI_ENTROPY_PROCESS_ENTRY
{
    ULONG ProcessId;
    ULONG LowToHighEntropyCount;
    ULONG HighEntropyRawCount;
    ULONG ConsecutiveCount;
    ULONG UniqueFileCount;
    ULONG UniqueDirectoryCount;
    BOOLEAN Active;
    UCHAR Reserved[3];
    LONGLONG LastSeenUnixMs;
    ULONGLONG FileHashes[RGMINI_ENTROPY_FILE_HASH_CAPACITY];
    ULONGLONG DirectoryHashes[RGMINI_ENTROPY_DIRECTORY_HASH_CAPACITY];
} RGMINI_ENTROPY_PROCESS_ENTRY, *PRGMINI_ENTROPY_PROCESS_ENTRY;

typedef struct _RGMINI_ENTROPY_PROCESS_TABLE
{
    KSPIN_LOCK Lock;
    RGMINI_ENTROPY_PROCESS_ENTRY Entries[RGMINI_ENTROPY_PROCESS_CAPACITY];
} RGMINI_ENTROPY_PROCESS_TABLE, *PRGMINI_ENTROPY_PROCESS_TABLE;

typedef struct _RGMINI_ENTROPY_RESULT
{
    BOOLEAN HasHighEntropyRaw;
    BOOLEAN HasLowToHighTransition;
    BOOLEAN ShouldAutoBlock;
    BOOLEAN TriggeredConsecutiveRule;
    BOOLEAN TriggeredCumulativeRule;
    BOOLEAN TriggeredHoneypotRule;
    ULONG LowToHighEntropyCount;
    ULONG HighEntropyRawCount;
    ULONG ConsecutiveCount;
    ULONG UniqueFileCount;
    ULONG UniqueDirectoryCount;
} RGMINI_ENTROPY_RESULT, *PRGMINI_ENTROPY_RESULT;

typedef struct _RGMINI_COMPLETION_CONTEXT
{
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG EventKind;
    ULONG Flags;
    ULONGLONG VolumeSerialNumber;
    ULONGLONG FileId;
    CHAR ProcessPath[ROLLBACKGUARD_PROCESS_PATH_CHARS];
    CHAR SourcePath[ROLLBACKGUARD_PATH_CHARS];
} RGMINI_COMPLETION_CONTEXT;

typedef struct _RGMINI_STREAM_CONTEXT
{
    ULONG CreatorProcessId;
    ULONG CreatorThreadId;
    CHAR CreatorProcessPath[ROLLBACKGUARD_PROCESS_PATH_CHARS];
} RGMINI_STREAM_CONTEXT;

typedef struct _RGMINI_FILE_STREAM_CONTEXT
{
    ULONG LastProcessId;
    ULONG LastThreadId;
    CHAR LastProcessPath[ROLLBACKGUARD_PROCESS_PATH_CHARS];
} RGMINI_FILE_STREAM_CONTEXT;

static constexpr ULONG RGMINI_CONTEXT_TAG = 'mcgR';
static constexpr ULONG RGMINI_STREAM_CONTEXT_TAG = 'scgR';
static constexpr ULONG RGMINI_FILE_STREAM_CONTEXT_TAG = 'fsgR';

PFLT_FILTER g_FilterHandle = nullptr;
PDEVICE_OBJECT g_ControlDevice = nullptr;
UNICODE_STRING g_DosName = {};
PRGMINI_EVENT_QUEUE g_EventQueue = nullptr;
RGMINI_TELEMETRY_CHANNEL g_TelemetryChannel = {};
PRGMINI_CONTROL_CHANNEL g_ControlChannel = nullptr;
PRGMINI_ENTROPY_PROCESS_TABLE g_EntropyProcessTable = nullptr;
volatile LONG64 g_EventSequence = 0;
KSPIN_LOCK g_BlockedProcessLock = {};
RGMINI_BLOCKED_PROCESS_ENTRY g_BlockedProcesses[ROLLBACKGUARD_BLOCKED_PROCESS_CAPACITY] = {};
KSPIN_LOCK g_RestrictedProcessLock = {};
RGMINI_RESTRICTED_PROCESS_ENTRY g_RestrictedProcesses[ROLLBACKGUARD_RESTRICTED_PROCESS_CAPACITY] = {};
KSPIN_LOCK g_ProcessTrustLock = {};
RGMINI_PROCESS_TRUST_ENTRY g_ProcessTrustEntries[ROLLBACKGUARD_RESTRICTED_PROCESS_CAPACITY] = {};
KSPIN_LOCK g_HoneypotLock = {};
CHAR g_HoneypotPaths[ROLLBACKGUARD_MAX_HONEY_PATHS][ROLLBACKGUARD_PATH_CHARS] = {};
ULONG g_HoneypotPathCount = 0;

static ULONG RgMiniGetRequestorPid(_In_ PFLT_CALLBACK_DATA Data);
static NTSTATUS RgMiniClearRestrictedProcessByPid(_In_ ULONG processId);
static VOID RgMiniClearRestrictedProcesses();
static LONGLONG RgMiniGetUnixTimeMs();
static NTSTATUS RgMiniSetProcessTrustByPid(_In_ ULONG processId, _In_ ULONG trustLevel);
static NTSTATUS RgMiniClearProcessTrustByPid(_In_ ULONG processId);
static VOID RgMiniClearProcessTrusts();
static BOOLEAN RgMiniTryGetProcessTrustInfo(
    _In_opt_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_opt_ ULONG* trustedPid,
    _Out_opt_ ULONG* trustLevel);

static BOOLEAN RgMiniIsControlEvent(_In_ const ROLLBACKGUARD_DRIVER_EVENT_RECORD* record)
{
    if (record == nullptr)
    {
        return FALSE;
    }

    return record->Kind == RollbackGuardEventHoneyFileTouched ||
        (record->Flags & ROLLBACKGUARD_EVENT_FLAG_KERNEL_AUTO_BLOCKED) != 0;
}

static VOID RgMiniCleanupTelemetryState(
    _In_opt_ PROLLBACKGUARD_SHARED_TELEMETRY_HEADER header,
    _In_opt_ PKEVENT signalEvent)
{
    if (header != nullptr)
    {
        MmUnmapViewInSystemSpace(header);
    }

    if (signalEvent != nullptr)
    {
        ObDereferenceObject(signalEvent);
    }
}

static PRGMINI_EVENT_QUEUE RgMiniAllocateEventQueue()
{
    auto* queue = static_cast<PRGMINI_EVENT_QUEUE>(ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(RGMINI_EVENT_QUEUE),
        ROLLBACKGUARD_EVENT_QUEUE_TAG));
    if (queue != nullptr)
    {
        RtlZeroMemory(queue, sizeof(*queue));
        KeInitializeSpinLock(&queue->Lock);
    }

    return queue;
}

static PRGMINI_CONTROL_CHANNEL RgMiniAllocateControlChannel()
{
    auto* channel = static_cast<PRGMINI_CONTROL_CHANNEL>(ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(RGMINI_CONTROL_CHANNEL),
        ROLLBACKGUARD_CONTROL_QUEUE_TAG));
    if (channel != nullptr)
    {
        RtlZeroMemory(channel, sizeof(*channel));
        KeInitializeSpinLock(&channel->Lock);
    }

    return channel;
}

static PRGMINI_ENTROPY_PROCESS_TABLE RgMiniAllocateEntropyProcessTable()
{
    auto* table = static_cast<PRGMINI_ENTROPY_PROCESS_TABLE>(ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(RGMINI_ENTROPY_PROCESS_TABLE),
        RGMINI_ENTROPY_TABLE_TAG));
    if (table != nullptr)
    {
        RtlZeroMemory(table, sizeof(*table));
        KeInitializeSpinLock(&table->Lock);
    }

    return table;
}

static NTSTATUS RgMiniBuildKernelObjectName(
    _In_z_ const WCHAR* source,
    _Out_ UNICODE_STRING* destination,
    _Out_writes_(bufferChars) WCHAR* buffer,
    _In_ SIZE_T bufferChars)
{
    if (source == nullptr || source[0] == L'\0' || destination == nullptr || buffer == nullptr || bufferChars == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    buffer[0] = L'\0';
    if (source[0] == L'\\')
    {
        NTSTATUS status = RtlStringCchCopyW(buffer, bufferChars, source);
        if (NT_SUCCESS(status))
        {
            RtlInitUnicodeString(destination, buffer);
        }

        return status;
    }

    NTSTATUS status = RtlStringCchCopyW(buffer, bufferChars, L"\\BaseNamedObjects\\");
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = RtlStringCchCatW(buffer, bufferChars, source);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    RtlInitUnicodeString(destination, buffer);
    return STATUS_SUCCESS;
}

static NTSTATUS RgMiniConfigureTelemetryChannel(_In_ const ROLLBACKGUARD_TELEMETRY_REGISTRATION_REQUEST* request)
{
    if (request == nullptr ||
        request->Version != ROLLBACKGUARD_SHARED_TELEMETRY_VERSION ||
        request->RingCapacity == 0 ||
        request->SectionBytes < sizeof(ROLLBACKGUARD_SHARED_TELEMETRY_HEADER) + sizeof(ROLLBACKGUARD_DRIVER_EVENT_RECORD) ||
        request->SectionName[0] == L'\0' ||
        request->SignalEventName[0] == L'\0')
    {
        return STATUS_INVALID_PARAMETER;
    }

    WCHAR sectionNameBuffer[ROLLBACKGUARD_OBJECT_NAME_CHARS + 32] = {};
    WCHAR signalNameBuffer[ROLLBACKGUARD_OBJECT_NAME_CHARS + 32] = {};
    UNICODE_STRING sectionName = {};
    UNICODE_STRING signalName = {};
    NTSTATUS status = RgMiniBuildKernelObjectName(request->SectionName, &sectionName, sectionNameBuffer, RTL_NUMBER_OF(sectionNameBuffer));
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = RgMiniBuildKernelObjectName(request->SignalEventName, &signalName, signalNameBuffer, RTL_NUMBER_OF(signalNameBuffer));
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    HANDLE sectionHandle = nullptr;
    HANDLE eventHandle = nullptr;
    PVOID sectionObject = nullptr;
    PROLLBACKGUARD_SHARED_TELEMETRY_HEADER mappedHeader = nullptr;
    PKEVENT signalEvent = nullptr;
    SIZE_T viewBytes = request->SectionBytes;

    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &sectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    status = ZwOpenSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE, &attributes);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = ObReferenceObjectByHandle(
        sectionHandle,
        SECTION_MAP_READ | SECTION_MAP_WRITE,
        nullptr,
        KernelMode,
        &sectionObject,
        nullptr);
    if (NT_SUCCESS(status))
    {
        status = MmMapViewInSystemSpace(sectionObject, reinterpret_cast<PVOID*>(&mappedHeader), &viewBytes);
        ObDereferenceObject(sectionObject);
        sectionObject = nullptr;
    }

    ZwClose(sectionHandle);
    sectionHandle = nullptr;
    if (!NT_SUCCESS(status))
    {
        RgMiniCleanupTelemetryState(mappedHeader, signalEvent);
        return status;
    }

    if (viewBytes < sizeof(ROLLBACKGUARD_SHARED_TELEMETRY_HEADER) ||
        viewBytes < sizeof(ROLLBACKGUARD_SHARED_TELEMETRY_HEADER) +
            (static_cast<SIZE_T>(request->RingCapacity) * sizeof(ROLLBACKGUARD_DRIVER_EVENT_RECORD)))
    {
        RgMiniCleanupTelemetryState(mappedHeader, signalEvent);
        return STATUS_BUFFER_TOO_SMALL;
    }

    InitializeObjectAttributes(&attributes, &signalName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    status = ZwOpenEvent(&eventHandle, EVENT_MODIFY_STATE | SYNCHRONIZE, &attributes);
    if (!NT_SUCCESS(status))
    {
        RgMiniCleanupTelemetryState(mappedHeader, signalEvent);
        return status;
    }

    status = ObReferenceObjectByHandle(
        eventHandle,
        EVENT_MODIFY_STATE | SYNCHRONIZE,
        nullptr,
        KernelMode,
        reinterpret_cast<PVOID*>(&signalEvent),
        nullptr);
    ZwClose(eventHandle);
    if (!NT_SUCCESS(status))
    {
        RgMiniCleanupTelemetryState(mappedHeader, signalEvent);
        return status;
    }

    mappedHeader->Version = ROLLBACKGUARD_SHARED_TELEMETRY_VERSION;
    mappedHeader->RecordSize = sizeof(ROLLBACKGUARD_DRIVER_EVENT_RECORD);
    mappedHeader->Capacity = request->RingCapacity;
    mappedHeader->Reserved = 0;

    PROLLBACKGUARD_SHARED_TELEMETRY_HEADER oldHeader = nullptr;
    PKEVENT oldSignalEvent = nullptr;
    ExAcquireFastMutex(&g_TelemetryChannel.Lock);
    oldHeader = g_TelemetryChannel.Header;
    oldSignalEvent = g_TelemetryChannel.SignalEvent;
    g_TelemetryChannel.Header = mappedHeader;
    g_TelemetryChannel.Records = reinterpret_cast<PROLLBACKGUARD_DRIVER_EVENT_RECORD>(mappedHeader + 1);
    g_TelemetryChannel.Capacity = request->RingCapacity;
    g_TelemetryChannel.ViewBytes = viewBytes;
    g_TelemetryChannel.SignalEvent = signalEvent;
    ExReleaseFastMutex(&g_TelemetryChannel.Lock);

    RgMiniCleanupTelemetryState(oldHeader, oldSignalEvent);
    return STATUS_SUCCESS;
}

static VOID RgMiniQueueLegacyEvent(_In_ const ROLLBACKGUARD_DRIVER_EVENT_RECORD* record)
{
    if (g_EventQueue == nullptr)
    {
        return;
    }

    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_EventQueue->Lock, &oldIrql);

    ULONG index = 0;
    if (g_EventQueue->Count < ROLLBACKGUARD_EVENT_QUEUE_CAPACITY)
    {
        index = (g_EventQueue->Head + g_EventQueue->Count) % ROLLBACKGUARD_EVENT_QUEUE_CAPACITY;
        g_EventQueue->Count++;
    }
    else
    {
        index = g_EventQueue->Head;
        g_EventQueue->Head = (g_EventQueue->Head + 1) % ROLLBACKGUARD_EVENT_QUEUE_CAPACITY;
    }

    g_EventQueue->Events[index] = *record;
    KeReleaseSpinLock(&g_EventQueue->Lock, oldIrql);
}

static VOID RgMiniWriteSharedTelemetry(_In_ const ROLLBACKGUARD_DRIVER_EVENT_RECORD* record)
{
    ExAcquireFastMutex(&g_TelemetryChannel.Lock);

    if (g_TelemetryChannel.Header != nullptr &&
        g_TelemetryChannel.Records != nullptr &&
        g_TelemetryChannel.Capacity > 0)
    {
        const ULONGLONG index = (record->SequenceId - 1ULL) % g_TelemetryChannel.Capacity;
        g_TelemetryChannel.Records[index] = *record;
        KeMemoryBarrier();
        g_TelemetryChannel.Header->WriteSequence = record->SequenceId;
        if (record->SequenceId > g_TelemetryChannel.Capacity)
        {
            g_TelemetryChannel.Header->OverwriteCount++;
        }

        if (g_TelemetryChannel.SignalEvent != nullptr)
        {
            KeSetEvent(g_TelemetryChannel.SignalEvent, IO_NO_INCREMENT, FALSE);
        }
    }

    ExReleaseFastMutex(&g_TelemetryChannel.Lock);
}

static VOID RgMiniCompleteControlIrp(
    _In_ PIRP irp,
    _In_opt_ const ROLLBACKGUARD_DRIVER_EVENT_RECORD* record,
    _In_ NTSTATUS status)
{
    ULONG_PTR information = 0;
    if (NT_SUCCESS(status) && record != nullptr)
    {
        auto* buffer = static_cast<PROLLBACKGUARD_DRIVER_EVENT_RECORD>(irp->AssociatedIrp.SystemBuffer);
        if (buffer == nullptr)
        {
            status = STATUS_INVALID_USER_BUFFER;
        }
        else
        {
            *buffer = *record;
            information = sizeof(ROLLBACKGUARD_DRIVER_EVENT_RECORD);
        }
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
}

static VOID RgMiniControlWaitCancel(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    IoReleaseCancelSpinLock(Irp->CancelIrql);

    if (g_ControlChannel == nullptr)
    {
        RgMiniCompleteControlIrp(Irp, nullptr, STATUS_CANCELLED);
        return;
    }

    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_ControlChannel->Lock, &oldIrql);
    if (g_ControlChannel->PendingIrp == Irp)
    {
        g_ControlChannel->PendingIrp = nullptr;
    }
    KeReleaseSpinLock(&g_ControlChannel->Lock, oldIrql);

    RgMiniCompleteControlIrp(Irp, nullptr, STATUS_CANCELLED);
}

static VOID RgMiniNotifyControlEvent(_In_ const ROLLBACKGUARD_DRIVER_EVENT_RECORD* record)
{
    if (g_ControlChannel == nullptr)
    {
        return;
    }

    PIRP pendingIrp = nullptr;

    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_ControlChannel->Lock, &oldIrql);
    if (g_ControlChannel->PendingIrp != nullptr)
    {
        pendingIrp = g_ControlChannel->PendingIrp;
        g_ControlChannel->PendingIrp = nullptr;
    }
    KeReleaseSpinLock(&g_ControlChannel->Lock, oldIrql);

    if (pendingIrp != nullptr)
    {
        if (IoSetCancelRoutine(pendingIrp, nullptr) != nullptr)
        {
            if (IoGetCurrentIrpStackLocation(pendingIrp)->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ROLLBACKGUARD_DRIVER_EVENT_RECORD))
            {
                RgMiniCompleteControlIrp(pendingIrp, record, STATUS_SUCCESS);
                return;
            }

            RgMiniCompleteControlIrp(pendingIrp, nullptr, STATUS_BUFFER_TOO_SMALL);
        }
    }

    KeAcquireSpinLock(&g_ControlChannel->Lock, &oldIrql);
    ULONG index = 0;
    if (g_ControlChannel->Count < ROLLBACKGUARD_CONTROL_QUEUE_CAPACITY)
    {
        index = (g_ControlChannel->Head + g_ControlChannel->Count) % ROLLBACKGUARD_CONTROL_QUEUE_CAPACITY;
        g_ControlChannel->Count++;
    }
    else
    {
        index = g_ControlChannel->Head;
        g_ControlChannel->Head = (g_ControlChannel->Head + 1) % ROLLBACKGUARD_CONTROL_QUEUE_CAPACITY;
    }

    g_ControlChannel->Events[index] = *record;
    KeReleaseSpinLock(&g_ControlChannel->Lock, oldIrql);
}

static VOID RgMiniCompletePendingControlWaits(_In_ NTSTATUS status)
{
    PIRP pendingIrp = nullptr;
    if (g_ControlChannel == nullptr)
    {
        return;
    }

    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_ControlChannel->Lock, &oldIrql);
    if (g_ControlChannel->PendingIrp != nullptr)
    {
        pendingIrp = g_ControlChannel->PendingIrp;
        g_ControlChannel->PendingIrp = nullptr;
    }
    g_ControlChannel->Head = 0;
    g_ControlChannel->Count = 0;
    KeReleaseSpinLock(&g_ControlChannel->Lock, oldIrql);

    if (pendingIrp != nullptr && IoSetCancelRoutine(pendingIrp, nullptr) != nullptr)
    {
        RgMiniCompleteControlIrp(pendingIrp, nullptr, status);
    }
}

static NTSTATUS RgMiniUnsupported(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS RgMiniCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static VOID RgMiniCopyUnicodeToAnsiBuffer(_In_opt_ PCUNICODE_STRING source, _Out_writes_(destChars) CHAR* dest, _In_ SIZE_T destChars)
{
    if (dest == nullptr || destChars == 0)
    {
        return;
    }

    dest[0] = '\0';
    if (source == nullptr || source->Buffer == nullptr || source->Length == 0)
    {
        return;
    }

    SIZE_T copyChars = source->Length / sizeof(WCHAR);
    if (copyChars + 1 > destChars)
    {
        copyChars = destChars - 1;
    }

    for (SIZE_T i = 0; i < copyChars; ++i)
    {
        const WCHAR wc = source->Buffer[i];
        dest[i] = (wc < 0x80) ? static_cast<CHAR>(wc) : '?';
    }

    dest[copyChars] = '\0';
}

static VOID RgMiniCopyAnsiToBuffer(_In_opt_z_ const CHAR* source, _Out_writes_(destChars) CHAR* dest, _In_ SIZE_T destChars)
{
    if (dest == nullptr || destChars == 0)
    {
        return;
    }

    dest[0] = '\0';
    if (source == nullptr || source[0] == '\0')
    {
        return;
    }

    SIZE_T copyLen = 0;
    while (copyLen + 1 < destChars && source[copyLen] != '\0')
    {
        copyLen++;
    }
    if (copyLen > 0)
    {
        RtlCopyMemory(dest, source, copyLen);
    }

    dest[copyLen] = '\0';
}

static CHAR RgMiniToLowerAscii(_In_ CHAR ch)
{
    if (ch >= 'A' && ch <= 'Z')
    {
        return static_cast<CHAR>(ch + ('a' - 'A'));
    }

    return ch;
}

static BOOLEAN RgMiniAnsiContainsInsensitive(_In_opt_z_ const CHAR* haystack, _In_z_ const CHAR* needle)
{
    if (haystack == nullptr || needle == nullptr || needle[0] == '\0')
    {
        return FALSE;
    }

    SIZE_T needleLen = 0;
    while (needle[needleLen] != '\0')
    {
        needleLen++;
    }

    if (needleLen == 0)
    {
        return FALSE;
    }

    for (SIZE_T i = 0; haystack[i] != '\0'; ++i)
    {
        SIZE_T j = 0;
        while (j < needleLen && haystack[i + j] != '\0')
        {
            const CHAR left = RgMiniToLowerAscii(haystack[i + j]);
            const CHAR right = RgMiniToLowerAscii(needle[j]);
            if (left != right)
            {
                break;
            }

            j++;
        }

        if (j == needleLen)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN RgMiniAnsiEndsWithInsensitive(_In_opt_z_ const CHAR* value, _In_z_ const CHAR* suffix)
{
    if (value == nullptr || suffix == nullptr || suffix[0] == '\0')
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

    const SIZE_T start = valueLen - suffixLen;
    for (SIZE_T i = 0; i < suffixLen; ++i)
    {
        if (RgMiniToLowerAscii(value[start + i]) != RgMiniToLowerAscii(suffix[i]))
        {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN RgMiniAnsiEqualsInsensitive(_In_opt_z_ const CHAR* left, _In_opt_z_ const CHAR* right)
{
    if (left == nullptr || right == nullptr)
    {
        return FALSE;
    }

    SIZE_T index = 0;
    while (left[index] != '\0' && right[index] != '\0')
    {
        if (RgMiniToLowerAscii(left[index]) != RgMiniToLowerAscii(right[index]))
        {
            return FALSE;
        }

        index++;
    }

    return left[index] == '\0' && right[index] == '\0';
}

static NTSTATUS RgMiniRegisterHoneypotPaths(_In_reads_bytes_(inputLength) const UCHAR* buffer, _In_ ULONG inputLength)
{
    if (buffer == nullptr || inputLength < sizeof(ULONG))
    {
        return STATUS_INVALID_PARAMETER;
    }

    const ULONG requestedCount = *reinterpret_cast<const ULONG*>(buffer);
    const ULONG maxByLength = static_cast<ULONG>((inputLength - sizeof(ULONG)) / ROLLBACKGUARD_PATH_CHARS);
    const ULONG count = min(requestedCount, min(maxByLength, static_cast<ULONG>(ROLLBACKGUARD_MAX_HONEY_PATHS)));

    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_HoneypotLock, &oldIrql);
    RtlZeroMemory(g_HoneypotPaths, sizeof(g_HoneypotPaths));
    g_HoneypotPathCount = 0;

    for (ULONG i = 0; i < count; ++i)
    {
        const auto* path = reinterpret_cast<const CHAR*>(buffer + sizeof(ULONG) + (i * ROLLBACKGUARD_PATH_CHARS));
        if (path[0] == '\0')
        {
            continue;
        }

        RgMiniCopyAnsiToBuffer(path, g_HoneypotPaths[g_HoneypotPathCount], ROLLBACKGUARD_PATH_CHARS);
        g_HoneypotPathCount++;
    }

    KeReleaseSpinLock(&g_HoneypotLock, oldIrql);
    return STATUS_SUCCESS;
}

static BOOLEAN RgMiniIsRegisteredHoneypotPath(_In_opt_z_ const CHAR* path)
{
    if (path == nullptr || path[0] == '\0')
    {
        return FALSE;
    }

    BOOLEAN matched = FALSE;
    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_HoneypotLock, &oldIrql);
    for (ULONG i = 0; i < g_HoneypotPathCount; ++i)
    {
        if (RgMiniAnsiEqualsInsensitive(path, g_HoneypotPaths[i]))
        {
            matched = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_HoneypotLock, oldIrql);

    return matched;
}

static ULONG RgMiniGetThreadPid(_In_opt_ PFLT_CALLBACK_DATA Data)
{
    if (Data != nullptr && Data->Thread != nullptr)
    {
        auto* process = IoThreadToProcess(Data->Thread);
        if (process != nullptr)
        {
            return HandleToULong(PsGetProcessId(process));
        }
    }

    return 0;
}

static VOID RgMiniResolveProcessPathByPid(_In_ ULONG processId, _Out_writes_(destChars) CHAR* dest, _In_ SIZE_T destChars)
{
    if (dest == nullptr || destChars == 0)
    {
        return;
    }

    dest[0] = '\0';
    if (processId == 0)
    {
        return;
    }

    PEPROCESS process = nullptr;
    const NTSTATUS lookupStatus = PsLookupProcessByProcessId(ULongToHandle(processId), &process);
    if (!NT_SUCCESS(lookupStatus) || process == nullptr)
    {
        return;
    }

    PUNICODE_STRING imageName = nullptr;
    const NTSTATUS imageStatus = SeLocateProcessImageName(process, &imageName);
    if (NT_SUCCESS(imageStatus) && imageName != nullptr)
    {
        RgMiniCopyUnicodeToAnsiBuffer(imageName, dest, destChars);
        ExFreePool(imageName);
    }

    if (dest[0] == '\0')
    {
        const auto* shortName = reinterpret_cast<const CHAR*>(PsGetProcessImageFileName(process));
        RgMiniCopyAnsiToBuffer(shortName, dest, destChars);
    }

    ObDereferenceObject(process);
}

static BOOLEAN RgMiniIsStabilityCriticalImagePath(_In_opt_z_ const CHAR* processPath)
{
    if (processPath == nullptr || processPath[0] == '\0')
    {
        return FALSE;
    }

    if (!RgMiniAnsiContainsInsensitive(processPath, "\\windows\\"))
    {
        return FALSE;
    }

    static const CHAR* kCriticalProcessSuffixes[] =
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

    for (SIZE_T i = 0; i < RTL_NUMBER_OF(kCriticalProcessSuffixes); ++i)
    {
        if (RgMiniAnsiEndsWithInsensitive(processPath, kCriticalProcessSuffixes[i]))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN RgMiniIsStabilityCriticalProcess(
    _In_ ULONG processId,
    _In_opt_z_ const CHAR* maybeProcessPath)
{
    if (processId <= 4)
    {
        return TRUE;
    }

    if (maybeProcessPath != nullptr && maybeProcessPath[0] != '\0')
    {
        return RgMiniIsStabilityCriticalImagePath(maybeProcessPath);
    }

    CHAR resolvedPath[ROLLBACKGUARD_PROCESS_PATH_CHARS] = {};
    RgMiniResolveProcessPathByPid(processId, resolvedPath, ROLLBACKGUARD_PROCESS_PATH_CHARS);
    return RgMiniIsStabilityCriticalImagePath(resolvedPath);
}

static VOID RgMiniCapturePathFromData(_In_ PFLT_CALLBACK_DATA Data, _Out_writes_(destChars) CHAR* dest, _In_ SIZE_T destChars)
{
    if (dest == nullptr || destChars == 0)
    {
        return;
    }

    dest[0] = '\0';
    if (Data == nullptr)
    {
        return;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);

    if (!NT_SUCCESS(status))
    {
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo);
    }

    if (!NT_SUCCESS(status) || nameInfo == nullptr)
    {
        return;
    }

    FltParseFileNameInformation(nameInfo);
    RgMiniCopyUnicodeToAnsiBuffer(&nameInfo->Name, dest, destChars);
    FltReleaseFileNameInformation(nameInfo);
}

static VOID RgMiniCaptureFileIdentity(
    _In_opt_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ ULONGLONG* volumeSerialNumber,
    _Out_ ULONGLONG* fileId)
{
    if (volumeSerialNumber != nullptr)
    {
        *volumeSerialNumber = 0;
    }

    if (fileId != nullptr)
    {
        *fileId = 0;
    }

    if (FltObjects == nullptr || FltObjects->Instance == nullptr || FltObjects->FileObject == nullptr)
    {
        return;
    }

    FILE_INTERNAL_INFORMATION internalInfo = {};
    ULONG bytesReturned = 0;
    NTSTATUS status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &internalInfo,
        sizeof(internalInfo),
        FileInternalInformation,
        &bytesReturned);

    if (NT_SUCCESS(status) && fileId != nullptr)
    {
        *fileId = static_cast<ULONGLONG>(internalInfo.IndexNumber.QuadPart);
    }

    FILE_FS_VOLUME_INFORMATION volumeInfo = {};
    IO_STATUS_BLOCK ioStatus = {};
    status = FltQueryVolumeInformation(
        FltObjects->Instance,
        &ioStatus,
        &volumeInfo,
        sizeof(volumeInfo),
        FileFsVolumeInformation);

    if (NT_SUCCESS(status) && volumeSerialNumber != nullptr)
    {
        *volumeSerialNumber = static_cast<ULONGLONG>(volumeInfo.VolumeSerialNumber);
    }
}

static BOOLEAN RgMiniPathStartsWithInsensitive(_In_opt_z_ const CHAR* value, _In_z_ const CHAR* prefix)
{
    if (value == nullptr || prefix == nullptr)
    {
        return FALSE;
    }

    SIZE_T index = 0;
    while (prefix[index] != '\0')
    {
        if (value[index] == '\0')
        {
            return FALSE;
        }

        if (RgMiniToLowerAscii(value[index]) != RgMiniToLowerAscii(prefix[index]))
        {
            return FALSE;
        }

        index++;
    }

    return TRUE;
}

static BOOLEAN RgMiniIsBackupPath(_In_opt_z_ const CHAR* path)
{
    if (path == nullptr || path[0] == '\0')
    {
        return FALSE;
    }

    return RgMiniPathStartsWithInsensitive(path, ROLLBACKGUARD_BACKUP_ROOT_DOSA) ||
        RgMiniPathStartsWithInsensitive(path, "\\??\\C:\\ProgramData\\RollbackGuard\\rollback\\files\\") ||
        RgMiniAnsiContainsInsensitive(path, "\\rollbackguard\\rollback\\files\\");
}

static BOOLEAN RgMiniIsMissingFileStatus(_In_ NTSTATUS status)
{
    return status == STATUS_OBJECT_NAME_NOT_FOUND ||
        status == STATUS_OBJECT_PATH_NOT_FOUND ||
        status == STATUS_NO_SUCH_FILE ||
        status == STATUS_NOT_FOUND ||
        status == STATUS_DELETE_PENDING ||
        status == STATUS_FILE_DELETED;
}

static NTSTATUS RgMiniBuildBackupPaths(
    _In_ ULONG processId,
    _In_ ULONGLONG volumeSerialNumber,
    _In_ ULONGLONG fileId,
    _In_ ULONGLONG fallbackToken,
    _Out_writes_(ROLLBACKGUARD_PATH_CHARS) CHAR* dosBinPath,
    _Out_writes_(ROLLBACKGUARD_PATH_CHARS) WCHAR* ntBinPath,
    _Out_writes_(ROLLBACKGUARD_PATH_CHARS) CHAR* dosMissingPath,
    _Out_writes_(ROLLBACKGUARD_PATH_CHARS) WCHAR* ntMissingPath)
{
    if (dosBinPath == nullptr || ntBinPath == nullptr || dosMissingPath == nullptr || ntMissingPath == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    dosBinPath[0] = '\0';
    ntBinPath[0] = L'\0';
    dosMissingPath[0] = '\0';
    ntMissingPath[0] = L'\0';

    const ULONGLONG stableId = (fileId != 0) ? fileId : fallbackToken;
    NTSTATUS formatStatus = RtlStringCchPrintfA(
        dosBinPath,
        ROLLBACKGUARD_PATH_CHARS,
        "%s%08lX_%016I64X_%016I64X.bin",
        ROLLBACKGUARD_BACKUP_ROOT_DOSA,
        processId,
        static_cast<unsigned long long>(volumeSerialNumber),
        static_cast<unsigned long long>(stableId));
    if (!NT_SUCCESS(formatStatus))
    {
        return formatStatus;
    }

    formatStatus = RtlStringCchPrintfW(
        ntBinPath,
        ROLLBACKGUARD_PATH_CHARS,
        L"%s%08lX_%016I64X_%016I64X.bin",
        ROLLBACKGUARD_BACKUP_ROOT_NT,
        processId,
        static_cast<unsigned long long>(volumeSerialNumber),
        static_cast<unsigned long long>(stableId));
    if (!NT_SUCCESS(formatStatus))
    {
        return formatStatus;
    }

    formatStatus = RtlStringCchPrintfA(
        dosMissingPath,
        ROLLBACKGUARD_PATH_CHARS,
        "%s%08lX_%016I64X_%016I64X.missing",
        ROLLBACKGUARD_BACKUP_ROOT_DOSA,
        processId,
        static_cast<unsigned long long>(volumeSerialNumber),
        static_cast<unsigned long long>(stableId));
    if (!NT_SUCCESS(formatStatus))
    {
        return formatStatus;
    }

    formatStatus = RtlStringCchPrintfW(
        ntMissingPath,
        ROLLBACKGUARD_PATH_CHARS,
        L"%s%08lX_%016I64X_%016I64X.missing",
        ROLLBACKGUARD_BACKUP_ROOT_NT,
        processId,
        static_cast<unsigned long long>(volumeSerialNumber),
        static_cast<unsigned long long>(stableId));
    if (!NT_SUCCESS(formatStatus))
    {
        return formatStatus;
    }

    return STATUS_SUCCESS;
}

static BOOLEAN RgMiniFileExistsByNtPath(_In_z_ const WCHAR* ntPath)
{
    if (ntPath == nullptr || ntPath[0] == L'\0')
    {
        return FALSE;
    }

    UNICODE_STRING path = {};
    RtlInitUnicodeString(&path, ntPath);

    OBJECT_ATTRIBUTES objectAttributes = {};
    InitializeObjectAttributes(
        &objectAttributes,
        &path,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        nullptr,
        nullptr);

    IO_STATUS_BLOCK ioStatus = {};
    HANDLE handle = nullptr;
    const NTSTATUS status = ZwCreateFile(
        &handle,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objectAttributes,
        &ioStatus,
        nullptr,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        nullptr,
        0);

    if (NT_SUCCESS(status))
    {
        ZwClose(handle);
        return TRUE;
    }

    return FALSE;
}

static VOID RgMiniDeleteFileByNtPath(_In_z_ const WCHAR* ntPath)
{
    if (ntPath == nullptr || ntPath[0] == L'\0')
    {
        return;
    }

    UNICODE_STRING path = {};
    RtlInitUnicodeString(&path, ntPath);

    OBJECT_ATTRIBUTES objectAttributes = {};
    InitializeObjectAttributes(
        &objectAttributes,
        &path,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        nullptr,
        nullptr);

    ZwDeleteFile(&objectAttributes);
}

static NTSTATUS RgMiniCreateMissingMarker(_In_z_ const WCHAR* ntMissingPath)
{
    if (ntMissingPath == nullptr || ntMissingPath[0] == L'\0')
    {
        return STATUS_INVALID_PARAMETER;
    }

    UNICODE_STRING path = {};
    RtlInitUnicodeString(&path, ntMissingPath);

    OBJECT_ATTRIBUTES objectAttributes = {};
    InitializeObjectAttributes(
        &objectAttributes,
        &path,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        nullptr,
        nullptr);

    IO_STATUS_BLOCK ioStatus = {};
    HANDLE handle = nullptr;
    NTSTATUS status = ZwCreateFile(
        &handle,
        GENERIC_WRITE | SYNCHRONIZE,
        &objectAttributes,
        &ioStatus,
        nullptr,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        nullptr,
        0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    static const CHAR MarkerText[] = "missing-before-prewrite";
    IO_STATUS_BLOCK writeStatus = {};
    status = ZwWriteFile(
        handle,
        nullptr,
        nullptr,
        nullptr,
        &writeStatus,
        const_cast<PCHAR>(MarkerText),
        static_cast<ULONG>(sizeof(MarkerText) - 1),
        nullptr,
        nullptr);

    ZwClose(handle);
    return status;
}

static NTSTATUS RgMiniOpenSourceReadHandle(
    _In_z_ const CHAR* targetPath,
    _Out_ HANDLE* sourceHandle)
{
    if (targetPath == nullptr || targetPath[0] == '\0' || sourceHandle == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *sourceHandle = nullptr;

    CHAR ntAnsiPath[ROLLBACKGUARD_PATH_CHARS] = {};
    if (((targetPath[0] >= 'A' && targetPath[0] <= 'Z') || (targetPath[0] >= 'a' && targetPath[0] <= 'z')) &&
        targetPath[1] == ':')
    {
        NTSTATUS formatStatus = RtlStringCchPrintfA(
            ntAnsiPath,
            ROLLBACKGUARD_PATH_CHARS,
            "\\??\\%s",
            targetPath);
        if (!NT_SUCCESS(formatStatus))
        {
            return formatStatus;
        }
    }
    else
    {
        RgMiniCopyAnsiToBuffer(targetPath, ntAnsiPath, ROLLBACKGUARD_PATH_CHARS);
    }

    ANSI_STRING ansiPath = {};
    RtlInitAnsiString(&ansiPath, ntAnsiPath);

    UNICODE_STRING unicodePath = {};
    NTSTATUS status = RtlAnsiStringToUnicodeString(&unicodePath, &ansiPath, TRUE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    OBJECT_ATTRIBUTES objectAttributes = {};
    InitializeObjectAttributes(
        &objectAttributes,
        &unicodePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        nullptr,
        nullptr);

    IO_STATUS_BLOCK ioStatus = {};
    status = ZwCreateFile(
        sourceHandle,
        GENERIC_READ | SYNCHRONIZE,
        &objectAttributes,
        &ioStatus,
        nullptr,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        nullptr,
        0);

    RtlFreeUnicodeString(&unicodePath);
    return status;
}

static NTSTATUS RgMiniCreateBackupWriteHandle(
    _In_z_ const WCHAR* ntBackupPath,
    _Out_ HANDLE* backupHandle)
{
    if (ntBackupPath == nullptr || ntBackupPath[0] == L'\0' || backupHandle == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *backupHandle = nullptr;

    UNICODE_STRING path = {};
    RtlInitUnicodeString(&path, ntBackupPath);

    OBJECT_ATTRIBUTES objectAttributes = {};
    InitializeObjectAttributes(
        &objectAttributes,
        &path,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        nullptr,
        nullptr);

    IO_STATUS_BLOCK ioStatus = {};
    return ZwCreateFile(
        backupHandle,
        GENERIC_WRITE | SYNCHRONIZE,
        &objectAttributes,
        &ioStatus,
        nullptr,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        nullptr,
        0);
}

static NTSTATUS RgMiniCopySourceToBackup(
    _In_ HANDLE sourceHandle,
    _In_ HANDLE backupHandle)
{
    if (sourceHandle == nullptr || backupHandle == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    auto* buffer = static_cast<PUCHAR>(ExAllocatePool2(POOL_FLAG_NON_PAGED, ROLLBACKGUARD_BACKUP_COPY_CHUNK, 'bkgR'));
    if (buffer == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS status = STATUS_SUCCESS;
    LARGE_INTEGER sourceOffset = {};
    sourceOffset.QuadPart = 0;

    while (true)
    {
        IO_STATUS_BLOCK readStatus = {};
        status = ZwReadFile(
            sourceHandle,
            nullptr,
            nullptr,
            nullptr,
            &readStatus,
            buffer,
            ROLLBACKGUARD_BACKUP_COPY_CHUNK,
            &sourceOffset,
            nullptr);

        if (status == STATUS_END_OF_FILE || readStatus.Information == 0)
        {
            status = STATUS_SUCCESS;
            break;
        }

        if (!NT_SUCCESS(status))
        {
            break;
        }

        const ULONG bytesRead = static_cast<ULONG>(readStatus.Information);
        IO_STATUS_BLOCK writeStatus = {};
        status = ZwWriteFile(
            backupHandle,
            nullptr,
            nullptr,
            nullptr,
            &writeStatus,
            buffer,
            bytesRead,
            nullptr,
            nullptr);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        if (writeStatus.Information != bytesRead)
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        sourceOffset.QuadPart += bytesRead;
    }

    ExFreePoolWithTag(buffer, 'bkgR');
    return status;
}

static NTSTATUS RgMiniCaptureSnapshotForTarget(
    _In_z_ const CHAR* targetPath,
    _In_opt_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG processId,
    _In_ ULONG threadId,
    _In_ ULONGLONG volumeSerialNumber,
    _In_ ULONGLONG fileId,
    _Out_writes_(ROLLBACKGUARD_PATH_CHARS) CHAR* snapshotPath)
{
    if (targetPath == nullptr || targetPath[0] == '\0' || snapshotPath == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    snapshotPath[0] = '\0';
    if (RgMiniIsBackupPath(targetPath))
    {
        return STATUS_NOT_SUPPORTED;
    }

    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    const ULONGLONG fallbackToken = (FltObjects != nullptr && FltObjects->FileObject != nullptr)
        ? static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(FltObjects->FileObject))
        : static_cast<ULONGLONG>(threadId);

    CHAR dosBinPath[ROLLBACKGUARD_PATH_CHARS] = {};
    WCHAR ntBinPath[ROLLBACKGUARD_PATH_CHARS] = {};
    CHAR dosMissingPath[ROLLBACKGUARD_PATH_CHARS] = {};
    WCHAR ntMissingPath[ROLLBACKGUARD_PATH_CHARS] = {};
    NTSTATUS status = RgMiniBuildBackupPaths(
        processId,
        volumeSerialNumber,
        fileId,
        fallbackToken,
        dosBinPath,
        ntBinPath,
        dosMissingPath,
        ntMissingPath);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (RgMiniFileExistsByNtPath(ntBinPath))
    {
        RgMiniCopyAnsiToBuffer(dosBinPath, snapshotPath, ROLLBACKGUARD_PATH_CHARS);
        return STATUS_SUCCESS;
    }

    if (RgMiniFileExistsByNtPath(ntMissingPath))
    {
        RgMiniCopyAnsiToBuffer(dosMissingPath, snapshotPath, ROLLBACKGUARD_PATH_CHARS);
        return STATUS_SUCCESS;
    }

    HANDLE sourceHandle = nullptr;
    status = RgMiniOpenSourceReadHandle(targetPath, &sourceHandle);
    if (!NT_SUCCESS(status))
    {
        if (RgMiniIsMissingFileStatus(status))
        {
            const NTSTATUS markerStatus = RgMiniCreateMissingMarker(ntMissingPath);
            if (NT_SUCCESS(markerStatus))
            {
                RgMiniCopyAnsiToBuffer(dosMissingPath, snapshotPath, ROLLBACKGUARD_PATH_CHARS);
                return STATUS_SUCCESS;
            }

            return markerStatus;
        }

        return status;
    }

    HANDLE backupHandle = nullptr;
    status = RgMiniCreateBackupWriteHandle(ntBinPath, &backupHandle);
    if (status == STATUS_OBJECT_NAME_COLLISION || status == STATUS_OBJECT_NAME_EXISTS)
    {
        ZwClose(sourceHandle);
        RgMiniCopyAnsiToBuffer(dosBinPath, snapshotPath, ROLLBACKGUARD_PATH_CHARS);
        return STATUS_SUCCESS;
    }

    if (!NT_SUCCESS(status))
    {
        ZwClose(sourceHandle);
        return status;
    }

    status = RgMiniCopySourceToBackup(sourceHandle, backupHandle);
    ZwClose(backupHandle);
    ZwClose(sourceHandle);

    if (!NT_SUCCESS(status))
    {
        RgMiniDeleteFileByNtPath(ntBinPath);
        if (RgMiniIsMissingFileStatus(status))
        {
            const NTSTATUS markerStatus = RgMiniCreateMissingMarker(ntMissingPath);
            if (NT_SUCCESS(markerStatus))
            {
                RgMiniCopyAnsiToBuffer(dosMissingPath, snapshotPath, ROLLBACKGUARD_PATH_CHARS);
                return STATUS_SUCCESS;
            }

            return markerStatus;
        }

        return status;
    }

    RgMiniCopyAnsiToBuffer(dosBinPath, snapshotPath, ROLLBACKGUARD_PATH_CHARS);
    return STATUS_SUCCESS;
}

static NTSTATUS RgMiniCapturePreWriteSnapshot(
    _In_z_ const CHAR* targetPath,
    _In_opt_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ RGMINI_COMPLETION_CONTEXT* context)
{
    if (context == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    return RgMiniCaptureSnapshotForTarget(
        targetPath,
        FltObjects,
        context->ProcessId,
        context->ThreadId,
        context->VolumeSerialNumber,
        context->FileId,
        context->SourcePath);
}

static ULONGLONG RgMiniHashPathFragmentInsensitive(
    _In_reads_(lengthChars) const CHAR* path,
    _In_ SIZE_T lengthChars)
{
    if (path == nullptr || lengthChars == 0)
    {
        return 0;
    }

    ULONGLONG hash = 1469598103934665603ULL;
    for (SIZE_T i = 0; i < lengthChars; ++i)
    {
        CHAR value = path[i];
        if (value == '\0')
        {
            break;
        }

        if (value == '/')
        {
            value = '\\';
        }

        const UCHAR normalized = static_cast<UCHAR>(RgMiniToLowerAscii(value));
        hash ^= normalized;
        hash *= 1099511628211ULL;
    }

    return hash == 0 ? 1ULL : hash;
}

static ULONGLONG RgMiniHashPathInsensitive(_In_opt_z_ const CHAR* path)
{
    if (path == nullptr || path[0] == '\0')
    {
        return 0;
    }

    SIZE_T lengthChars = 0;
    for (; lengthChars < (ROLLBACKGUARD_PATH_CHARS - 1) && path[lengthChars] != '\0'; ++lengthChars)
    {
    }

    return RgMiniHashPathFragmentInsensitive(path, lengthChars);
}

static ULONGLONG RgMiniHashDirectoryPathInsensitive(_In_opt_z_ const CHAR* path)
{
    if (path == nullptr || path[0] == '\0')
    {
        return 0;
    }

    SIZE_T lastSeparator = static_cast<SIZE_T>(-1);
    SIZE_T lengthChars = 0;
    for (; lengthChars < (ROLLBACKGUARD_PATH_CHARS - 1) && path[lengthChars] != '\0'; ++lengthChars)
    {
        if (path[lengthChars] == '\\' || path[lengthChars] == '/')
        {
            lastSeparator = lengthChars;
        }
    }

    if (lastSeparator == static_cast<SIZE_T>(-1) || lastSeparator == 0)
    {
        return 0;
    }

    return RgMiniHashPathFragmentInsensitive(path, lastSeparator);
}

static VOID RgMiniResetEntropyEntry(_Out_ PRGMINI_ENTROPY_PROCESS_ENTRY entry)
{
    if (entry == nullptr)
    {
        return;
    }

    RtlZeroMemory(entry, sizeof(*entry));
}

static PRGMINI_ENTROPY_PROCESS_ENTRY RgMiniAcquireEntropyEntryLocked(
    _In_ ULONG processId,
    _In_ LONGLONG nowMs,
    _In_ BOOLEAN createIfMissing)
{
    if (g_EntropyProcessTable == nullptr || processId == 0)
    {
        return nullptr;
    }

    ULONG freeIndex = RGMINI_ENTROPY_PROCESS_CAPACITY;
    ULONG oldestIndex = RGMINI_ENTROPY_PROCESS_CAPACITY;
    LONGLONG oldestSeenMs = nowMs;

    for (ULONG i = 0; i < RGMINI_ENTROPY_PROCESS_CAPACITY; ++i)
    {
        auto* entry = &g_EntropyProcessTable->Entries[i];
        if (!entry->Active)
        {
            if (freeIndex == RGMINI_ENTROPY_PROCESS_CAPACITY)
            {
                freeIndex = i;
            }
            continue;
        }

        const BOOLEAN expired = entry->LastSeenUnixMs > 0 &&
            nowMs > entry->LastSeenUnixMs &&
            (nowMs - entry->LastSeenUnixMs) > RGMINI_ENTROPY_ENTRY_EXPIRY_MS;
        if (expired)
        {
            RgMiniResetEntropyEntry(entry);
            if (freeIndex == RGMINI_ENTROPY_PROCESS_CAPACITY)
            {
                freeIndex = i;
            }
            continue;
        }

        if (entry->ProcessId == processId)
        {
            entry->LastSeenUnixMs = nowMs;
            return entry;
        }

        if (oldestIndex == RGMINI_ENTROPY_PROCESS_CAPACITY || entry->LastSeenUnixMs < oldestSeenMs)
        {
            oldestIndex = i;
            oldestSeenMs = entry->LastSeenUnixMs;
        }
    }

    if (!createIfMissing)
    {
        return nullptr;
    }

    ULONG selectedIndex = freeIndex;
    if (selectedIndex == RGMINI_ENTROPY_PROCESS_CAPACITY)
    {
        selectedIndex = oldestIndex;
    }

    if (selectedIndex == RGMINI_ENTROPY_PROCESS_CAPACITY)
    {
        return nullptr;
    }

    auto* selected = &g_EntropyProcessTable->Entries[selectedIndex];
    RgMiniResetEntropyEntry(selected);
    selected->Active = TRUE;
    selected->ProcessId = processId;
    selected->LastSeenUnixMs = nowMs;
    return selected;
}

static VOID RgMiniTrackEntropyHash(
    _In_ ULONGLONG hash,
    _Inout_updates_(capacity) ULONGLONG* slots,
    _In_ ULONG capacity,
    _Inout_ ULONG* count)
{
    if (hash == 0 || slots == nullptr || count == nullptr || capacity == 0)
    {
        return;
    }

    ULONG freeIndex = capacity;
    for (ULONG i = 0; i < capacity; ++i)
    {
        if (slots[i] == hash)
        {
            return;
        }

        if (slots[i] == 0 && freeIndex == capacity)
        {
            freeIndex = i;
        }
    }

    if (freeIndex == capacity)
    {
        return;
    }

    slots[freeIndex] = hash;
    if (*count < MAXULONG)
    {
        (*count)++;
    }
}

static BOOLEAN RgMiniLooksCompressedMagic(_In_reads_bytes_(length) const UCHAR* buffer, _In_ ULONG length)
{
    if (buffer == nullptr || length < 2)
    {
        return FALSE;
    }

    if (length >= 4 &&
        buffer[0] == 'P' &&
        buffer[1] == 'K' &&
        (buffer[2] == 0x03 || buffer[2] == 0x05 || buffer[2] == 0x07) &&
        (buffer[3] == 0x04 || buffer[3] == 0x06 || buffer[3] == 0x08))
    {
        return TRUE;
    }

    if (buffer[0] == 0xFF && buffer[1] == 0xD8)
    {
        return TRUE;
    }

    if (length >= 8 &&
        buffer[0] == 0x89 &&
        buffer[1] == 'P' &&
        buffer[2] == 'N' &&
        buffer[3] == 'G' &&
        buffer[4] == 0x0D &&
        buffer[5] == 0x0A &&
        buffer[6] == 0x1A &&
        buffer[7] == 0x0A)
    {
        return TRUE;
    }

    if (length >= 6 &&
        buffer[0] == 0x37 &&
        buffer[1] == 0x7A &&
        buffer[2] == 0xBC &&
        buffer[3] == 0xAF &&
        buffer[4] == 0x27 &&
        buffer[5] == 0x1C)
    {
        return TRUE;
    }

    if (length >= 2 && buffer[0] == 0x1F && buffer[1] == 0x8B)
    {
        return TRUE;
    }

    if (length >= 7 &&
        buffer[0] == 0x52 &&
        buffer[1] == 0x61 &&
        buffer[2] == 0x72 &&
        buffer[3] == 0x21 &&
        buffer[4] == 0x1A &&
        buffer[5] == 0x07 &&
        (buffer[6] == 0x00 || buffer[6] == 0x01))
    {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN RgMiniTryComputeChiSquareFromBuffer(
    _In_reads_bytes_(length) const UCHAR* buffer,
    _In_ ULONG length,
    _Out_ ULONGLONG* chiSquare)
{
    if (buffer == nullptr || chiSquare == nullptr || length < RGMINI_ENTROPY_MIN_WRITE_BYTES)
    {
        return FALSE;
    }

    if (RgMiniLooksCompressedMagic(buffer, length))
    {
        return FALSE;
    }

    ULONG counts[256] = {};
    for (ULONG i = 0; i < length; ++i)
    {
        counts[buffer[i]]++;
    }

    const ULONGLONG denominator = static_cast<ULONGLONG>(length) * 256ULL;
    if (denominator == 0)
    {
        return FALSE;
    }

    ULONGLONG total = 0;
    for (ULONG i = 0; i < RTL_NUMBER_OF(counts); ++i)
    {
        const LONGLONG diff = (static_cast<LONGLONG>(counts[i]) * 256LL) - static_cast<LONGLONG>(length);
        total += (static_cast<ULONGLONG>(diff * diff) / denominator);
    }

    *chiSquare = total;
    return TRUE;
}

static BOOLEAN RgMiniTryMapWriteBufferSample(
    _In_ PFLT_CALLBACK_DATA Data,
    _Outptr_result_bytebuffer_(*sampleLength) const UCHAR** sampleBuffer,
    _Out_ ULONG* sampleLength)
{
    if (sampleBuffer == nullptr || sampleLength == nullptr)
    {
        return FALSE;
    }

    *sampleBuffer = nullptr;
    *sampleLength = 0;

    if (Data == nullptr || Data->Iopb == nullptr)
    {
        return FALSE;
    }

    const ULONG writeLength = Data->Iopb->Parameters.Write.Length;
    if (writeLength < RGMINI_ENTROPY_MIN_WRITE_BYTES)
    {
        return FALSE;
    }

    const ULONG desiredSampleLength = min(writeLength, RGMINI_ENTROPY_SAMPLE_BYTES);
    const UCHAR* buffer = nullptr;
    if (Data->Iopb->Parameters.Write.MdlAddress != nullptr)
    {
        buffer = static_cast<const UCHAR*>(MmGetSystemAddressForMdlSafe(
            Data->Iopb->Parameters.Write.MdlAddress,
            NormalPagePriority));
    }
    else
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        {
            return FALSE;
        }

        const NTSTATUS lockStatus = FltLockUserBuffer(Data);
        if (!NT_SUCCESS(lockStatus) || Data->Iopb->Parameters.Write.MdlAddress == nullptr)
        {
            return FALSE;
        }

        buffer = static_cast<const UCHAR*>(MmGetSystemAddressForMdlSafe(
            Data->Iopb->Parameters.Write.MdlAddress,
            NormalPagePriority));
    }

    if (buffer == nullptr)
    {
        return FALSE;
    }

    *sampleBuffer = buffer;
    *sampleLength = desiredSampleLength;
    return TRUE;
}

static BOOLEAN RgMiniTryReadFileEntropySample(
    _In_opt_z_ const CHAR* path,
    _Out_ ULONGLONG* chiSquare)
{
    if (chiSquare != nullptr)
    {
        *chiSquare = 0;
    }

    if (path == nullptr || path[0] == '\0' || chiSquare == nullptr)
    {
        return FALSE;
    }

    if (RgMiniAnsiEndsWithInsensitive(path, ".missing") || KeGetCurrentIrql() > PASSIVE_LEVEL)
    {
        return FALSE;
    }

    HANDLE handle = nullptr;
    NTSTATUS status = RgMiniOpenSourceReadHandle(path, &handle);
    if (!NT_SUCCESS(status) || handle == nullptr)
    {
        return FALSE;
    }

    UCHAR buffer[RGMINI_ENTROPY_SAMPLE_BYTES] = {};
    IO_STATUS_BLOCK ioStatus = {};
    status = ZwReadFile(
        handle,
        nullptr,
        nullptr,
        nullptr,
        &ioStatus,
        buffer,
        sizeof(buffer),
        nullptr,
        nullptr);
    ZwClose(handle);

    if (!NT_SUCCESS(status) || ioStatus.Information < RGMINI_ENTROPY_MIN_WRITE_BYTES)
    {
        return FALSE;
    }

    return RgMiniTryComputeChiSquareFromBuffer(buffer, static_cast<ULONG>(ioStatus.Information), chiSquare);
}

static VOID RgMiniResetEntropyStateByPid(_In_ ULONG processId)
{
    if (processId == 0 || g_EntropyProcessTable == nullptr)
    {
        return;
    }

    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_EntropyProcessTable->Lock, &oldIrql);
    auto* entry = RgMiniAcquireEntropyEntryLocked(processId, RgMiniGetUnixTimeMs(), FALSE);
    if (entry != nullptr)
    {
        RgMiniResetEntropyEntry(entry);
    }
    KeReleaseSpinLock(&g_EntropyProcessTable->Lock, oldIrql);
}

static VOID RgMiniClearEntropyState()
{
    if (g_EntropyProcessTable == nullptr)
    {
        return;
    }

    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_EntropyProcessTable->Lock, &oldIrql);
    RtlZeroMemory(g_EntropyProcessTable->Entries, sizeof(g_EntropyProcessTable->Entries));
    KeReleaseSpinLock(&g_EntropyProcessTable->Lock, oldIrql);
}

static VOID RgMiniEvaluateEntropyForWrite(
    _In_ ULONG processId,
    _In_opt_z_ const CHAR* targetPath,
    _In_ ULONGLONG writeChiSquare,
    _In_ BOOLEAN hasWriteChiSquare,
    _In_ ULONGLONG sourceChiSquare,
    _In_ BOOLEAN hasSourceChiSquare,
    _Out_ PRGMINI_ENTROPY_RESULT result)
{
    if (result == nullptr)
    {
        return;
    }

    RtlZeroMemory(result, sizeof(*result));
    if (processId == 0 || g_EntropyProcessTable == nullptr || !hasWriteChiSquare)
    {
        return;
    }

    const BOOLEAN hasHighEntropyRaw = writeChiSquare < RGMINI_ENTROPY_HIGH_CHI_THRESHOLD;
    const BOOLEAN hasLowToHighTransition = hasHighEntropyRaw &&
        hasSourceChiSquare &&
        sourceChiSquare > RGMINI_ENTROPY_LOW_CHI_THRESHOLD;

    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_EntropyProcessTable->Lock, &oldIrql);

    const LONGLONG nowMs = RgMiniGetUnixTimeMs();
    auto* entry = RgMiniAcquireEntropyEntryLocked(processId, nowMs, TRUE);
    if (entry != nullptr)
    {
        if (hasHighEntropyRaw && entry->HighEntropyRawCount < MAXULONG)
        {
            entry->HighEntropyRawCount++;
        }

        if (hasLowToHighTransition)
        {
            if (entry->LowToHighEntropyCount < MAXULONG)
            {
                entry->LowToHighEntropyCount++;
            }

            if (entry->ConsecutiveCount < MAXULONG)
            {
                entry->ConsecutiveCount++;
            }

            RgMiniTrackEntropyHash(
                RgMiniHashPathInsensitive(targetPath),
                entry->FileHashes,
                RGMINI_ENTROPY_FILE_HASH_CAPACITY,
                &entry->UniqueFileCount);
            RgMiniTrackEntropyHash(
                RgMiniHashDirectoryPathInsensitive(targetPath),
                entry->DirectoryHashes,
                RGMINI_ENTROPY_DIRECTORY_HASH_CAPACITY,
                &entry->UniqueDirectoryCount);

            if (entry->ConsecutiveCount >= 3)
            {
                result->ShouldAutoBlock = TRUE;
                result->TriggeredConsecutiveRule = TRUE;
            }

            if (entry->LowToHighEntropyCount >= 8)
            {
                result->ShouldAutoBlock = TRUE;
                result->TriggeredCumulativeRule = TRUE;
            }
        }
        else
        {
            entry->ConsecutiveCount = 0;
        }

        result->LowToHighEntropyCount = entry->LowToHighEntropyCount;
        result->HighEntropyRawCount = entry->HighEntropyRawCount;
        result->ConsecutiveCount = entry->ConsecutiveCount;
        result->UniqueFileCount = entry->UniqueFileCount;
        result->UniqueDirectoryCount = entry->UniqueDirectoryCount;
    }

    KeReleaseSpinLock(&g_EntropyProcessTable->Lock, oldIrql);

    result->HasHighEntropyRaw = hasHighEntropyRaw;
    result->HasLowToHighTransition = hasLowToHighTransition;
}

static BOOLEAN RgMiniTryGetStreamCreatorIdentity(
    _In_opt_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ ULONG* processId,
    _Out_writes_(ROLLBACKGUARD_PROCESS_PATH_CHARS) CHAR* processPath)
{
    if (processId == nullptr || processPath == nullptr)
    {
        return FALSE;
    }

    *processId = 0;
    processPath[0] = '\0';

    if (FltObjects == nullptr || FltObjects->Instance == nullptr || FltObjects->FileObject == nullptr)
    {
        return FALSE;
    }

    RGMINI_STREAM_CONTEXT* streamContext = nullptr;
    const NTSTATUS status = FltGetStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        reinterpret_cast<PFLT_CONTEXT*>(&streamContext));

    if (!NT_SUCCESS(status) || streamContext == nullptr)
    {
        return FALSE;
    }

    *processId = streamContext->CreatorProcessId;
    RgMiniCopyAnsiToBuffer(streamContext->CreatorProcessPath, processPath, ROLLBACKGUARD_PROCESS_PATH_CHARS);
    FltReleaseContext(streamContext);
    return (*processId > 0);
}

static BOOLEAN RgMiniTryGetStreamWriterIdentity(
    _In_opt_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ ULONG* processId,
    _Out_writes_(ROLLBACKGUARD_PROCESS_PATH_CHARS) CHAR* processPath)
{
    if (processId == nullptr || processPath == nullptr)
    {
        return FALSE;
    }

    *processId = 0;
    processPath[0] = '\0';

    if (FltObjects == nullptr || FltObjects->Instance == nullptr || FltObjects->FileObject == nullptr)
    {
        return FALSE;
    }

    RGMINI_FILE_STREAM_CONTEXT* streamContext = nullptr;
    const NTSTATUS status = FltGetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        reinterpret_cast<PFLT_CONTEXT*>(&streamContext));

    if (!NT_SUCCESS(status) || streamContext == nullptr)
    {
        return FALSE;
    }

    *processId = streamContext->LastProcessId;
    RgMiniCopyAnsiToBuffer(streamContext->LastProcessPath, processPath, ROLLBACKGUARD_PROCESS_PATH_CHARS);
    FltReleaseContext(streamContext);
    return (*processId > 0);
}

static VOID RgMiniUpsertStreamWriterIdentity(
    _In_opt_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG processId,
    _In_ ULONG threadId,
    _In_opt_z_ const CHAR* processPath)
{
    if (FltObjects == nullptr || FltObjects->Instance == nullptr || FltObjects->FileObject == nullptr)
    {
        return;
    }

    if (processId <= 1)
    {
        return;
    }

    CHAR normalizedPath[ROLLBACKGUARD_PROCESS_PATH_CHARS] = {};
    RgMiniCopyAnsiToBuffer(processPath, normalizedPath, ROLLBACKGUARD_PROCESS_PATH_CHARS);
    if (normalizedPath[0] == '\0')
    {
        RgMiniResolveProcessPathByPid(processId, normalizedPath, ROLLBACKGUARD_PROCESS_PATH_CHARS);
    }

    RGMINI_FILE_STREAM_CONTEXT* streamContext = nullptr;
    NTSTATUS status = FltGetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        reinterpret_cast<PFLT_CONTEXT*>(&streamContext));

    if (NT_SUCCESS(status) && streamContext != nullptr)
    {
        const BOOLEAN shouldUpdate =
            (streamContext->LastProcessId <= 1) ||
            (streamContext->LastProcessId <= 4 && processId > 1) ||
            (streamContext->LastProcessPath[0] == '\0' && normalizedPath[0] != '\0');

        if (shouldUpdate)
        {
            streamContext->LastProcessId = processId;
            streamContext->LastThreadId = threadId;
            RgMiniCopyAnsiToBuffer(normalizedPath, streamContext->LastProcessPath, ROLLBACKGUARD_PROCESS_PATH_CHARS);
        }

        FltReleaseContext(streamContext);
        return;
    }

    RGMINI_FILE_STREAM_CONTEXT* newContext = nullptr;
    status = FltAllocateContext(
        g_FilterHandle,
        FLT_STREAM_CONTEXT,
        sizeof(RGMINI_FILE_STREAM_CONTEXT),
        NonPagedPoolNx,
        reinterpret_cast<PFLT_CONTEXT*>(&newContext));

    if (!NT_SUCCESS(status) || newContext == nullptr)
    {
        return;
    }

    RtlZeroMemory(newContext, sizeof(*newContext));
    newContext->LastProcessId = processId;
    newContext->LastThreadId = threadId;
    RgMiniCopyAnsiToBuffer(normalizedPath, newContext->LastProcessPath, ROLLBACKGUARD_PROCESS_PATH_CHARS);

    status = FltSetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        newContext,
        nullptr);

    FltReleaseContext(newContext);
    UNREFERENCED_PARAMETER(status);
}

static LONGLONG RgMiniGetUnixTimeMs()
{
    LARGE_INTEGER now = {};
    KeQuerySystemTime(&now);

    constexpr LONGLONG EpochDiff100ns = 116444736000000000LL;
    return (now.QuadPart - EpochDiff100ns) / 10000;
}

static VOID RgMiniQueueEvent(_In_ const ROLLBACKGUARD_DRIVER_EVENT_RECORD* record)
{
    if (record == nullptr)
    {
        return;
    }

    ROLLBACKGUARD_DRIVER_EVENT_RECORD published = *record;
    published.SequenceId = static_cast<ULONGLONG>(InterlockedIncrement64(&g_EventSequence));

    RgMiniQueueLegacyEvent(&published);
    RgMiniWriteSharedTelemetry(&published);

    if (RgMiniIsControlEvent(&published))
    {
        RgMiniNotifyControlEvent(&published);
    }
}

static VOID RgMiniQueuePreOperationSnapshotEvent(
    _In_ const RGMINI_COMPLETION_CONTEXT* context,
    _In_z_ const CHAR* targetPath,
    _In_z_ const CHAR* snapshotPath)
{
    if (context == nullptr ||
        targetPath == nullptr || targetPath[0] == '\0' ||
        snapshotPath == nullptr || snapshotPath[0] == '\0')
    {
        return;
    }

    ROLLBACKGUARD_DRIVER_EVENT_RECORD record = {};
    record.Kind = RollbackGuardEventFileWrite;
    record.ProcessId = context->ProcessId;
    record.ThreadId = context->ThreadId;
    record.TimestampUnixMs = RgMiniGetUnixTimeMs();
    record.Flags = ROLLBACKGUARD_EVENT_FLAG_PRE_OPERATION;
    record.VolumeSerialNumber = context->VolumeSerialNumber;
    record.FileId = context->FileId;
    RgMiniCopyAnsiToBuffer(context->ProcessPath, record.ProcessPath, ROLLBACKGUARD_PROCESS_PATH_CHARS);
    RgMiniCopyAnsiToBuffer(targetPath, record.TargetPath, ROLLBACKGUARD_PATH_CHARS);
    RgMiniCopyAnsiToBuffer(snapshotPath, record.SourcePath, ROLLBACKGUARD_PATH_CHARS);

    RgMiniQueueEvent(&record);
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[RollbackGuard.MiniFilter] preop-snapshot pid=%lu target=%s snapshot=%s\n",
        record.ProcessId,
        record.TargetPath,
        record.SourcePath);
}

static BOOLEAN RgMiniIsBlockedPid(_In_ ULONG processId)
{
    if (processId == 0)
    {
        return FALSE;
    }

    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_BlockedProcessLock, &oldIrql);
    for (ULONG i = 0; i < ROLLBACKGUARD_BLOCKED_PROCESS_CAPACITY; ++i)
    {
        if (g_BlockedProcesses[i].Active && g_BlockedProcesses[i].ProcessId == processId)
        {
            KeReleaseSpinLock(&g_BlockedProcessLock, oldIrql);
            return TRUE;
        }
    }

    KeReleaseSpinLock(&g_BlockedProcessLock, oldIrql);
    return FALSE;
}

static NTSTATUS RgMiniBlockProcessByPid(_In_ ULONG processId)
{
    if (processId <= 4)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (RgMiniIsStabilityCriticalProcess(processId, nullptr))
    {
        return STATUS_ACCESS_DENIED;
    }

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(processId), &process);
    if (!NT_SUCCESS(status) || process == nullptr)
    {
        return status;
    }

    ULONG freeIndex = ROLLBACKGUARD_BLOCKED_PROCESS_CAPACITY;
    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_BlockedProcessLock, &oldIrql);
    for (ULONG i = 0; i < ROLLBACKGUARD_BLOCKED_PROCESS_CAPACITY; ++i)
    {
        if (!g_BlockedProcesses[i].Active)
        {
            if (freeIndex == ROLLBACKGUARD_BLOCKED_PROCESS_CAPACITY)
            {
                freeIndex = i;
            }
            continue;
        }

        if (g_BlockedProcesses[i].ProcessId == processId || g_BlockedProcesses[i].ProcessObject == process)
        {
            KeReleaseSpinLock(&g_BlockedProcessLock, oldIrql);
            ObDereferenceObject(process);
            return STATUS_SUCCESS;
        }
    }

    if (freeIndex == ROLLBACKGUARD_BLOCKED_PROCESS_CAPACITY)
    {
        KeReleaseSpinLock(&g_BlockedProcessLock, oldIrql);
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_BlockedProcesses[freeIndex].ProcessId = processId;
    g_BlockedProcesses[freeIndex].ProcessObject = process;
    g_BlockedProcesses[freeIndex].Active = TRUE;

    KeReleaseSpinLock(&g_BlockedProcessLock, oldIrql);
    return STATUS_SUCCESS;
}

static NTSTATUS RgMiniUnblockProcessByPid(_In_ ULONG processId)
{
    if (processId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PEPROCESS processToDereference = nullptr;

    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_BlockedProcessLock, &oldIrql);
    for (ULONG i = 0; i < ROLLBACKGUARD_BLOCKED_PROCESS_CAPACITY; ++i)
    {
        if (!g_BlockedProcesses[i].Active || g_BlockedProcesses[i].ProcessId != processId)
        {
            continue;
        }

        processToDereference = g_BlockedProcesses[i].ProcessObject;
        g_BlockedProcesses[i].ProcessId = 0;
        g_BlockedProcesses[i].ProcessObject = nullptr;
        g_BlockedProcesses[i].Active = FALSE;
        break;
    }
    KeReleaseSpinLock(&g_BlockedProcessLock, oldIrql);

    if (processToDereference != nullptr)
    {
        ObDereferenceObject(processToDereference);
    }

    RgMiniClearRestrictedProcessByPid(processId);
    RgMiniResetEntropyStateByPid(processId);

    return STATUS_SUCCESS;
}

static VOID RgMiniClearBlockedProcesses()
{
    PEPROCESS toDereference[ROLLBACKGUARD_BLOCKED_PROCESS_CAPACITY] = {};
    ULONG derefCount = 0;

    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_BlockedProcessLock, &oldIrql);
    for (ULONG i = 0; i < ROLLBACKGUARD_BLOCKED_PROCESS_CAPACITY; ++i)
    {
        if (!g_BlockedProcesses[i].Active)
        {
            continue;
        }

        if (g_BlockedProcesses[i].ProcessObject != nullptr && derefCount < ROLLBACKGUARD_BLOCKED_PROCESS_CAPACITY)
        {
            toDereference[derefCount++] = g_BlockedProcesses[i].ProcessObject;
        }

        g_BlockedProcesses[i].ProcessId = 0;
        g_BlockedProcesses[i].ProcessObject = nullptr;
        g_BlockedProcesses[i].Active = FALSE;
    }
    KeReleaseSpinLock(&g_BlockedProcessLock, oldIrql);

    for (ULONG i = 0; i < derefCount; ++i)
    {
        if (toDereference[i] != nullptr)
        {
            ObDereferenceObject(toDereference[i]);
        }
    }

    RgMiniClearRestrictedProcesses();
    RgMiniClearProcessTrusts();
    RgMiniClearEntropyState();
}

static NTSTATUS RgMiniSetRestrictedProcessByPid(_In_ ULONG processId, _In_ ULONG startupDelayMs)
{
    if (processId <= 4)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (RgMiniIsStabilityCriticalProcess(processId, nullptr))
    {
        return STATUS_ACCESS_DENIED;
    }

    const LONGLONG delayUntilMs = (startupDelayMs == 0)
        ? 0
        : (RgMiniGetUnixTimeMs() + startupDelayMs);

    ULONG freeIndex = ROLLBACKGUARD_RESTRICTED_PROCESS_CAPACITY;
    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_RestrictedProcessLock, &oldIrql);
    for (ULONG i = 0; i < ROLLBACKGUARD_RESTRICTED_PROCESS_CAPACITY; ++i)
    {
        if (!g_RestrictedProcesses[i].Active)
        {
            if (freeIndex == ROLLBACKGUARD_RESTRICTED_PROCESS_CAPACITY)
            {
                freeIndex = i;
            }
            continue;
        }

        if (g_RestrictedProcesses[i].ProcessId != processId)
        {
            continue;
        }

        if (delayUntilMs > g_RestrictedProcesses[i].DelayUntilMs)
        {
            g_RestrictedProcesses[i].DelayUntilMs = delayUntilMs;
        }
        KeReleaseSpinLock(&g_RestrictedProcessLock, oldIrql);
        return STATUS_SUCCESS;
    }

    if (freeIndex == ROLLBACKGUARD_RESTRICTED_PROCESS_CAPACITY)
    {
        KeReleaseSpinLock(&g_RestrictedProcessLock, oldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_RestrictedProcesses[freeIndex].ProcessId = processId;
    g_RestrictedProcesses[freeIndex].DelayUntilMs = delayUntilMs;
    g_RestrictedProcesses[freeIndex].Active = TRUE;
    KeReleaseSpinLock(&g_RestrictedProcessLock, oldIrql);
    return STATUS_SUCCESS;
}

static NTSTATUS RgMiniClearRestrictedProcessByPid(_In_ ULONG processId)
{
    if (processId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_RestrictedProcessLock, &oldIrql);
    for (ULONG i = 0; i < ROLLBACKGUARD_RESTRICTED_PROCESS_CAPACITY; ++i)
    {
        if (!g_RestrictedProcesses[i].Active || g_RestrictedProcesses[i].ProcessId != processId)
        {
            continue;
        }

        g_RestrictedProcesses[i].ProcessId = 0;
        g_RestrictedProcesses[i].DelayUntilMs = 0;
        g_RestrictedProcesses[i].Active = FALSE;
        break;
    }
    KeReleaseSpinLock(&g_RestrictedProcessLock, oldIrql);
    return STATUS_SUCCESS;
}

static VOID RgMiniClearRestrictedProcesses()
{
    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_RestrictedProcessLock, &oldIrql);
    RtlZeroMemory(g_RestrictedProcesses, sizeof(g_RestrictedProcesses));
    KeReleaseSpinLock(&g_RestrictedProcessLock, oldIrql);
}

static NTSTATUS RgMiniSetProcessTrustByPid(_In_ ULONG processId, _In_ ULONG trustLevel)
{
    if (processId <= 4)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (trustLevel > RgMiniProcessTrustUnsigned)
    {
        trustLevel = RgMiniProcessTrustUnknown;
    }

    ULONG freeIndex = ROLLBACKGUARD_RESTRICTED_PROCESS_CAPACITY;
    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_ProcessTrustLock, &oldIrql);
    for (ULONG i = 0; i < ROLLBACKGUARD_RESTRICTED_PROCESS_CAPACITY; ++i)
    {
        if (!g_ProcessTrustEntries[i].Active)
        {
            if (freeIndex == ROLLBACKGUARD_RESTRICTED_PROCESS_CAPACITY)
            {
                freeIndex = i;
            }
            continue;
        }

        if (g_ProcessTrustEntries[i].ProcessId != processId)
        {
            continue;
        }

        g_ProcessTrustEntries[i].TrustLevel = trustLevel;
        KeReleaseSpinLock(&g_ProcessTrustLock, oldIrql);
        return STATUS_SUCCESS;
    }

    if (freeIndex == ROLLBACKGUARD_RESTRICTED_PROCESS_CAPACITY)
    {
        KeReleaseSpinLock(&g_ProcessTrustLock, oldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_ProcessTrustEntries[freeIndex].ProcessId = processId;
    g_ProcessTrustEntries[freeIndex].TrustLevel = trustLevel;
    g_ProcessTrustEntries[freeIndex].Active = TRUE;
    KeReleaseSpinLock(&g_ProcessTrustLock, oldIrql);
    return STATUS_SUCCESS;
}

static NTSTATUS RgMiniClearProcessTrustByPid(_In_ ULONG processId)
{
    if (processId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_ProcessTrustLock, &oldIrql);
    for (ULONG i = 0; i < ROLLBACKGUARD_RESTRICTED_PROCESS_CAPACITY; ++i)
    {
        if (!g_ProcessTrustEntries[i].Active || g_ProcessTrustEntries[i].ProcessId != processId)
        {
            continue;
        }

        g_ProcessTrustEntries[i].ProcessId = 0;
        g_ProcessTrustEntries[i].TrustLevel = RgMiniProcessTrustUnknown;
        g_ProcessTrustEntries[i].Active = FALSE;
        break;
    }
    KeReleaseSpinLock(&g_ProcessTrustLock, oldIrql);
    return STATUS_SUCCESS;
}

static VOID RgMiniClearProcessTrusts()
{
    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_ProcessTrustLock, &oldIrql);
    RtlZeroMemory(g_ProcessTrustEntries, sizeof(g_ProcessTrustEntries));
    KeReleaseSpinLock(&g_ProcessTrustLock, oldIrql);
}

static BOOLEAN RgMiniTryGetProcessTrustInfo(
    _In_opt_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_opt_ ULONG* trustedPid,
    _Out_opt_ ULONG* trustLevel)
{
    if (trustedPid != nullptr)
    {
        *trustedPid = 0;
    }

    if (trustLevel != nullptr)
    {
        *trustLevel = RgMiniProcessTrustUnknown;
    }

    auto resolveTrustEntry = [&](_In_ ULONG candidatePid) -> BOOLEAN
    {
        if (candidatePid == 0)
        {
            return FALSE;
        }

        KIRQL oldIrql = PASSIVE_LEVEL;
        KeAcquireSpinLock(&g_ProcessTrustLock, &oldIrql);
        for (ULONG i = 0; i < ROLLBACKGUARD_RESTRICTED_PROCESS_CAPACITY; ++i)
        {
            if (!g_ProcessTrustEntries[i].Active || g_ProcessTrustEntries[i].ProcessId != candidatePid)
            {
                continue;
            }

            if (trustedPid != nullptr)
            {
                *trustedPid = candidatePid;
            }
            if (trustLevel != nullptr)
            {
                *trustLevel = g_ProcessTrustEntries[i].TrustLevel;
            }
            KeReleaseSpinLock(&g_ProcessTrustLock, oldIrql);
            return TRUE;
        }
        KeReleaseSpinLock(&g_ProcessTrustLock, oldIrql);
        return FALSE;
    };

    if (Data != nullptr)
    {
        const ULONG processId = RgMiniGetRequestorPid(Data);
        if (resolveTrustEntry(processId))
        {
            return TRUE;
        }
    }

    ULONG streamPid = 0;
    CHAR streamPath[ROLLBACKGUARD_PROCESS_PATH_CHARS] = {};
    if (RgMiniTryGetStreamWriterIdentity(FltObjects, &streamPid, streamPath) &&
        resolveTrustEntry(streamPid))
    {
        return TRUE;
    }

    ULONG creatorPid = 0;
    CHAR creatorPath[ROLLBACKGUARD_PROCESS_PATH_CHARS] = {};
    if (RgMiniTryGetStreamCreatorIdentity(FltObjects, &creatorPid, creatorPath) &&
        resolveTrustEntry(creatorPid))
    {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN RgMiniTryGetRestrictedProcessInfo(
    _In_opt_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_opt_ ULONG* restrictedPid,
    _Out_opt_ LONGLONG* delayUntilMs)
{
    if (restrictedPid != nullptr)
    {
        *restrictedPid = 0;
    }
    if (delayUntilMs != nullptr)
    {
        *delayUntilMs = 0;
    }

    auto resolveRestrictedEntry = [&](_In_ ULONG candidatePid, _In_opt_z_ const CHAR* candidatePath) -> BOOLEAN
    {
        if (candidatePid == 0)
        {
            return FALSE;
        }

        if (RgMiniIsStabilityCriticalProcess(candidatePid, candidatePath))
        {
            RgMiniClearRestrictedProcessByPid(candidatePid);
            return FALSE;
        }

        KIRQL oldIrql = PASSIVE_LEVEL;
        KeAcquireSpinLock(&g_RestrictedProcessLock, &oldIrql);
        for (ULONG i = 0; i < ROLLBACKGUARD_RESTRICTED_PROCESS_CAPACITY; ++i)
        {
            if (!g_RestrictedProcesses[i].Active || g_RestrictedProcesses[i].ProcessId != candidatePid)
            {
                continue;
            }

            if (restrictedPid != nullptr)
            {
                *restrictedPid = candidatePid;
            }
            if (delayUntilMs != nullptr)
            {
                *delayUntilMs = g_RestrictedProcesses[i].DelayUntilMs;
            }
            KeReleaseSpinLock(&g_RestrictedProcessLock, oldIrql);
            return TRUE;
        }
        KeReleaseSpinLock(&g_RestrictedProcessLock, oldIrql);
        return FALSE;
    };

    if (Data != nullptr)
    {
        const ULONG processId = RgMiniGetRequestorPid(Data);
        if (resolveRestrictedEntry(processId, nullptr))
        {
            return TRUE;
        }
    }

    ULONG streamPid = 0;
    CHAR streamPath[ROLLBACKGUARD_PROCESS_PATH_CHARS] = {};
    if (RgMiniTryGetStreamWriterIdentity(FltObjects, &streamPid, streamPath) &&
        resolveRestrictedEntry(streamPid, streamPath))
    {
        return TRUE;
    }

    ULONG creatorPid = 0;
    CHAR creatorPath[ROLLBACKGUARD_PROCESS_PATH_CHARS] = {};
    if (RgMiniTryGetStreamCreatorIdentity(FltObjects, &creatorPid, creatorPath) &&
        resolveRestrictedEntry(creatorPid, creatorPath))
    {
        return TRUE;
    }

    return FALSE;
}

static VOID RgMiniApplyRestrictedDelay(_In_ LONGLONG delayUntilMs)
{
    if (delayUntilMs <= 0 || KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }

    const LONGLONG nowMs = RgMiniGetUnixTimeMs();
    if (delayUntilMs <= nowMs)
    {
        return;
    }

    LARGE_INTEGER interval = {};
    interval.QuadPart = -(10LL * 1000LL * (delayUntilMs - nowMs));
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

static BOOLEAN RgMiniShouldBlockData(
    _In_opt_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_opt_ ULONG* blockedPid)
{
    if (blockedPid != nullptr)
    {
        *blockedPid = 0;
    }

    if (Data == nullptr)
    {
        return FALSE;
    }

    ULONG processId = RgMiniGetRequestorPid(Data);
    if (processId > 0 && RgMiniIsBlockedPid(processId))
    {
        if (RgMiniIsStabilityCriticalProcess(processId, nullptr))
        {
            RgMiniUnblockProcessByPid(processId);
            return FALSE;
        }

        if (blockedPid != nullptr)
        {
            *blockedPid = processId;
        }
        return TRUE;
    }

    ULONG streamPid = 0;
    CHAR streamPath[ROLLBACKGUARD_PROCESS_PATH_CHARS] = {};
    if (RgMiniTryGetStreamWriterIdentity(FltObjects, &streamPid, streamPath) && streamPid > 0 && RgMiniIsBlockedPid(streamPid))
    {
        if (RgMiniIsStabilityCriticalProcess(streamPid, streamPath))
        {
            RgMiniUnblockProcessByPid(streamPid);
            return FALSE;
        }

        if (blockedPid != nullptr)
        {
            *blockedPid = streamPid;
        }
        return TRUE;
    }

    ULONG creatorPid = 0;
    CHAR creatorPath[ROLLBACKGUARD_PROCESS_PATH_CHARS] = {};
    if (RgMiniTryGetStreamCreatorIdentity(FltObjects, &creatorPid, creatorPath) && creatorPid > 0 && RgMiniIsBlockedPid(creatorPid))
    {
        if (RgMiniIsStabilityCriticalProcess(creatorPid, creatorPath))
        {
            RgMiniUnblockProcessByPid(creatorPid);
            return FALSE;
        }

        if (blockedPid != nullptr)
        {
            *blockedPid = creatorPid;
        }
        return TRUE;
    }

    return FALSE;
}

static NTSTATUS RgMiniDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    auto* stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR bytesReturned = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_ROLLBACKGUARD_GET_EVENTS:
    {
        if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        auto* batch = static_cast<PROLLBACKGUARD_DRIVER_EVENT_BATCH>(Irp->AssociatedIrp.SystemBuffer);
        if (batch == nullptr)
        {
            status = STATUS_INVALID_USER_BUFFER;
            break;
        }

        RtlZeroMemory(batch, min(static_cast<ULONG>(sizeof(*batch)), stack->Parameters.DeviceIoControl.OutputBufferLength));

        ULONG maxRecords = 0;
        if (stack->Parameters.DeviceIoControl.OutputBufferLength > sizeof(ULONG))
        {
            maxRecords = static_cast<ULONG>((stack->Parameters.DeviceIoControl.OutputBufferLength - sizeof(ULONG)) /
                sizeof(ROLLBACKGUARD_DRIVER_EVENT_RECORD));
        }

        if (maxRecords > ROLLBACKGUARD_MAX_EVENTS)
        {
            maxRecords = ROLLBACKGUARD_MAX_EVENTS;
        }

        ULONG available = 0;
        if (g_EventQueue != nullptr)
        {
            KIRQL oldIrql = PASSIVE_LEVEL;
            KeAcquireSpinLock(&g_EventQueue->Lock, &oldIrql);

            available = min(g_EventQueue->Count, maxRecords);
            for (ULONG i = 0; i < available; ++i)
            {
                const ULONG idx = g_EventQueue->Head;
                batch->Events[i] = g_EventQueue->Events[idx];
                g_EventQueue->Head = (g_EventQueue->Head + 1) % ROLLBACKGUARD_EVENT_QUEUE_CAPACITY;
                g_EventQueue->Count--;
            }

            KeReleaseSpinLock(&g_EventQueue->Lock, oldIrql);
        }

        batch->Count = available;
        bytesReturned = sizeof(ULONG) + (static_cast<ULONG_PTR>(available) * sizeof(ROLLBACKGUARD_DRIVER_EVENT_RECORD));
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_ROLLBACKGUARD_REGISTER_TELEMETRY:
    {
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ROLLBACKGUARD_TELEMETRY_REGISTRATION_REQUEST))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        auto* request = static_cast<PROLLBACKGUARD_TELEMETRY_REGISTRATION_REQUEST>(Irp->AssociatedIrp.SystemBuffer);
        if (request == nullptr)
        {
            status = STATUS_INVALID_USER_BUFFER;
            break;
        }

        status = RgMiniConfigureTelemetryChannel(request);
        bytesReturned = 0;
        break;
    }
    case IOCTL_ROLLBACKGUARD_WAIT_CONTROL_EVENT:
    {
        if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ROLLBACKGUARD_DRIVER_EVENT_RECORD))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Irp->AssociatedIrp.SystemBuffer == nullptr)
        {
            status = STATUS_INVALID_USER_BUFFER;
            break;
        }

        ROLLBACKGUARD_DRIVER_EVENT_RECORD queued = {};
        if (g_ControlChannel == nullptr)
        {
            status = STATUS_DEVICE_NOT_READY;
            break;
        }

        KIRQL oldIrql = PASSIVE_LEVEL;
        KeAcquireSpinLock(&g_ControlChannel->Lock, &oldIrql);

        if (g_ControlChannel->Count > 0)
        {
            const ULONG index = g_ControlChannel->Head;
            queued = g_ControlChannel->Events[index];
            g_ControlChannel->Head = (g_ControlChannel->Head + 1) % ROLLBACKGUARD_CONTROL_QUEUE_CAPACITY;
            g_ControlChannel->Count--;
            KeReleaseSpinLock(&g_ControlChannel->Lock, oldIrql);
        }
        else
        {
            if (g_ControlChannel->PendingIrp != nullptr)
            {
                KeReleaseSpinLock(&g_ControlChannel->Lock, oldIrql);
                status = STATUS_DEVICE_BUSY;
                break;
            }

            IoMarkIrpPending(Irp);
            g_ControlChannel->PendingIrp = Irp;
            IoSetCancelRoutine(Irp, RgMiniControlWaitCancel);

            if (Irp->Cancel)
            {
                if (IoSetCancelRoutine(Irp, nullptr) != nullptr)
                {
                    g_ControlChannel->PendingIrp = nullptr;
                    KeReleaseSpinLock(&g_ControlChannel->Lock, oldIrql);
                    status = STATUS_CANCELLED;
                    break;
                }

                KeReleaseSpinLock(&g_ControlChannel->Lock, oldIrql);
                return STATUS_PENDING;
            }

            KeReleaseSpinLock(&g_ControlChannel->Lock, oldIrql);
            return STATUS_PENDING;
        }

        auto* outRecord = static_cast<PROLLBACKGUARD_DRIVER_EVENT_RECORD>(Irp->AssociatedIrp.SystemBuffer);
        *outRecord = queued;
        bytesReturned = sizeof(ROLLBACKGUARD_DRIVER_EVENT_RECORD);
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_ROLLBACKGUARD_SET_HONEY_PATHS:
    {
        auto* buffer = static_cast<const UCHAR*>(Irp->AssociatedIrp.SystemBuffer);
        status = RgMiniRegisterHoneypotPaths(buffer, stack->Parameters.DeviceIoControl.InputBufferLength);
        bytesReturned = 0;
        break;
    }
    case IOCTL_ROLLBACKGUARD_COMMAND:
    {
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ROLLBACKGUARD_DRIVER_COMMAND_REQUEST))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        auto* command = static_cast<PROLLBACKGUARD_DRIVER_COMMAND_REQUEST>(Irp->AssociatedIrp.SystemBuffer);
        if (command == nullptr)
        {
            status = STATUS_INVALID_USER_BUFFER;
            break;
        }

        switch (command->Command)
        {
        case RollbackGuardCommandBlock:
            status = RgMiniBlockProcessByPid(command->ProcessId);
            break;
        case RollbackGuardCommandSuspend:
            // Compatibility path: in blocked-pid architecture, "suspend" is aliased to block-only.
            status = RgMiniBlockProcessByPid(command->ProcessId);
            break;
        case RollbackGuardCommandResume:
            // Compatibility path: in blocked-pid architecture, "resume" is aliased to unblock-only.
            status = RgMiniUnblockProcessByPid(command->ProcessId);
            break;
        case RollbackGuardCommandSetRestricted:
            status = RgMiniSetRestrictedProcessByPid(command->ProcessId, command->Reserved);
            break;
        case RollbackGuardCommandClearRestricted:
            status = RgMiniClearRestrictedProcessByPid(command->ProcessId);
            break;
        case RollbackGuardCommandSetProcessTrust:
            status = RgMiniSetProcessTrustByPid(command->ProcessId, command->Reserved);
            break;
        case RollbackGuardCommandClearProcessTrust:
            status = RgMiniClearProcessTrustByPid(command->ProcessId);
            break;
        case RollbackGuardCommandTerminate:
            status = RgMiniUnblockProcessByPid(command->ProcessId);
            break;
        case RollbackGuardCommandEnableRollback:
            status = STATUS_SUCCESS;
            break;
        default:
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        bytesReturned = 0;
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static ULONG RgMiniGetRequestorPid(_In_ PFLT_CALLBACK_DATA Data)
{
    if (Data == nullptr)
    {
        return 0;
    }

    const ULONG requestorPid = static_cast<ULONG>(FltGetRequestorProcessId(Data));
    if (requestorPid != 0)
    {
        return requestorPid;
    }

    return RgMiniGetThreadPid(Data);
}

static RGMINI_COMPLETION_CONTEXT* RgMiniAllocContext(
    _In_ ULONG eventKind,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PCFLT_RELATED_OBJECTS FltObjects)
{
    auto* context = static_cast<RGMINI_COMPLETION_CONTEXT*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(RGMINI_COMPLETION_CONTEXT), RGMINI_CONTEXT_TAG));
    if (context == nullptr)
    {
        return nullptr;
    }

    RtlZeroMemory(context, sizeof(*context));
    context->EventKind = eventKind;
    context->Flags = 0;
    context->ProcessId = RgMiniGetRequestorPid(Data);
    context->ThreadId = HandleToULong(PsGetCurrentThreadId());
    RgMiniResolveProcessPathByPid(context->ProcessId, context->ProcessPath, ROLLBACKGUARD_PROCESS_PATH_CHARS);
    RgMiniCaptureFileIdentity(FltObjects, &context->VolumeSerialNumber, &context->FileId);

    ULONG creatorPid = 0;
    CHAR creatorPath[ROLLBACKGUARD_PROCESS_PATH_CHARS] = {};
    if (RgMiniTryGetStreamCreatorIdentity(FltObjects, &creatorPid, creatorPath))
    {
        const BOOLEAN preferCreator = (context->ProcessId <= 4 && creatorPid > 1) ||
            (context->ProcessPath[0] == '\0' && creatorPid > 1);
        if (preferCreator)
        {
            context->ProcessId = creatorPid;
            RgMiniCopyAnsiToBuffer(creatorPath, context->ProcessPath, ROLLBACKGUARD_PROCESS_PATH_CHARS);
        }
    }

    ULONG streamPid = 0;
    CHAR streamPath[ROLLBACKGUARD_PROCESS_PATH_CHARS] = {};
    if (RgMiniTryGetStreamWriterIdentity(FltObjects, &streamPid, streamPath))
    {
        const BOOLEAN preferStream = (context->ProcessId <= 4 && streamPid > 1) ||
            (context->ProcessPath[0] == '\0' && streamPath[0] != '\0');
        if (preferStream)
        {
            context->ProcessId = streamPid;
            RgMiniCopyAnsiToBuffer(streamPath, context->ProcessPath, ROLLBACKGUARD_PROCESS_PATH_CHARS);
        }
    }

    if (context->ProcessPath[0] == '\0')
    {
        RgMiniResolveProcessPathByPid(context->ProcessId, context->ProcessPath, ROLLBACKGUARD_PROCESS_PATH_CHARS);
    }

    return context;
}

static VOID RgMiniFreeContext(_In_opt_ RGMINI_COMPLETION_CONTEXT* context)
{
    if (context != nullptr)
    {
        ExFreePoolWithTag(context, RGMINI_CONTEXT_TAG);
    }
}

static VOID RgMiniPublishEvent(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ const RGMINI_COMPLETION_CONTEXT* context)
{
    if (context == nullptr || context->EventKind == RollbackGuardEventUnknown)
    {
        return;
    }

    ROLLBACKGUARD_DRIVER_EVENT_RECORD record = {};
    record.Kind = context->EventKind;
    record.ProcessId = context->ProcessId;
    record.ThreadId = context->ThreadId;
    record.TimestampUnixMs = RgMiniGetUnixTimeMs();
    record.Flags = context->Flags;
    record.VolumeSerialNumber = context->VolumeSerialNumber;
    record.FileId = context->FileId;
    RgMiniCopyAnsiToBuffer(context->ProcessPath, record.ProcessPath, ROLLBACKGUARD_PROCESS_PATH_CHARS);
    RgMiniCopyAnsiToBuffer(context->SourcePath, record.SourcePath, ROLLBACKGUARD_PATH_CHARS);

    if (record.ProcessPath[0] == '\0' && KeGetCurrentIrql() == PASSIVE_LEVEL)
    {
        RgMiniResolveProcessPathByPid(record.ProcessId, record.ProcessPath, ROLLBACKGUARD_PROCESS_PATH_CHARS);
    }

    if (KeGetCurrentIrql() <= APC_LEVEL)
    {
        RgMiniCapturePathFromData(Data, record.TargetPath, ROLLBACKGUARD_PATH_CHARS);
    }
    else
    {
        record.TargetPath[0] = '\0';
    }

    if (RgMiniIsRegisteredHoneypotPath(record.TargetPath) ||
        RgMiniIsRegisteredHoneypotPath(record.SourcePath))
    {
        record.Kind = RollbackGuardEventHoneyFileTouched;
    }

    RgMiniQueueEvent(&record);

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[RollbackGuard.MiniFilter] kind=%lu pid=%lu proc=%s target=%s source=%s\n",
        record.Kind,
        record.ProcessId,
        record.ProcessPath[0] == '\0' ? "<unknown>" : record.ProcessPath,
        record.TargetPath[0] == '\0' ? "<unknown>" : record.TargetPath,
        record.SourcePath[0] == '\0' ? "<none>" : record.SourcePath);
}

EXTERN_C FLT_PREOP_CALLBACK_STATUS RgMiniPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);

    if (CompletionContext != nullptr)
    {
        *CompletionContext = nullptr;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

EXTERN_C FLT_POSTOP_CALLBACK_STATUS RgMiniPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(Data->IoStatus.Status) ||
        FltObjects == nullptr ||
        FltObjects->Instance == nullptr ||
        FltObjects->FileObject == nullptr)
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    RGMINI_STREAM_CONTEXT* streamContext = nullptr;
    NTSTATUS status = FltAllocateContext(
        g_FilterHandle,
        FLT_STREAMHANDLE_CONTEXT,
        sizeof(RGMINI_STREAM_CONTEXT),
        NonPagedPoolNx,
        reinterpret_cast<PFLT_CONTEXT*>(&streamContext));

    if (!NT_SUCCESS(status) || streamContext == nullptr)
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    RtlZeroMemory(streamContext, sizeof(*streamContext));
    streamContext->CreatorProcessId = RgMiniGetRequestorPid(Data);
    streamContext->CreatorThreadId = HandleToULong(PsGetCurrentThreadId());
    RgMiniResolveProcessPathByPid(
        streamContext->CreatorProcessId,
        streamContext->CreatorProcessPath,
        ROLLBACKGUARD_PROCESS_PATH_CHARS);

    status = FltSetStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        streamContext,
        nullptr);

    RgMiniUpsertStreamWriterIdentity(
        FltObjects,
        streamContext->CreatorProcessId,
        streamContext->CreatorThreadId,
        streamContext->CreatorProcessPath);

    FltReleaseContext(streamContext);
    UNREFERENCED_PARAMETER(status);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

EXTERN_C FLT_PREOP_CALLBACK_STATUS RgMiniPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    if (CompletionContext == nullptr)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    *CompletionContext = nullptr;

    if (Data->Iopb->Parameters.Write.Length == 0)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Paging writes arrive at DISPATCH_LEVEL — any call that touches pageable memory
    // (FltGetFileNameInformation, SeLocateProcessImageName, etc.) at that IRQL will
    // immediately trigger DRIVER_IRQL_NOT_LESS_OR_EQUAL.  Bail out before doing
    // anything that requires PASSIVE_LEVEL or APC_LEVEL.
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    CHAR targetPath[ROLLBACKGUARD_PATH_CHARS] = {};
    RgMiniCapturePathFromData(Data, targetPath, ROLLBACKGUARD_PATH_CHARS);
    if (RgMiniIsBackupPath(targetPath))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG trustedPid = 0;
    ULONG trustLevel = RgMiniProcessTrustUnknown;
    const BOOLEAN hasTrustLevel = RgMiniTryGetProcessTrustInfo(
        Data,
        FltObjects,
        &trustedPid,
        &trustLevel);
    if (hasTrustLevel && trustLevel == RgMiniProcessTrustMicrosoftSigned)
    {
        if (trustedPid > 0)
        {
            if (RgMiniIsBlockedPid(trustedPid))
            {
                RgMiniUnblockProcessByPid(trustedPid);
            }
            RgMiniClearRestrictedProcessByPid(trustedPid);
            RgMiniResetEntropyStateByPid(trustedPid);
        }

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG blockedPid = 0;
    if (RgMiniShouldBlockData(Data, FltObjects, &blockedPid))
    {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "[RollbackGuard.MiniFilter] blocked write pid=%lu\n",
            blockedPid);
        return FLT_PREOP_COMPLETE;
    }

    ULONG restrictedPid = 0;
    LONGLONG restrictedDelayUntilMs = 0;
    const BOOLEAN isRestrictedProcess = RgMiniTryGetRestrictedProcessInfo(
        Data,
        FltObjects,
        &restrictedPid,
        &restrictedDelayUntilMs);
    if (isRestrictedProcess)
    {
        RgMiniApplyRestrictedDelay(restrictedDelayUntilMs);
    }

    auto* context = RgMiniAllocContext(RollbackGuardEventFileWrite, Data, FltObjects);
    if (context == nullptr)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    RgMiniUpsertStreamWriterIdentity(FltObjects, context->ProcessId, context->ThreadId, context->ProcessPath);
    context->Flags |= ROLLBACKGUARD_EVENT_FLAG_PRE_OPERATION;

    const BOOLEAN shouldSkipBackup = trustLevel == RgMiniProcessTrustSigned;
    NTSTATUS snapshotStatus = STATUS_SUCCESS;
    if (!shouldSkipBackup)
    {
        snapshotStatus = RgMiniCapturePreWriteSnapshot(targetPath, FltObjects, context);
        if (!NT_SUCCESS(snapshotStatus))
        {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "[RollbackGuard.MiniFilter] prewrite snapshot failed-allow pid=%lu status=0x%08X target=%s\n",
                context->ProcessId,
                snapshotStatus,
                targetPath[0] == '\0' ? "<unknown>" : targetPath);
            context->SourcePath[0] = '\0';

            if (isRestrictedProcess)
            {
                RgMiniFreeContext(context);
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID,
                    DPFLTR_WARNING_LEVEL,
                    "[RollbackGuard.MiniFilter] restricted prewrite snapshot deny pid=%lu status=0x%08X target=%s\n",
                    restrictedPid,
                    snapshotStatus,
                    targetPath[0] == '\0' ? "<unknown>" : targetPath);
                return FLT_PREOP_COMPLETE;
            }
        }
    }
    else
    {
        context->SourcePath[0] = '\0';
    }

    const BOOLEAN touchesHoneypot = RgMiniIsRegisteredHoneypotPath(targetPath);
    const UCHAR* writeSample = nullptr;
    ULONG writeSampleLength = 0;
    ULONGLONG writeChiSquare = 0;
    const BOOLEAN hasWriteChiSquare =
        RgMiniTryMapWriteBufferSample(Data, &writeSample, &writeSampleLength) &&
        RgMiniTryComputeChiSquareFromBuffer(writeSample, writeSampleLength, &writeChiSquare);

    ULONGLONG sourceChiSquare = 0;
    BOOLEAN hasSourceChiSquare = FALSE;
    if (context->SourcePath[0] != '\0')
    {
        hasSourceChiSquare = RgMiniTryReadFileEntropySample(context->SourcePath, &sourceChiSquare);
    }
    else if (shouldSkipBackup && targetPath[0] != '\0')
    {
        hasSourceChiSquare = RgMiniTryReadFileEntropySample(targetPath, &sourceChiSquare);
    }

    RGMINI_ENTROPY_RESULT entropyResult = {};
    RgMiniEvaluateEntropyForWrite(
        context->ProcessId,
        targetPath,
        writeChiSquare,
        hasWriteChiSquare,
        sourceChiSquare,
        hasSourceChiSquare,
        &entropyResult);

    if (touchesHoneypot)
    {
        entropyResult.ShouldAutoBlock = TRUE;
        entropyResult.TriggeredHoneypotRule = TRUE;
        context->Flags |= ROLLBACKGUARD_EVENT_FLAG_KERNEL_RULE_HONEYPOT;
    }

    if (entropyResult.HasHighEntropyRaw)
    {
        context->Flags |= ROLLBACKGUARD_EVENT_FLAG_KERNEL_HIGH_ENTROPY_RAW;
    }

    if (entropyResult.HasLowToHighTransition)
    {
        context->Flags |= ROLLBACKGUARD_EVENT_FLAG_KERNEL_LOW_TO_HIGH;
    }

    if (entropyResult.TriggeredConsecutiveRule)
    {
        context->Flags |= ROLLBACKGUARD_EVENT_FLAG_KERNEL_RULE_CONSECUTIVE;
    }

    if (entropyResult.TriggeredCumulativeRule)
    {
        context->Flags |= ROLLBACKGUARD_EVENT_FLAG_KERNEL_RULE_CUMULATIVE;
    }

    if (entropyResult.ShouldAutoBlock)
    {
        const NTSTATUS blockStatus = RgMiniBlockProcessByPid(context->ProcessId);
        if (NT_SUCCESS(blockStatus))
        {
            context->Flags |= ROLLBACKGUARD_EVENT_FLAG_KERNEL_AUTO_BLOCKED;
            RgMiniPublishEvent(Data, context);

            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "[RollbackGuard.MiniFilter] entropy autoblock pid=%lu low2high=%lu raw=%lu consecutive=%lu dirs=%lu target=%s honeypot=%lu\n",
                context->ProcessId,
                entropyResult.LowToHighEntropyCount,
                entropyResult.HighEntropyRawCount,
                entropyResult.ConsecutiveCount,
                entropyResult.UniqueDirectoryCount,
                targetPath[0] == '\0' ? "<unknown>" : targetPath,
                touchesHoneypot ? 1UL : 0UL);
            RgMiniFreeContext(context);
            return FLT_PREOP_COMPLETE;
        }

        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[RollbackGuard.MiniFilter] entropy autoblock skipped pid=%lu status=0x%08X target=%s\n",
            context->ProcessId,
            blockStatus,
            targetPath[0] == '\0' ? "<unknown>" : targetPath);
    }

    RgMiniPublishEvent(Data, context);
    *CompletionContext = context;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

EXTERN_C FLT_POSTOP_CALLBACK_STATUS RgMiniPostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);

    auto* context = static_cast<RGMINI_COMPLETION_CONTEXT*>(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
    {
        RgMiniFreeContext(context);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (context != nullptr &&
        KeGetCurrentIrql() == PASSIVE_LEVEL &&
        NT_SUCCESS(Data->IoStatus.Status) &&
        Data->IoStatus.Information > 0)
    {
        context->Flags &= ~ROLLBACKGUARD_EVENT_FLAG_PRE_OPERATION;
        RgMiniPublishEvent(Data, context);
    }

    RgMiniFreeContext(context);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

EXTERN_C FLT_PREOP_CALLBACK_STATUS RgMiniPreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    if (CompletionContext == nullptr)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    *CompletionContext = nullptr;

    ULONG trustedPid = 0;
    ULONG trustLevel = RgMiniProcessTrustUnknown;
    const BOOLEAN hasTrustLevel = RgMiniTryGetProcessTrustInfo(
        Data,
        FltObjects,
        &trustedPid,
        &trustLevel);
    if (hasTrustLevel && trustLevel == RgMiniProcessTrustMicrosoftSigned)
    {
        if (trustedPid > 0)
        {
            if (RgMiniIsBlockedPid(trustedPid))
            {
                RgMiniUnblockProcessByPid(trustedPid);
            }
            RgMiniClearRestrictedProcessByPid(trustedPid);
            RgMiniResetEntropyStateByPid(trustedPid);
        }

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG blockedPid = 0;
    if (RgMiniShouldBlockData(Data, FltObjects, &blockedPid))
    {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "[RollbackGuard.MiniFilter] blocked setinfo pid=%lu\n",
            blockedPid);
        return FLT_PREOP_COMPLETE;
    }

    ULONG restrictedPid = 0;
    LONGLONG restrictedDelayUntilMs = 0;
    const BOOLEAN isRestrictedProcess = RgMiniTryGetRestrictedProcessInfo(
        Data,
        FltObjects,
        &restrictedPid,
        &restrictedDelayUntilMs);
    if (isRestrictedProcess)
    {
        RgMiniApplyRestrictedDelay(restrictedDelayUntilMs);
    }

    ULONG eventKind = RollbackGuardEventUnknown;

    const FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx)
    {
        eventKind = RollbackGuardEventFileRename;
    }
    else if (infoClass == FileDispositionInformation)
    {
        auto* info = static_cast<PFILE_DISPOSITION_INFORMATION>(Data->Iopb->Parameters.SetFileInformation.InfoBuffer);
        if (info != nullptr && info->DeleteFile)
        {
            eventKind = RollbackGuardEventFileDelete;
        }
    }
    else if (infoClass == FileDispositionInformationEx)
    {
        auto* info = static_cast<PFILE_DISPOSITION_INFORMATION_EX>(Data->Iopb->Parameters.SetFileInformation.InfoBuffer);
        if (info != nullptr && FlagOn(info->Flags, FILE_DISPOSITION_DELETE))
        {
            eventKind = RollbackGuardEventFileDelete;
        }
    }

    if (eventKind == RollbackGuardEventUnknown)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Kernel-side behavioral auto-preblock is intentionally disabled.
    // Enforcement is performed in user-mode after signature evaluation,
    // so only unsigned execution paths are subject to blocking.

    auto* context = RgMiniAllocContext(eventKind, Data, FltObjects);
    if (context == nullptr)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (eventKind == RollbackGuardEventFileRename)
    {
        RgMiniCapturePathFromData(Data, context->SourcePath, ROLLBACKGUARD_PATH_CHARS);
    }

    RgMiniUpsertStreamWriterIdentity(FltObjects, context->ProcessId, context->ThreadId, context->ProcessPath);

    CHAR snapshotTargetPath[ROLLBACKGUARD_PATH_CHARS] = {};
    if (eventKind == RollbackGuardEventFileRename)
    {
        RgMiniCopyAnsiToBuffer(context->SourcePath, snapshotTargetPath, ROLLBACKGUARD_PATH_CHARS);
    }
    else if (eventKind == RollbackGuardEventFileDelete)
    {
        RgMiniCapturePathFromData(Data, snapshotTargetPath, ROLLBACKGUARD_PATH_CHARS);
    }

    const BOOLEAN shouldSkipBackup = trustLevel == RgMiniProcessTrustSigned;
    if (!shouldSkipBackup && snapshotTargetPath[0] != '\0' && !RgMiniIsBackupPath(snapshotTargetPath))
    {
        CHAR snapshotPath[ROLLBACKGUARD_PATH_CHARS] = {};
        const NTSTATUS snapshotStatus = RgMiniCaptureSnapshotForTarget(
            snapshotTargetPath,
            FltObjects,
            context->ProcessId,
            context->ThreadId,
            context->VolumeSerialNumber,
            context->FileId,
            snapshotPath);

        if (NT_SUCCESS(snapshotStatus) && snapshotPath[0] != '\0')
        {
            RgMiniQueuePreOperationSnapshotEvent(context, snapshotTargetPath, snapshotPath);
        }
        else
        {
            if (isRestrictedProcess)
            {
                RgMiniFreeContext(context);
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID,
                    DPFLTR_WARNING_LEVEL,
                    "[RollbackGuard.MiniFilter] restricted setinfo snapshot deny pid=%lu kind=%lu status=0x%08X target=%s\n",
                    restrictedPid,
                    eventKind,
                    snapshotStatus,
                    snapshotTargetPath);
                return FLT_PREOP_COMPLETE;
            }

            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "[RollbackGuard.MiniFilter] setinfo preop snapshot failed-allow pid=%lu kind=%lu status=0x%08X target=%s\n",
                context->ProcessId,
                eventKind,
                snapshotStatus,
                snapshotTargetPath);
        }
    }

    *CompletionContext = context;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

EXTERN_C FLT_POSTOP_CALLBACK_STATUS RgMiniPostSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);

    auto* context = static_cast<RGMINI_COMPLETION_CONTEXT*>(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
    {
        RgMiniFreeContext(context);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (context != nullptr &&
        KeGetCurrentIrql() == PASSIVE_LEVEL &&
        NT_SUCCESS(Data->IoStatus.Status))
    {
        RgMiniPublishEvent(Data, context);
    }

    RgMiniFreeContext(context);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

EXTERN_C NTSTATUS RgMiniUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    RgMiniClearBlockedProcesses();
    RgMiniClearRestrictedProcesses();
    RgMiniClearProcessTrusts();
    RgMiniClearEntropyState();
    RgMiniCompletePendingControlWaits(STATUS_DEVICE_NOT_READY);

    PROLLBACKGUARD_SHARED_TELEMETRY_HEADER telemetryHeader = nullptr;
    PKEVENT telemetrySignal = nullptr;
    ExAcquireFastMutex(&g_TelemetryChannel.Lock);
    telemetryHeader = g_TelemetryChannel.Header;
    telemetrySignal = g_TelemetryChannel.SignalEvent;
    g_TelemetryChannel.Header = nullptr;
    g_TelemetryChannel.Records = nullptr;
    g_TelemetryChannel.Capacity = 0;
    g_TelemetryChannel.ViewBytes = 0;
    g_TelemetryChannel.SignalEvent = nullptr;
    ExReleaseFastMutex(&g_TelemetryChannel.Lock);

    RgMiniCleanupTelemetryState(telemetryHeader, telemetrySignal);
    if (g_ControlChannel != nullptr)
    {
        ExFreePoolWithTag(g_ControlChannel, ROLLBACKGUARD_CONTROL_QUEUE_TAG);
        g_ControlChannel = nullptr;
    }

    if (g_EventQueue != nullptr)
    {
        ExFreePoolWithTag(g_EventQueue, ROLLBACKGUARD_EVENT_QUEUE_TAG);
        g_EventQueue = nullptr;
    }

    if (g_EntropyProcessTable != nullptr)
    {
        ExFreePoolWithTag(g_EntropyProcessTable, RGMINI_ENTROPY_TABLE_TAG);
        g_EntropyProcessTable = nullptr;
    }

    if (g_DosName.Buffer != nullptr)
    {
        IoDeleteSymbolicLink(&g_DosName);
        g_DosName.Buffer = nullptr;
        g_DosName.Length = 0;
        g_DosName.MaximumLength = 0;
    }

    if (g_ControlDevice != nullptr)
    {
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = nullptr;
    }

    if (g_FilterHandle != nullptr)
    {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = nullptr;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[RollbackGuard.MiniFilter] unloaded\n");
    return STATUS_SUCCESS;
}

EXTERN_C NTSTATUS RgMiniInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    if (VolumeFilesystemType == FLT_FSTYPE_RAW)
    {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
    {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

EXTERN_C VOID FLTAPI RgMiniStreamHandleContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ContextType);
}

EXTERN_C VOID FLTAPI RgMiniFileStreamContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ContextType);
}

CONST FLT_CONTEXT_REGISTRATION g_RgMiniContextRegistration[] =
{
    {
        FLT_STREAMHANDLE_CONTEXT,
        0,
        RgMiniStreamHandleContextCleanup,
        sizeof(RGMINI_STREAM_CONTEXT),
        RGMINI_STREAM_CONTEXT_TAG
    },
    {
        FLT_STREAM_CONTEXT,
        0,
        RgMiniFileStreamContextCleanup,
        sizeof(RGMINI_FILE_STREAM_CONTEXT),
        RGMINI_FILE_STREAM_CONTEXT_TAG
    },
    { FLT_CONTEXT_END }
};

CONST FLT_OPERATION_REGISTRATION g_RgMiniCallbacks[] =
{
    { IRP_MJ_CREATE, 0, RgMiniPreCreate, RgMiniPostCreate },
    { IRP_MJ_WRITE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, RgMiniPreWrite, RgMiniPostWrite },
    { IRP_MJ_SET_INFORMATION, 0, RgMiniPreSetInfo, RgMiniPostSetInfo },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION g_RgMiniRegistration =
{
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    g_RgMiniContextRegistration,
    g_RgMiniCallbacks,
    RgMiniUnload,
    RgMiniInstanceSetup,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr
};

EXTERN_C NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    g_EventQueue = RgMiniAllocateEventQueue();
    g_ControlChannel = RgMiniAllocateControlChannel();
    g_EntropyProcessTable = RgMiniAllocateEntropyProcessTable();
    if (g_EventQueue == nullptr || g_ControlChannel == nullptr || g_EntropyProcessTable == nullptr)
    {
        if (g_ControlChannel != nullptr)
        {
            ExFreePoolWithTag(g_ControlChannel, ROLLBACKGUARD_CONTROL_QUEUE_TAG);
            g_ControlChannel = nullptr;
        }

        if (g_EventQueue != nullptr)
        {
            ExFreePoolWithTag(g_EventQueue, ROLLBACKGUARD_EVENT_QUEUE_TAG);
            g_EventQueue = nullptr;
        }

        if (g_EntropyProcessTable != nullptr)
        {
            ExFreePoolWithTag(g_EntropyProcessTable, RGMINI_ENTROPY_TABLE_TAG);
            g_EntropyProcessTable = nullptr;
        }

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ExInitializeFastMutex(&g_TelemetryChannel.Lock);
    g_TelemetryChannel.Header = nullptr;
    g_TelemetryChannel.Records = nullptr;
    g_TelemetryChannel.Capacity = 0;
    g_TelemetryChannel.ViewBytes = 0;
    g_TelemetryChannel.SignalEvent = nullptr;
    g_EventSequence = 0;

    KeInitializeSpinLock(&g_BlockedProcessLock);
    RtlZeroMemory(g_BlockedProcesses, sizeof(g_BlockedProcesses));
    KeInitializeSpinLock(&g_RestrictedProcessLock);
    RtlZeroMemory(g_RestrictedProcesses, sizeof(g_RestrictedProcesses));
    KeInitializeSpinLock(&g_ProcessTrustLock);
    RtlZeroMemory(g_ProcessTrustEntries, sizeof(g_ProcessTrustEntries));
    KeInitializeSpinLock(&g_HoneypotLock);
    RtlZeroMemory(g_HoneypotPaths, sizeof(g_HoneypotPaths));
    g_HoneypotPathCount = 0;

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
    {
        DriverObject->MajorFunction[i] = RgMiniUnsupported;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = RgMiniCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = RgMiniCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RgMiniDeviceControl;

    UNICODE_STRING deviceName;
    RtlInitUnicodeString(&deviceName, ROLLBACKGUARD_MINIFILTER_DEVICE_NAME);

    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_ControlDevice);

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RollbackGuard.MiniFilter] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    g_ControlDevice->Flags |= DO_BUFFERED_IO;
    g_ControlDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    RtlInitUnicodeString(&g_DosName, ROLLBACKGUARD_MINIFILTER_DOS_NAME);
    status = IoCreateSymbolicLink(&g_DosName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RollbackGuard.MiniFilter] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = nullptr;
        ExFreePoolWithTag(g_ControlChannel, ROLLBACKGUARD_CONTROL_QUEUE_TAG);
        g_ControlChannel = nullptr;
        ExFreePoolWithTag(g_EventQueue, ROLLBACKGUARD_EVENT_QUEUE_TAG);
        g_EventQueue = nullptr;
        ExFreePoolWithTag(g_EntropyProcessTable, RGMINI_ENTROPY_TABLE_TAG);
        g_EntropyProcessTable = nullptr;
        return status;
    }

    status = FltRegisterFilter(DriverObject, &g_RgMiniRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RollbackGuard.MiniFilter] FltRegisterFilter failed: 0x%08X\n", status);
        IoDeleteSymbolicLink(&g_DosName);
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = nullptr;
        ExFreePoolWithTag(g_ControlChannel, ROLLBACKGUARD_CONTROL_QUEUE_TAG);
        g_ControlChannel = nullptr;
        ExFreePoolWithTag(g_EventQueue, ROLLBACKGUARD_EVENT_QUEUE_TAG);
        g_EventQueue = nullptr;
        ExFreePoolWithTag(g_EntropyProcessTable, RGMINI_ENTROPY_TABLE_TAG);
        g_EntropyProcessTable = nullptr;
        return status;
    }

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RollbackGuard.MiniFilter] FltStartFiltering failed: 0x%08X\n", status);
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = nullptr;

        IoDeleteSymbolicLink(&g_DosName);
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = nullptr;
        ExFreePoolWithTag(g_ControlChannel, ROLLBACKGUARD_CONTROL_QUEUE_TAG);
        g_ControlChannel = nullptr;
        ExFreePoolWithTag(g_EventQueue, ROLLBACKGUARD_EVENT_QUEUE_TAG);
        g_EventQueue = nullptr;
        ExFreePoolWithTag(g_EntropyProcessTable, RGMINI_ENTROPY_TABLE_TAG);
        g_EntropyProcessTable = nullptr;
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[RollbackGuard.MiniFilter] started\n");
    return STATUS_SUCCESS;
}
