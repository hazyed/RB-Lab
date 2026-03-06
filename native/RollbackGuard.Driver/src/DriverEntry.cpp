#include "../include/DriverContracts.h"

#include <ntstrsafe.h>

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE (0x0001)
#endif

#define ROLLBACKGUARD_EVENT_QUEUE_CAPACITY 256
#define ROLLBACKGUARD_CONTROL_QUEUE_CAPACITY 256
#define ROLLBACKGUARD_EVENT_QUEUE_TAG 'EqgR'
#define ROLLBACKGUARD_CONTROL_QUEUE_TAG 'CqgR'

extern "C" NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process);
extern "C" NTKERNELAPI NTSTATUS PsSuspendProcess(_In_ PEPROCESS Process);
extern "C" NTKERNELAPI NTSTATUS PsResumeProcess(_In_ PEPROCESS Process);

typedef struct _ROLLBACKGUARD_EVENT_QUEUE
{
    KSPIN_LOCK Lock;
    ULONG Head;
    ULONG Count;
    ROLLBACKGUARD_DRIVER_EVENT_RECORD Events[ROLLBACKGUARD_EVENT_QUEUE_CAPACITY];
} ROLLBACKGUARD_EVENT_QUEUE, *PROLLBACKGUARD_EVENT_QUEUE;

typedef struct _ROLLBACKGUARD_TELEMETRY_CHANNEL
{
    FAST_MUTEX Lock;
    PROLLBACKGUARD_SHARED_TELEMETRY_HEADER Header;
    PROLLBACKGUARD_DRIVER_EVENT_RECORD Records;
    ULONG Capacity;
    SIZE_T ViewBytes;
    PKEVENT SignalEvent;
} ROLLBACKGUARD_TELEMETRY_CHANNEL;

typedef struct _ROLLBACKGUARD_CONTROL_CHANNEL
{
    KSPIN_LOCK Lock;
    ULONG Head;
    ULONG Count;
    PIRP PendingIrp;
    ROLLBACKGUARD_DRIVER_EVENT_RECORD Events[ROLLBACKGUARD_CONTROL_QUEUE_CAPACITY];
} ROLLBACKGUARD_CONTROL_CHANNEL, *PROLLBACKGUARD_CONTROL_CHANNEL;

static PROLLBACKGUARD_EVENT_QUEUE g_EventQueue = nullptr;
static ROLLBACKGUARD_TELEMETRY_CHANNEL g_TelemetryChannel = {};
static PROLLBACKGUARD_CONTROL_CHANNEL g_ControlChannel = nullptr;
static volatile LONG64 g_EventSequence = 0;

static BOOLEAN RollbackGuardIsControlEvent(_In_ ULONG kind)
{
    switch (kind)
    {
    case RollbackGuardEventShadowDeleteAttempt:
    case RollbackGuardEventHoneyFileTouched:
    case RollbackGuardEventProcessInject:
    case RollbackGuardEventThreadCreateRemote:
    case RollbackGuardEventSuspiciousHandleProcess:
    case RollbackGuardEventSuspiciousHandleThread:
    case RollbackGuardEventImageLoadUnsigned:
        return TRUE;
    default:
        return FALSE;
    }
}

static VOID RollbackGuardCleanupTelemetryState(
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

static PROLLBACKGUARD_EVENT_QUEUE RollbackGuardAllocateEventQueue()
{
    auto* queue = static_cast<PROLLBACKGUARD_EVENT_QUEUE>(ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(ROLLBACKGUARD_EVENT_QUEUE),
        ROLLBACKGUARD_EVENT_QUEUE_TAG));
    if (queue != nullptr)
    {
        RtlZeroMemory(queue, sizeof(*queue));
        KeInitializeSpinLock(&queue->Lock);
    }

    return queue;
}

static PROLLBACKGUARD_CONTROL_CHANNEL RollbackGuardAllocateControlChannel()
{
    auto* channel = static_cast<PROLLBACKGUARD_CONTROL_CHANNEL>(ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(ROLLBACKGUARD_CONTROL_CHANNEL),
        ROLLBACKGUARD_CONTROL_QUEUE_TAG));
    if (channel != nullptr)
    {
        RtlZeroMemory(channel, sizeof(*channel));
        KeInitializeSpinLock(&channel->Lock);
    }

    return channel;
}

static NTSTATUS RollbackGuardBuildKernelObjectName(
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

static NTSTATUS RollbackGuardConfigureTelemetryChannel(_In_ const ROLLBACKGUARD_TELEMETRY_REGISTRATION_REQUEST* request)
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
    NTSTATUS status = RollbackGuardBuildKernelObjectName(
        request->SectionName,
        &sectionName,
        sectionNameBuffer,
        RTL_NUMBER_OF(sectionNameBuffer));
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = RollbackGuardBuildKernelObjectName(
        request->SignalEventName,
        &signalName,
        signalNameBuffer,
        RTL_NUMBER_OF(signalNameBuffer));
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
        RollbackGuardCleanupTelemetryState(mappedHeader, signalEvent);
        return status;
    }

    if (viewBytes < sizeof(ROLLBACKGUARD_SHARED_TELEMETRY_HEADER) ||
        viewBytes < sizeof(ROLLBACKGUARD_SHARED_TELEMETRY_HEADER) +
            (static_cast<SIZE_T>(request->RingCapacity) * sizeof(ROLLBACKGUARD_DRIVER_EVENT_RECORD)))
    {
        RollbackGuardCleanupTelemetryState(mappedHeader, signalEvent);
        return STATUS_BUFFER_TOO_SMALL;
    }

    InitializeObjectAttributes(&attributes, &signalName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    status = ZwOpenEvent(&eventHandle, EVENT_MODIFY_STATE | SYNCHRONIZE, &attributes);
    if (!NT_SUCCESS(status))
    {
        RollbackGuardCleanupTelemetryState(mappedHeader, signalEvent);
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
    eventHandle = nullptr;
    if (!NT_SUCCESS(status))
    {
        RollbackGuardCleanupTelemetryState(mappedHeader, signalEvent);
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

    RollbackGuardCleanupTelemetryState(oldHeader, oldSignalEvent);
    return STATUS_SUCCESS;
}

static VOID RollbackGuardQueueLegacyEvent(_In_ const ROLLBACKGUARD_DRIVER_EVENT_RECORD* record)
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

static VOID RollbackGuardWriteSharedTelemetry(_In_ const ROLLBACKGUARD_DRIVER_EVENT_RECORD* record)
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

static VOID RollbackGuardCompleteControlIrp(
    _In_ PIRP irp,
    _In_ const ROLLBACKGUARD_DRIVER_EVENT_RECORD* record,
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

static VOID RollbackGuardControlWaitCancel(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    IoReleaseCancelSpinLock(Irp->CancelIrql);

    if (g_ControlChannel == nullptr)
    {
        RollbackGuardCompleteControlIrp(Irp, nullptr, STATUS_CANCELLED);
        return;
    }

    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_ControlChannel->Lock, &oldIrql);
    if (g_ControlChannel->PendingIrp == Irp)
    {
        g_ControlChannel->PendingIrp = nullptr;
    }
    KeReleaseSpinLock(&g_ControlChannel->Lock, oldIrql);

    RollbackGuardCompleteControlIrp(Irp, nullptr, STATUS_CANCELLED);
}

static VOID RollbackGuardNotifyControlEvent(_In_ const ROLLBACKGUARD_DRIVER_EVENT_RECORD* record)
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
                RollbackGuardCompleteControlIrp(pendingIrp, record, STATUS_SUCCESS);
                return;
            }

            RollbackGuardCompleteControlIrp(pendingIrp, nullptr, STATUS_BUFFER_TOO_SMALL);
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

static VOID RollbackGuardCompletePendingControlWaits(_In_ NTSTATUS status)
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
        RollbackGuardCompleteControlIrp(pendingIrp, nullptr, status);
    }
}

static NTSTATUS RollbackGuardUnsupported(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

VOID RollbackGuardCopyAnsiToBuffer(
    _In_opt_z_ const CHAR* source,
    _Out_writes_(destChars) CHAR* dest,
    _In_ SIZE_T destChars)
{
    if (dest == nullptr || destChars == 0)
    {
        return;
    }

    dest[0] = '\0';
    if (source == nullptr)
    {
        return;
    }

    SIZE_T index = 0;
    while (index + 1 < destChars && source[index] != '\0')
    {
        dest[index] = source[index];
        ++index;
    }

    dest[index] = '\0';
}

VOID RollbackGuardCopyUnicodeToAnsiBuffer(
    _In_opt_ PCUNICODE_STRING source,
    _Out_writes_(destChars) CHAR* dest,
    _In_ SIZE_T destChars)
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

LONGLONG RollbackGuardGetUnixTimeMs()
{
    LARGE_INTEGER now = {};
    KeQuerySystemTime(&now);

    constexpr LONGLONG EpochDiff100ns = 116444736000000000LL;
    return (now.QuadPart - EpochDiff100ns) / 10000;
}

VOID RollbackGuardQueueEvent(_In_ const ROLLBACKGUARD_DRIVER_EVENT_RECORD* record)
{
    if (record == nullptr)
    {
        return;
    }

    ROLLBACKGUARD_DRIVER_EVENT_RECORD published = *record;
    published.SequenceId = static_cast<ULONGLONG>(InterlockedIncrement64(&g_EventSequence));

    RollbackGuardQueueLegacyEvent(&published);
    RollbackGuardWriteSharedTelemetry(&published);

    if (RollbackGuardIsControlEvent(published.Kind))
    {
        RollbackGuardNotifyControlEvent(&published);
    }
}

static NTSTATUS RollbackGuardOpenProcessHandle(_In_ ULONG processId, _In_ ACCESS_MASK desiredAccess, _Out_ PHANDLE processHandle)
{
    if (processId == 0 || processHandle == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *processHandle = nullptr;

    CLIENT_ID clientId = {};
    clientId.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(processId));
    clientId.UniqueThread = nullptr;

    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

    return ZwOpenProcess(processHandle, desiredAccess, &attributes, &clientId);
}

static NTSTATUS RollbackGuardTerminateProcessByPid(_In_ ULONG processId)
{
    HANDLE processHandle = nullptr;
    NTSTATUS status = RollbackGuardOpenProcessHandle(processId, PROCESS_TERMINATE, &processHandle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = ZwTerminateProcess(processHandle, STATUS_ACCESS_DENIED);
    ZwClose(processHandle);
    return status;
}

static NTSTATUS RollbackGuardSuspendProcessByPid(_In_ ULONG processId)
{
    if (processId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(
        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(processId)),
        &process);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = PsSuspendProcess(process);
    ObDereferenceObject(process);
    return status;
}

static NTSTATUS RollbackGuardResumeProcessByPid(_In_ ULONG processId)
{
    if (processId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(
        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(processId)),
        &process);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = PsResumeProcess(process);
    ObDereferenceObject(process);
    return status;
}

_Use_decl_annotations_
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING deviceName;
    UNICODE_STRING dosDeviceName;
    PDEVICE_OBJECT deviceObject = nullptr;

    RtlInitUnicodeString(&deviceName, ROLLBACKGUARD_DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        sizeof(ROLLBACKGUARD_DEVICE_CONTEXT),
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject);

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RollbackGuard] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    RtlInitUnicodeString(&dosDeviceName, ROLLBACKGUARD_DOS_DEVICE_NAME);
    status = IoCreateSymbolicLink(&dosDeviceName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RollbackGuard] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    auto* context = static_cast<PROLLBACKGUARD_DEVICE_CONTEXT>(deviceObject->DeviceExtension);
    RtlZeroMemory(context, sizeof(*context));
    context->RollbackModeEnabled = FALSE;
    context->RollbackModeProcessId = 0;

    g_EventQueue = RollbackGuardAllocateEventQueue();
    g_ControlChannel = RollbackGuardAllocateControlChannel();
    if (g_EventQueue == nullptr || g_ControlChannel == nullptr)
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

        IoDeleteSymbolicLink(&dosDeviceName);
        IoDeleteDevice(deviceObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ExInitializeFastMutex(&g_TelemetryChannel.Lock);
    g_TelemetryChannel.Header = nullptr;
    g_TelemetryChannel.Records = nullptr;
    g_TelemetryChannel.Capacity = 0;
    g_TelemetryChannel.ViewBytes = 0;
    g_TelemetryChannel.SignalEvent = nullptr;
    g_EventSequence = 0;

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
    {
        DriverObject->MajorFunction[i] = RollbackGuardUnsupported;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = RollbackGuardCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = RollbackGuardCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RollbackGuardDeviceControl;
    DriverObject->DriverUnload = RollbackGuardUnload;

    if (NT_SUCCESS(RegisterProcessMonitor(context)))
    {
        context->ProcessMonitorRegistered = TRUE;
    }

    if (NT_SUCCESS(RegisterRegistryMonitor(context)))
    {
        context->RegistryMonitorRegistered = TRUE;
    }

    if (NT_SUCCESS(RegisterFileMonitor(context)))
    {
        context->FileMonitorRegistered = TRUE;
    }

    if (NT_SUCCESS(RegisterThreadMonitor(context)))
    {
        context->ThreadMonitorRegistered = TRUE;
    }

    if (NT_SUCCESS(RegisterImageMonitor(context)))
    {
        context->ImageMonitorRegistered = TRUE;
    }

    if (NT_SUCCESS(RegisterObjectMonitor(context)))
    {
        context->ObjectMonitorRegistered = TRUE;
    }

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[RollbackGuard] Driver loaded.\\.\\RollbackGuard ready.\n");
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS RollbackGuardCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS RollbackGuardDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    auto* context = static_cast<PROLLBACKGUARD_DEVICE_CONTEXT>(DeviceObject->DeviceExtension);
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

        status = RollbackGuardConfigureTelemetryChannel(request);
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
            IoSetCancelRoutine(Irp, RollbackGuardControlWaitCancel);

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
    case IOCTL_ROLLBACKGUARD_COMMAND:
    {
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ROLLBACKGUARD_DRIVER_COMMAND_REQUEST))
        {
            status = STATUS_BUFFER_TOO_SMALL;
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
            // Blocked-pids I/O denial lives in the minifilter, not the core driver.
            status = STATUS_NOT_SUPPORTED;
            break;
        case RollbackGuardCommandTerminate:
            status = RollbackGuardTerminateProcessByPid(command->ProcessId);
            break;
        case RollbackGuardCommandEnableRollback:
            if (context != nullptr)
            {
                context->RollbackModeEnabled = TRUE;
                context->RollbackModeProcessId = command->ProcessId;
            }
            status = STATUS_SUCCESS;
            break;
        case RollbackGuardCommandSuspend:
            status = RollbackGuardSuspendProcessByPid(command->ProcessId);
            break;
        case RollbackGuardCommandResume:
            status = RollbackGuardResumeProcessByPid(command->ProcessId);
            break;
        case RollbackGuardCommandSetRestricted:
        case RollbackGuardCommandClearRestricted:
            // Startup restricted-mode delay is enforced by the minifilter path.
            status = STATUS_NOT_SUPPORTED;
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

_Use_decl_annotations_
VOID RollbackGuardUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING dosDeviceName;
    RtlInitUnicodeString(&dosDeviceName, ROLLBACKGUARD_DOS_DEVICE_NAME);

    RollbackGuardCompletePendingControlWaits(STATUS_DEVICE_NOT_READY);

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

    RollbackGuardCleanupTelemetryState(telemetryHeader, telemetrySignal);
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

    if (DriverObject->DeviceObject != nullptr)
    {
        auto* context = static_cast<PROLLBACKGUARD_DEVICE_CONTEXT>(DriverObject->DeviceObject->DeviceExtension);
        if (context != nullptr)
        {
            if (context->ProcessMonitorRegistered)
            {
                UnregisterProcessMonitor(context);
            }

            if (context->RegistryMonitorRegistered)
            {
                UnregisterRegistryMonitor(context);
            }

            if (context->FileMonitorRegistered)
            {
                UnregisterFileMonitor(context);
            }

            if (context->ThreadMonitorRegistered)
            {
                UnregisterThreadMonitor(context);
            }

            if (context->ImageMonitorRegistered)
            {
                UnregisterImageMonitor(context);
            }

            if (context->ObjectMonitorRegistered)
            {
                UnregisterObjectMonitor(context);
            }
        }

        IoDeleteSymbolicLink(&dosDeviceName);
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[RollbackGuard] Driver unloaded.\n");
}
