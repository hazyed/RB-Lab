#include "../include/DriverContracts.h"

_Use_decl_annotations_
NTSTATUS RegisterFileMonitor(PROLLBACKGUARD_DEVICE_CONTEXT context)
{
    UNREFERENCED_PARAMETER(context);
    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
VOID UnregisterFileMonitor(PROLLBACKGUARD_DEVICE_CONTEXT context)
{
    UNREFERENCED_PARAMETER(context);
}
