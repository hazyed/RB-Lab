#include "../include/DriverContracts.h"

static LARGE_INTEGER g_RegistryCookie = {};
static BOOLEAN g_RegistryCallbackRegistered = FALSE;

static VOID RollbackGuardAppendAnsi(_Inout_updates_(destChars) CHAR* dest, _In_ SIZE_T destChars, _In_opt_z_ const CHAR* value)
{
    if (dest == nullptr || destChars == 0 || value == nullptr)
    {
        return;
    }

    SIZE_T end = 0;
    while (end < destChars && dest[end] != '\0')
    {
        ++end;
    }

    if (end >= destChars - 1)
    {
        dest[destChars - 1] = '\0';
        return;
    }

    SIZE_T i = 0;
    while (end + i + 1 < destChars && value[i] != '\0')
    {
        dest[end + i] = value[i];
        ++i;
    }

    dest[end + i] = '\0';
}

static VOID RollbackGuardBuildRegistryTarget(
    _In_opt_ PCUNICODE_STRING keyName,
    _In_opt_ PCUNICODE_STRING valueName,
    _Out_writes_(ROLLBACKGUARD_PATH_CHARS) CHAR* target)
{
    target[0] = '\0';

    CHAR keyBuffer[ROLLBACKGUARD_PATH_CHARS] = {};
    CHAR valueBuffer[ROLLBACKGUARD_PATH_CHARS] = {};

    RollbackGuardCopyUnicodeToAnsiBuffer(keyName, keyBuffer, ROLLBACKGUARD_PATH_CHARS);
    RollbackGuardCopyUnicodeToAnsiBuffer(valueName, valueBuffer, ROLLBACKGUARD_PATH_CHARS);

    if (keyBuffer[0] != '\0')
    {
        RollbackGuardCopyAnsiToBuffer(keyBuffer, target, ROLLBACKGUARD_PATH_CHARS);
    }

    if (valueBuffer[0] == '\0')
    {
        return;
    }

    if (target[0] != '\0')
    {
        const SIZE_T targetLen = strlen(target);
        if (targetLen > 0 && target[targetLen - 1] != '\\')
        {
            RollbackGuardAppendAnsi(target, ROLLBACKGUARD_PATH_CHARS, "\\");
        }
    }

    RollbackGuardAppendAnsi(target, ROLLBACKGUARD_PATH_CHARS, valueBuffer);
}

static NTSTATUS RollbackGuardRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);

    const REG_NOTIFY_CLASS notifyClass = static_cast<REG_NOTIFY_CLASS>(reinterpret_cast<ULONG_PTR>(Argument1));

    PVOID keyObject = nullptr;
    PCUNICODE_STRING valueName = nullptr;
    ULONG eventKind = RollbackGuardEventUnknown;

    if (notifyClass == RegNtPreSetValueKey)
    {
        auto* info = static_cast<PREG_SET_VALUE_KEY_INFORMATION>(Argument2);
        if (info == nullptr)
        {
            return STATUS_SUCCESS;
        }

        keyObject = info->Object;
        valueName = info->ValueName;
        eventKind = RollbackGuardEventRegistrySet;
    }
    else if (notifyClass == RegNtPreDeleteValueKey)
    {
        auto* info = static_cast<PREG_DELETE_VALUE_KEY_INFORMATION>(Argument2);
        if (info == nullptr)
        {
            return STATUS_SUCCESS;
        }

        keyObject = info->Object;
        valueName = info->ValueName;
        eventKind = RollbackGuardEventRegistryDelete;
    }
    else
    {
        return STATUS_SUCCESS;
    }

    ROLLBACKGUARD_DRIVER_EVENT_RECORD record = {};
    record.Kind = eventKind;
    record.ProcessId = HandleToULong(PsGetCurrentProcessId());
    record.ThreadId = HandleToULong(PsGetCurrentThreadId());
    record.TimestampUnixMs = RollbackGuardGetUnixTimeMs();
    record.Flags = 0;

    record.ProcessPath[0] = '\0';

    PCUNICODE_STRING objectName = nullptr;
    const NTSTATUS keyStatus = CmCallbackGetKeyObjectIDEx(
        &g_RegistryCookie,
        keyObject,
        nullptr,
        &objectName,
        0);

    if (NT_SUCCESS(keyStatus))
    {
        RollbackGuardBuildRegistryTarget(objectName, valueName, record.TargetPath);
        CmCallbackReleaseKeyObjectIDEx(objectName);
    }
    else
    {
        RollbackGuardCopyUnicodeToAnsiBuffer(valueName, record.TargetPath, ROLLBACKGUARD_PATH_CHARS);
    }

    record.SourcePath[0] = '\0';

    RollbackGuardQueueEvent(&record);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS RegisterRegistryMonitor(PROLLBACKGUARD_DEVICE_CONTEXT context)
{
    NTSTATUS status = CmRegisterCallback(RollbackGuardRegistryCallback, context, &g_RegistryCookie);
    if (NT_SUCCESS(status))
    {
        g_RegistryCallbackRegistered = TRUE;
    }

    return status;
}

_Use_decl_annotations_
VOID UnregisterRegistryMonitor(PROLLBACKGUARD_DEVICE_CONTEXT context)
{
    UNREFERENCED_PARAMETER(context);

    if (g_RegistryCallbackRegistered)
    {
        CmUnRegisterCallback(g_RegistryCookie);
        g_RegistryCallbackRegistered = FALSE;
        g_RegistryCookie.QuadPart = 0;
    }
}
