#include <ntddk.h>

PVOID g_TargetObject = NULL;
BOOLEAN g_Monitoring = TRUE;

VOID WatchdogThread(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);

    if (g_TargetObject != NULL) {
        KeWaitForSingleObject(g_TargetObject, Executive, KernelMode, FALSE, NULL);

        if (g_Monitoring) {
            KeBugCheckEx(0xDEADDEAD, 0x1337, 0, 0, 0);
        }

        ObDereferenceObject(g_TargetObject);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    HANDLE threadHandle;
    NTSTATUS status = PsCreateSystemThread(
        &threadHandle, 
        THREAD_ALL_ACCESS, 
        NULL, 
        NULL, 
        NULL, 
        WatchdogThread, 
        NULL
    );

    if (NT_SUCCESS(status)) {
        ZwClose(threadHandle);
    }

    return STATUS_SUCCESS;
}