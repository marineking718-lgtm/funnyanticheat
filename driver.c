/*
 * Minimal WDM driver entry point for anticheat.sys.
 * Build this file with the Windows Driver Kit and install it through a
 * properly signed INF/service; a driver cannot safely load itself.
 */
#include <ntddk.h>

#define ANTICHEAT_DEVICE L"\\Device\\Anticheat"
#define ANTICHEAT_DOS_NAME L"\\DosDevices\\Anticheat"
#define IOCTL_ANTICHEAT_PING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

static VOID AnticheatUnload(_In_ PDRIVER_OBJECT DriverObject);

static VOID AnticheatUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING dosName;

	RtlInitUnicodeString(&dosName, ANTICHEAT_DOS_NAME);
	IoDeleteSymbolicLink(&dosName);

	if (DriverObject->DeviceObject != NULL)
		IoDeleteDevice(DriverObject->DeviceObject);
}

static NTSTATUS AnticheatCreateClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

static NTSTATUS AnticheatCleanup(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

static NTSTATUS AnticheatDeviceControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp)
{
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

	UNREFERENCED_PARAMETER(DeviceObject);

	if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_ANTICHEAT_PING) {
		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
	} else {
		Irp->IoStatus.Information = 0;
	}

	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	UNICODE_STRING deviceName;
	UNICODE_STRING dosName;
	PDEVICE_OBJECT deviceObject = NULL;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(RegistryPath);

	RtlInitUnicodeString(&deviceName, ANTICHEAT_DEVICE);
	RtlInitUnicodeString(&dosName, ANTICHEAT_DOS_NAME);

	status = IoCreateDevice(
		DriverObject, 0, &deviceName,
		FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
	if (!NT_SUCCESS(status))
		return status;

	status = IoCreateSymbolicLink(&dosName, &deviceName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(deviceObject);
		return status;
	}

	deviceObject->Flags |= DO_BUFFERED_IO;

	DriverObject->DriverUnload = AnticheatUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = AnticheatCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = AnticheatCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = AnticheatCleanup;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AnticheatDeviceControl;
	deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	return STATUS_SUCCESS;
}
