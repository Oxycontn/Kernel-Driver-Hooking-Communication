#include "Functions.h"

PDEVICE_OBJECT pDeviceObject;
UNICODE_STRING dev, dos;

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);
	UNREFERENCED_PARAMETER(pDriverObject);

	pDriverObject->DriverUnload = (PDRIVER_UNLOAD)UnloadDriver;

	DebugMessage("Driver Loaded");

	RtlInitUnicodeString(&dev, L"\\Device\\KernelDriverHooking");
	RtlInitUnicodeString(&dos, L"\\DosDevices\\KernelDriverHooking");

	IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	IoCreateSymbolicLink(&dos, &dev);

	pDeviceObject->Flags |= DO_DIRECT_IO;
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	CallHook(&Hook);

	return STATUS_SUCCESS;
}

extern "C" NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);

	DebugMessage("Driver UnLoaded");

	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(pDriverObject->DeviceObject);

	return STATUS_SUCCESS;
}