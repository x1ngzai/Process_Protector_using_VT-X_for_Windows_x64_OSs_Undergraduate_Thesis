#include "vt.h"
#include "vtasm.h"
#include "SSDT.h"
#include "ProcessLink.h"
ULONG imagename_offset = 0;
ULONG process_offset = 0;
ULONG GetImageNameOffset()
{
	ULONG nNameOffset;
	PEPROCESS process = IoGetCurrentProcess();
	for (nNameOffset = 0; nNameOffset < PAGE_SIZE - 7; nNameOffset++)
	{
		if (_stricmp("System", (PCHAR)process + nNameOffset) == 0)
		{
			KdPrint(("[vtprotect] ImageNameOffset is 0x%x", nNameOffset));
			return nNameOffset;
		}
	}
	return 0;
}
ULONG GetProcessOffset()
{
	ULONG processoffset;
	PKTHREAD thread = KeGetCurrentThread();
	PEPROCESS process = IoGetCurrentProcess();
	for (processoffset = 0x180; processoffset < PAGE_SIZE - 7; processoffset++)
	{
		if ((PEPROCESS)*(ULONG64*)((ULONG64)thread + processoffset) == process)
		{
			KdPrint(("[vtprotect] ProcessOffset is 0x%x", processoffset));
			return processoffset;
		}
	}
	return 0;

}
NTSTATUS vtCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS vtDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{

	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}


void   DriverUnload(PDRIVER_OBJECT DriverObject)
{
	StopVT();
	UNICODE_STRING Win32Device;
	RtlInitUnicodeString(&Win32Device, L"\\DosDevices\\vt");
	IoDeleteSymbolicLink(&Win32Device);
	IoDeleteDevice(DriverObject->DeviceObject);
	DeleteLink();// Delete the linked list
}
#pragma INITCODE
EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING strRegPath)
{
	UNREFERENCED_PARAMETER(strRegPath);
	UNICODE_STRING DeviceName, Win32Device;
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS status;
	unsigned i;

	RtlInitUnicodeString(&DeviceName, L"\\Device\\vtprotect");
	RtlInitUnicodeString(&Win32Device, L"\\DosDevices\\vtprotect");

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = vtDefaultHandler;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = vtCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = vtCreateClose;
	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = vtDefaultHandler;
	status = IoCreateDevice(DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&DeviceObject);
	if (!NT_SUCCESS(status))
		return status;
	if (!DeviceObject)
		return STATUS_UNEXPECTED_IO_ERROR;

	DeviceObject->Flags |= DO_DIRECT_IO;
	DeviceObject->AlignmentRequirement = FILE_WORD_ALIGNMENT;
	status = IoCreateSymbolicLink(&Win32Device, &DeviceName);

	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	imagename_offset=GetImageNameOffset();// Get the offset of ImageName relative to EPROCESS
	process_offset=GetProcessOffset();// Get the offset of EPROCESS corresponding to PKTHREAD
	
	
	SSDTInitialize();
	StartVT();
	DriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;

}