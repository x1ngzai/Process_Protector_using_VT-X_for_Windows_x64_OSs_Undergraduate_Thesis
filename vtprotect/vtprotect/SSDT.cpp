#include "SSDT.h"
#include "ProcessLink.h"
#include "vtasm.h"
#include "vt.h"
EXTERN_C ULONG64 FucList[500] = { 0 };
extern ULONG64 SYS_CALL64;
extern ULONG imagename_offset;
extern ULONG process_offset;
BOOLEAN Hook(char* fuc, PVOID prefuc);
void SSDTInitialize();
BOOLEAN IsSystemProcess(PEPROCESS process);
BOOLEAN IsExplorer(PEPROCESS process);
void Pre_NtGetContextThread(
	_In_       HANDLE&   hThread,
	_In_       PCONTEXT& lpContext
)
{
	if (IsSystemProcess(IoGetCurrentProcess()) || IsProtect(IoGetCurrentProcess()))return;
	PKTHREAD KThread;
	NTSTATUS state =
		ObReferenceObjectByHandle(hThread, EVENT_ALL_ACCESS,
			NULL,
			KernelMode,
			(PVOID *)&KThread,
			NULL
		);
	if (!NT_SUCCESS(state))return;
	if (!MmIsAddressValid(KThread))return;
	PEPROCESS EProcess = (PEPROCESS)*(ULONG64*)((ULONG64)KThread + process_offset);
	if (!MmIsAddressValid(EProcess))return;
	if (IsProtect(EProcess))
	{
		hThread = 0;
	}
}
void Pre_NtSetThreadContext(
	_In_       HANDLE&   hThread,
	_In_       PCONTEXT& lpContext
)
{
	if (IsSystemProcess(IoGetCurrentProcess()) || IsProtect(IoGetCurrentProcess()))return;
	PKTHREAD KThread;
	NTSTATUS state =
		ObReferenceObjectByHandle(hThread, EVENT_ALL_ACCESS,
			NULL,
			KernelMode,
			(PVOID *)&KThread,
			NULL
		);
	if (!NT_SUCCESS(state))return;
	if (!MmIsAddressValid(KThread))return;
	PEPROCESS EProcess = (PEPROCESS)*(ULONG64*)((ULONG64)KThread + process_offset);
	if (!MmIsAddressValid(EProcess))return;
	if (IsProtect(EProcess))
	{
		hThread = 0;
	}
}
void Pre_NtOpenProcess(
	_Out_    PHANDLE&            ProcessHandle,
	_In_     ACCESS_MASK&        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES& ObjectAttributes,
	_In_opt_ PCLIENT_ID&         ClientId
)
{
	if (!MmIsAddressValid(ClientId))return;
	if (IsSystemProcess(IoGetCurrentProcess()) || IsProtect(IoGetCurrentProcess()))return;
		if (IsProtect(ClientId->UniqueProcess))
		{
			ClientId->UniqueProcess = 0;
			ClientId->UniqueThread = 0;
			return;
		}
		PEPROCESS EProcess;
		NTSTATUS state=PsLookupProcessByProcessId(ClientId->UniqueProcess, &EProcess);
		if (!NT_SUCCESS(state))return;
		if (!MmIsAddressValid(EProcess))return;
		if (IsProtect(EProcess))
		{
			ClientId->UniqueProcess = 0;
			ClientId->UniqueThread = 0;
		}
}
void Pre_NtOpenThread(
	_Out_    PHANDLE&            ThreadHandle,
	_In_     ACCESS_MASK&        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES& ObjectAttributes,
	_In_opt_ PCLIENT_ID&         ClientId
)
{
	if (!MmIsAddressValid(ClientId))return;
	if (IsSystemProcess(IoGetCurrentProcess()) || IsProtect(IoGetCurrentProcess()))return;
	PKTHREAD KThread;
	NTSTATUS state=PsLookupThreadByThreadId(ClientId->UniqueThread, &KThread);
	if (!NT_SUCCESS(state))return;
	PEPROCESS EProcess = (PEPROCESS)*(ULONG64*)((ULONG64)KThread + process_offset);
	if (!MmIsAddressValid(EProcess))return;
	if (IsProtect(EProcess))
	{
		ClientId->UniqueThread = NULL;
	}

}

void Pre_NtCreateFile(
	_Out_    PHANDLE&            FileHandle,
	_In_     ACCESS_MASK&        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES& ObjectAttributes,
	_Out_    PIO_STATUS_BLOCK&   IoStatusBlock,
	_In_opt_ PLARGE_INTEGER&     AllocationSize,
	_In_     ULONG&              FileAttributes,
	_In_     ULONG&              ShareAccess,
	_In_     ULONG&              CreateDisposition,
	_In_     ULONG&              CreateOptions,
	_In_     PVOID&              EaBuffer,
	_In_     ULONG&              EaLength
)
{
	if (IsSystemProcess(IoGetCurrentProcess()) || IsProtect(IoGetCurrentProcess()))return;
    if(CreateDisposition==FILE_OPEN|| CreateDisposition == FILE_CREATE || CreateDisposition == FILE_OPEN_IF || CreateDisposition == FILE_OVERWRITE|| CreateDisposition == FILE_OVERWRITE_IF)
	if (wcsstr(ObjectAttributes->ObjectName->Buffer, L"\\csrss.exe") != NULL || wcsstr(ObjectAttributes->ObjectName->Buffer, L"\\winlogon.exe") != NULL || wcsstr(ObjectAttributes->ObjectName->Buffer, L"\\svchost.exe") != NULL || wcsstr(ObjectAttributes->ObjectName->Buffer, L"\\lsm.exe") != NULL)
	{
		ObjectAttributes =0;
	}
}
void Pre_NtOpenFile(
	_Out_ PHANDLE&            FileHandle,
	_In_  ACCESS_MASK&        DesiredAccess,
	_In_  POBJECT_ATTRIBUTES& ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK&   IoStatusBlock,
	_In_  ULONG&              ShareAccess,
	_In_  ULONG&              OpenOptions
)
{
	if (IsProtect(IoGetCurrentProcess()))return;
	     if(OpenOptions&FILE_NON_DIRECTORY_FILE)
			 if (wcsstr(ObjectAttributes->ObjectName->Buffer, L"\\csrss.exe") != NULL || wcsstr(ObjectAttributes->ObjectName->Buffer, L"\\winlogon.exe") != NULL || wcsstr(ObjectAttributes->ObjectName->Buffer, L"\\svchost.exe") != NULL || wcsstr(ObjectAttributes->ObjectName->Buffer, L"\\lsm.exe") != NULL)
		{
			ObjectAttributes = 0;
		}
}
void Pre_NtQueryInformationProcess(
	_In_      HANDLE&           ProcessHandle,
	_In_      PROCESSINFOCLASS& ProcessInformationClass,
	_Out_     PVOID&            ProcessInformation,
	_In_      ULONG&            ProcessInformationLength,
	_Out_opt_ PULONG&           ReturnLength
)
{
	if (IsSystemProcess(IoGetCurrentProcess()) || IsProtect(IoGetCurrentProcess()))return;
	PEPROCESS EProcess;
	NTSTATUS state =
		ObReferenceObjectByHandle(ProcessHandle, EVENT_ALL_ACCESS,
			NULL,
			KernelMode,
			(PVOID *)&EProcess,
			NULL
		);
	if (!NT_SUCCESS(state))return;
	if (!MmIsAddressValid(EProcess))return;
		if (IsProtect(EProcess))
		{
			ProcessHandle = 0;
		}
}
void Pre_NtQueryInformationThread(
	_In_      HANDLE&          ThreadHandle,
	_In_      THREADINFOCLASS& ThreadInformationClass,
	_Inout_   PVOID&           ThreadInformation,
	_In_      ULONG&           ThreadInformationLength,
	_Out_opt_ PULONG&          ReturnLength
)
{
	if (IsSystemProcess(IoGetCurrentProcess()) || IsProtect(IoGetCurrentProcess()))return;
	PKTHREAD KThread;
	NTSTATUS state =
		ObReferenceObjectByHandle(ThreadHandle, EVENT_ALL_ACCESS,
			NULL,
			KernelMode,
			(PVOID *)&KThread,
			NULL
		);
	if (!NT_SUCCESS(state))return;
	if (!MmIsAddressValid(KThread))return;
	PEPROCESS EProcess = (PEPROCESS)*(ULONG64*)((ULONG64)KThread + process_offset);
	if (!MmIsAddressValid(EProcess))return;
		if (IsProtect(EProcess))
		{
			ThreadHandle = 0;
		}
}
void Pre_NtDebugActiveProcess(
	_In_       HANDLE&   ProcessHandle,
	_In_       PCONTEXT& DebugObjectHandle
)
{
	if (IsProtect(IoGetCurrentProcess()))return;
	PEPROCESS EProcess;
	NTSTATUS state =
		ObReferenceObjectByHandle(ProcessHandle, EVENT_ALL_ACCESS,
			NULL,
			KernelMode,
			(PVOID *)&EProcess,
			NULL
		);
	if (!NT_SUCCESS(state))return;
	if (!MmIsAddressValid(EProcess))return;
		if (IsProtect(EProcess))
		{
			ProcessHandle = 0;
		}
}
void Pre_NtSuspendProcess(
	_In_ HANDLE& hProcess
)
{
	if (IsSystemProcess(IoGetCurrentProcess()) || IsProtect(IoGetCurrentProcess()))return;
	PEPROCESS EProcess;
	NTSTATUS state =
		ObReferenceObjectByHandle(hProcess, EVENT_ALL_ACCESS,
			NULL,
			KernelMode,
			(PVOID *)&EProcess,
			NULL
		);
	if (!NT_SUCCESS(state))return;
	if (!MmIsAddressValid(EProcess))return;
		if (IsProtect(EProcess))
		{
			hProcess = 0;
		}
}
void Pre_NtResumeProcess(
	_In_ HANDLE& hProcess
)
{
	if (IsSystemProcess(IoGetCurrentProcess())|| IsProtect(IoGetCurrentProcess()))return;
	PEPROCESS EProcess;
	NTSTATUS state =
		ObReferenceObjectByHandle(hProcess, EVENT_ALL_ACCESS,
			NULL,
			KernelMode,
			(PVOID *)&EProcess,
			NULL
		);
	if (!NT_SUCCESS(state))return;
	if (!MmIsAddressValid(EProcess))return;
		if (IsProtect(EProcess))
		{
			hProcess = 0;
		}
}
void Pre_NtSuspendThread(
	_In_      HANDLE& hThread,
	_Out_opt_ PULONG& PreviousSuspendCount
)
{
	if (IsSystemProcess(IoGetCurrentProcess()) || IsProtect(IoGetCurrentProcess()))return;
	PKTHREAD KThread;
	NTSTATUS state =
		ObReferenceObjectByHandle(hThread, EVENT_ALL_ACCESS,
			NULL,
			KernelMode,
			(PVOID *)&KThread,
			NULL
		);
	if (!NT_SUCCESS(state))return;
	if (!MmIsAddressValid(KThread))return;
	PEPROCESS EProcess = (PEPROCESS)*(ULONG64*)((ULONG64)KThread + process_offset);
	if (!MmIsAddressValid(EProcess))return;
		if (IsProtect(EProcess) )
		{
			hThread = 0;
		}
}
void Pre_NtResumeThread(
	_In_      HANDLE& hThread,
	_Out_opt_ PULONG& PreviousSuspendCount
)
{
	if (IsSystemProcess(IoGetCurrentProcess()) || IsProtect(IoGetCurrentProcess()))return;
	PKTHREAD KThread;
	NTSTATUS state =
		ObReferenceObjectByHandle(hThread, EVENT_ALL_ACCESS,
			NULL,
			KernelMode,
			(PVOID *)&KThread,
			NULL
		);
	if (!NT_SUCCESS(state))return;
	if (!MmIsAddressValid(KThread))return;
	PEPROCESS EProcess = (PEPROCESS)*(ULONG64*)((ULONG64)KThread + process_offset);
	if (!MmIsAddressValid(EProcess))return;
		if (IsProtect(EProcess))
		{
			hThread = 0;
		}
}
void Pre_NtTerminateProcess(
	_In_opt_ HANDLE&   ProcessHandle,
	_In_     NTSTATUS& ExitStatus
)
{
	if (IsSystemProcess(IoGetCurrentProcess()) || IsProtect(IoGetCurrentProcess()))return;
	PEPROCESS EProcess;
	NTSTATUS state =
		ObReferenceObjectByHandle(ProcessHandle, EVENT_ALL_ACCESS,
			NULL,
			KernelMode,
			(PVOID *)&EProcess,
			NULL
		);
	if (!NT_SUCCESS(state))return;
	if (!MmIsAddressValid(EProcess))return;
		if (IsProtect(EProcess))
		{
			ProcessHandle = 0;
		}
}
void Pre_NtAllocateVirtualMemory(
	_In_    HANDLE&    ProcessHandle,
	_Inout_ PVOID*&    BaseAddress,
	_In_    ULONG_PTR& ZeroBits,
	_Inout_ PSIZE_T&   RegionSize,
	_In_    ULONG&     AllocationType,
	_In_    ULONG&     Protect
)
{
	if (IsSystemProcess(IoGetCurrentProcess()) || IsProtect(IoGetCurrentProcess()))return;
	PEPROCESS EProcess;
	NTSTATUS state =
		ObReferenceObjectByHandle(ProcessHandle, EVENT_ALL_ACCESS,
			NULL,
			KernelMode,
			(PVOID *)&EProcess,
			NULL
		);
	if (!NT_SUCCESS(state))return;
	if (!MmIsAddressValid(EProcess))return;
	if (IsProtect(EProcess))
	{
		ProcessHandle = 0;
	}
}
void Pre_NtWriteVirtualMemory(
	_In_      HANDLE& ProcessHandle,
	_In_      PVOID&  BaseAddress,
	_In_      PVOID&  Buffer,
	_In_      ULONG&  NumberOfBytesToWrite,
	_Out_opt_ PULONG& NumberOfBytesWritten
)
{
	if (IsSystemProcess(IoGetCurrentProcess()) || IsProtect(IoGetCurrentProcess()))return;
	PEPROCESS EProcess;
	NTSTATUS state =
		ObReferenceObjectByHandle(ProcessHandle, EVENT_ALL_ACCESS,
			NULL,
			KernelMode,
			(PVOID *)&EProcess,
			NULL
		);
	if (!NT_SUCCESS(state))return;
	if (!MmIsAddressValid(EProcess))return;
	if (IsProtect(EProcess))
	{
		ProcessHandle = 0;
	}
}
void Pre_NtReadVirtualMemory(
	_In_      HANDLE& ProcessHandle,
	_In_      PVOID&  BaseAddress,
	_In_      PVOID&  Buffer,
	_In_      ULONG&  NumberOfBytesToRead,
	_Out_opt_ PULONG& NumberOfBytesReaded
) 
{
	if (IsSystemProcess(IoGetCurrentProcess()) || IsProtect(IoGetCurrentProcess()))return;
	PEPROCESS EProcess;
	NTSTATUS state =
		ObReferenceObjectByHandle(ProcessHandle, EVENT_ALL_ACCESS,
			NULL,
			KernelMode,
			(PVOID *)&EProcess,
			NULL
		);
	if (!NT_SUCCESS(state))return;
	if (!MmIsAddressValid(EProcess))return;
	if (IsProtect(EProcess))
	{
		ProcessHandle = 0;
	}
}

USHORT GetSSDTIndex(char* fuc)
{
	NTSTATUS Status;
	HANDLE FileHandle;
	IO_STATUS_BLOCK ioStatus;
	FILE_STANDARD_INFORMATION FileInformation;
	//Set ntdll.dll path
	UNICODE_STRING uniFileName;
	RtlInitUnicodeString(&uniFileName, L"\\SystemRoot\\System32\\ntdll.dll");
	//Initialize the properties of the file
	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, &uniFileName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	//Create file
	Status = IoCreateFile(&FileHandle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &objectAttributes,
		&ioStatus, 0, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
	if (!NT_SUCCESS(Status))
	{
		Log("IoCreateFile failed!", Status);
		return false;
	}
	
	//Get file information
	Status = ZwQueryInformationFile(FileHandle, &ioStatus, &FileInformation,
		sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(Status))
	{
		Log("ZwQueryInformationFile failed!", Status);
		ZwClose(FileHandle);
		return false;
	}
	//Check if file size too big
	if (FileInformation.EndOfFile.HighPart != 0)
	{
		Log("ntdll's file size is too big", 0);
		ZwClose(FileHandle);
		return false;
	}
	//Get the size of the file
	ULONG FileSize = FileInformation.EndOfFile.LowPart;
	//Allocate memory
	PVOID File_Buffer = ExAllocatePool(PagedPool, FileSize);
	if (File_Buffer == NULL)
	{
		Log("File_Buffer ExAllocatePool() == NULL", 0);
		ZwClose(FileHandle);
		return false;
	}
	//Read and map the PE file into memory
	LARGE_INTEGER byteOffset;
	byteOffset.LowPart = 0;
	byteOffset.HighPart = 0;
	Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &ioStatus, File_Buffer, FileSize, &byteOffset, NULL);
	if (!NT_SUCCESS(Status))
	{
		Log("ZwReadFile failed!", Status);
		ZwClose(FileHandle);
		return false;
	}
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS64 NtHeaders;
	PIMAGE_SECTION_HEADER SectionHeader;
	DosHeader = (PIMAGE_DOS_HEADER)File_Buffer;
	NtHeaders = (PIMAGE_NT_HEADERS64)((ULONG64)DosHeader + DosHeader->e_lfanew);
	ULONG ImageSize = NtHeaders->OptionalHeader.SizeOfImage;
	PVOID Image_Buffer = ExAllocatePool(PagedPool, ImageSize);
	if (Image_Buffer == NULL)
	{
		Log("Image_Buffer ExAllocatePool() == NULL", 0);
		ExFreePool(File_Buffer);
		ZwClose(FileHandle);
		return FALSE;
	}
	RtlCopyMemory(Image_Buffer, File_Buffer, NtHeaders->OptionalHeader.SizeOfHeaders);
	DosHeader = (PIMAGE_DOS_HEADER)Image_Buffer;
	NtHeaders = (PIMAGE_NT_HEADERS64)((ULONG64)DosHeader + DosHeader->e_lfanew);
	SectionHeader = (PIMAGE_SECTION_HEADER)((ULONG64)NtHeaders + sizeof(IMAGE_NT_HEADERS64));
	for (int current = 0; current < NtHeaders->FileHeader.NumberOfSections; current++)
	{
		PVOID pDest = (PVOID)((ULONG64)Image_Buffer + SectionHeader[current].VirtualAddress);
		PVOID pSrc = (PVOID)((ULONG64)File_Buffer + SectionHeader[current].PointerToRawData);
		ULONG SectionSize = SectionHeader[current].SizeOfRawData;
		if (SectionSize == 0)
		{
			if (SectionHeader[current].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
			{
				SectionSize = NtHeaders->OptionalHeader.SizeOfInitializedData;
			}
			else if (SectionHeader[current].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
			{
				SectionSize = NtHeaders->OptionalHeader.SizeOfUninitializedData;
			}
			else
			{
				continue;
			}
		}
		RtlCopyMemory(pDest, pSrc, SectionSize);
	}
	ExFreePool(File_Buffer);
	BOOLEAN isFind = FALSE;
	PIMAGE_EXPORT_DIRECTORY ExpDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG64)DosHeader);
	PULONG AddressOfNames = (PULONG)(ExpDir->AddressOfNames + (ULONG64)DosHeader);
	PULONG AddressOfFunction = (PULONG)(ExpDir->AddressOfFunctions + (ULONG64)DosHeader);
	PUSHORT AddressOfNameOrdinals = (PUSHORT)(ExpDir->AddressOfNameOrdinals + (ULONG64)DosHeader);
	USHORT SSDTIndex = 0;
	for (ULONG i = 0; i < ExpDir->NumberOfNames; i++)
	{
		char* fucname = (char*)(AddressOfNames[i] + (ULONG64)DosHeader);

		BYTE* fucadd = (BYTE*)(AddressOfFunction[AddressOfNameOrdinals[i]] + (ULONG64)DosHeader);
		if (_stricmp(fucname, fuc) == 0)
		{
			for (int i = 0; i < 0x10; i++)
			{
				if (fucadd[i] == 0xb8 && fucadd[i + 3] == 0 && fucadd[i + 4] == 0)
				{
					SSDTIndex = ((PUSHORT)fucadd)[2];
					break;
				}
			}
			KdPrint(("[vtprotect] FucName:%s   SSDTIndex:%d\n", fucname, SSDTIndex));
			isFind = TRUE;
			break;
		}
	}
	if (!isFind)
	{
		KdPrint(("[vtprotect] Can't find the FucName: %s in ntdll!\n", fuc));
	}
	ExFreePool(Image_Buffer);
	ZwClose(FileHandle);

	return SSDTIndex;
}
BOOLEAN Hook(char* fuc, PVOID prefuc)
{
	USHORT SSDTIndex = GetSSDTIndex(fuc);
	if (SSDTIndex)
	{
		FucList[SSDTIndex] = (ULONG64)prefuc;
		return TRUE;
	}
	return FALSE;
}
ULONGLONG GetKeServiceDescriptorTable64() 
{
	PUCHAR StartSearchAddress = (PUCHAR)ReadMsr(MSR_LSTAR);
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONG templong = 0;
	ULONGLONG addr = 0;
	for (i = StartSearchAddress; i<EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15) //4c8d15
			{
				memcpy(&templong, i + 3, 4);
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				return addr;
			}
		}
	}
	return 0;
}
void SSDTInitialize()
{
	Hook("NtOpenProcess", Pre_NtOpenProcess);
	Hook("NtOpenThread", Pre_NtOpenThread);
	Hook("NtCreateFile", Pre_NtCreateFile);
	Hook("NtOpenFile", Pre_NtOpenFile);
	Hook("NtGetContextThread", Pre_NtGetContextThread);
	Hook("NtSetContextThread", Pre_NtSetThreadContext);
	Hook("NtQueryInformationProcess", Pre_NtQueryInformationProcess);
	Hook("NtQueryInformationThread", Pre_NtQueryInformationThread);
	Hook("NtDebugActiveProcess", Pre_NtDebugActiveProcess);
	Hook("NtSuspendProcess", Pre_NtSuspendProcess);
	Hook("NtResumeProcess", Pre_NtResumeProcess);
	Hook("NtSuspendThread", Pre_NtSuspendThread);
	Hook("NtResumeThread", Pre_NtResumeThread);
	Hook("NtTerminateProcess", Pre_NtTerminateProcess);
	Hook("NtAllocateVirtualMemory", Pre_NtAllocateVirtualMemory);
	Hook("NtReadVirtualMemory", Pre_NtReadVirtualMemory);
	Hook("NtWriteVirtualMemory", Pre_NtWriteVirtualMemory);
}

BOOLEAN IsSystemProcess(PEPROCESS process)
{
	if (_stricmp("csrss.exe", (PCHAR)process + imagename_offset) == 0)
		return TRUE;
	if (_stricmp("winlogon.exe", (PCHAR)process + imagename_offset) == 0)
		return TRUE;
	if (_stricmp("svchost.exe", (PCHAR)process + imagename_offset) == 0)
		return TRUE;
	if (_stricmp("smss.exe", (PCHAR)process + imagename_offset) == 0)
		return TRUE;
	if (_stricmp("lsm.exe", (PCHAR)process + imagename_offset) == 0)
		return TRUE;
	return FALSE;
}