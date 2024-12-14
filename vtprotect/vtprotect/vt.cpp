
#include "vt.h"
#include "vmmentry.h"
#include "vtasm.h"
KMUTEX g_GlobalMutex;
VMX_CPU g_VMXCPU[128];



enum SEGREGS
{
	ES = 0,
	CS,
	SS,
	DS,
	FS,
	GS,
	LDTR,
	TR
};




NTSTATUS AllocateVMXRegion(ULONG64 uCPUID)
{
	PVOID pVMXONRegion;
	PVOID pVMCSRegion;
	PVOID pHostEsp;
	pVMXONRegion = ExAllocatePool(NonPagedPool, 0x1000); //4KB
	if (!pVMXONRegion)
	{
		Log("ERROR:Allocting VMXON Region Failed!", 0);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory(pVMXONRegion, 0x1000);

	pVMCSRegion = ExAllocatePool(NonPagedPool, 0x1000);
	if (!pVMCSRegion)
	{
		Log("ERROR:Allocting VMCS Region Failed!", 0);
		ExFreePool(pVMXONRegion);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory(pVMCSRegion, 0x1000);
	pHostEsp = ExAllocatePool(NonPagedPool, 0x2000);
	if (!pHostEsp)
	{
		Log("ERROR:Allocting HostEsp Failed!", 0);
		ExFreePool(pVMXONRegion);
		ExFreePool(pVMCSRegion);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory(pHostEsp, 0x2000);

	Log("TIP:VMXON Region Address", pVMXONRegion);
	Log("TIP:VMCS Region Address", pVMCSRegion);
	Log("TIP:HostEsp Address", pHostEsp);

	g_VMXCPU[uCPUID].pVMXONRegion = pVMXONRegion;
	g_VMXCPU[uCPUID].pVMXONRegion_PA = MmGetPhysicalAddress(pVMXONRegion);
	g_VMXCPU[uCPUID].pVMCSRegion = pVMCSRegion;
	g_VMXCPU[uCPUID].pVMCSRegion_PA = MmGetPhysicalAddress(pVMCSRegion);
	g_VMXCPU[uCPUID].pHostEsp = pHostEsp;
	return STATUS_SUCCESS;
}
NTSTATUS InitializeSegmentSelector(PSEGMENT_SELECTOR SegmentSelector, USHORT Selector, ULONG64 GdtBase)
{
	PSEGMENT_DESCRIPTOR2 SegDesc;

	if (!SegmentSelector)
	{
		return STATUS_INVALID_PARAMETER;
	}

	//
	// If the segment selector's T1 = 1, it indicates an entry in the LDT; this functionality is not implemented here
	//
	if (Selector & 0x4)
	{

		return STATUS_INVALID_PARAMETER;
	}

	//
	// Extract the original segment descriptor from the GDT
	//
	SegDesc = (PSEGMENT_DESCRIPTOR2)((PUCHAR)GdtBase + (Selector & ~0x7));

	//
	// Segment Selector
	//
	SegmentSelector->sel = Selector;

	//
	// Segment Base: bits 15-39 and bits 55-63
	//
	SegmentSelector->base = SegDesc->base0 | SegDesc->base1 << 16 | SegDesc->base2 << 24;

	//
	// Segment Limit: bits 0-15 and bits 47-51
	//
	SegmentSelector->limit = SegDesc->limit0 | (SegDesc->limit1attr1 & 0xf) << 16;

	//
	// Segment Attributes: bits 39-47 and bits 51-55
	//
	SegmentSelector->attributes.UCHARs = SegDesc->attr0 | (SegDesc->limit1attr1 & 0xf0) << 4;

	//
	// Here, check the DT bit in the attributes to determine whether it is a system segment descriptor or a code/data segment descriptor
	//
	if (!(SegDesc->attr0 & LA_STANDARD))
	{
		ULONG64 tmp;

		
		tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));

		SegmentSelector->base = (SegmentSelector->base & 0xffffffff) | (tmp << 32);
	}

	//
	// This is the Granularity bit of the segment limit: 1 for 4KB, 0 for 1 byte
	//
	if (SegmentSelector->attributes.fields.g)
	{
		//
		// If the granularity bit is 1, multiply by 4KB (left shift by 12 bits)
		//
		SegmentSelector->limit = (SegmentSelector->limit << 12) + 0xfff;
	}

	return STATUS_SUCCESS;
}
NTSTATUS FillGuestSelectorData(ULONG64 GdtBase, ULONG Segreg, USHORT
	Selector)
{
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG uAccessRights;

	InitializeSegmentSelector(&SegmentSelector, Selector, GdtBase);
	uAccessRights = ((PUCHAR)& SegmentSelector.attributes)[0] + (((PUCHAR)&
		SegmentSelector.attributes)[1] << 12);

	if (!Selector)
		uAccessRights |= 0x10000;

	Vmx_VmWrite(GUEST_ES_SELECTOR + Segreg * 2, Selector & 0xFFF8);
	Vmx_VmWrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.base);
	Vmx_VmWrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.limit);
	Vmx_VmWrite(GUEST_ES_AR_BYTES + Segreg * 2, uAccessRights);



	return STATUS_SUCCESS;
}
BOOLEAN IsVTEnabled()
{
	ULONG64 uRet_EAX, uRet_ECX, uRet_EDX, uRet_EBX;
	_CPUID_ECX uCPUID;
	_CR0 uCr0;
	_CR4 uCr4;
	IA32_FEATURE_CONTROL_MSR msr;
	//1. CPUID
	_CPUID(1, &uRet_EAX, &uRet_EBX, &uRet_ECX, &uRet_EDX);
	*((PULONG64)&uCPUID) = uRet_ECX;
	if (uCPUID.VMX != 1)
	{
		Log("ERROR:Your CPU doesn't support VT-x!", 0);
		return FALSE;
	}

	// 2. CR0 CR4
	*((PULONG64)&uCr0) = GetCr0();
	*((PULONG64)&uCr4) = GetCr4();

	if (uCr0.PE != 1 || uCr0.PG != 1 || uCr0.NE != 1)
	{
		Log("ERROR:VT-x is not turned on!", 0);
		return FALSE;
	}

	if (uCr4.VMXE == 1)
	{
		Log("ERROR:VT-x has been turned on by other driver!", 0);
		return FALSE;
	}

	// 3. MSR
	*((PULONG64)&msr) = ReadMsr(MSR_IA32_FEATURE_CONTROL);
	if (msr.Lock != 1)
	{
		Log("ERROR:VT-x instruction hasn't been locked!", 0);
		return FALSE;
	}
	Log("SUCCESS:Your CPU support VT-x!", 0);
	return TRUE;
}
void SetupVMXRegion(ULONG64 uCPUID)
{
	VMX_BASIC_MSR Msr;
	ULONG uRevId;
	_CR4 uCr4;
	_EFLAGS uEflags;

	RtlZeroMemory(&Msr, sizeof(Msr));

	*((PULONG64)&Msr) = ReadMsr(MSR_IA32_VMX_BASIC);
	uRevId = Msr.RevId;

	*((PULONG)g_VMXCPU[uCPUID].pVMXONRegion) = uRevId;
	*((PULONG)g_VMXCPU[uCPUID].pVMCSRegion) = uRevId;

	Log("TIP:VMX Version", uRevId);

	*((PULONG64)&uCr4) = GetCr4();
	uCr4.VMXE = 1;
	SetCr4(*((PULONG64)&uCr4));

	Vmx_VmxOn(g_VMXCPU[uCPUID].pVMXONRegion_PA.QuadPart);
	*((PULONG64)&uEflags) = GetRflags();
	if (uEflags.CF != 0)
	{
		Log("ERROR:VMXON Failed!", 0);
		return;
	}
	Log("SUCCESS:VMXON Success!", 0);
}
ULONG64 NTAPI VmxAdjustControls(
	ULONG64 Ctl,
	ULONG64 Msr
)
{
	LARGE_INTEGER MsrValue;

	MsrValue.QuadPart = ReadMsr(Msr);
	Ctl &= MsrValue.HighPart;     /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.LowPart;      /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}
EXTERN_C void NTAPI SetupVMCS(ULONG64 _rsp,ULONG64 _rip)
{
	_EFLAGS uEflags;
	ULONG64 GdtBase, IdtBase;
	SEGMENT_SELECTOR SegmentSelector;
	ULONG64 uCPUBase;
	ULONG64 uCPUID;

	uCPUID = KeGetCurrentProcessorNumber();

	Vmx_VmClear(g_VMXCPU[uCPUID].pVMCSRegion_PA.QuadPart);
	*((PULONG64)&uEflags) = GetRflags();
	if (uEflags.CF != 0 || uEflags.ZF != 0)
	{
		Log("ERROR:VMCLEAR Failed!", 0);
		return;
	}
	Log("SUCCESS:VMCLEAR Success!", 0);
	Vmx_VmPtrld(g_VMXCPU[uCPUID].pVMCSRegion_PA.QuadPart);

	GdtBase = GetGdtBase();
	IdtBase = GetIdtBase();

	//
	// 1.Guest State Area
	//
	Vmx_VmWrite(GUEST_CR0, GetCr0());
	Vmx_VmWrite(GUEST_CR3, GetCr3());
	Vmx_VmWrite(GUEST_CR4, GetCr4());

	Vmx_VmWrite(GUEST_DR7, 0x400);
	Vmx_VmWrite(GUEST_RFLAGS, GetRflags());

	FillGuestSelectorData(GdtBase, ES, (USHORT)GetEs());
	FillGuestSelectorData(GdtBase, FS, (USHORT)GetFs());
	FillGuestSelectorData(GdtBase, DS, (USHORT)GetDs());
	FillGuestSelectorData(GdtBase, CS, (USHORT)GetCs());
	FillGuestSelectorData(GdtBase, SS, (USHORT)GetSs());
	FillGuestSelectorData(GdtBase, GS, (USHORT)GetGs());
	FillGuestSelectorData(GdtBase, TR, (USHORT)GetTr());
	FillGuestSelectorData(GdtBase, LDTR, (USHORT)GetLdtr());

	Vmx_VmWrite(GUEST_CS_BASE, 0);
	Vmx_VmWrite(GUEST_DS_BASE, 0);
	Vmx_VmWrite(GUEST_ES_BASE, 0);
	Vmx_VmWrite(GUEST_SS_BASE, 0);
	Vmx_VmWrite(GUEST_FS_BASE, ReadMsr(MSR_FS_BASE));
	Vmx_VmWrite(GUEST_GS_BASE, ReadMsr(MSR_GS_BASE));
	Vmx_VmWrite(GUEST_GDTR_BASE, GdtBase);
	Vmx_VmWrite(GUEST_GDTR_LIMIT, GetGdtLimit());
	Vmx_VmWrite(GUEST_IDTR_BASE, IdtBase);
	Vmx_VmWrite(GUEST_IDTR_LIMIT, GetIdtLimit());

	Vmx_VmWrite(GUEST_IA32_DEBUGCTL, ReadMsr(MSR_IA32_DEBUGCTL));
	Vmx_VmWrite(GUEST_IA32_DEBUGCTL_HIGH, ReadMsr(MSR_IA32_DEBUGCTL) >> 32);
	Vmx_VmWrite(GUEST_IA32_EFER, ReadMsr(MSR_EFER));

	Vmx_VmWrite(GUEST_SYSENTER_CS, ReadMsr(MSR_IA32_SYSENTER_CS));
	Vmx_VmWrite(GUEST_SYSENTER_ESP, ReadMsr(MSR_IA32_SYSENTER_ESP));
	Vmx_VmWrite(GUEST_SYSENTER_EIP, ReadMsr(MSR_IA32_SYSENTER_EIP)); // KiFastCallEntry

																		 //Vmx_VmWrite(GUEST_RSP, GetGuestRSP());
																		 //Vmx_VmWrite(GUEST_RIP, GetGuestReturn());// Specify the entry point for the VMLAUNCH guest
	Vmx_VmWrite(GUEST_RSP, _rsp);
	Vmx_VmWrite(GUEST_RIP, _rip);

	Vmx_VmWrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	Vmx_VmWrite(GUEST_ACTIVITY_STATE, 0);
	Vmx_VmWrite(VMCS_LINK_POINTER, 0xffffffff);
	Vmx_VmWrite(VMCS_LINK_POINTER_HIGH, 0xffffffff);

	//
	// 2.Host State Area
	//
	Vmx_VmWrite(HOST_CR0, GetCr0());
	Vmx_VmWrite(HOST_CR3, GetCr3());
	Vmx_VmWrite(HOST_CR4, GetCr4());

	Vmx_VmWrite(HOST_ES_SELECTOR, GetEs() & 0xF8);
	Vmx_VmWrite(HOST_CS_SELECTOR, GetCs() & 0xF8);
	Vmx_VmWrite(HOST_DS_SELECTOR, GetDs() & 0xF8);
	Vmx_VmWrite(HOST_FS_SELECTOR, GetFs() & 0xF8);
	Vmx_VmWrite(HOST_GS_SELECTOR, GetGs() & 0xF8);
	Vmx_VmWrite(HOST_SS_SELECTOR, GetSs() & 0xF8);
	Vmx_VmWrite(HOST_TR_SELECTOR, GetTr() & 0xF8);


	Vmx_VmWrite(HOST_ES_SELECTOR, KGDT64_R0_DATA);
	Vmx_VmWrite(HOST_CS_SELECTOR, KGDT64_R0_CODE);
	Vmx_VmWrite(HOST_SS_SELECTOR, KGDT64_R0_DATA);
	Vmx_VmWrite(HOST_DS_SELECTOR, KGDT64_R0_DATA);
	Vmx_VmWrite(HOST_FS_SELECTOR, GetFs() & 0xf8);
	Vmx_VmWrite(HOST_GS_SELECTOR, GetGs() & 0xf8);
	Vmx_VmWrite(HOST_TR_SELECTOR, GetTr() & 0xf8);

	Vmx_VmWrite(HOST_FS_BASE, ReadMsr(MSR_FS_BASE));
	Vmx_VmWrite(HOST_GS_BASE, ReadMsr(MSR_GS_BASE));
	InitializeSegmentSelector(&SegmentSelector, (USHORT)GetTr(), GdtBase);
	Vmx_VmWrite(HOST_TR_BASE, SegmentSelector.base);

	Vmx_VmWrite(HOST_GDTR_BASE, GdtBase);
	Vmx_VmWrite(HOST_IDTR_BASE, IdtBase);

	Vmx_VmWrite(HOST_IA32_EFER, ReadMsr(MSR_EFER));
	Vmx_VmWrite(HOST_IA32_SYSENTER_CS, ReadMsr(MSR_IA32_SYSENTER_CS));
	Vmx_VmWrite(HOST_IA32_SYSENTER_ESP, ReadMsr(MSR_IA32_SYSENTER_ESP));
	Vmx_VmWrite(HOST_IA32_SYSENTER_EIP, ReadMsr(MSR_IA32_SYSENTER_EIP)); // KiFastCallEntry

	Vmx_VmWrite(HOST_RSP, ((ULONG64)g_VMXCPU[uCPUID].pHostEsp) + 0x1FFF);//8KB 0x2000
																		 //Vmx_VmWrite(HOST_RIP,(ULONG64)&VMMEntryPoint);// Define the entry point for our VMM handler

	Vmx_VmWrite(HOST_RIP, (ULONG64)&VMMEntryPoint_fuc);


	//
	// 3.Virtual Machine Execution Control Fields
	//
	Vmx_VmWrite(PIN_BASED_VM_EXEC_CONTROL, VmxAdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));

	Vmx_VmWrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	Vmx_VmWrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	Vmx_VmWrite(TSC_OFFSET, 0);
	Vmx_VmWrite(TSC_OFFSET_HIGH, 0);

	uCPUBase = VmxAdjustControls(0, MSR_IA32_VMX_PROCBASED_CTLS);

	// The following code enables the RDTSC event
	uCPUBase = VmxAdjustControls(0, MSR_IA32_VMX_PROCBASED_CTLS);
	uCPUBase |= CPU_BASED_RDTSC_EXITING;
	uCPUBase |= CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	Vmx_VmWrite(CPU_BASED_VM_EXEC_CONTROL, uCPUBase);

	ULONG64 uTemp64 = 0;
	uTemp64 |= SECONDARY_EXEC_RDTSCP;  // enable RDTSCP
	Vmx_VmWrite(SECONDARY_VM_EXEC_CONTROL, uTemp64);

	//uCPUBase |= CPU_BASED_MOV_DR_EXITING; // Intercept debug register operations
	//uCPUBase |= CPU_BASED_USE_IO_BITMAPS; // Intercept keyboard and mouse messages
	uCPUBase |= CPU_BASED_ACTIVATE_MSR_BITMAP; // Intercept MSR operations

	Vmx_VmWrite(CPU_BASED_VM_EXEC_CONTROL, uCPUBase);

	/*
	Vmx_VmWrite(IO_BITMAP_A,0);
	Vmx_VmWrite(IO_BITMAP_A_HIGH,0);
	Vmx_VmWrite(IO_BITMAP_B,0);
	Vmx_VmWrite(IO_BITMAP_B_HIGH,0);
	*/

	Vmx_VmWrite(CR3_TARGET_COUNT, 0);
	Vmx_VmWrite(CR3_TARGET_VALUE0, 0);
	Vmx_VmWrite(CR3_TARGET_VALUE1, 0);
	Vmx_VmWrite(CR3_TARGET_VALUE2, 0);
	Vmx_VmWrite(CR3_TARGET_VALUE3, 0);

	//
	// 4.VMEntry Execution Control Fields
	//
	Vmx_VmWrite(VM_ENTRY_CONTROLS, VmxAdjustControls(VM_ENTRY_IA32E_MODE | VM_ENTRY_LOAD_IA32_EFER, MSR_IA32_VMX_ENTRY_CTLS));
	Vmx_VmWrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	Vmx_VmWrite(VM_ENTRY_INTR_INFO_FIELD, 0);


	//
	// 5.VMExit Execution Control Fields
	//
	Vmx_VmWrite(VM_EXIT_CONTROLS, VmxAdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
	Vmx_VmWrite(VM_EXIT_MSR_LOAD_COUNT, 0);
	Vmx_VmWrite(VM_EXIT_MSR_STORE_COUNT, 0);

	Vmx_VmLaunch();

	g_VMXCPU[uCPUID].bVTStartSuccess = FALSE;

	Log("ERROR:VmLaunch Failed!", Vmx_VmRead(VM_INSTRUCTION_ERROR));

}




NTSTATUS StartVT()
{
	NTSTATUS status = STATUS_SUCCESS;



	KIRQL OldIrql;

	KeInitializeMutex(&g_GlobalMutex, 0);
	KeWaitForMutexObject(&g_GlobalMutex, Executive, KernelMode, FALSE, 0);
	ULONG64 uCPUID;
	for (int i = 0; i < KeNumberProcessors; i++)
	{
		KeSetSystemAffinityThreadEx((1i64 << i));

		OldIrql = KeRaiseIrqlToDpcLevel();
		//////////////////////
		if (!IsVTEnabled())goto bug;
	uCPUID = i;
		AllocateVMXRegion(uCPUID);
		SetupVMXRegion(uCPUID);

		g_VMXCPU[uCPUID].bVTStartSuccess = TRUE;

		SetupVMCS_fuc();
		
		if (g_VMXCPU[uCPUID].bVTStartSuccess)
		{
			Log("VmLaunch Success!", 1);
		}
		else
		{
			Log("ERROR:VmLaunch Failed!", Vmx_VmRead(VM_INSTRUCTION_ERROR));
		}
		///////////////////////
		Vmx_VmCall('MSR');
	bug:  KeLowerIrql(OldIrql);
		KeRevertToUserAffinityThread();
	}
	KeReleaseMutex(&g_GlobalMutex, FALSE);


	KdPrint(("StartVT"));
	return status;
}


NTSTATUS StopVT()
{


	NTSTATUS status = STATUS_SUCCESS;
	KIRQL OldIrql;

	KeInitializeMutex(&g_GlobalMutex, 0);
	KeWaitForMutexObject(&g_GlobalMutex, Executive, KernelMode, FALSE, 0);
	ULONG64 uCPUID;
	_CR4 uCr4;
	for (int i = 0; i < KeNumberProcessors; i++)
	{
		KeSetSystemAffinityThreadEx((1i64 << i));

		OldIrql = KeRaiseIrqlToDpcLevel();
		//////////////////////
		uCPUID = KeGetCurrentProcessorNumber();
		if (g_VMXCPU[uCPUID].bVTStartSuccess)
		{
			Vmx_VmCall('SVT');
			*((PULONG64)&uCr4) = GetCr4();
			uCr4.VMXE = 0;
			SetCr4(*((PULONG64)&uCr4));
			ExFreePool(g_VMXCPU[uCPUID].pVMXONRegion);
			ExFreePool(g_VMXCPU[uCPUID].pVMCSRegion);
			ExFreePool(g_VMXCPU[uCPUID].pHostEsp);

			Log("SUCCESS:This CPU has leaved VMX", uCPUID);
		}  

		KeLowerIrql(OldIrql);
		

		KeRevertToUserAffinityThread();
	}

	KeReleaseMutex(&g_GlobalMutex, FALSE);

	KdPrint(("StopVT"));
	return status;
}