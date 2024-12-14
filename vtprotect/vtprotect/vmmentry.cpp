#include "vmmentry.h"
#include "vt.h"
#include "vtasm.h"
#include "ProcessLink.h"
extern ULONG imagename_offset;
#define DirectoryTableBase 0x28
EXTERN_C ULONG64 SYS_CALL64 = 0;
#define protectcode 0x23333

void HandleCPUID(GUEST_REGS* g_GuestRegs)
{
	ULONG64 type = g_GuestRegs->rax;
	if (type == protectcode)
	{
		AddLink(IoGetCurrentProcess(), PsGetCurrentProcessId());
		KdPrint(("[vtprotect] AddLink ImageName: %s\n", (ULONG64)IoGetCurrentProcess() + imagename_offset));
		return;
	}
	_CPUID(type, &g_GuestRegs->rax, &g_GuestRegs->rbx, &g_GuestRegs->rcx, &g_GuestRegs->rdx);
	if (type == 1)
	{
		_CPUID_ECX uCPUID;
		*((PULONG64)&uCPUID) = g_GuestRegs->rcx;
		uCPUID.VMX = 0;
		*((_CPUID_ECX*)&g_GuestRegs->rcx) = uCPUID;
	}
}

void HandleInvd()
{
	_Invd();
}
bool HandleVmCall(GUEST_REGS* g_GuestRegs)
{
	if (g_GuestRegs->rax == 'SVT')
	{
		if (SYS_CALL64)
		{
			WriteMsr(MSR_LSTAR, SYS_CALL64);
		}
		Vmx_VmxOff();
		return TRUE;
	}
	if (g_GuestRegs->rax == 'MSR')
	{
		if(!SYS_CALL64)
		SYS_CALL64 = ReadMsr(MSR_LSTAR);
		WriteMsr(MSR_LSTAR, (ULONG64)sys_fuc);
		return FALSE;
	}
	return FALSE;
}

void HandleMsrRead(GUEST_REGS* g_GuestRegs)
{
	switch (g_GuestRegs->rcx)
	{
	case MSR_IA32_SYSENTER_CS:
	{
		g_GuestRegs->rax = Vmx_VmRead(GUEST_SYSENTER_CS);
		g_GuestRegs->rdx = Vmx_VmRead(GUEST_SYSENTER_CS) >> 32;
		break;
	}
	case MSR_IA32_SYSENTER_ESP:
	{
		g_GuestRegs->rax = Vmx_VmRead(GUEST_SYSENTER_ESP);
		g_GuestRegs->rdx = Vmx_VmRead(GUEST_SYSENTER_ESP) >> 32;
		break;
	}
	case MSR_IA32_SYSENTER_EIP:
	{
			g_GuestRegs->rax = Vmx_VmRead(GUEST_SYSENTER_EIP);
			g_GuestRegs->rdx = Vmx_VmRead(GUEST_SYSENTER_EIP) >> 32;
		break;
	}
	case MSR_FS_BASE:
	{
		g_GuestRegs->rax = Vmx_VmRead(GUEST_FS_BASE);
		g_GuestRegs->rdx = Vmx_VmRead(GUEST_FS_BASE) >> 32;
		break;
	}
	case MSR_GS_BASE:
	{
		g_GuestRegs->rax = Vmx_VmRead(GUEST_GS_BASE);
		g_GuestRegs->rdx = Vmx_VmRead(GUEST_GS_BASE) >> 32;
		break;
	}
	case MSR_EFER:
	{
		g_GuestRegs->rax = ReadMsr(MSR_EFER);
		g_GuestRegs->rdx = ReadMsr(MSR_EFER) >> 32;
		break;
	}
	case MSR_LSTAR:
	{
		if (SYS_CALL64)
		{
			g_GuestRegs->rax = (ULONG64)SYS_CALL64;
			g_GuestRegs->rdx = (ULONG64)SYS_CALL64 >> 32;
			break;
		}
	}
	default:
		g_GuestRegs->rax = ReadMsr(g_GuestRegs->rcx);
		g_GuestRegs->rdx = ReadMsr(g_GuestRegs->rcx) >> 32;
	}

}

void HandleMsrWrite(GUEST_REGS* g_GuestRegs)
{
	switch (g_GuestRegs->rcx)
	{
	case MSR_IA32_SYSENTER_CS:
	{
		Vmx_VmWrite(GUEST_SYSENTER_CS, g_GuestRegs->rax | (g_GuestRegs->rdx << 32));
		break;
	}
	case MSR_IA32_SYSENTER_ESP:
	{
		Vmx_VmWrite(GUEST_SYSENTER_ESP, g_GuestRegs->rax | (g_GuestRegs->rdx << 32));
		break;
	}
	case MSR_IA32_SYSENTER_EIP:  // KiFastCallEntry
	{

		Vmx_VmWrite(GUEST_SYSENTER_EIP, g_GuestRegs->rax | (g_GuestRegs->rdx << 32));
		break;
	}
	case MSR_FS_BASE:
	{
		Vmx_VmWrite(GUEST_FS_BASE, (g_GuestRegs->rax) | (g_GuestRegs->rdx << 32));
		break;
	}
	case MSR_GS_BASE:
	{
		Vmx_VmWrite(GUEST_GS_BASE, (g_GuestRegs->rax) | (g_GuestRegs->rdx << 32));
		break;
	}
	case MSR_EFER:
	{
		WriteMsr(MSR_EFER, (g_GuestRegs->rax) | (g_GuestRegs->rdx << 32));
		break;
	}
	case MSR_LSTAR:
	{
		break;
	}
	default:
		WriteMsr(g_GuestRegs->rcx, (g_GuestRegs->rax) | (g_GuestRegs->rdx << 32));
	}

}
void HandleCrAccess(GUEST_REGS* g_GuestRegs)
{
	ULONG64		movcrControlRegister;
	ULONG64		movcrAccessType;
	ULONG64		movcrOperandType;
	ULONG64		movcrGeneralPurposeRegister;
	ULONG64		movcrLMSWSourceData;
	ULONG64		ExitQualification;

	ExitQualification = Vmx_VmRead(EXIT_QUALIFICATION);
	movcrControlRegister = (ExitQualification & 0x0000000F);
	movcrAccessType = ((ExitQualification & 0x00000030) >> 4);
	movcrOperandType = ((ExitQualification & 0x00000040) >> 6);
	movcrGeneralPurposeRegister = ((ExitQualification & 0x00000F00) >> 8);

	//	Control Register Access (CR3 <-- reg32)
	//



	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 0)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs->rax);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 1)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs->rcx);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 2)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs->rdx);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 3)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs->rbx);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 4)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs->rsp);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 5)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs->rbp);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 6)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs->rsi);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 7)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs->rdi);
	}
	//	Control Register Access (reg32 <-- CR3)
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 0)
	{
		g_GuestRegs->rax = g_GuestRegs->cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 1)
	{
		g_GuestRegs->rcx = g_GuestRegs->cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 2)
	{
		g_GuestRegs->rdx = g_GuestRegs->cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 3)
	{
		g_GuestRegs->rbx = g_GuestRegs->cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 4)
	{
		g_GuestRegs->rsp = g_GuestRegs->cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 5)
	{
		g_GuestRegs->rbp = g_GuestRegs->cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 6)
	{
		g_GuestRegs->rsi = g_GuestRegs->cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 7)
	{
		g_GuestRegs->rdi = g_GuestRegs->cr3;
	}
}
void HandleRDTSC(GUEST_REGS* g_GuestRegs)
{

	_Rdtsc(&g_GuestRegs->rax, &g_GuestRegs->rdx);
}

// Work for Windows 10
void HandleRDTSCP(GUEST_REGS* g_GuestRegs)
{
	g_GuestRegs->rax = (GetTSC() & 0xFFFFFFFF);
	g_GuestRegs->rdx = (GetTSC() >> 32);
}

EXTERN_C bool VMMEntryPoint(GUEST_REGS g_GuestRegs)
{
	ULONG64 ExitReason;
	ULONG64 ExitInstructionLength;
	bool isOff =FALSE;
	ExitReason = Vmx_VmRead(VM_EXIT_REASON);
	ExitInstructionLength = Vmx_VmRead(VM_EXIT_INSTRUCTION_LEN);

	g_GuestRegs.rsp = Vmx_VmRead(GUEST_RSP);
	g_GuestRegs.rip = Vmx_VmRead(GUEST_RIP);
	g_GuestRegs.cr3 = Vmx_VmRead(GUEST_CR3);
	switch (ExitReason)
	{
	case EXIT_REASON_EXCEPTION_NMI:
	{
		break;
	}
	case EXIT_REASON_CPUID:
	{
		HandleCPUID(&g_GuestRegs);
		break;
	}
	case EXIT_REASON_INVD:
	{
		HandleInvd();
		break;
	}
	case EXIT_REASON_VMCALL:
	{
		isOff = HandleVmCall(&g_GuestRegs);
		break;
	}
	case EXIT_REASON_MSR_READ:
	{
		HandleMsrRead(&g_GuestRegs);
		break;
	}
	case EXIT_REASON_MSR_WRITE:
	{
		HandleMsrWrite(&g_GuestRegs);
		break;
	}
	case EXIT_REASON_CR_ACCESS:
	{
		HandleCrAccess(&g_GuestRegs);
		break;
	}
	case EXIT_REASON_RDTSC:  // 16
	{
		HandleRDTSC(&g_GuestRegs);
		break;
	}
	case EXIT_REASON_RDTSCP: // 51
	{
		HandleRDTSCP(&g_GuestRegs);
		break;
	}
	default:
		break;
	}

	g_GuestRegs.rip += ExitInstructionLength;
	if (!isOff)
	{
		Vmx_VmWrite(GUEST_RIP, g_GuestRegs.rip);
		Vmx_VmWrite(GUEST_RSP, g_GuestRegs.rsp);
	}
	return isOff;
}
