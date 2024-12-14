#pragma once
#include "stdafx.h"
typedef union
{
	struct
	{
		unsigned PE : 1;
		unsigned MP : 1;
		unsigned EM : 1;
		unsigned TS : 1;
		unsigned ET : 1;
		unsigned NE : 1;
		unsigned Reserved_1 : 10;
		unsigned WP : 1;
		unsigned Reserved_2 : 1;
		unsigned AM : 1;
		unsigned Reserved_3 : 10;
		unsigned NW : 1;
		unsigned CD : 1;
		unsigned PG : 1;
		unsigned Reserved_64 : 32;
	};

}_CR0;

typedef union
{
	struct {
		unsigned VME : 1;
		unsigned PVI : 1;
		unsigned TSD : 1;
		unsigned DE : 1;
		unsigned PSE : 1;
		unsigned PAE : 1;
		unsigned MCE : 1;
		unsigned PGE : 1;
		unsigned PCE : 1;
		unsigned OSFXSR : 1;
		unsigned PSXMMEXCPT : 1;
		unsigned UNKONOWN_1 : 1;		//These are zero
		unsigned UNKONOWN_2 : 1;		//These are zero
		unsigned VMXE : 1;			//It's zero in normal
		unsigned Reserved : 18;		//These are zero
		unsigned Reserved_64 : 32;
	};
}_CR4;

typedef union
{
	struct
	{
		unsigned CF : 1;
		unsigned Unknown_1 : 1;	//Always 1
		unsigned PF : 1;
		unsigned Unknown_2 : 1;	//Always 0
		unsigned AF : 1;
		unsigned Unknown_3 : 1;	//Always 0
		unsigned ZF : 1;
		unsigned SF : 1;
		unsigned TF : 1;
		unsigned IF : 1;
		unsigned DF : 1;
		unsigned OF : 1;
		unsigned TOPL : 2;
		unsigned NT : 1;
		unsigned Unknown_4 : 1;
		unsigned RF : 1;
		unsigned VM : 1;
		unsigned AC : 1;
		unsigned VIF : 1;
		unsigned VIP : 1;
		unsigned ID : 1;
		unsigned Reserved : 10;	//Always 0
		unsigned Reserved_64 : 32;	//Always 0
	};
}_EFLAGS;

typedef union
{
	struct
	{
		unsigned SSE3 : 1;
		unsigned PCLMULQDQ : 1;
		unsigned DTES64 : 1;
		unsigned MONITOR : 1;
		unsigned DS_CPL : 1;
		unsigned VMX : 1;
		unsigned SMX : 1;
		unsigned EIST : 1;
		unsigned TM2 : 1;
		unsigned SSSE3 : 1;
		unsigned Reserved : 22;
		unsigned Reserved_64 : 32;
	};

}_CPUID_ECX;

typedef struct _IA32_FEATURE_CONTROL_MSR
{
	unsigned Lock : 1;		// Bit 0 is the lock bit - cannot be modified once lock is set
	unsigned Reserved1 : 1;		// Undefined
	unsigned EnableVmxon : 1;		// Bit 2. If this bit is clear, VMXON causes a general protection exception
	unsigned Reserved2 : 29;	// Undefined
	unsigned Reserved3 : 32;	// Undefined

} IA32_FEATURE_CONTROL_MSR;

typedef struct _VMX_BASIC_MSR
{
	unsigned RevId : 32;//∞Ê±æ∫≈–≈œ¢
	unsigned szVmxOnRegion : 12;
	unsigned ClearBit : 1;
	unsigned Reserved : 3;
	unsigned PhysicalWidth : 1;
	unsigned DualMonitor : 1;
	unsigned MemoryType : 4;
	unsigned VmExitInformation : 1;
	unsigned Reserved2 : 9;
} VMX_BASIC_MSR, *PVMX_BASIC_MSR;





//////////////////////////


extern "C"
{
	void   _CPUID(ULONG64 in_rax, ULONG64* out_rax, ULONG64* out_rbx, ULONG64* out_rcx, ULONG64* out_rdx);
	void  _Rdtsc(PULONG64 arg1, PULONG64 arg2);
	void  _Invd();
	ULONG64  ReadMsr(ULONG64 type);
	void  WriteMsr(ULONG64 type, ULONG64 num);
	ULONG64  GetCs();
	ULONG64  GetDs();
	ULONG64  GetEs();
	ULONG64  GetSs();
	ULONG64  GetFs();
	ULONG64  GetGs();
	ULONG64  GetCr0();
	ULONG64  GetCr3();
	ULONG64  GetCr4();
	ULONG64  GetRflags();
	void  SetCr0(ULONG64 arg);
	void  SetCr2(ULONG64 arg);
	void  SetCr3(ULONG64 arg);
	void  SetCr4(ULONG64 arg);
	ULONG64  GetGdtBase();
	ULONG64  GetGdtLimit();
	ULONG64  GetIdtBase();
	ULONG64  GetIdtLimit();
	ULONG64  GetLdtr();
	ULONG64  GetTr();
	ULONG64  GetTSC();
	void Vmx_VmxOn(ULONG64 arg);
	void  Vmx_VmClear(ULONG64 arg);
	void  Vmx_VmPtrld(ULONG64 arg);
	void  Vmx_VmWrite(ULONG64 arg1, ULONG64 arg2);
	ULONG64  Vmx_VmRead(ULONG64 typeoferror);
	void  Vmx_VmLaunch();
	void  Vmx_VmxOff();
	void  VMMEntryPoint_fuc();
	void  SetupVMCS_fuc();
	void HandleVmCall_jmp(ULONG64 _rsp, ULONG64 _rip);
	void Vmx_VmCall(ULONG type);
	void sys_fuc();
}